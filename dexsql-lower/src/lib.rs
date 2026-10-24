//! Lower supported read-only SQL into the small relational IR.
//!
//! This crate stops before DEX-specific scan resolution. The resulting plan
//! contains named table/raw-edge leaves and textual scalar expressions; the
//! optimizer can rewrite those nodes before a resolver attaches physical slots.

use dexsql_ir::{PlanNode, ScanKind, Schema};
use sqlparser::ast::{
    Expr, GroupByExpr, JoinConstraint, JoinOperator, LimitClause, Query, Select, SelectItem,
    SetExpr, Statement, TableFactor, TableWithJoins,
};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowerError(pub String);

impl std::fmt::Display for LowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LowerError {}

/// Parse and lower exactly one read-only SELECT statement.
pub fn lower_sql(sql: &str) -> Result<PlanNode, LowerError> {
    let statements = Parser::parse_sql(&SQLiteDialect {}, sql)
        .map_err(|error| LowerError(format!("SQL parse error: {error}")))?;
    if statements.len() != 1 {
        return Err(LowerError(format!(
            "expected one SQL statement, found {}",
            statements.len()
        )));
    }
    lower_statement(&statements[0])
}

/// Lower a parsed statement. Keeping this public lets the CLI reuse its parser
/// result without reparsing a query when it starts routing plans here.
pub fn lower_statement(statement: &Statement) -> Result<PlanNode, LowerError> {
    let Statement::Query(query) = statement else {
        return Err(LowerError(
            "only read-only SELECT statements are supported".into(),
        ));
    };
    lower_query(query)
}

pub fn lower_query(query: &Query) -> Result<PlanNode, LowerError> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Err(LowerError("set operations are not lowered yet".into()));
    };
    let mut plan = lower_select(select)?;

    if let Some(order_by) = &query.order_by {
        let keys = match &order_by.kind {
            sqlparser::ast::OrderByKind::Expressions(items) => items
                .iter()
                .map(|item| item.expr.to_string())
                .collect::<Vec<_>>(),
            sqlparser::ast::OrderByKind::All(_) => {
                return Err(LowerError("ORDER BY ALL is not lowered yet".into()));
            }
        };
        if !keys.is_empty() {
            plan = PlanNode::Sort {
                input: Box::new(plan),
                keys,
            };
        }
    }
    if let Some(limit) = query.limit_clause.as_ref() {
        let (limit, offset) = parse_limit(limit)?;
        plan = PlanNode::Limit {
            input: Box::new(plan),
            limit,
            offset,
        };
    }
    Ok(plan)
}

fn lower_select(select: &Select) -> Result<PlanNode, LowerError> {
    let Some(first) = select.from.first() else {
        return Err(LowerError("SELECT has no FROM relation".into()));
    };
    let mut plan = lower_table_with_joins(first)?;
    if select.from.len() > 1 {
        return Err(LowerError(
            "comma-separated FROM relations are not lowered yet".into(),
        ));
    }
    if let Some(selection) = &select.selection {
        plan = PlanNode::Filter {
            input: Box::new(plan),
            predicate: selection.to_string(),
        };
    }

    let groups = match &select.group_by {
        GroupByExpr::Expressions(expressions, modifiers) => {
            if !modifiers.is_empty() {
                return Err(LowerError("GROUP BY modifiers are not lowered yet".into()));
            }
            expressions
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        }
        GroupByExpr::All(_) => return Err(LowerError("GROUP BY ALL is not lowered yet".into())),
    };
    let projections = select
        .projection
        .iter()
        .map(select_item_text)
        .collect::<Vec<_>>();
    let aggregates = select
        .projection
        .iter()
        .filter_map(aggregate_name)
        .collect::<Vec<_>>();
    if !groups.is_empty() || !aggregates.is_empty() {
        plan = PlanNode::Aggregate {
            input: Box::new(plan),
            groups,
            aggregates,
        };
    }
    if !projections.is_empty() {
        plan = PlanNode::Project {
            input: Box::new(plan),
            expressions: projections,
        };
    }
    Ok(plan)
}

fn lower_table_with_joins(table: &TableWithJoins) -> Result<PlanNode, LowerError> {
    let mut plan = lower_table_factor(&table.relation)?;
    for join in &table.joins {
        let right = lower_table_factor(&join.relation)?;
        let on = join_constraint_text(&join.join_operator);
        plan = PlanNode::Join {
            left: Box::new(plan),
            right: Box::new(right),
            on,
        };
    }
    Ok(plan)
}

fn join_constraint_text(operator: &JoinOperator) -> String {
    let constraint = match operator {
        JoinOperator::Join(value)
        | JoinOperator::Inner(value)
        | JoinOperator::Left(value)
        | JoinOperator::LeftOuter(value)
        | JoinOperator::Right(value)
        | JoinOperator::RightOuter(value)
        | JoinOperator::FullOuter(value)
        | JoinOperator::CrossJoin(value)
        | JoinOperator::Semi(value)
        | JoinOperator::LeftSemi(value)
        | JoinOperator::RightSemi(value)
        | JoinOperator::Anti(value)
        | JoinOperator::LeftAnti(value)
        | JoinOperator::RightAnti(value)
        | JoinOperator::StraightJoin(value) => value,
        JoinOperator::AsOf { constraint, .. } => constraint,
        JoinOperator::CrossApply => return "CROSS APPLY".into(),
        JoinOperator::OuterApply => return "OUTER APPLY".into(),
        JoinOperator::ArrayJoin => return "ARRAY JOIN".into(),
        JoinOperator::LeftArrayJoin => return "LEFT ARRAY JOIN".into(),
        JoinOperator::InnerArrayJoin => return "INNER ARRAY JOIN".into(),
    };
    match constraint {
        JoinConstraint::On(expr) => expr.to_string(),
        JoinConstraint::Using(columns) => format!(
            "USING ({})",
            columns
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        JoinConstraint::Natural => "NATURAL".into(),
        JoinConstraint::None => String::new(),
    }
}

fn lower_table_factor(factor: &TableFactor) -> Result<PlanNode, LowerError> {
    let TableFactor::Table {
        name,
        alias,
        args,
        with_hints,
        ..
    } = factor
    else {
        return Err(LowerError(format!(
            "table factor is not a base table: {factor}"
        )));
    };
    if args.is_some() || !with_hints.is_empty() {
        return Err(LowerError(
            "table functions and hints are not lowered yet".into(),
        ));
    }
    let table = name.to_string();
    let alias = alias
        .as_ref()
        .map(|value| value.name.value.clone())
        .unwrap_or_else(|| table.rsplit('.').next().unwrap_or(&table).to_owned());
    let kind = if table.eq_ignore_ascii_case("method_strings")
        || table.eq_ignore_ascii_case("method_numbers")
        || table.eq_ignore_ascii_case("method_calls")
        || table.eq_ignore_ascii_case("method_field_accesses")
        || table.eq_ignore_ascii_case("method_used_types")
    {
        ScanKind::RawEdge { table, alias }
    } else if table.eq_ignore_ascii_case("methods") {
        ScanKind::MethodView { alias }
    } else {
        ScanKind::Table { name: table, alias }
    };
    Ok(PlanNode::Scan {
        kind,
        schema: Schema::default(),
    })
}

fn select_item_text(item: &SelectItem) -> String {
    item.to_string()
}

fn aggregate_name(item: &SelectItem) -> Option<String> {
    let expression = match item {
        SelectItem::UnnamedExpr(expr)
        | SelectItem::ExprWithAlias { expr, .. }
        | SelectItem::ExprWithAliases { expr, .. } => expr,
        SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(_, _) => return None,
    };
    let Expr::Function(function) = expression else {
        return None;
    };
    let name = function.name.to_string();
    if matches!(
        name.to_ascii_lowercase().as_str(),
        "count" | "sum" | "avg" | "min" | "max" | "group_concat"
    ) {
        Some(name)
    } else {
        None
    }
}

fn parse_limit(limit: &LimitClause) -> Result<(usize, usize), LowerError> {
    use sqlparser::ast::Value;
    let (limit, offset) = match limit {
        LimitClause::LimitOffset { limit, offset, .. } => {
            (limit.as_ref(), offset.as_ref().map(|value| &value.value))
        }
        LimitClause::OffsetCommaLimit { offset, limit } => (Some(limit), Some(offset)),
    };
    let parse = |expr: Option<&Expr>, name: &str| -> Result<usize, LowerError> {
        let Some(Expr::Value(value)) = expr else {
            return Err(LowerError(format!("{name} must be a numeric literal")));
        };
        let Value::Number(number, _) = &value.value else {
            return Err(LowerError(format!("{name} must be a numeric literal")));
        };
        number
            .parse::<usize>()
            .map_err(|_| LowerError(format!("{name} is out of range: {number}")))
    };
    Ok((
        parse(limit, "LIMIT")?,
        offset.map_or(Ok(0), |expr| parse(Some(expr), "OFFSET"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{lower_sql, PlanNode, ScanKind};

    #[test]
    fn lowers_method_filter_order_limit() {
        let plan = lower_sql(
            "SELECT m.descriptor FROM methods m WHERE m.param_count = 0 ORDER BY m.descriptor LIMIT 10 OFFSET 2",
        )
        .unwrap();
        let PlanNode::Limit {
            input,
            limit,
            offset,
        } = plan
        else {
            panic!("expected limit")
        };
        assert_eq!((limit, offset), (10, 2));
        let PlanNode::Sort { input, keys } = *input else {
            panic!("expected sort")
        };
        assert_eq!(keys, ["m.descriptor"]);
        let PlanNode::Project { input, .. } = *input else {
            panic!("expected project")
        };
        let PlanNode::Filter { input, predicate } = *input else {
            panic!("expected filter")
        };
        assert_eq!(predicate, "m.param_count = 0");
        assert!(matches!(
            *input,
            PlanNode::Scan {
                kind: ScanKind::MethodView { ref alias },
                ..
            } if alias == "m"
        ));
    }

    #[test]
    fn lowers_raw_edge_and_aggregate() {
        let plan = lower_sql(
            "SELECT ms.method, count(DISTINCT ms.string_idx) FROM method_strings ms GROUP BY ms.method",
        )
        .unwrap();
        let PlanNode::Project { input, .. } = plan else {
            panic!("expected project")
        };
        let PlanNode::Aggregate {
            input,
            groups,
            aggregates,
        } = *input
        else {
            panic!("expected aggregate")
        };
        assert_eq!(groups, ["ms.method"]);
        assert_eq!(aggregates, ["count"]);
        assert!(matches!(
            *input,
            PlanNode::Scan {
                kind: ScanKind::RawEdge { ref table, .. },
                ..
            } if table == "method_strings"
        ));
    }
}
