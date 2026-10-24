//! Single-relation execution without a materialized source table.
//!
//! DEX ids stay in the cache; only requested cells are decoded into a reusable
//! row. Aggregates retain one state per group instead of all group members.
use super::*;
use dexsql_cache::{ClassInfo, DexFile};
use sqlparser::ast::{Expr, FunctionArg, FunctionArgExpr, FunctionArguments, Select, SelectItem};

#[derive(Clone)]
struct Aggregate {
    key: Arc<str>,
    name: String,
    argument: Option<Expr>,
    separator: Option<Expr>,
    distinct: bool,
}

enum Accumulator {
    Count(u64),
    Numeric { count: u64, sum: f64, all_int: bool },
    Extreme(Option<Scalar>),
    Concat(Vec<Scalar>),
}
struct State {
    accumulator: Accumulator,
    seen: Option<Box<HashSet<membership::Key>>>,
}
impl State {
    fn extra_bytes(&self) -> u64 {
        self.seen.as_ref().map_or(0, |seen| seen.len() as u64 * 64)
            + match &self.accumulator {
                Accumulator::Concat(parts) => parts.len() as u64 * 32,
                _ => 0,
            }
    }
    fn new(spec: &Aggregate) -> Self {
        let accumulator = match spec.name.as_str() {
            "count" => Accumulator::Count(0),
            "sum" | "total" | "avg" => Accumulator::Numeric {
                count: 0,
                sum: 0.0,
                all_int: true,
            },
            "min" | "max" => Accumulator::Extreme(None),
            "group_concat" | "string_agg" => Accumulator::Concat(Vec::new()),
            _ => unreachable!(),
        };
        Self {
            accumulator,
            seen: spec.distinct.then(|| Box::new(HashSet::new())),
        }
    }
    fn update(&mut self, spec: &Aggregate, row: &RelRow) -> Result<(), String> {
        let value = match &spec.argument {
            Some(expr) => match eval_scalar(expr, row, &[]) {
                Ok(value) => value,
                Err(_) if spec.name == "count" => return Ok(()),
                Err(error) => return Err(error),
            },
            None => Scalar::Int(1),
        };
        if matches!(value, Scalar::Null) {
            return Ok(());
        }
        if let Some(seen) = self.seen.as_mut() {
            let key = membership::set_key(&value);
            if !seen.insert(key) {
                return Ok(());
            }
        }
        match &mut self.accumulator {
            Accumulator::Count(count) => *count += 1,
            Accumulator::Numeric {
                count,
                sum,
                all_int,
            } => {
                *count += 1;
                *sum += value.numeric().unwrap_or(0.0);
                *all_int &= matches!(value, Scalar::Int(_));
            }
            Accumulator::Extreme(extreme) => {
                let replace = extreme.as_ref().is_none_or(|old| {
                    let order = compare_scalar(&value, old);
                    if spec.name == "min" {
                        order.is_lt()
                    } else {
                        order.is_gt()
                    }
                });
                if replace {
                    *extreme = Some(value);
                }
            }
            Accumulator::Concat(parts) => parts.push(value),
        }
        Ok(())
    }
    fn finish(&self, spec: &Aggregate, row: &RelRow) -> Result<Scalar, String> {
        Ok(match &self.accumulator {
            Accumulator::Count(count) => Scalar::Int(*count as i64),
            Accumulator::Numeric { count: 0, .. } if spec.name != "total" => Scalar::Null,
            Accumulator::Numeric {
                sum, all_int: true, ..
            } if spec.name == "sum" => Scalar::Int(*sum as i64),
            Accumulator::Numeric { sum, count, .. } if spec.name == "avg" => {
                aggregate_real_scalar(*sum / *count as f64)
            }
            Accumulator::Numeric { sum, .. } => scalar_functions::real_scalar(*sum),
            Accumulator::Extreme(value) => value.clone().unwrap_or(Scalar::Null),
            Accumulator::Concat(parts) if parts.is_empty() => Scalar::Null,
            Accumulator::Concat(parts) => {
                let separator = match &spec.separator {
                    Some(expr) => scalar_text(&eval_scalar(expr, row, &[])?)
                        .ok_or("group_concat separator must be text")?,
                    None => ",".to_owned(),
                };
                let mut parts = parts.clone();
                if spec.distinct {
                    parts.sort_by(compare_scalar);
                }
                Scalar::text(
                    parts
                        .iter()
                        .filter_map(scalar_text)
                        .collect::<Vec<_>>()
                        .join(&separator),
                )
            }
        })
    }
}

// Visit the expression forms evaluated by the scalar executor. Unknown AST
// forms fall back to generic execution before any source rows are consumed.
pub(super) fn walk(expr: &mut Expr, f: &mut impl FnMut(&mut Expr) -> Option<bool>) -> Option<()> {
    if f(expr)? {
        return Some(());
    }
    match expr {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_) => {}
        Expr::Nested(expr)
        | Expr::UnaryOp { expr, .. }
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::IsTrue(expr)
        | Expr::IsNotTrue(expr)
        | Expr::IsFalse(expr)
        | Expr::IsNotFalse(expr) => walk(expr, f)?,
        Expr::BinaryOp { left, right, .. } => {
            walk(left, f)?;
            walk(right, f)?;
        }
        Expr::InList { expr, list, .. } => {
            walk(expr, f)?;
            for expr in list {
                walk(expr, f)?;
            }
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            walk(expr, f)?;
            walk(low, f)?;
            walk(high, f)?;
        }
        Expr::Like {
            expr,
            pattern,
            escape_char,
            ..
        }
        | Expr::ILike {
            expr,
            pattern,
            escape_char,
            ..
        } => {
            walk(expr, f)?;
            walk(pattern, f)?;
            if let Some(expr) = escape_char {
                walk(expr, f)?;
            }
        }
        Expr::Substring {
            expr,
            substring_from,
            substring_for,
            ..
        } => {
            walk(expr, f)?;
            if let Some(expr) = substring_from {
                walk(expr, f)?;
            }
            if let Some(expr) = substring_for {
                walk(expr, f)?;
            }
        }
        Expr::Trim {
            expr,
            trim_what,
            trim_characters,
            ..
        } => {
            walk(expr, f)?;
            if let Some(expr) = trim_what {
                walk(expr, f)?;
            }
            for expr in trim_characters.iter_mut().flatten() {
                walk(expr, f)?;
            }
        }
        Expr::Function(function) => {
            if function.over.is_some()
                || function.filter.is_some()
                || !function.within_group.is_empty()
            {
                return None;
            }
            let FunctionArguments::List(args) = &mut function.args else {
                return None;
            };
            if !args.clauses.is_empty() {
                return None;
            }
            for arg in &mut args.args {
                match arg {
                    FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => walk(expr, f)?,
                    _ => return None,
                }
            }
        }
        _ => return None,
    }
    Some(())
}

fn rewrite(
    expr: &mut Expr,
    alias: &str,
    specs: &mut Vec<Aggregate>,
    needed: &mut HashSet<String>,
    allow_aggregate: bool,
) -> Option<()> {
    walk(expr, &mut |expr| {
        match expr {
            Expr::Identifier(id) => {
                needed.insert(id.value.to_ascii_lowercase());
            }
            Expr::CompoundIdentifier(ids) => {
                if ids.len() != 2
                    || (!alias.is_empty() && !ids[0].value.eq_ignore_ascii_case(alias))
                {
                    return None;
                }
                needed.insert(if alias.is_empty() {
                    format!("{}.{}", ids[0].value, ids[1].value).to_ascii_lowercase()
                } else {
                    ids[1].value.to_ascii_lowercase()
                });
            }
            Expr::Function(function) => {
                let name = function.name.0.last()?.to_string().to_ascii_lowercase();
                let FunctionArguments::List(args) = &function.args else {
                    return None;
                };
                let aggregate = matches!(
                    name.as_str(),
                    "count" | "sum" | "total" | "avg" | "group_concat" | "string_agg"
                ) || matches!(name.as_str(), "min" | "max") && args.args.len() == 1;
                if !aggregate {
                    return Some(false);
                }
                if !allow_aggregate
                    || function.over.is_some()
                    || function.filter.is_some()
                    || !function.within_group.is_empty()
                    || !args.clauses.is_empty()
                {
                    return None;
                }
                let argument = match args.args.first() {
                    Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(expr))) => Some(expr.clone()),
                    Some(FunctionArg::Unnamed(FunctionArgExpr::Wildcard)) | None
                        if name == "count" =>
                    {
                        None
                    }
                    _ => return None,
                };
                let separator = match args.args.get(1) {
                    Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)))
                        if matches!(name.as_str(), "group_concat" | "string_agg") =>
                    {
                        Some(expr.clone())
                    }
                    None => None,
                    _ => return None,
                };
                if args.args.len() > 2 {
                    return None;
                }
                for mut child in argument.iter().chain(separator.iter()).cloned() {
                    rewrite(&mut child, alias, specs, needed, false)?;
                }
                let encoded = function
                    .to_string()
                    .as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let key = intern_rel_component(&format!("\0aggregate:{encoded}"));
                if !specs.iter().any(|spec| spec.key == key) {
                    specs.push(Aggregate {
                        key: key.clone(),
                        name,
                        argument,
                        separator,
                        distinct: args.duplicate_treatment
                            == Some(sqlparser::ast::DuplicateTreatment::Distinct),
                    });
                }
                *expr = Expr::Identifier(sqlparser::ast::Ident::new(key.as_ref()));
                return Some(true);
            }
            _ => {}
        }
        Some(false)
    })
}

struct Group {
    values: Vec<Scalar>,
    states: Vec<State>,
}

pub(super) fn supports_table(table: &str) -> bool {
    matches!(
        table,
        "methods"
            | "classes"
            | "fields"
            | "method_strings"
            | "method_calls"
            | "method_field_accesses"
            | "method_used_types"
            | "method_numbers"
            | "method_using_numbers"
            | "dex_files"
            | "strings"
            | "type_ids"
            | "types"
            | "type_lists"
            | "type_list_entries"
            | "proto_ids"
            | "protos"
            | "proto_params"
            | "field_ids"
            | "method_ids"
    )
}

pub(super) fn execute(
    query: &sqlparser::ast::Query,
    select: &Select,
    ds: &Dataset,
    caches: &NamedCaches,
    cli_limit: Option<u64>,
) -> Option<Result<SelectOutput, String>> {
    if select.from.len() != 1 || !select.from[0].joins.is_empty() {
        return None;
    }
    let sqlparser::ast::TableFactor::Table {
        name, alias, args, ..
    } = &select.from[0].relation
    else {
        return None;
    };
    if args.is_some() || name.0.len() != 1 {
        return None;
    }
    let table = name.0.last()?.as_ident()?.value.to_ascii_lowercase();
    if caches.has_definition(&table)
        || caches.tables.borrow().contains_key(&table)
        || !supports_table(&table)
    {
        return None;
    }
    let schema = dexsql_schema::TABLES
        .iter()
        .find(|schema| schema.name == table)?
        .columns
        .iter()
        .map(|column| column.name.to_owned())
        .collect::<Vec<_>>();
    let alias = alias
        .as_ref()
        .map(|alias| alias.name.value.as_str())
        .unwrap_or(&table);
    let scan_predicates = select
        .selection
        .as_ref()
        .and_then(|expr| push_predicates(expr, alias))
        .map(|predicates| {
            predicates
                .into_iter()
                .filter(|predicate| {
                    !matches!(predicate.kind, PushPredicateKind::In)
                        || predicate.values.len() < membership::HASH_THRESHOLD
                })
                .collect::<Vec<_>>()
        });
    execute_with_input(
        query,
        select,
        &schema,
        alias,
        cli_limit,
        |columns, visit| {
            let columns = columns.iter().map(String::as_str).collect::<Vec<_>>();
            visit_source(
                ds,
                &table,
                alias,
                &columns,
                scan_predicates.as_deref(),
                visit,
            )
        },
    )
}

/// Execute the common projection/grouping/order sink over a caller-owned row
/// stream. Qualified schema entries are full `alias.column` lookup keys.
pub(super) fn execute_input(
    query: &sqlparser::ast::Query,
    select: &Select,
    schema: &[String],
    cli_limit: Option<u64>,
    visit: impl FnOnce(&[String], &mut dyn FnMut(&RelRow) -> Result<bool, String>) -> Result<(), String>,
) -> Option<Result<SelectOutput, String>> {
    execute_with_input(query, select, schema, "", cli_limit, visit)
}

fn execute_with_input(
    query: &sqlparser::ast::Query,
    select: &Select,
    schema: &[String],
    alias: &str,
    cli_limit: Option<u64>,
    visit_input: impl FnOnce(
        &[String],
        &mut dyn FnMut(&RelRow) -> Result<bool, String>,
    ) -> Result<(), String>,
) -> Option<Result<SelectOutput, String>> {
    if select.prewhere.is_some()
        || !select.lateral_views.is_empty()
        || !select.connect_by.is_empty()
        || !select.cluster_by.is_empty()
        || !select.distribute_by.is_empty()
        || !select.sort_by.is_empty()
        || !select.named_window.is_empty()
        || select.qualify.is_some()
        || select.value_table_mode.is_some()
        || select
            .distinct
            .as_ref()
            .is_some_and(|value| !matches!(value, sqlparser::ast::Distinct::Distinct))
    {
        return None;
    }
    let mut projection = Vec::new();
    for item in &select.projection {
        match item {
            SelectItem::UnnamedExpr(expr) => {
                projection.push((expr.clone(), expression_label(expr)))
            }
            SelectItem::ExprWithAlias { expr, alias } => {
                projection.push((expr.clone(), alias.value.clone()))
            }
            SelectItem::Wildcard(options)
                if !alias.is_empty() && *options == Default::default() =>
            {
                for column in schema {
                    projection.push((
                        Expr::Identifier(sqlparser::ast::Ident::new(column)),
                        column.clone(),
                    ));
                }
            }
            SelectItem::QualifiedWildcard(
                sqlparser::ast::SelectItemQualifiedWildcardKind::ObjectName(name),
                options,
            ) if !alias.is_empty()
                && *options == Default::default()
                && name.to_string().eq_ignore_ascii_case(alias) =>
            {
                for column in schema {
                    projection.push((
                        Expr::Identifier(sqlparser::ast::Ident::new(column)),
                        column.clone(),
                    ));
                }
            }
            _ => return None,
        }
    }
    let mut group_exprs = match &select.group_by {
        sqlparser::ast::GroupByExpr::Expressions(exprs, modifiers) if modifiers.is_empty() => {
            exprs.clone()
        }
        _ => return None,
    };
    let mut selection = select.selection.clone();
    let mut having = select.having.clone();
    let mut orders = match &query.order_by {
        Some(order) => match &order.kind {
            sqlparser::ast::OrderByKind::Expressions(exprs) if order.interpolate.is_none() => exprs
                .iter()
                .map(|order| order.expr.clone())
                .collect::<Vec<_>>(),
            _ => return None,
        },
        None => Vec::new(),
    };
    let mut specs = Vec::new();
    let mut needed = HashSet::new();
    for expr in selection.iter_mut().chain(group_exprs.iter_mut()) {
        rewrite(expr, alias, &mut specs, &mut needed, false)?;
    }
    for (expr, _) in &mut projection {
        rewrite(expr, alias, &mut specs, &mut needed, true)?;
    }
    // Output aliases are visible in HAVING/ORDER BY, but do not require source cells.
    let mut alias_needed = HashSet::new();
    for expr in having.iter_mut().chain(orders.iter_mut()) {
        rewrite(expr, alias, &mut specs, &mut alias_needed, true)?;
    }
    needed.extend(alias_needed.into_iter().filter(|name| {
        !projection
            .iter()
            .any(|(_, label)| label.eq_ignore_ascii_case(name))
    }));
    if needed
        .iter()
        .any(|name| !schema.iter().any(|column| column == name))
    {
        return None;
    }
    let membership_scope = membership::Scope::new();
    for expr in selection
        .iter_mut()
        .chain(group_exprs.iter_mut())
        .chain(projection.iter_mut().map(|(expr, _)| expr))
        .chain(having.iter_mut())
        .chain(orders.iter_mut())
        .chain(
            specs
                .iter_mut()
                .flat_map(|spec| spec.argument.iter_mut().chain(spec.separator.iter_mut())),
        )
    {
        walk(expr, &mut |expr| {
            membership_scope.compile(expr);
            Some(false)
        })?;
    }
    let grouped = !specs.is_empty() || !group_exprs.is_empty();
    let requested = schema
        .iter()
        .filter(|name| needed.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let columns = projection
        .iter()
        .map(|(_, label)| label.clone())
        .collect::<Vec<_>>();
    // SQL OFFSET is applied by the caller; retain the first offset + limit
    // projected rows only when there is no ordering/grouping/distinct step.
    let bound = if !grouped && query.order_by.is_none() {
        let offset = query_offset_value(query.limit_clause.as_ref()).unwrap_or(0);
        match (query_limit_value(query.limit_clause.as_ref()), cli_limit) {
            (Some(sql), Some(cli)) => Some(offset.saturating_add(sql.min(cli as usize))),
            (Some(sql), None) => Some(offset.saturating_add(sql)),
            (None, Some(cli)) => Some(offset.saturating_add(cli as usize)),
            _ => None,
        }
    } else {
        None
    };
    let ordered_bound = if query.order_by.is_some() {
        let offset = query_offset_value(query.limit_clause.as_ref()).unwrap_or(0);
        match (query_limit_value(query.limit_clause.as_ref()), cli_limit) {
            (Some(sql), Some(cli)) => Some(offset.saturating_add(sql.min(cli as usize))),
            (Some(sql), None) => Some(offset.saturating_add(sql)),
            (None, Some(cli)) => Some(offset.saturating_add(cli as usize)),
            _ => None,
        }
    } else {
        None
    };
    let descending = query
        .order_by
        .as_ref()
        .and_then(|order| match &order.kind {
            sqlparser::ast::OrderByKind::Expressions(exprs) => Some(
                exprs
                    .iter()
                    .map(|order| order.options.sort == Some(sqlparser::ast::OrderBySort::Desc))
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .unwrap_or_default();
    Some((|| {
        let mut output = Vec::new();
        let mut seen = HashSet::new();
        let mut groups: HashMap<Vec<membership::Key>, Group> = HashMap::new();
        let mut aggregate_payload_bytes = 0u64;
        if grouped && group_exprs.is_empty() {
            groups.insert(
                Vec::new(),
                Group {
                    values: Vec::new(),
                    states: specs.iter().map(State::new).collect(),
                },
            );
        }
        let mut emit = |row: &RelRow, output: &mut Vec<ProjectedRow>| -> Result<(), String> {
            let values = projection
                .iter()
                .map(|(expr, _)| eval_scalar(expr, row, &[]))
                .collect::<Result<Vec<_>, _>>()?;
            if select.distinct.is_some()
                && !seen.insert(values.iter().map(membership::set_key).collect::<Vec<_>>())
            {
                return Ok(());
            }
            let mut context = if orders.is_empty() && having.is_none() {
                RelRow::default()
            } else {
                row.clone()
            };
            if !orders.is_empty() || having.is_some() {
                for ((_, label), value) in projection.iter().zip(&values) {
                    context.values.insert(
                        intern_rel_component(&label.to_ascii_lowercase()),
                        value.clone(),
                    );
                }
            }
            if having
                .as_ref()
                .is_some_and(|expr| !eval_bool(expr, &context, &[]).unwrap_or(false))
            {
                return Ok(());
            }
            let keys = orders
                .iter()
                .map(|expr| {
                    if let Expr::Value(value) = expr {
                        if let sqlparser::ast::Value::Number(value, _) = &value.value {
                            if let Ok(index) = value.parse::<usize>() {
                                return values
                                    .get(index.wrapping_sub(1))
                                    .cloned()
                                    .unwrap_or(Scalar::Null);
                            }
                        }
                    }
                    eval_scalar(expr, &context, &[]).unwrap_or(Scalar::Null)
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            output.push(ProjectedRow {
                values,
                order_row: None,
                group: Vec::new(),
                sort_keys: (!orders.is_empty()).then_some(keys),
            });
            if let Some(bound) = ordered_bound {
                // Sort bounded batches, retaining the same stable tie order as
                // a full sort while storing at most 2*k candidates.
                if output.len() >= bound.saturating_mul(2).max(1) {
                    output.sort_by(|a, b| {
                        for ((a, b), descending) in a
                            .sort_keys
                            .as_ref()
                            .unwrap()
                            .iter()
                            .zip(b.sort_keys.as_ref().unwrap())
                            .zip(&descending)
                        {
                            let order = compare_scalar(a, b);
                            let order = if *descending { order.reverse() } else { order };
                            if !order.is_eq() {
                                return order;
                            }
                        }
                        std::cmp::Ordering::Equal
                    });
                    output.truncate(bound);
                }
            }
            charge_materialized(output.len() as u64 * (columns.len().max(1) as u64 * 32))?;
            Ok(())
        };
        if bound != Some(0) {
            visit_input(&requested, &mut |row| {
                if selection
                    .as_ref()
                    .is_some_and(|expr| !eval_bool(expr, row, &[]).unwrap_or(false))
                {
                    return Ok(false);
                }
                if grouped {
                    let key = group_exprs
                        .iter()
                        .map(|expr| {
                            eval_scalar(expr, row, &[]).map(|value| membership::set_key(&value))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let group = groups.entry(key).or_insert_with(|| Group {
                        values: requested
                            .iter()
                            .map(|column| row.get(column).cloned().unwrap_or(Scalar::Null))
                            .collect(),
                        states: specs.iter().map(State::new).collect(),
                    });
                    if group.values.is_empty() {
                        group.values = requested
                            .iter()
                            .map(|column| row.get(column).cloned().unwrap_or(Scalar::Null))
                            .collect();
                    }
                    for (state, spec) in group.states.iter_mut().zip(&specs) {
                        let before = state.extra_bytes();
                        state.update(spec, row)?;
                        aggregate_payload_bytes += state.extra_bytes().saturating_sub(before);
                    }
                    charge_materialized(
                        aggregate_payload_bytes
                            + groups.len() as u64
                                * ((requested.len() + specs.len()).max(1) as u64 * 32),
                    )?;
                } else {
                    emit(row, &mut output)?;
                }
                Ok(bound.is_some_and(|bound| output.len() >= bound))
            })?;
        }
        for (_, group) in groups {
            let mut row = RelRow::with_capacity(requested.len());
            for (column, value) in requested.iter().zip(group.values) {
                if alias.is_empty() {
                    row.values.insert(intern_rel_component(column), value);
                } else {
                    row.put(alias, column, value);
                }
            }
            for (state, spec) in group.states.iter().zip(&specs) {
                row.values
                    .insert(spec.key.clone(), state.finish(spec, &row)?);
            }
            emit(&row, &mut output)?;
        }
        Ok(SelectOutput {
            columns,
            rows: output,
        })
    })())
}

#[derive(Clone, Copy)]
pub(super) enum Source<'a> {
    File,
    PoolString(u32),
    PoolType(u32),
    PoolProto(u32),
    ProtoParam {
        proto_idx: u32,
        ordinal: usize,
        type_idx: u16,
    },
    TypeList {
        off: usize,
        end: usize,
    },
    TypeListEntry {
        off: usize,
        ordinal: usize,
        type_idx: u16,
    },
    Method(u32),
    Class(&'a ClassInfo),
    Field(u32),
    String(&'a dexsql_cache::MethodStringRef),
    Call(&'a dexsql_cache::MethodCallRef),
    FieldAccess(&'a dexsql_cache::MethodFieldRef),
    Type(&'a dexsql_cache::MethodTypeRef),
    Number(&'a dexsql_cache::MethodNumberRef),
}

pub(super) struct Cells<'a> {
    file: &'a DexFile,
    strings: Vec<Option<Arc<str>>>,
    methods: Vec<Option<Arc<str>>>,
    fields: Vec<Option<Arc<str>>>,
    definitions: Vec<Option<(u32, bool)>>,
}
impl<'a> Cells<'a> {
    pub(super) fn new(
        file: &'a DexFile,
        table: &str,
        needs_definitions: bool,
        columns: &[&str],
    ) -> Self {
        let mut definitions = if needs_definitions {
            vec![None; file.methods.len()]
        } else {
            Vec::new()
        };
        if needs_definitions {
            for class in &file.classes {
                for method in &class.methods {
                    if let Some(slot) = definitions.get_mut(method.method_idx as usize) {
                        *slot = Some((method.access_flags, method.is_direct));
                    }
                }
            }
        }
        // Pool rows visit each id once, so retaining every decoded value only
        // duplicates the source pool. Reference rows benefit from memoization.
        let memoize_strings = matches!(
            table,
            "methods"
                | "classes"
                | "fields"
                | "method_strings"
                | "method_calls"
                | "method_field_accesses"
                | "method_used_types"
                | "method_numbers"
                | "method_using_numbers"
        );
        let needs_strings = memoize_strings
            && columns.iter().any(|column| {
                matches!(
                    *column,
                    "value"
                        | "name"
                        | "method_name"
                        | "method_class"
                        | "class_descriptor"
                        | "return_descriptor"
                        | "superclass_descriptor"
                        | "source_file"
                        | "type_descriptor"
                        | "callee_class"
                        | "callee_name"
                        | "field_class"
                        | "field_name"
                        | "field_type"
                ) || (*column == "descriptor" && table == "classes")
            });
        let needs_methods = match table {
            "methods" => false,
            "method_calls" => columns.contains(&"method") || columns.contains(&"callee"),
            "classes" | "fields" => false,
            _ => columns.contains(&"method"),
        };
        let needs_fields = match table {
            "method_field_accesses" => columns.contains(&"field"),
            _ => false,
        };
        Self {
            file,
            strings: if needs_strings {
                vec![None; file.strings.len()]
            } else {
                Vec::new()
            },
            methods: if needs_methods {
                vec![None; file.methods.len()]
            } else {
                Vec::new()
            },
            fields: if needs_fields {
                vec![None; file.fields.len()]
            } else {
                Vec::new()
            },
            definitions,
        }
    }
    fn string(&mut self, index: u32) -> Scalar {
        let Some(slot) = self.strings.get_mut(index as usize) else {
            return Scalar::text(self.file.string(index));
        };
        Scalar::Text(
            slot.get_or_insert_with(|| Arc::from(self.file.string(index)))
                .clone(),
        )
    }
    fn typ(&mut self, index: u32) -> Scalar {
        self.file
            .types
            .get(index as usize)
            .map(|typ| typ.descriptor_idx)
            .map(|index| self.string(index))
            .unwrap_or_else(|| Scalar::text(""))
    }
    fn method(&mut self, index: u32) -> Scalar {
        let Some(slot) = self.methods.get_mut(index as usize) else {
            return Scalar::text(self.file.method_descriptor_direct(index));
        };
        Scalar::Text(
            slot.get_or_insert_with(|| Arc::from(self.file.method_descriptor_direct(index)))
                .clone(),
        )
    }
    fn field(&mut self, index: u32) -> Scalar {
        let Some(slot) = self.fields.get_mut(index as usize) else {
            return Scalar::text(self.file.field_descriptor_direct(index));
        };
        Scalar::Text(
            slot.get_or_insert_with(|| Arc::from(self.file.field_descriptor_direct(index)))
                .clone(),
        )
    }
    pub(super) fn value(
        &mut self,
        source: Source<'_>,
        column: &str,
        opcode: Option<&(usize, String)>,
    ) -> Scalar {
        let method_idx = match source {
            Source::Method(index) => index,
            Source::String(row) => row.method_idx,
            Source::Call(row) => row.method_idx,
            Source::FieldAccess(row) => row.method_idx,
            Source::Type(row) => row.method_idx,
            Source::Number(row) => row.method_idx,
            _ => u32::MAX,
        };
        if matches!(column, "file_id" | "string_pool_id") {
            return Scalar::Int(self.file.file_id as i64);
        }
        match source {
            Source::File => {
                return match column {
                    "source_path" => {
                        Scalar::text(self.file.source_path.to_string_lossy().into_owned())
                    }
                    "entry_name" => Scalar::text(&self.file.entry_name),
                    "byte_len" | "file_size" => Scalar::Int(self.file.byte_len as i64),
                    "dex_version" => Scalar::text(&self.file.dex_version),
                    "checksum" => Scalar::Int(self.file.checksum as i64),
                    "signature_hex" => Scalar::text(&self.file.signature_hex),
                    "header_size" => Scalar::Int(self.file.header_size as i64),
                    "endian_tag" => Scalar::Int(self.file.endian_tag as i64),
                    "link_size" => Scalar::Int(read_u32_at(self.file.raw(), 44) as i64),
                    "link_off" => Scalar::Int(read_u32_at(self.file.raw(), 48) as i64),
                    "map_off" => Scalar::Int(self.file.map_off as i64),
                    "string_count" => Scalar::Int(self.file.strings.len() as i64),
                    "string_ids_off" => Scalar::Int(self.file.string_ids_off as i64),
                    "type_count" => Scalar::Int(self.file.types.len() as i64),
                    "type_ids_off" => Scalar::Int(self.file.type_ids_off as i64),
                    "proto_count" => Scalar::Int(self.file.protos.len() as i64),
                    "proto_ids_off" => Scalar::Int(self.file.proto_ids_off as i64),
                    "field_count" => Scalar::Int(self.file.fields.len() as i64),
                    "field_ids_off" => Scalar::Int(self.file.field_ids_off as i64),
                    "method_count" => Scalar::Int(self.file.methods.len() as i64),
                    "method_ids_off" => Scalar::Int(self.file.method_ids_off as i64),
                    "class_count" => Scalar::Int(self.file.classes.len() as i64),
                    "class_defs_off" => Scalar::Int(self.file.class_defs_off as i64),
                    "data_size" => Scalar::Int(self.file.data_size as i64),
                    "data_off" => Scalar::Int(self.file.data_off as i64),
                    _ => Scalar::Null,
                };
            }
            Source::PoolString(index) => {
                return match column {
                    "string_idx" => Scalar::Int(index as i64),
                    "value" => self.string(index),
                    _ => Scalar::Null,
                };
            }
            Source::PoolType(index) => {
                return match column {
                    "type_idx" => Scalar::Int(index as i64),
                    "descriptor_idx" => self
                        .file
                        .types
                        .get(index as usize)
                        .map(|typ| Scalar::Int(typ.descriptor_idx as i64))
                        .unwrap_or(Scalar::Null),
                    "descriptor" => self.typ(index),
                    "java_name" => Scalar::text(java_name(self.file.type_descriptor(index))),
                    _ => Scalar::Null,
                };
            }
            Source::PoolProto(index) => {
                let Some(proto) = self.file.protos.get(index as usize) else {
                    return Scalar::Null;
                };
                return match column {
                    "proto_idx" => Scalar::Int(index as i64),
                    "shorty_idx" => Scalar::Int(proto.shorty_idx as i64),
                    "shorty" => self.string(proto.shorty_idx),
                    "return_type_idx" => Scalar::Int(proto.return_type_idx as i64),
                    "return_descriptor" => self.typ(proto.return_type_idx),
                    "parameters_off" => Scalar::Int(read_u32_at(
                        self.file.raw(),
                        self.file.proto_ids_off as usize + index as usize * 12 + 8,
                    ) as i64),
                    "param_count" => Scalar::Int(proto.parameters.len() as i64),
                    "param_descriptors" => Scalar::text(
                        proto
                            .parameters
                            .iter()
                            .map(|index| self.file.type_descriptor(*index as u32))
                            .collect::<Vec<_>>()
                            .join(","),
                    ),
                    _ => Scalar::Null,
                };
            }
            Source::ProtoParam {
                proto_idx,
                ordinal,
                type_idx,
            } => {
                return match column {
                    "proto_idx" => Scalar::Int(proto_idx as i64),
                    "ordinal" => Scalar::Int(ordinal as i64),
                    "type_idx" => Scalar::Int(type_idx as i64),
                    "descriptor" => self.typ(type_idx as u32),
                    _ => Scalar::Null,
                };
            }
            Source::TypeList { off, end } => {
                return match column {
                    "type_list_off" => Scalar::Int(off as i64),
                    "type_list_end_off" => Scalar::Int(end as i64),
                    "size" => Scalar::Int(read_u32_at(self.file.raw(), off) as i64),
                    _ => Scalar::Null,
                };
            }
            Source::TypeListEntry {
                off,
                ordinal,
                type_idx,
            } => {
                return match column {
                    "type_list_off" => Scalar::Int(off as i64),
                    "ordinal" => Scalar::Int(ordinal as i64),
                    "type_idx" => Scalar::Int(type_idx as i64),
                    _ => Scalar::Null,
                };
            }
            _ => {}
        }
        if let Source::Class(class) = source {
            return match column {
                "class_def_idx" => Scalar::Int(class.class_def_idx as i64),
                "class_idx" => Scalar::Int(class.class_idx as i64),
                "descriptor" => self.typ(class.class_idx),
                "access_flags" => Scalar::Int(class.access_flags as i64),
                "superclass_descriptor" => class
                    .superclass_idx
                    .map(|index| self.typ(index))
                    .unwrap_or_else(|| Scalar::text("")),
                "interface_count" => Scalar::Int(class.interfaces.len() as i64),
                "field_count" => Scalar::Int(class.fields.len() as i64),
                "method_count" => Scalar::Int(class.methods.len() as i64),
                "source_file" => class
                    .source_file_idx
                    .map(|index| self.string(index))
                    .unwrap_or_else(|| Scalar::text("")),
                _ => Scalar::Null,
            };
        }
        if let Source::Field(index) = source {
            let Some(field) = self.file.fields.get(index as usize) else {
                return Scalar::Null;
            };
            return match column {
                "field_idx" => Scalar::Int(index as i64),
                "class_idx" => Scalar::Int(field.class_idx as i64),
                "class_descriptor" => self.typ(field.class_idx as u32),
                "type_idx" => Scalar::Int(field.type_idx as i64),
                "type_descriptor" => self.typ(field.type_idx as u32),
                "name" => self.string(field.name_idx),
                "name_idx" => Scalar::Int(field.name_idx as i64),
                "descriptor" => self.field(index),
                _ => Scalar::Null,
            };
        }
        let method = self.file.methods.get(method_idx as usize);
        match column {
            "method_idx" => return Scalar::Int(method_idx as i64),
            "class_idx" => {
                return Scalar::Int(method.map(|method| method.class_idx).unwrap_or(0) as i64);
            }
            "method" | "descriptor" => return self.method(method_idx),
            "method_class" | "class_descriptor" => {
                return method
                    .map(|method| method.class_idx as u32)
                    .map(|index| self.typ(index))
                    .unwrap_or_else(|| Scalar::text(""));
            }
            "name_idx" => {
                return method
                    .map(|method| Scalar::Int(method.name_idx as i64))
                    .unwrap_or(Scalar::Null);
            }
            "method_name" | "name" => {
                return method
                    .map(|method| method.name_idx)
                    .map(|index| self.string(index))
                    .unwrap_or_else(|| Scalar::text(""));
            }
            _ => {}
        }
        match source {
            Source::Method(index) => {
                let proto =
                    method.and_then(|method| self.file.protos.get(method.proto_idx as usize));
                let meta = self.definitions.get(index as usize).copied().flatten();
                match column {
                    "proto_idx" => method
                        .map(|method| Scalar::Int(method.proto_idx as i64))
                        .unwrap_or(Scalar::Null),
                    "return_descriptor" => proto
                        .map(|proto| proto.return_type_idx)
                        .map(|index| self.typ(index))
                        .unwrap_or(Scalar::Null),
                    "param_count" => proto
                        .map(|proto| Scalar::Int(proto.parameters.len() as i64))
                        .unwrap_or(Scalar::Null),
                    "param_descriptors" => proto
                        .map(|proto| {
                            Scalar::text(
                                proto
                                    .parameters
                                    .iter()
                                    .map(|index| self.file.type_descriptor(*index as u32))
                                    .collect::<Vec<_>>()
                                    .join(","),
                            )
                        })
                        .unwrap_or(Scalar::Null),
                    "access_flags" => meta
                        .map(|(flags, _)| Scalar::Int(flags as i64))
                        .unwrap_or(Scalar::Null),
                    "method_kind" => meta
                        .map(|(_, direct)| Scalar::text(if direct { "direct" } else { "virtual" }))
                        .unwrap_or(Scalar::Null),
                    "opcode_count" => meta
                        .map(|_| Scalar::Int(opcode.map(|value| value.0).unwrap_or(0) as i64))
                        .unwrap_or(Scalar::Null),
                    "opcode_hex" => opcode
                        .map(|value| Scalar::text(value.1.clone()))
                        .or_else(|| meta.map(|_| Scalar::text("")))
                        .unwrap_or(Scalar::Null),
                    _ => Scalar::Null,
                }
            }
            Source::String(row) => match column {
                "value" => self.string(row.string_idx),
                "string_idx" => Scalar::Int(row.string_idx as i64),
                _ => Scalar::Null,
            },
            Source::Call(row) => match column {
                "callee" => self.method(row.callee_method_idx),
                "callee_method_idx" => Scalar::Int(row.callee_method_idx as i64),
                "callee_class" => self
                    .file
                    .methods
                    .get(row.callee_method_idx as usize)
                    .map(|method| method.class_idx as u32)
                    .map(|index| self.typ(index))
                    .unwrap_or_else(|| Scalar::text("")),
                "callee_name" => self
                    .file
                    .methods
                    .get(row.callee_method_idx as usize)
                    .map(|method| method.name_idx)
                    .map(|index| self.string(index))
                    .unwrap_or_else(|| Scalar::text("")),
                _ => Scalar::Null,
            },
            Source::FieldAccess(row) => {
                let field = self.file.fields.get(row.field_idx as usize);
                match column {
                    "field" => self.field(row.field_idx),
                    "field_idx" => Scalar::Int(row.field_idx as i64),
                    "field_class" => field
                        .map(|field| field.class_idx as u32)
                        .map(|index| self.typ(index))
                        .unwrap_or_else(|| Scalar::text("")),
                    "field_name" => field
                        .map(|field| field.name_idx)
                        .map(|index| self.string(index))
                        .unwrap_or_else(|| Scalar::text("")),
                    "field_type" => field
                        .map(|field| field.type_idx as u32)
                        .map(|index| self.typ(index))
                        .unwrap_or_else(|| Scalar::text("")),
                    "using_type" => Scalar::text(
                        if (0x52..=0x58).contains(&row.opcode)
                            || (0x60..=0x66).contains(&row.opcode)
                        {
                            "get"
                        } else {
                            "put"
                        },
                    ),
                    _ => Scalar::Null,
                }
            }
            Source::Type(row) => match column {
                "type_descriptor" => self.typ(row.type_idx),
                "type_name" => Scalar::text(java_name(self.file.type_descriptor(row.type_idx))),
                "type_idx" => Scalar::Int(row.type_idx as i64),
                _ => Scalar::Null,
            },
            Source::Number(row) => match column {
                "number_type" => Scalar::text(number_type_label(row)),
                "opcode" => Scalar::Int(row.opcode as i64),
                "long_value" => Scalar::Int(row.long_value),
                "double_value" => row
                    .double_value
                    .map(|value| Scalar::Real(format_double_value(value)))
                    .unwrap_or(Scalar::Null),
                _ => Scalar::Null,
            },
            _ => Scalar::Null,
        }
    }
}

pub(super) fn visit_source(
    ds: &Dataset,
    table: &str,
    alias: &str,
    columns: &[&str],
    predicates: Option<&[PushPredicate]>,
    mut visit: impl FnMut(&RelRow) -> Result<bool, String>,
) -> Result<(), String> {
    visit_source_records(ds, table, alias, columns, predicates, |row, _, _| {
        visit(row)
    })
}

/// Expose the borrowed cache record alongside its reduced row. Join build
/// sides retain this record identity, then decode output cells only on match.
pub(super) fn visit_source_records<'a>(
    ds: &'a Dataset,
    table: &str,
    alias: &str,
    columns: &[&str],
    predicates: Option<&[PushPredicate]>,
    mut visit: impl FnMut(&RelRow, usize, Source<'a>) -> Result<bool, String>,
) -> Result<(), String> {
    let needs_opcode = columns
        .iter()
        .any(|column| matches!(*column, "opcode_count" | "opcode_hex"));
    let needs_opcode_hex = columns.contains(&"opcode_hex");
    let needs_definitions = needs_opcode
        || columns
            .iter()
            .any(|column| matches!(*column, "access_flags" | "method_kind"));
    for (file_index, file) in ds.files.iter().enumerate() {
        let mut cells = Cells::new(
            file,
            table,
            needs_definitions && table == "methods",
            columns,
        );
        let mut row = RelRow::with_capacity(columns.len());
        let mut consume = |source| {
            row.values.clear();
            row.columns.clear();
            let opcode = if let Source::Method(index) = source {
                if needs_opcode_hex {
                    file.method_opcode_summary(index)
                } else if needs_opcode {
                    file.method_opcode_count(index)
                        .map(|count| (count, String::new()))
                } else {
                    None
                }
            } else {
                None
            };
            if predicates.is_some_and(|predicates| {
                !predicates_match(predicates, |column| {
                    cells.value(source, column, opcode.as_ref())
                })
            }) {
                return Ok(false);
            }
            for column in columns {
                let value = cells.value(source, column, opcode.as_ref());
                row.put(alias, column, value);
            }
            visit(&row, file_index, source)
        };
        match table {
            "dex_files" => {
                if consume(Source::File)? {
                    return Ok(());
                }
            }
            "strings" => {
                for index in 0..file.strings.len() as u32 {
                    if consume(Source::PoolString(index))? {
                        return Ok(());
                    }
                }
            }
            "type_ids" | "types" => {
                for index in 0..file.types.len() as u32 {
                    if consume(Source::PoolType(index))? {
                        return Ok(());
                    }
                }
            }
            "type_lists" => {
                for (off, end) in type_list_offsets(file) {
                    if consume(Source::TypeList { off, end })? {
                        return Ok(());
                    }
                }
            }
            "type_list_entries" => {
                for (off, _) in type_list_offsets(file) {
                    let size = read_u32_at(file.raw(), off) as usize;
                    for ordinal in 0..size {
                        let type_idx = read_u16_at(file.raw(), off + 4 + ordinal * 2);
                        if consume(Source::TypeListEntry {
                            off,
                            ordinal,
                            type_idx,
                        })? {
                            return Ok(());
                        }
                    }
                }
            }
            "proto_ids" | "protos" => {
                for index in 0..file.protos.len() as u32 {
                    if consume(Source::PoolProto(index))? {
                        return Ok(());
                    }
                }
            }
            "proto_params" => {
                for (proto_idx, proto) in file.protos.iter().enumerate() {
                    for (ordinal, type_idx) in proto.parameters.iter().copied().enumerate() {
                        if consume(Source::ProtoParam {
                            proto_idx: proto_idx as u32,
                            ordinal,
                            type_idx,
                        })? {
                            return Ok(());
                        }
                    }
                }
            }
            "methods" | "method_ids" => {
                for index in 0..file.methods.len() as u32 {
                    if consume(Source::Method(index))? {
                        return Ok(());
                    }
                }
            }
            "classes" => {
                for class in &file.classes {
                    if consume(Source::Class(class))? {
                        return Ok(());
                    }
                }
            }
            "fields" | "field_ids" => {
                for index in 0..file.fields.len() as u32 {
                    if consume(Source::Field(index))? {
                        return Ok(());
                    }
                }
            }
            "method_strings" => {
                for reference in &file.method_strings {
                    if consume(Source::String(reference))? {
                        return Ok(());
                    }
                }
            }
            "method_calls" => {
                for reference in &file.method_calls {
                    if consume(Source::Call(reference))? {
                        return Ok(());
                    }
                }
            }
            "method_field_accesses" => {
                for reference in &file.method_field_accesses {
                    if consume(Source::FieldAccess(reference))? {
                        return Ok(());
                    }
                }
            }
            "method_used_types" => {
                for reference in &file.method_used_types {
                    if consume(Source::Type(reference))? {
                        return Ok(());
                    }
                }
            }
            "method_numbers" | "method_using_numbers" => {
                for reference in &file.method_numbers {
                    if consume(Source::Number(reference))? {
                        return Ok(());
                    }
                }
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Dataset {
        Dataset::load_paths(&[
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/beta.dex"),
        ])
        .unwrap()
    }
    fn parse(sql: &str) -> sqlparser::ast::Query {
        let statement =
            sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::SQLiteDialect {}, sql)
                .unwrap()
                .remove(0);
        let sqlparser::ast::Statement::Query(query) = statement else {
            panic!()
        };
        *query
    }
    #[test]
    fn streaming_matches_generic_relations_and_aggregates() {
        let ds = fixture();
        let caches = NamedCaches::default();
        let mut queries = Vec::new();
        for table in [
            "methods",
            "classes",
            "fields",
            "method_strings",
            "method_calls",
            "method_field_accesses",
            "method_used_types",
            "method_numbers",
            "method_using_numbers",
        ] {
            queries.push(format!("SELECT * FROM {table} ORDER BY file_id, 2, 3"));
            queries.push(format!("SELECT * FROM {table} ORDER BY 2 LIMIT 2 OFFSET 1"));
            queries.push(format!("SELECT count(*) AS n FROM {table}"));
            queries.push(format!("SELECT file_id,count(*),sum(method_idx),avg(method_idx),min(method_idx),max(method_idx) FROM {table} GROUP BY file_id ORDER BY file_id"));
        }
        queries.extend([
            "SELECT class_descriptor,count(*) AS n,sum(method_idx) AS total FROM methods GROUP BY class_descriptor HAVING count(*)>1 ORDER BY total DESC,class_descriptor",
            "SELECT method,count(DISTINCT string_idx) AS n FROM method_strings GROUP BY method ORDER BY method",
            "SELECT method,group_concat(value,'|') AS strings FROM method_strings GROUP BY method ORDER BY method",
            "SELECT length(group_concat(name)) AS n FROM methods",
            "SELECT 1+count(name),min(name,name),max(name,name) FROM methods",
            "SELECT DISTINCT class_descriptor FROM methods ORDER BY class_descriptor",
            "SELECT method_idx FROM methods LIMIT 0",
            "SELECT m.name, m.descriptor FROM methods m ORDER BY m.method_idx DESC LIMIT 2 OFFSET 1",
        ].into_iter().map(str::to_owned));
        for sql in queries {
            let query = parse(&sql);
            let select = query.body.as_select().unwrap();
            let Some(streamed) = execute(&query, select, &ds, &caches, None) else {
                continue;
            };
            let mut streamed = streamed.unwrap_or_else(|error| panic!("{sql}: {error}"));
            let generic = execute_select_core(select, &ds, Some(&ds), &caches, true, None, None);
            let Ok(mut generic) = generic else {
                continue;
            };
            apply_query_order_limit(&mut streamed, &query, None).unwrap();
            apply_query_order_limit(&mut generic, &query, None).unwrap();
            let render = |output: SelectOutput| {
                (
                    output.columns,
                    output
                        .rows
                        .into_iter()
                        .map(|row| row.values)
                        .collect::<Vec<_>>(),
                )
            };
            assert_eq!(render(streamed), render(generic), "{sql}");
        }
    }
    fn render(output: SelectOutput) -> (Vec<String>, Vec<Vec<Scalar>>) {
        (
            output.columns,
            output.rows.into_iter().map(|row| row.values).collect(),
        )
    }

    #[test]
    fn pool_sources_stream_and_match_materialized_scans() {
        let ds = fixture();
        let caches = NamedCaches::default();
        let mut queries = Vec::new();
        for (table, pool, index) in [
            ("dex_files", "file_id", "file_id"),
            ("strings", "string_pool_id", "string_idx"),
            ("type_ids", "file_id", "type_idx"),
            ("types", "file_id", "type_idx"),
            ("type_lists", "file_id", "type_list_off"),
            ("type_list_entries", "file_id", "ordinal"),
            ("proto_ids", "file_id", "proto_idx"),
            ("protos", "file_id", "proto_idx"),
            ("proto_params", "file_id", "ordinal"),
            ("field_ids", "file_id", "field_idx"),
            ("method_ids", "file_id", "method_idx"),
        ] {
            // Unordered full projections also compare the observable scan order.
            queries.push(format!("SELECT * FROM {table}"));
            queries.push(format!("SELECT q.* FROM {table} q LIMIT 2 OFFSET 1"));
            queries.push(format!(
                "SELECT count(*),count(DISTINCT {index}) FROM {table}"
            ));
            queries.push(format!("SELECT {pool},count(*),sum({index}),avg({index}),min({index}),max({index}) FROM {table} GROUP BY {pool} ORDER BY {pool}"));
            queries.push(format!(
                "SELECT DISTINCT {pool} FROM {table} ORDER BY {pool}"
            ));
            queries.push(format!("SELECT q.{index} AS k FROM {table} q WHERE q.{index} BETWEEN 0 AND 2 ORDER BY k DESC LIMIT 2 OFFSET 1"));
            queries.push(format!(
                "SELECT {index}+1 AS n FROM {table} WHERE {index} IN (0,1,3) ORDER BY n LIMIT 2"
            ));
            queries.push(format!("SELECT {index} FROM {table} WHERE {index}<0"));
            queries.push(format!("SELECT {index} FROM {table} LIMIT 0"));
        }
        queries.extend([
            "SELECT value,length(value) FROM strings WHERE value LIKE '%a%' ORDER BY value LIMIT 3",
            "SELECT descriptor,java_name FROM types WHERE descriptor IS NOT NULL ORDER BY java_name",
            "SELECT shorty,count(*),sum(param_count) FROM protos GROUP BY shorty HAVING count(*)>0 ORDER BY shorty",
            "SELECT param_descriptors FROM protos WHERE param_count=0 ORDER BY proto_idx",
            "SELECT descriptor,count(*) FROM proto_params GROUP BY descriptor ORDER BY descriptor",
            "SELECT name_idx,class_idx FROM method_ids WHERE name_idx>=0 ORDER BY name_idx DESC LIMIT 1",
        ].into_iter().map(str::to_owned));
        for sql in queries {
            let query = parse(&sql);
            let select = query.body.as_select().unwrap();
            let mut streamed = execute(&query, select, &ds, &caches, None)
                .unwrap_or_else(|| panic!("streaming source not selected: {sql}"))
                .unwrap_or_else(|error| panic!("streaming {sql}: {error}"));
            let mut generic =
                execute_select_core(select, &ds, Some(&ds), &caches, true, None, None)
                    .unwrap_or_else(|error| panic!("generic {sql}: {error}"));
            apply_query_order_limit(&mut streamed, &query, None).unwrap();
            apply_query_order_limit(&mut generic, &query, None).unwrap();
            assert_eq!(render(streamed), render(generic), "{sql}");
        }
    }

    #[test]
    fn pool_scans_do_not_retain_decoded_cells_or_unrelated_descriptor_caches() {
        let ds = fixture();
        let file = &ds.files[0];
        let mut strings = Cells::new(file, "strings", false, &["value"]);
        for index in 0..file.strings.len() as u32 {
            assert_eq!(strings.string(index), Scalar::text(file.string(index)));
        }
        assert!(strings.strings.is_empty());
        let mut types = Cells::new(file, "types", false, &["descriptor", "java_name"]);
        for index in 0..file.types.len() as u32 {
            assert_eq!(types.typ(index), Scalar::text(file.type_descriptor(index)));
        }
        assert!(types.strings.is_empty());
        assert!(types.methods.is_empty());
        assert!(types.fields.is_empty());
        let classes = Cells::new(file, "classes", false, &["descriptor"]);
        assert!(classes.methods.is_empty());
        assert!(classes.fields.is_empty());
        let mut methods = Cells::new(file, "methods", false, &["descriptor"]);
        for index in 0..file.methods.len() as u32 {
            assert_eq!(
                methods.method(index),
                Scalar::text(file.method_descriptor_direct(index))
            );
        }
        assert!(methods.methods.is_empty());
        assert!(methods.fields.is_empty());
        assert!(methods.strings.is_empty());
        let mut fields = Cells::new(file, "fields", false, &["descriptor"]);
        for index in 0..file.fields.len() as u32 {
            assert_eq!(
                fields.field(index),
                Scalar::text(file.field_descriptor_direct(index))
            );
        }
        assert!(fields.fields.is_empty());
        assert!(fields.methods.is_empty());
        assert!(fields.strings.is_empty());
    }

    #[test]
    fn caller_owned_input_keeps_qualified_group_cells_and_requests_only_used_columns() {
        let query = parse(
            "SELECT l.file_id,count(r.name) AS n FROM methods l JOIN methods r ON l.method_idx=r.method_idx GROUP BY l.file_id HAVING n>0 ORDER BY n DESC,l.file_id",
        );
        let schema = [
            "file_id",
            "l.file_id",
            "l.method_idx",
            "r.method_idx",
            "r.name",
        ]
        .map(str::to_owned);
        let mut output = execute_input(
            &query,
            query.body.as_select().unwrap(),
            &schema,
            None,
            |requested, visit| {
                assert_eq!(requested, &["l.file_id", "r.name"]);
                let mut row = RelRow::default();
                for (file_id, name) in [(2, "first"), (1, "second"), (2, "third")] {
                    row.values.clear();
                    row.put("l", "file_id", Scalar::Int(file_id));
                    row.put("r", "name", Scalar::text(name));
                    if visit(&row)? {
                        break;
                    }
                }
                Ok(())
            },
        )
        .unwrap()
        .unwrap();
        apply_query_order_limit(&mut output, &query, None).unwrap();
        assert_eq!(
            render(output).1,
            vec![
                vec![Scalar::Int(2), Scalar::Int(2)],
                vec![Scalar::Int(1), Scalar::Int(1)],
            ]
        );
    }

    #[test]
    fn caller_owned_input_stops_after_offset_and_limit() {
        let query = parse(
            "SELECT l.method_idx FROM methods l JOIN methods r ON l.method_idx=r.method_idx LIMIT 2 OFFSET 1",
        );
        let schema = ["l.method_idx".to_owned()];
        let mut visits = 0;
        let mut output = execute_input(
            &query,
            query.body.as_select().unwrap(),
            &schema,
            None,
            |requested, visit| {
                assert_eq!(requested, &schema);
                let mut row = RelRow::default();
                for index in 0..100 {
                    visits += 1;
                    row.values.clear();
                    row.put("l", "method_idx", Scalar::Int(index));
                    if visit(&row)? {
                        break;
                    }
                }
                Ok(())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(visits, 3);
        apply_query_order_limit(&mut output, &query, None).unwrap();
        assert_eq!(
            render(output).1,
            vec![vec![Scalar::Int(1)], vec![Scalar::Int(2)]]
        );
    }

    #[test]
    fn large_membership_lists_work_in_all_streaming_sink_positions() {
        let ds = fixture();
        let caches = NamedCaches::default();
        let numbers = (0..128)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let strings = (0..128)
            .map(|value| format!("'unused{value}'"))
            .collect::<Vec<_>>()
            .join(",");
        let queries = [
            format!("SELECT method_idx,method_idx IN ({numbers},NULL) FROM methods ORDER BY file_id,method_idx"),
            format!("SELECT method_idx FROM methods WHERE method_idx IN ({numbers}) ORDER BY file_id,method_idx"),
            format!("SELECT method_idx FROM methods WHERE method_idx NOT IN ({numbers},NULL) ORDER BY file_id,method_idx"),
            format!("SELECT method_idx FROM methods WHERE NOT (method_idx IN ({numbers},NULL)) ORDER BY file_id,method_idx"),
            format!("SELECT method_idx FROM methods WHERE name IN ({strings},'alpha') ORDER BY file_id,method_idx"),
            format!("SELECT file_id,count(method_idx IN ({numbers},NULL)) FROM methods GROUP BY file_id ORDER BY file_id"),
            format!("SELECT file_id,count(*) AS n FROM methods GROUP BY file_id HAVING count(*) IN ({numbers}) ORDER BY file_id"),
            format!("SELECT file_id,method_idx FROM methods ORDER BY method_idx IN ({numbers}) DESC,file_id,method_idx LIMIT 3"),
        ];
        for sql in queries {
            let query = parse(&sql);
            let select = query.body.as_select().unwrap();
            let mut streamed = execute(&query, select, &ds, &caches, None)
                .unwrap()
                .unwrap();
            let mut generic =
                execute_select_core(select, &ds, Some(&ds), &caches, true, None, None).unwrap();
            apply_query_order_limit(&mut streamed, &query, None).unwrap();
            apply_query_order_limit(&mut generic, &query, None).unwrap();
            assert_eq!(render(streamed), render(generic), "{sql}");
        }
    }

    #[test]
    fn named_relations_and_invalid_qualifiers_do_not_bypass_resolution() {
        let ds = fixture();
        let caches = NamedCaches::default();
        caches
            .define_session("methods", "SELECT 17 AS method_idx", false)
            .unwrap();
        let query = parse("SELECT method_idx FROM methods");
        assert!(execute(&query, query.body.as_select().unwrap(), &ds, &caches, None).is_none());
        let query = parse("SELECT other.name FROM classes c");
        assert!(execute(
            &query,
            query.body.as_select().unwrap(),
            &ds,
            &NamedCaches::default(),
            None
        )
        .is_none());
    }

    fn stream_values(sql: &str, values: &[Scalar]) -> Vec<Vec<Scalar>> {
        let query = parse(sql);
        let schema = ["k".to_owned(), "r.k".to_owned()];
        let mut output = execute_input(
            &query,
            query.body.as_select().unwrap(),
            &schema,
            None,
            |_, visit| {
                let mut row = RelRow::default();
                for value in values {
                    row.values.clear();
                    row.put("r", "k", value.clone());
                    if visit(&row)? {
                        break;
                    }
                }
                Ok(())
            },
        )
        .unwrap()
        .unwrap();
        apply_query_order_limit(&mut output, &query, None).unwrap();
        output.rows.into_iter().map(|row| row.values).collect()
    }

    #[test]
    fn grouping_merges_integer_real_keys_and_keeps_text_separate() {
        let values = [
            Scalar::Int(1),
            Scalar::Real("1.0".to_owned()),
            Scalar::text("1"),
            Scalar::Int(2),
            Scalar::Null,
            Scalar::Null,
        ];
        assert_eq!(
            stream_values(
                "SELECT k,count(*) FROM methods r GROUP BY k ORDER BY k",
                &values
            ),
            vec![
                vec![Scalar::Null, Scalar::Int(2)],
                vec![Scalar::Int(1), Scalar::Int(2)],
                vec![Scalar::Int(2), Scalar::Int(1)],
                vec![Scalar::text("1"), Scalar::Int(1)],
            ]
        );
        let ds = fixture();
        let sql = "SELECT k,count(*) FROM (SELECT 1 AS k UNION ALL SELECT 1.0 UNION ALL SELECT '1' UNION ALL SELECT 2 UNION ALL SELECT NULL UNION ALL SELECT NULL) r GROUP BY k ORDER BY k";
        assert_eq!(
            execute_statement(sql, Some(&ds), &NamedCaches::default(), None)
                .unwrap()
                .rows,
            vec![
                vec!["NULL".to_owned(), "2".to_owned()],
                vec!["1".to_owned(), "2".to_owned()],
                vec!["2".to_owned(), "1".to_owned()],
                vec!["1".to_owned(), "1".to_owned()],
            ]
        );
    }

    #[test]
    fn aggregate_distinct_preserves_integers_above_f64_exact_precision() {
        let values = [
            Scalar::Int(9007199254740992),
            Scalar::Int(9007199254740993),
            Scalar::Real("9007199254740992.0".to_owned()),
            Scalar::Int(1),
            Scalar::Real("1.0".to_owned()),
            Scalar::text("1"),
            Scalar::Null,
        ];
        assert_eq!(
            stream_values("SELECT count(DISTINCT k) FROM methods r", &values),
            vec![vec![Scalar::Int(4)]]
        );
        let ds = fixture();
        let sql = "SELECT count(DISTINCT k) FROM (SELECT 9007199254740992 AS k UNION ALL SELECT 9007199254740993 UNION ALL SELECT 9007199254740992.0 UNION ALL SELECT 1 UNION ALL SELECT 1.0 UNION ALL SELECT '1' UNION ALL SELECT NULL) r";
        assert_eq!(
            execute_statement(sql, Some(&ds), &NamedCaches::default(), None)
                .unwrap()
                .rows,
            vec![vec!["4".to_owned()]]
        );
    }

    #[test]
    fn output_distinct_uses_numeric_identity_and_retains_null_nan_separately() {
        let values = [
            Scalar::Int(1),
            Scalar::Real("1.0".to_owned()),
            Scalar::text("1"),
            Scalar::Null,
            Scalar::Null,
            Scalar::Int(9007199254740992),
            Scalar::Int(9007199254740993),
            Scalar::Real("9007199254740992.0".to_owned()),
        ];
        assert_eq!(
            stream_values("SELECT DISTINCT k FROM methods r ORDER BY k", &values),
            vec![
                vec![Scalar::Null],
                vec![Scalar::Int(1)],
                vec![Scalar::Int(9007199254740992)],
                vec![Scalar::Int(9007199254740993)],
                vec![Scalar::text("1")],
            ]
        );
        let ds = fixture();
        let sql = "SELECT DISTINCT k FROM (SELECT 1 AS k UNION ALL SELECT 1.0 UNION ALL SELECT '1' UNION ALL SELECT NULL UNION ALL SELECT NULL UNION ALL SELECT 9007199254740992 UNION ALL SELECT 9007199254740993 UNION ALL SELECT 9007199254740992.0) r ORDER BY k";
        assert_eq!(
            execute_statement(sql, Some(&ds), &NamedCaches::default(), None)
                .unwrap()
                .rows,
            vec![
                vec!["NULL".to_owned()],
                vec!["1".to_owned()],
                vec!["9007199254740992".to_owned()],
                vec!["9007199254740993".to_owned()],
                vec!["1".to_owned()],
            ]
        );
        assert_ne!(
            membership::set_key(&Scalar::Null),
            membership::set_key(&Scalar::Real("NaN".to_owned()))
        );
        assert_eq!(
            membership::set_key(&Scalar::Real("NaN".to_owned())),
            membership::set_key(&Scalar::Real("-NaN".to_owned()))
        );
        assert_eq!(membership::key(&Scalar::Real("NaN".to_owned())), None);
        assert_eq!(
            stream_values(
                "SELECT DISTINCT k FROM methods r",
                &[
                    Scalar::Null,
                    Scalar::Real("NaN".to_owned()),
                    Scalar::Real("-NaN".to_owned())
                ]
            )
            .len(),
            2
        );
    }
}
