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
    seen: Option<Box<HashSet<Scalar>>>,
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
            let key = match value.numeric() {
                Some(number)
                    if number >= i64::MIN as f64
                        && number < i64::MAX as f64
                        && number.fract() == 0.0 =>
                {
                    Scalar::Int(number as i64)
                }
                Some(number) => scalar_functions::real_scalar(number),
                None => value.clone(),
            };
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
fn walk(expr: &mut Expr, f: &mut impl FnMut(&mut Expr) -> Option<bool>) -> Option<()> {
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
                if ids.len() != 2 || !ids[0].value.eq_ignore_ascii_case(alias) {
                    return None;
                }
                needed.insert(ids[1].value.to_ascii_lowercase());
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

pub(super) fn execute(
    query: &sqlparser::ast::Query,
    select: &Select,
    ds: &Dataset,
    caches: &NamedCaches,
    cli_limit: Option<u64>,
) -> Option<Result<SelectOutput, String>> {
    if select.from.len() != 1
        || !select.from[0].joins.is_empty()
        || select.prewhere.is_some()
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
    if caches.has_definition(&table) || caches.tables.borrow().contains_key(&table) {
        return None;
    }
    if !matches!(
        table.as_str(),
        "methods"
            | "classes"
            | "fields"
            | "method_strings"
            | "method_calls"
            | "method_field_accesses"
            | "method_used_types"
            | "method_numbers"
            | "method_using_numbers"
    ) {
        return None;
    }
    let schema = dexsql_schema::TABLES
        .iter()
        .find(|schema| schema.name == table)?;
    let alias = alias
        .as_ref()
        .map(|alias| alias.name.value.as_str())
        .unwrap_or(&table);
    let mut projection = Vec::new();
    for item in &select.projection {
        match item {
            SelectItem::UnnamedExpr(expr) => {
                projection.push((expr.clone(), expression_label(expr)))
            }
            SelectItem::ExprWithAlias { expr, alias } => {
                projection.push((expr.clone(), alias.value.clone()))
            }
            SelectItem::Wildcard(options) if *options == Default::default() => {
                for column in schema.columns {
                    projection.push((
                        Expr::Identifier(sqlparser::ast::Ident::new(column.name)),
                        column.name.to_owned(),
                    ));
                }
            }
            SelectItem::QualifiedWildcard(
                sqlparser::ast::SelectItemQualifiedWildcardKind::ObjectName(name),
                options,
            ) if *options == Default::default() && name.to_string().eq_ignore_ascii_case(alias) => {
                for column in schema.columns {
                    projection.push((
                        Expr::Identifier(sqlparser::ast::Ident::new(column.name)),
                        column.name.to_owned(),
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
        .any(|name| !schema.columns.iter().any(|column| column.name == name))
    {
        return None;
    }
    let scan_predicates = select
        .selection
        .as_ref()
        .and_then(|expr| push_predicates(expr, alias));
    let grouped = !specs.is_empty() || !group_exprs.is_empty();
    let requested: Vec<&str> = schema
        .columns
        .iter()
        .map(|column| column.name)
        .filter(|name| needed.contains(*name))
        .collect();
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
        let mut groups: HashMap<Vec<Scalar>, Group> = HashMap::new();
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
            if select.distinct.is_some() && !seen.insert(values.clone()) {
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
            visit_source(
                ds,
                &table,
                alias,
                &requested,
                scan_predicates.as_deref(),
                |row| {
                    if selection
                        .as_ref()
                        .is_some_and(|expr| !eval_bool(expr, row, &[]).unwrap_or(false))
                    {
                        return Ok(false);
                    }
                    if grouped {
                        let key = group_exprs
                            .iter()
                            .map(|expr| eval_scalar(expr, row, &[]))
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
                },
            )?;
        }
        for (_, group) in groups {
            let mut row = RelRow::with_capacity(requested.len());
            for (column, value) in requested.iter().zip(group.values) {
                row.put(alias, column, value);
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
enum Source<'a> {
    Method(u32),
    Class(&'a ClassInfo),
    Field(u32),
    String(&'a dexsql_cache::MethodStringRef),
    Call(&'a dexsql_cache::MethodCallRef),
    FieldAccess(&'a dexsql_cache::MethodFieldRef),
    Type(&'a dexsql_cache::MethodTypeRef),
    Number(&'a dexsql_cache::MethodNumberRef),
}

struct Cells<'a> {
    file: &'a DexFile,
    strings: Vec<Option<Arc<str>>>,
    methods: Vec<Option<Arc<str>>>,
    fields: Vec<Option<Arc<str>>>,
    definitions: Vec<Option<(u32, bool)>>,
}
impl<'a> Cells<'a> {
    fn new(file: &'a DexFile, needs_definitions: bool, columns: &[&str]) -> Self {
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
        let needs_strings = columns.iter().any(|column| {
            matches!(
                *column,
                "value"
                    | "name"
                    | "method_name"
                    | "method_class"
                    | "class_descriptor"
                    | "descriptor"
                    | "return_descriptor"
                    | "superclass_descriptor"
                    | "source_file"
                    | "type_descriptor"
                    | "callee_class"
                    | "callee_name"
                    | "field_class"
                    | "field_name"
                    | "field_type"
            )
        });
        let needs_methods = columns
            .iter()
            .any(|column| matches!(*column, "method" | "descriptor" | "callee"));
        let needs_fields = columns.contains(&"field") || columns.contains(&"descriptor");
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
            return Scalar::text("");
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
            return Scalar::text("");
        };
        Scalar::Text(
            slot.get_or_insert_with(|| Arc::from(self.file.method_descriptor_direct(index)))
                .clone(),
        )
    }
    fn field(&mut self, index: u32) -> Scalar {
        let Some(slot) = self.fields.get_mut(index as usize) else {
            return Scalar::text("");
        };
        Scalar::Text(
            slot.get_or_insert_with(|| Arc::from(self.file.field_descriptor_direct(index)))
                .clone(),
        )
    }
    fn value(
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
        if column == "file_id" {
            return Scalar::Int(self.file.file_id as i64);
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
                "descriptor" => self.field(index),
                _ => Scalar::Null,
            };
        }
        let method = self.file.methods.get(method_idx as usize);
        match column {
            "method_idx" => return Scalar::Int(method_idx as i64),
            "class_idx" => {
                return Scalar::Int(method.map(|method| method.class_idx).unwrap_or(0) as i64)
            }
            "method" | "descriptor" => return self.method(method_idx),
            "method_class" | "class_descriptor" => {
                return method
                    .map(|method| method.class_idx as u32)
                    .map(|index| self.typ(index))
                    .unwrap_or_else(|| Scalar::text(""))
            }
            "method_name" | "name" => {
                return method
                    .map(|method| method.name_idx)
                    .map(|index| self.string(index))
                    .unwrap_or_else(|| Scalar::text(""))
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

fn visit_source(
    ds: &Dataset,
    table: &str,
    alias: &str,
    columns: &[&str],
    predicates: Option<&[PushPredicate]>,
    mut visit: impl FnMut(&RelRow) -> Result<bool, String>,
) -> Result<(), String> {
    let needs_opcode = columns
        .iter()
        .any(|column| matches!(*column, "opcode_count" | "opcode_hex"));
    let needs_opcode_hex = columns.contains(&"opcode_hex");
    let needs_definitions = needs_opcode
        || columns
            .iter()
            .any(|column| matches!(*column, "access_flags" | "method_kind"));
    for file in &ds.files {
        let mut cells = Cells::new(file, needs_definitions && table == "methods", columns);
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
            visit(&row)
        };
        match table {
            "methods" => {
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
            "fields" => {
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
}
