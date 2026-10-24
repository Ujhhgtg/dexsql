//! Decorrelate simple EXISTS predicates into one inner-key set per query.
use super::{charge_materialized, eval_bool, membership, streaming, Dataset, NamedCaches};
use sqlparser::ast::{BinaryOperator, Expr, GroupByExpr, Query, SelectItem, TableFactor};
use sqlparser::tokenizer::{Token, Tokenizer};
use std::collections::HashSet;

fn unsupported(reason: &str) -> String {
    format!("unsupported correlated EXISTS: {reason}")
}

/// `None` leaves an uncorrelated subquery to the ordinary bounded executor.
/// Correlated shapes outside this deliberately small subset fail before a
/// relation scan, rather than becoming an uncorrelated answer by accident.
pub(super) fn exists(
    query: &Query,
    negated: bool,
    outer_aliases: &HashSet<String>,
    ds: &Dataset,
    caches: &NamedCaches,
) -> Result<Option<Expr>, String> {
    let select = query.body.as_select();
    let mut shadowed = HashSet::new();
    if let Some(select) = select {
        for from in &select.from {
            shadowed.insert(super::factor_alias(&from.relation).to_ascii_lowercase());
            for join in &from.joins {
                shadowed.insert(super::factor_alias(&join.relation).to_ascii_lowercase());
            }
        }
    }
    if !mentions_outer(query, outer_aliases, &shadowed)? {
        return Ok(None);
    }
    let select = select.ok_or_else(|| unsupported("set operations are not supported"))?;
    if query.with.is_some()
        || query.limit_clause.is_some()
        || query.fetch.is_some()
        || !query.locks.is_empty()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
        || select.from.len() != 1
        || !select.from[0].joins.is_empty()
        || select.prewhere.is_some()
        || select.having.is_some()
        || select.top.is_some()
        || select.into.is_some()
        || !select.lateral_views.is_empty()
        || !select.connect_by.is_empty()
        || !select.cluster_by.is_empty()
        || !select.distribute_by.is_empty()
        || !select.sort_by.is_empty()
        || !select.named_window.is_empty()
        || select.qualify.is_some()
        || select.value_table_mode.is_some()
        || !matches!(&select.group_by, GroupByExpr::Expressions(exprs, modifiers) if exprs.is_empty() && modifiers.is_empty())
    {
        return Err(unsupported(
            "requires a single ungrouped table without LIMIT/OFFSET",
        ));
    }
    let TableFactor::Table {
        name,
        alias,
        args,
        with_hints,
        version,
        with_ordinality,
        partitions,
        json_path,
        sample,
        index_hints,
    } = &select.from[0].relation
    else {
        return Err(unsupported("derived inner relations are not supported"));
    };
    if name.0.len() != 1
        || args.is_some()
        || !with_hints.is_empty()
        || version.is_some()
        || *with_ordinality
        || !partitions.is_empty()
        || json_path.is_some()
        || sample.is_some()
        || !index_hints.is_empty()
        || alias
            .as_ref()
            .is_some_and(|alias| !alias.columns.is_empty())
    {
        return Err(unsupported("inner table modifiers are not supported"));
    }
    let table = name.0[0]
        .as_ident()
        .ok_or_else(|| unsupported("invalid inner table name"))?
        .value
        .to_ascii_lowercase();
    if !streaming::supports_table(&table)
        || caches.has_definition(&table)
        || caches.tables.borrow().contains_key(&table)
    {
        return Err(unsupported(
            "inner relation must be a built-in streaming table",
        ));
    }
    let alias = alias
        .as_ref()
        .map(|alias| alias.name.value.to_ascii_lowercase())
        .unwrap_or_else(|| table.clone());
    let schema = dexsql_schema::TABLES
        .iter()
        .find(|schema| schema.name == table)
        .ok_or_else(|| unsupported("missing inner schema"))?;
    // EXISTS ignores ordinary projection values, but aggregate/window
    // projections change cardinality and require a different plan.
    for item in &select.projection {
        let expr = match item {
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => expr,
            SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(_, _) => continue,
            _ => return Err(unsupported("projection aliases are not supported")),
        };
        let mut expr = expr.clone();
        streaming::walk(&mut expr, &mut |expr| {
            if matches!(expr, Expr::Function(_) | Expr::CompoundIdentifier(_)) {
                None
            } else {
                Some(false)
            }
        })
        .ok_or_else(|| {
            unsupported("aggregate, window, and function projections are not supported")
        })?;
    }
    let selection = select
        .selection
        .as_ref()
        .ok_or_else(|| unsupported("missing correlation predicate"))?;
    let mut atoms = Vec::new();
    conjuncts(selection, &mut atoms);
    let mut inner_keys = Vec::new();
    let mut outer_keys = Vec::new();
    let mut local = Vec::new();
    let mut requested = HashSet::new();
    for atom in atoms {
        if let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = atom
        {
            let pair = inner_column(left, &alias, schema)
                .zip(outer_column(right, outer_aliases, &shadowed))
                .or_else(|| {
                    inner_column(right, &alias, schema).zip(outer_column(
                        left,
                        outer_aliases,
                        &shadowed,
                    ))
                });
            if let Some((column, outer)) = pair {
                requested.insert(column.clone());
                inner_keys.push(column);
                outer_keys.push(outer.clone());
                continue;
            }
        }
        collect_local(atom, &alias, schema, &mut requested)?;
        local.push(atom.clone());
    }
    if inner_keys.is_empty() {
        return Err(unsupported(
            "requires an inner-column = outer-column equality",
        ));
    }
    let mut local = local.into_iter().reduce(|left, right| Expr::BinaryOp {
        left: Box::new(left),
        op: BinaryOperator::And,
        right: Box::new(right),
    });
    let requested = schema
        .columns
        .iter()
        .map(|column| column.name)
        .filter(|column| requested.contains(*column))
        .collect::<Vec<_>>();
    let mut keys = HashSet::new();
    let mut bytes = 0u64;
    {
        // Only the local filter's lists belong to this temporary scope. The
        // semijoin is registered afterward in the outer query's scope.
        let local_scope = membership::Scope::new();
        if let Some(local) = &mut local {
            streaming::walk(local, &mut |expr| {
                local_scope.compile(expr);
                Some(false)
            })
            .ok_or_else(|| unsupported("unsupported local expression"))?;
        }
        streaming::visit_source(ds, &table, &alias, &requested, None, |row| {
            if let Some(local) = &local {
                if !eval_bool(local, row, &[])? {
                    return Ok(false);
                }
            }
            let key = inner_keys
                .iter()
                .map(|column| row.get(column).and_then(membership::key))
                .collect::<Option<Vec<_>>>();
            if let Some(key) = key {
                let key_bytes = 48
                    + key
                        .iter()
                        .map(|key| {
                            std::mem::size_of::<membership::Key>() as u64
                                + match key {
                                    membership::Key::Text(text) => text.len() as u64,
                                    membership::Key::Blob(bytes) => bytes.len() as u64,
                                    membership::Key::InvalidReal(text) => text.len() as u64,
                                    _ => 0,
                                }
                        })
                        .sum::<u64>();
                if keys.insert(key) {
                    bytes = bytes.saturating_add(key_bytes);
                    charge_materialized(bytes)?;
                }
            }
            Ok(false)
        })?;
    }
    Ok(Some(membership::register_rows(keys, negated, outer_keys)))
}

fn conjuncts<'a>(expr: &'a Expr, output: &mut Vec<&'a Expr>) {
    match expr {
        Expr::Nested(expr) => conjuncts(expr, output),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            conjuncts(left, output);
            conjuncts(right, output);
        }
        _ => output.push(expr),
    }
}

fn inner_column(expr: &Expr, alias: &str, schema: &dexsql_schema::TableMeta) -> Option<String> {
    let column = match expr {
        Expr::Nested(expr) => return inner_column(expr, alias, schema),
        Expr::Identifier(column) => &column.value,
        Expr::CompoundIdentifier(parts)
            if parts.len() == 2 && parts[0].value.eq_ignore_ascii_case(alias) =>
        {
            &parts[1].value
        }
        _ => return None,
    };
    schema
        .columns
        .iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case(column))
        .map(|column| column.name.to_owned())
}

fn outer_column<'a>(
    expr: &'a Expr,
    aliases: &HashSet<String>,
    shadowed: &HashSet<String>,
) -> Option<&'a Expr> {
    match expr {
        Expr::Nested(expr) => outer_column(expr, aliases, shadowed),
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
            let alias = parts[0].value.to_ascii_lowercase();
            (aliases.contains(&alias) && !shadowed.contains(&alias)).then_some(expr)
        }
        _ => None,
    }
}

fn collect_local(
    expr: &Expr,
    alias: &str,
    schema: &dexsql_schema::TableMeta,
    requested: &mut HashSet<String>,
) -> Result<(), String> {
    let mut expr = expr.clone();
    streaming::walk(&mut expr, &mut |expr| {
        match expr {
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
                requested.insert(inner_column(expr, alias, schema)?);
            }
            Expr::Function(function) => {
                let name = function
                    .name
                    .0
                    .last()?
                    .as_ident()?
                    .value
                    .to_ascii_lowercase();
                if matches!(
                    name.as_str(),
                    "count" | "sum" | "total" | "avg" | "group_concat" | "string_agg"
                ) {
                    return None;
                }
            }
            _ => {}
        }
        Some(false)
    })
    .ok_or_else(|| {
        unsupported("correlation is only supported in AND-connected equality predicates")
    })
}

/// Token inspection covers unsupported nested AST forms too, while ignoring
/// strings and comments that merely contain an outer alias spelling.
fn mentions_outer(
    query: &Query,
    aliases: &HashSet<String>,
    shadowed: &HashSet<String>,
) -> Result<bool, String> {
    if aliases.is_empty() {
        return Ok(false);
    }
    let sql = query.to_string();
    let tokens = Tokenizer::new(&sqlparser::dialect::SQLiteDialect {}, &sql)
        .tokenize()
        .map_err(|error| unsupported(&error.to_string()))?
        .into_iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .collect::<Vec<_>>();
    Ok(tokens.windows(3).any(|tokens| {
        matches!(tokens,
            [Token::Word(alias), Token::Period, Token::Word(_)]
                if aliases.contains(&alias.value.to_ascii_lowercase())
                    && !shadowed.contains(&alias.value.to_ascii_lowercase())
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::super::{eval_scalar, RelRow, Scalar};
    use super::*;
    use std::path::PathBuf;

    fn fixture() -> Dataset {
        Dataset::load_paths(&[
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/beta.dex"),
        ])
        .unwrap()
    }
    fn query(sql: &str) -> Query {
        let statement =
            sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::SQLiteDialect {}, sql)
                .unwrap()
                .remove(0);
        let sqlparser::ast::Statement::Query(query) = statement else {
            panic!()
        };
        *query
    }
    fn compiled(sql: &str, ds: &Dataset, negated: bool) -> Expr {
        exists(
            &query(sql),
            negated,
            &HashSet::from(["m".to_owned()]),
            ds,
            &NamedCaches::default(),
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn multikey_exists_builds_once_and_matches_fixture_references() {
        let ds = fixture();
        let _scope = membership::Scope::new();
        let sql = "SELECT 1 FROM method_calls c WHERE c.file_id=m.file_id AND c.method_idx=m.method_idx AND c.callee_method_idx>=1";
        let exists = compiled(sql, &ds, false);
        let not_exists = compiled(sql, &ds, true);
        // Repeated probes reuse the same inner-key set, with no subquery or
        // inner-source scan in the generated expression.
        assert!(matches!(exists, Expr::Function(_)));
        for file in &ds.files {
            for method_idx in 0..file.methods.len() as u32 {
                let expected = file
                    .method_calls
                    .iter()
                    .any(|call| call.method_idx == method_idx && call.callee_method_idx >= 1);
                let mut row = RelRow::default();
                row.put("m", "file_id", Scalar::Int(file.file_id as i64));
                row.put("m", "method_idx", Scalar::Int(method_idx as i64));
                for _ in 0..4 {
                    assert_eq!(
                        eval_scalar(&exists, &row, &[]).unwrap(),
                        Scalar::Int(expected as i64)
                    );
                    assert_eq!(
                        eval_scalar(&not_exists, &row, &[]).unwrap(),
                        Scalar::Int((!expected) as i64)
                    );
                }
            }
        }
    }

    #[test]
    fn exists_keys_are_type_strict_and_null_does_not_match() {
        let ds = fixture();
        let _scope = membership::Scope::new();
        let expr = compiled("SELECT 1 FROM methods i WHERE i.method_idx=m.k", &ds, false);
        let negated = compiled("SELECT 1 FROM methods i WHERE m.k=i.method_idx", &ds, true);
        for (key, expected) in [
            (Scalar::Int(0), true),
            (Scalar::Real("-0.0".to_owned()), true),
            (Scalar::text("0"), false),
            (Scalar::Null, false),
            (Scalar::Int(i64::MAX), false),
        ] {
            let mut row = RelRow::default();
            row.put("m", "k", key);
            assert_eq!(
                eval_scalar(&expr, &row, &[]).unwrap(),
                Scalar::Int(expected as i64)
            );
            assert_eq!(
                eval_scalar(&negated, &row, &[]).unwrap(),
                Scalar::Int((!expected) as i64)
            );
        }
    }

    #[test]
    fn local_large_in_filter_and_empty_inner_set_are_bounded() {
        let ds = fixture();
        let _scope = membership::Scope::new();
        let numbers = (0..4096)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let expr = compiled(
            &format!(
                "SELECT 1 FROM methods i WHERE i.method_idx=m.k AND i.method_idx IN ({numbers})"
            ),
            &ds,
            false,
        );
        let empty = compiled(
            "SELECT 1 FROM methods i WHERE i.method_idx=m.k AND i.method_idx<0",
            &ds,
            true,
        );
        let mut row = RelRow::default();
        row.put("m", "k", Scalar::Int(0));
        assert_eq!(eval_scalar(&expr, &row, &[]).unwrap(), Scalar::Int(1));
        assert_eq!(eval_scalar(&empty, &row, &[]).unwrap(), Scalar::Int(1));
        row.values.clear();
        row.put("m", "k", Scalar::Null);
        assert_eq!(eval_scalar(&empty, &row, &[]).unwrap(), Scalar::Int(1));
    }

    #[test]
    fn unsupported_correlations_fail_before_inner_scan() {
        let ds = fixture();
        let aliases = HashSet::from(["m".to_owned()]);
        for sql in [
            "SELECT 1 FROM methods i WHERE i.method_idx>m.k",
            "SELECT 1 FROM methods i WHERE i.method_idx=m.k OR i.method_idx=0",
            "SELECT 1 FROM methods i WHERE i.method_idx=m.k LIMIT 1",
            "SELECT count(*) FROM methods i WHERE i.method_idx=m.k",
            "SELECT 1 FROM methods i WHERE i.method_idx=m.k GROUP BY i.file_id",
            "SELECT 1 FROM methods i JOIN strings s ON s.string_idx=i.name WHERE i.method_idx=m.k",
            "SELECT 1 FROM methods i WHERE i.method_idx=m.k AND m.file_id=0",
        ] {
            let error =
                exists(&query(sql), false, &aliases, &ds, &NamedCaches::default()).unwrap_err();
            assert!(
                error.contains("unsupported correlated EXISTS"),
                "{sql}: {error}"
            );
        }
    }

    #[test]
    fn inner_alias_shadowing_and_alias_text_do_not_create_correlation() {
        let ds = fixture();
        let aliases = HashSet::from(["m".to_owned()]);
        for sql in [
            "SELECT 1 FROM methods m WHERE m.method_idx=0",
            "SELECT 1 FROM methods i WHERE i.name='m.name'",
            "SELECT 1 FROM methods i WHERE i.method_idx=0 /* m.method_idx */",
        ] {
            assert!(
                exists(&query(sql), false, &aliases, &ds, &NamedCaches::default())
                    .unwrap()
                    .is_none()
            );
        }
    }
}
