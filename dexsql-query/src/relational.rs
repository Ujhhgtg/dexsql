//! Pipelined inner joins over reduced cache rows.
//!
//! Only build-side cache record identities and hash row ordinals are retained.
//! Probe rows and intermediate join results feed the common streaming sink;
//! they never become a materialized relation of per-row hash maps.
use super::*;
use sqlparser::ast::{BinaryOperator, Expr, Query, Select, TableFactor};
use std::hash::{Hash, Hasher};

struct Source {
    table: String,
    alias: String,
    columns: Vec<String>,
}

struct Join<'a> {
    constraint: Option<&'a Expr>,
    // Qualified keys, oriented as (existing input, new build input).
    keys: Vec<(String, String)>,
}

use super::membership::key;

fn row_hash(row: &RelRow, columns: impl Iterator<Item = impl AsRef<str>>) -> Option<u64> {
    let mut hash = rustc_hash::FxHasher::default();
    for column in columns {
        key(row.get(column.as_ref())?)?.hash(&mut hash);
    }
    Some(hash.finish())
}

fn source(factor: &TableFactor, caches: &NamedCaches) -> Option<Source> {
    let TableFactor::Table {
        name, alias, args, ..
    } = factor
    else {
        return None;
    };
    if name.0.len() != 1 || args.is_some() {
        return None;
    }
    let table = name.0.last()?.as_ident()?.value.to_ascii_lowercase();
    if !streaming::supports_table(&table)
        || caches.has_definition(&table)
        || caches.tables.borrow().contains_key(&table)
    {
        return None;
    }
    let schema = dexsql_schema::TABLES
        .iter()
        .find(|schema| schema.name == table)?;
    Some(Source {
        alias: alias
            .as_ref()
            .map(|alias| alias.name.value.to_ascii_lowercase())
            .unwrap_or_else(|| table.clone()),
        table,
        columns: schema
            .columns
            .iter()
            .map(|column| column.name.to_owned())
            .collect(),
    })
}

fn column_owner(expr: &Expr, sources: &[Source]) -> Option<(usize, String)> {
    match expr {
        Expr::Identifier(id) => {
            let name = id.value.to_ascii_lowercase();
            let owner = sources
                .iter()
                .position(|source| source.columns.contains(&name))?;
            Some((owner, name))
        }
        Expr::CompoundIdentifier(ids) if ids.len() == 2 => {
            let alias = ids[0].value.to_ascii_lowercase();
            let name = ids[1].value.to_ascii_lowercase();
            let owner = sources
                .iter()
                .position(|source| source.alias == alias && source.columns.contains(&name))?;
            Some((owner, name))
        }
        _ => None,
    }
}

fn join_keys(expr: &Expr, sources: &[Source], level: usize, keys: &mut Vec<(String, String)>) {
    let mut conjuncts = Vec::new();
    flatten_and(expr, &mut conjuncts);
    for expr in conjuncts {
        let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = expr
        else {
            continue;
        };
        let (Some((a, ac)), Some((b, bc))) =
            (column_owner(left, sources), column_owner(right, sources))
        else {
            continue;
        };
        let pair = if a < level && b == level {
            Some((
                format!("{}.{}", sources[a].alias, ac),
                format!("{}.{}", sources[b].alias, bc),
            ))
        } else if b < level && a == level {
            Some((
                format!("{}.{}", sources[b].alias, bc),
                format!("{}.{}", sources[a].alias, ac),
            ))
        } else {
            None
        };
        if let Some(pair) = pair {
            if !keys.contains(&pair) {
                keys.push(pair);
            }
        }
    }
}

// Push only predicates belonging to this source. An unqualified column uses
// the first source exposing it, just like RelRow::merge; pushing it to every
// side would incorrectly filter a different same-named column.
fn predicates(select: &Select, sources: &[Source], level: usize) -> Vec<PushPredicate> {
    let mut conjuncts = Vec::new();
    if let Some(expr) = &select.selection {
        flatten_and(expr, &mut conjuncts);
    }
    conjuncts
        .into_iter()
        .filter_map(|expr| {
            let predicate = simple_push_predicate(expr)?;
            if matches!(predicate.kind, PushPredicateKind::In)
                && predicate.values.len() >= membership::HASH_THRESHOLD
            {
                return None;
            }
            let column = match expr {
                Expr::BinaryOp { left, right, .. } => {
                    if column_owner(left, sources).is_some() {
                        left.as_ref()
                    } else {
                        right.as_ref()
                    }
                }
                Expr::InList { expr, .. } | Expr::Like { expr, .. } | Expr::ILike { expr, .. } => {
                    expr
                }
                _ => return None,
            };
            (column_owner(column, sources)?.0 == level).then_some(predicate)
        })
        .collect()
}

fn local_selection<'a>(select: &'a Select, sources: &[Source], level: usize) -> Vec<&'a Expr> {
    let mut conjuncts = Vec::new();
    if let Some(expr) = &select.selection {
        flatten_and(expr, &mut conjuncts);
    }
    conjuncts.into_iter().filter(|expr| {
        let mut expr = (*expr).clone();
        let mut local = true;
        let supported = streaming::walk(&mut expr, &mut |expr| {
            if matches!(expr, Expr::InList { list, .. } if list.len() >= membership::HASH_THRESHOLD) {
                local = false;
            }
            if matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_)) {
                local &= column_owner(expr, sources).is_some_and(|(owner, _)| owner == level);
            }
            Some(false)
        }).is_some();
        supported && local
    }).collect()
}

pub(super) fn execute(
    query: &Query,
    select: &Select,
    ds: &Dataset,
    caches: &NamedCaches,
    cli_limit: Option<u64>,
) -> Option<Result<SelectOutput, String>> {
    let mut sources = Vec::new();
    let mut joins = Vec::new();
    for table in &select.from {
        if !sources.is_empty() {
            joins.push(Join {
                constraint: None,
                keys: Vec::new(),
            });
        }
        sources.push(source(&table.relation, caches)?);
        for join in &table.joins {
            let constraint = join_constraint(&join.join_operator).ok()?;
            sources.push(source(&join.relation, caches)?);
            joins.push(Join {
                constraint,
                keys: Vec::new(),
            });
        }
    }
    if sources.len() < 2 {
        return None;
    }
    let mut aliases = HashSet::new();
    if sources.iter().any(|source| !aliases.insert(&source.alias)) {
        return None;
    }
    for (index, join) in joins.iter_mut().enumerate() {
        if let Some(expr) = join.constraint {
            join_keys(expr, &sources, index + 1, &mut join.keys);
        }
        if let Some(expr) = &select.selection {
            join_keys(expr, &sources, index + 1, &mut join.keys);
        }
        // Bounded row queries can pull a Cartesian/non-equality side lazily.
        // Unbounded products keep the existing generic work cap.
        let bounded = query.order_by.is_none()
            && (query_limit_value(query.limit_clause.as_ref()).is_some() || cli_limit.is_some())
            && select
                .projection
                .iter()
                .all(|item| item_expr(item).is_some_and(scan_projection_is_row_local))
            && select.having.is_none()
            && matches!(&select.group_by, sqlparser::ast::GroupByExpr::Expressions(exprs, modifiers) if exprs.is_empty() && modifiers.is_empty());
        if join.keys.is_empty() && !bounded {
            return None;
        }
    }
    let mut schema = Vec::new();
    for source in &sources {
        for column in &source.columns {
            if !schema.contains(column) {
                schema.push(column.clone());
            }
            schema.push(format!("{}.{}", source.alias, column));
        }
    }
    streaming::execute_input(query, select, &schema, cli_limit, |needed, visit| {
        let mut required: HashSet<String> = needed.iter().cloned().collect();
        for join in &joins {
            if let Some(expr) = join.constraint {
                let mut columns = HashSet::new();
                if !collect_expr_columns(expr, &mut columns) {
                    return Err("unsupported SQL expression in JOIN".into());
                }
                // Conservatively retain same-named columns on both sides for
                // ON residuals; qualified projection demands stay precise.
                for column in columns {
                    for source in &sources {
                        if source.columns.contains(&column) {
                            required.insert(format!("{}.{}", source.alias, column));
                        }
                    }
                }
            }
            for (left, right) in &join.keys {
                required.insert(left.clone());
                required.insert(right.clone());
            }
        }
        let columns: Vec<Vec<&str>> = sources
            .iter()
            .enumerate()
            .map(|(index, source)| {
                source
                    .columns
                    .iter()
                    .filter(|column| {
                        required.contains(&format!("{}.{}", source.alias, column))
                            || required.contains(column.as_str())
                                && sources
                                    .iter()
                                    .position(|source| source.columns.contains(column))
                                    == Some(index)
                    })
                    .map(String::as_str)
                    .collect()
            })
            .collect();
        let filters: Vec<_> = (0..sources.len())
            .map(|index| predicates(select, &sources, index))
            .collect();
        let locals: Vec<_> = (0..sources.len())
            .map(|index| local_selection(select, &sources, index))
            .collect();
        let mut builds = Vec::new();
        let mut retained = 0u64;
        for (index, join) in joins.iter().enumerate() {
            let source = &sources[index + 1];
            let columns = &columns[index + 1];
            let mut build = Build {
                rows: Vec::new(),
                index: FxHashMap::default(),
                table: source.table.clone(),
                alias: source.alias.clone(),
                predicates: filters[index + 1].clone(),
                cells: ds
                    .files
                    .iter()
                    .map(|file| {
                        RefCell::new(streaming::Cells::new(
                            file,
                            &source.table,
                            source.table == "methods"
                                && columns.iter().any(|column| {
                                    matches!(
                                        *column,
                                        "access_flags"
                                            | "method_kind"
                                            | "opcode_count"
                                            | "opcode_hex"
                                    )
                                }),
                            columns,
                        ))
                    })
                    .collect(),
                columns: columns
                    .iter()
                    .map(|column| {
                        (
                            intern_rel_component(&format!("{}.{}", source.alias, column)),
                            intern_rel_component(column),
                        )
                    })
                    .collect(),
            };
            if join.keys.is_empty() {
                builds.push(build);
                continue;
            }
            let mut key_columns: HashSet<String> = join
                .keys
                .iter()
                .map(|(_, column)| column.rsplit('.').next().unwrap().to_owned())
                .collect();
            for expr in &locals[index + 1] {
                collect_expr_columns(expr, &mut key_columns);
            }
            let keys: Vec<&str> = key_columns.iter().map(String::as_str).collect();
            streaming::visit_source_records(
                ds,
                &source.table,
                &source.alias,
                &keys,
                Some(&filters[index + 1]),
                |row, file_index, record| {
                    if locals[index + 1]
                        .iter()
                        .any(|expr| !eval_bool(expr, row, &[]).unwrap_or(false))
                    {
                        return Ok(false);
                    }
                    let Some(key) = row_hash(row, join.keys.iter().map(|(_, right)| right)) else {
                        return Ok(false);
                    };
                    // Only borrowed record identities survive this scan;
                    // repeated keys share one hash bucket and its payload.
                    retained = retained.saturating_add(
                        2 * std::mem::size_of::<(usize, streaming::Source<'_>)>() as u64 + 16,
                    );
                    if !build.index.contains_key(&key) {
                        retained = retained.saturating_add(96);
                    }
                    charge_materialized(retained)?;
                    build.index.entry(key).or_default().push(build.rows.len());
                    build.rows.push((file_index, record));
                    Ok(false)
                },
            )?;
            if build.rows.is_empty() {
                return Ok(());
            }
            builds.push(build);
        }
        streaming::visit_source(
            ds,
            &sources[0].table,
            &sources[0].alias,
            &columns[0],
            Some(&filters[0]),
            |row| {
                if locals[0]
                    .iter()
                    .any(|expr| !eval_bool(expr, row, &[]).unwrap_or(false))
                {
                    Ok(false)
                } else {
                    probe(0, row, &joins, &builds, ds, visit)
                }
            },
        )
    })
}

struct Build<'a> {
    rows: Vec<(usize, streaming::Source<'a>)>,
    // Fingerprints only: equality is checked against source values on probe.
    // Long descriptors need not remain duplicated inside the join index.
    index: FxHashMap<u64, Vec<usize>>,
    cells: Vec<RefCell<streaming::Cells<'a>>>,
    table: String,
    alias: String,
    predicates: Vec<PushPredicate>,
    columns: Vec<(Arc<str>, Arc<str>)>,
}

fn probe(
    level: usize,
    left: &RelRow,
    joins: &[Join<'_>],
    builds: &[Build<'_>],
    ds: &Dataset,
    visit: &mut dyn FnMut(&RelRow) -> Result<bool, String>,
) -> Result<bool, String> {
    if level == builds.len() {
        return visit(left);
    }
    let join = &joins[level];
    let build = &builds[level];
    if join.keys.is_empty() {
        let columns = build
            .columns
            .iter()
            .map(|(_, column)| column.as_ref())
            .collect::<Vec<_>>();
        let mut stopped = false;
        streaming::visit_source(
            ds,
            &build.table,
            &build.alias,
            &columns,
            Some(&build.predicates),
            |right| {
                let merged = left.merge(right);
                if join
                    .constraint
                    .is_some_and(|expr| !eval_bool(expr, &merged, &[]).unwrap_or(false))
                {
                    return Ok(false);
                }
                stopped = probe(level + 1, &merged, joins, builds, ds, visit)?;
                Ok(stopped)
            },
        )?;
        return Ok(stopped);
    }
    let Some(key) = row_hash(left, join.keys.iter().map(|(left, _)| left)) else {
        return Ok(false);
    };
    let Some(matches) = build.index.get(&key) else {
        return Ok(false);
    };
    let mut merged = left.clone();
    for (qualified, column) in &build.columns {
        merged.values.insert(qualified.clone(), Scalar::Null);
        if !left.values.contains_key(column) {
            merged.values.insert(column.clone(), Scalar::Null);
        }
        if !merged.columns.contains(column) {
            merged.columns.push(column.clone());
        }
    }
    for index in matches {
        let (file_index, record) = build.rows[*index];
        let file = &ds.files[file_index];
        let opcode = if let streaming::Source::Method(index) = record {
            if build
                .columns
                .iter()
                .any(|(_, column)| column.as_ref() == "opcode_hex")
            {
                file.method_opcode_summary(index)
            } else if build
                .columns
                .iter()
                .any(|(_, column)| column.as_ref() == "opcode_count")
            {
                file.method_opcode_count(index)
                    .map(|count| (count, String::new()))
            } else {
                None
            }
        } else {
            None
        };
        let mut cells = build.cells[file_index].borrow_mut();
        for (qualified, column) in &build.columns {
            let value = cells.value(record, column, opcode.as_ref());
            merged.values.insert(qualified.clone(), value.clone());
            if !left.values.contains_key(column) {
                merged.values.insert(column.clone(), value);
            }
        }
        drop(cells);
        if join.keys.iter().any(|(left, right)| {
            !merged
                .get(left)
                .zip(merged.get(right))
                .is_some_and(|(left, right)| left.sql_eq(right))
        }) {
            continue;
        }
        if join
            .constraint
            .is_some_and(|expr| !eval_bool(expr, &merged, &[]).unwrap_or(false))
        {
            continue;
        }
        if probe(level + 1, &merged, joins, builds, ds, visit)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Dataset {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex");
        Dataset::load_paths(&[root.join("alpha.dex"), root.join("beta.dex")]).unwrap()
    }

    fn parse(sql: &str) -> Query {
        let mut statements =
            sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::SQLiteDialect {}, sql)
                .unwrap();
        let sqlparser::ast::Statement::Query(query) = statements.remove(0) else {
            panic!()
        };
        *query
    }

    fn run(sql: &str, ds: &Dataset, limit: Option<u64>) -> QueryResult {
        let query = parse(sql);
        let mut output = execute(
            &query,
            query.body.as_select().unwrap(),
            ds,
            &NamedCaches::default(),
            limit,
        )
        .expect("pipelined join")
        .unwrap();
        apply_query_order_limit(&mut output, &query, limit).unwrap();
        typed_to_result((
            output.columns,
            output.rows.into_iter().map(|row| row.values).collect(),
        ))
    }

    #[test]
    fn composite_keys_preserve_duplicates_and_dex_identity() {
        let ds = fixture();
        let all = run("SELECT a.file_id,a.method_idx,b.method_idx FROM methods a JOIN methods b ON a.method_idx=b.method_idx ORDER BY a.file_id,a.method_idx,b.file_id", &ds, None);
        let expected = ds
            .files
            .iter()
            .map(|file| file.methods.len())
            .sum::<usize>();
        assert!(
            all.rows.len() > expected,
            "fixture must exercise duplicate dex-local keys"
        );
        let exact = run("SELECT a.file_id,a.method_idx FROM methods a JOIN methods b ON a.file_id=b.file_id AND a.method_idx=b.method_idx ORDER BY a.file_id,a.method_idx", &ds, None);
        assert_eq!(exact.rows.len(), expected);
        let count = run("SELECT count(*) FROM methods a JOIN methods b ON a.method_idx=b.method_idx AND a.file_id=b.file_id", &ds, None);
        assert_eq!(count.rows, vec![vec![expected.to_string()]]);
    }

    #[test]
    fn joins_feed_aggregates_distinct_order_and_limits() {
        let ds = fixture();
        for sql in [
            "SELECT DISTINCT a.file_id,a.method_idx FROM methods a JOIN methods b ON a.method_idx=b.method_idx WHERE b.method_idx<>1 ORDER BY a.file_id,a.method_idx DESC LIMIT 4 OFFSET 1",
            "SELECT a.method_idx,b.name FROM methods a JOIN methods b ON b.method_idx=a.method_idx WHERE a.method_idx IN (0,2) ORDER BY a.method_idx,b.name LIMIT 3",
        ] {
            let query = parse(sql);
            // The old hash join loses self-join matches, so use its small
            // Cartesian evaluator as an independent nested-loop oracle.
            let oracle = parse(&sql
                .replace("JOIN methods b ON a.method_idx=b.method_idx WHERE", ", methods b WHERE a.method_idx=b.method_idx AND")
                .replace("JOIN methods b ON b.method_idx=a.method_idx WHERE", ", methods b WHERE b.method_idx=a.method_idx AND"));
            let select = oracle.body.as_select().unwrap();
            let mut materialized = execute_select_core(select, &ds, Some(&ds),
                &NamedCaches::default(), false, None, None).unwrap();
            apply_query_order_limit(&mut materialized, &query, None).unwrap();
            let expected = typed_to_result((materialized.columns,
                materialized.rows.into_iter().map(|row| row.values).collect()));
            let actual = run(sql, &ds, None);
            assert_eq!(actual.columns, expected.columns, "{sql}");
            assert_eq!(actual.rows, expected.rows, "{sql}");
        }
        let grouped = run("SELECT a.file_id,count(*),sum(a.method_idx),count(DISTINCT a.method_idx) FROM methods a JOIN methods b ON a.method_idx=b.method_idx GROUP BY a.file_id HAVING count(*)>0 ORDER BY a.file_id", &ds, None);
        let expected = ds
            .files
            .iter()
            .map(|file| {
                let mut count = 0usize;
                let mut sum = 0usize;
                for index in 0..file.methods.len() {
                    let matches = ds
                        .files
                        .iter()
                        .filter(|other| index < other.methods.len())
                        .count();
                    count += matches;
                    sum += matches * index;
                }
                vec![
                    file.file_id.to_string(),
                    count.to_string(),
                    sum.to_string(),
                    file.methods.len().to_string(),
                ]
            })
            .collect::<Vec<_>>();
        assert_eq!(grouped.rows, expected);
        let sql = "SELECT a.method_idx,b.file_id FROM methods a JOIN methods b ON a.method_idx=b.method_idx LIMIT 5 OFFSET 2";
        assert_eq!(run(sql, &ds, Some(1)).rows, run(sql, &ds, None).rows[..1]);
        assert!(run(sql, &ds, Some(0)).rows.is_empty());
    }

    #[test]
    fn multiway_and_comma_joins_keep_residuals_and_column_ownership() {
        let ds = fixture();
        let exact = run("SELECT a.file_id,a.method_idx FROM methods a JOIN method_ids b ON a.method_idx=b.method_idx AND a.file_id=b.file_id JOIN proto_ids p ON b.proto_idx=p.proto_idx AND b.file_id=p.file_id WHERE a.method_idx<3 ORDER BY a.file_id,a.method_idx", &ds, None);
        let expected = ds
            .files
            .iter()
            .enumerate()
            .flat_map(|(file_id, file)| {
                (0..file.methods.len().min(3))
                    .map(move |index| vec![file_id.to_string(), index.to_string()])
            })
            .collect::<Vec<_>>();
        assert_eq!(exact.rows, expected);
        let comma = run("SELECT a.file_id,a.method_idx FROM methods a,method_ids b WHERE a.file_id=b.file_id AND a.method_idx=b.method_idx AND method_idx<3 ORDER BY a.file_id,a.method_idx", &ds, None);
        assert_eq!(comma.rows, expected);
        let residual = run("SELECT a.method_idx FROM methods a JOIN method_ids b ON a.method_idx=b.method_idx AND a.file_id=b.file_id AND b.proto_idx>=0 ORDER BY a.method_idx", &ds, None);
        assert_eq!(
            residual.rows.len(),
            ds.files
                .iter()
                .map(|file| file.methods.len())
                .sum::<usize>()
        );
    }

    #[test]
    fn null_keys_do_not_join_and_empty_build_preserves_count() {
        let ds = fixture();
        let result = run(
            "SELECT count(*) FROM methods a JOIN methods b ON a.access_flags=b.access_flags",
            &ds,
            None,
        );
        let mut expected = 0;
        let mut values = Vec::new();
        streaming::visit_source(&ds, "methods", "a", &["access_flags"], None, |row| {
            values.push(row.get("access_flags").unwrap().clone());
            Ok(false)
        })
        .unwrap();
        for left in &values {
            for right in &values {
                if !matches!(left, Scalar::Null)
                    && !matches!(right, Scalar::Null)
                    && left.sql_eq(right)
                {
                    expected += 1;
                }
            }
        }
        assert_eq!(result.rows, vec![vec![expected.to_string()]]);
        assert_eq!(run("SELECT count(*) FROM methods a JOIN methods b ON a.method_idx=b.method_idx WHERE b.method_idx=-1", &ds, None).rows, vec![vec!["0".to_owned()]]);
    }

    #[test]
    fn compound_output_labels_use_one_based_ordering() {
        let ds = fixture();
        for sql in [
            "SELECT 1 AS n UNION ALL SELECT 3 ORDER BY n DESC",
            "SELECT 1 AS n UNION SELECT 3 ORDER BY n DESC",
        ] {
            assert_eq!(
                execute_statement(sql, Some(&ds), &NamedCaches::default(), None)
                    .unwrap()
                    .rows,
                vec![vec!["3".to_owned()], vec!["1".to_owned()]]
            );
        }
    }

    #[test]
    fn bounded_cross_and_non_equality_joins_pull_until_satisfied() {
        let ds = fixture();
        for sql in [
            "SELECT a.file_id,a.method_idx,b.file_id,b.method_idx FROM methods a CROSS JOIN methods b LIMIT 3 OFFSET 2",
            "SELECT a.method_idx,b.method_idx FROM methods a JOIN methods b ON a.method_idx<b.method_idx LIMIT 3 OFFSET 1",
            "SELECT a.method_idx,b.method_idx FROM methods a,methods b WHERE b.method_idx>2 AND a.method_idx=1 LIMIT 4",
        ] {
            let query = parse(sql);
            let select = query.body.as_select().unwrap();
            let mut oracle = select.clone();
            // Move a non-equality ON to WHERE for the old nested-loop oracle.
            for table in &mut oracle.from {
                if let Some(join) = table.joins.first_mut() {
                    if let Some(expr) = join_constraint(&join.join_operator).unwrap() {
                        oracle.selection = Some(expr.clone());
                        join.join_operator = sqlparser::ast::JoinOperator::CrossJoin(sqlparser::ast::JoinConstraint::None);
                    }
                }
            }
            let mut expected = execute_select_core(&oracle, &ds, Some(&ds), &NamedCaches::default(), false, None, None).unwrap();
            apply_query_order_limit(&mut expected, &query, None).unwrap();
            assert_eq!(run(sql, &ds, None).rows, typed_to_result((expected.columns, expected.rows.into_iter().map(|row| row.values).collect())).rows, "{sql}");
        }
    }

    #[test]
    fn fingerprint_collisions_are_verified_against_borrowed_records() {
        let ds = fixture();
        let mut left = RelRow::default();
        left.put("a", "method_idx", Scalar::Int(0));
        let hash = row_hash(&left, ["a.method_idx"].into_iter()).unwrap();
        // Deliberately index a different source record under this fingerprint.
        let build = Build {
            rows: vec![(0, streaming::Source::Method(1))],
            index: FxHashMap::from_iter([(hash, vec![0])]),
            cells: ds
                .files
                .iter()
                .map(|file| {
                    RefCell::new(streaming::Cells::new(
                        file,
                        "methods",
                        false,
                        &["method_idx"],
                    ))
                })
                .collect(),
            table: "methods".to_owned(),
            alias: "b".to_owned(),
            predicates: Vec::new(),
            columns: vec![(
                intern_rel_component("b.method_idx"),
                intern_rel_component("method_idx"),
            )],
        };
        let joins = [Join {
            constraint: None,
            keys: vec![("a.method_idx".to_owned(), "b.method_idx".to_owned())],
        }];
        let mut visited = 0;
        assert!(!probe(0, &left, &joins, &[build], &ds, &mut |_| {
            visited += 1;
            Ok(false)
        })
        .unwrap());
        assert_eq!(visited, 0);
    }

    #[test]
    fn fallback_derived_joins_keep_scalar_types_and_composite_keys() {
        let ds = fixture();
        for (sql, count) in [
            ("SELECT count(*) FROM (SELECT '1' AS k) a JOIN (SELECT 1 AS k) b ON a.k=b.k", "0"),
            ("SELECT count(*) FROM (SELECT 1 AS k) a JOIN (SELECT 1.0 AS k) b ON a.k=b.k", "1"),
            ("SELECT count(*) FROM (SELECT NULL AS k) a JOIN (SELECT NULL AS k) b ON a.k=b.k", "0"),
            ("WITH x AS (SELECT file_id,method_idx FROM methods) SELECT count(*) FROM x a JOIN x b ON a.file_id=b.file_id AND a.method_idx=b.method_idx", "28"),
        ] {
            assert_eq!(execute_statement(sql, Some(&ds), &NamedCaches::default(), None).unwrap().rows, vec![vec![count.to_owned()]], "{sql}");
        }
    }

    #[test]
    fn fallback_comma_products_preserve_empty_inputs_at_each_position() {
        let ds = fixture();
        // Every expected result was checked against the original executable;
        // see artifacts/general/final-regression-oracle.json. Derived sources
        // force this through the generic product path rather than the pipeline.
        for (sql, expected) in [
            ("SELECT count(*) FROM (SELECT method_idx FROM methods WHERE method_idx<0) a, (SELECT 2 AS k) b", "0"),
            ("SELECT count(*) FROM (SELECT 1 AS k) a, (SELECT method_idx FROM methods WHERE method_idx<0) b, (SELECT 2 AS k) c", "0"),
            ("SELECT count(*) FROM (SELECT method_idx FROM methods WHERE method_idx=0) a, (SELECT method_idx FROM methods WHERE method_idx<0) b", "0"),
            ("SELECT count(*) FROM (SELECT method_idx FROM methods WHERE method_idx=0) a, (SELECT 2 AS k) b, (SELECT 3 AS k) c", "2"),
        ] {
            assert_eq!(
                execute_statement(sql, Some(&ds), &NamedCaches::default(), None).unwrap().rows,
                vec![vec![expected.to_owned()]],
                "{sql}",
            );
        }
    }

    #[test]
    fn set_membership_preserves_numeric_equality_and_null_type_identity() {
        let ds = fixture();
        // Include source-backed operands so reduced streaming set operands and
        // typed derived results use the same numeric/NULL equality contract.
        for (sql, expected) in [
            ("SELECT count(*) FROM (SELECT 1 AS k INTERSECT SELECT 1.0) t", "1"),
            ("SELECT count(*) FROM (SELECT 1 AS k EXCEPT SELECT 1.0) t", "0"),
            ("SELECT count(*) FROM (SELECT 0 AS k INTERSECT SELECT -0.0) t", "1"),
            ("SELECT count(*) FROM (SELECT NULL AS k INTERSECT SELECT 'NULL') t", "0"),
            ("SELECT count(*) FROM (SELECT NULL AS k EXCEPT SELECT 'NULL') t", "1"),
            ("SELECT count(*) FROM (SELECT NULL AS k INTERSECT SELECT NULL) t", "1"),
            ("SELECT count(*) FROM (SELECT method_idx AS k FROM methods WHERE method_idx=0 INTERSECT SELECT 0.0) t", "1"),
            ("SELECT count(*) FROM (SELECT method_idx AS k FROM methods WHERE method_idx=0 EXCEPT SELECT 0.0) t", "0"),
            ("SELECT count(*) FROM (SELECT 9007199254740993 AS k INTERSECT SELECT 9007199254740992.0) t", "0"),
        ] {
            assert_eq!(
                execute_statement(sql, Some(&ds), &NamedCaches::default(), None).unwrap().rows,
                vec![vec![expected.to_owned()]],
                "{sql}",
            );
        }
    }
}
