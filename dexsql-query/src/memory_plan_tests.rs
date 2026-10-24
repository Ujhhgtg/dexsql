use super::*;

fn parse(sql: &str) -> sqlparser::ast::Query {
    let statements =
        sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::SQLiteDialect {}, sql).unwrap();
    let sqlparser::ast::Statement::Query(query) = statements.into_iter().next().unwrap() else {
        panic!("expected query");
    };
    *query
}

fn select(query: &sqlparser::ast::Query) -> &sqlparser::ast::Select {
    query.body.as_select().unwrap()
}

#[test]
fn physical_scan_limit_preserves_offsets_and_aggregates() {
    let query = parse("SELECT descriptor FROM methods LIMIT 3 OFFSET 5");
    assert_eq!(query_scan_limit(select(&query), &query, None), Some(8));
    assert_eq!(query_scan_limit(select(&query), &query, Some(1)), Some(6));
    let query = parse("SELECT descriptor FROM methods LIMIT 5, 3");
    assert_eq!(query_scan_limit(select(&query), &query, None), Some(8));
    for sql in [
        "SELECT count(*) FROM methods LIMIT 1",
        "SELECT 1 + count(name) FROM methods LIMIT 1",
        "SELECT length(group_concat(name)) FROM methods LIMIT 1",
        "SELECT sum(method_idx) FROM methods LIMIT 1",
        "SELECT count(*) OVER () FROM methods LIMIT 1",
    ] {
        let query = parse(sql);
        assert_eq!(
            query_scan_limit(select(&query), &query, None),
            None,
            "{sql}"
        );
    }
}

#[test]
fn physical_scan_limit_requires_complete_predicate_pushdown() {
    for sql in [
        "SELECT descriptor FROM methods WHERE missing = 5 LIMIT 1",
        "SELECT descriptor FROM methods m WHERE other.method_idx = 5 LIMIT 1",
        "SELECT descriptor FROM methods WHERE method_idx + 1 = 5 LIMIT 1",
        "SELECT value FROM strings WHERE string_idx = 5 LIMIT 1",
    ] {
        let query = parse(sql);
        assert_eq!(
            query_scan_limit(select(&query), &query, None),
            None,
            "{sql}"
        );
    }
    for sql in [
        "SELECT descriptor FROM methods m WHERE m.method_idx = 5 LIMIT 1",
        "SELECT descriptor FROM classes WHERE class_idx = 5 LIMIT 1",
        "SELECT descriptor FROM fields WHERE field_idx = 5 LIMIT 1",
    ] {
        let query = parse(sql);
        assert_eq!(
            query_scan_limit(select(&query), &query, None),
            Some(1),
            "{sql}"
        );
    }
}

#[test]
fn pruning_keeps_group_having_and_order_dependencies() {
    let query = parse("SELECT class_descriptor, sum(method_idx) AS n FROM methods WHERE param_count = 1 GROUP BY class_descriptor HAVING sum(method_idx) > 1 ORDER BY name");
    let columns = query_scan_columns(select(&query), &query).unwrap();
    for required in ["class_descriptor", "method_idx", "param_count", "name"] {
        assert!(columns.contains(required), "missing {required}");
    }
    for sql in [
        "SELECT * FROM methods",
        "SELECT m.* FROM methods m",
        "SELECT count(*) FILTER (WHERE method_idx > 5) FROM methods",
        "SELECT sum(method_idx) OVER (ORDER BY name) FROM methods",
    ] {
        let query = parse(sql);
        assert!(
            query_scan_columns(select(&query), &query).is_none(),
            "{sql}"
        );
    }
}

#[test]
fn methods_topk_rejects_predicates_it_cannot_evaluate() {
    let ds = Dataset::default();
    for sql in [
        "SELECT descriptor FROM methods WHERE method_idx=5 ORDER BY descriptor LIMIT 1",
        "SELECT descriptor FROM methods WHERE file_id=0 ORDER BY descriptor LIMIT 1",
        "SELECT descriptor FROM methods WHERE param_count='1' ORDER BY descriptor LIMIT 1",
        "SELECT other.descriptor FROM methods ORDER BY descriptor LIMIT 1",
        "SELECT m.descriptor FROM methods m ORDER BY other.descriptor LIMIT 1",
    ] {
        assert!(fast_methods_topk(&parse(sql), &ds, None).is_none(), "{sql}");
    }
}

#[test]
fn topk_offset_and_generic_scanner_predicates_match_unbounded_results() {
    let ds = Dataset::load_paths(&[
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex")
    ])
    .unwrap();
    let caches = NamedCaches::default();
    for predicate in ["", " WHERE param_count=0"] {
        let all = fast_methods_topk(
            &parse(&format!(
                "SELECT descriptor FROM methods{predicate} ORDER BY descriptor LIMIT 100"
            )),
            &ds,
            None,
        )
        .unwrap()
        .unwrap();
        for cli_limit in [None, Some(1)] {
            let limited = fast_methods_topk(
                &parse(&format!("SELECT descriptor FROM methods{predicate} ORDER BY descriptor LIMIT 2 OFFSET 1")),
                &ds, cli_limit,
            ).unwrap().unwrap();
            assert_eq!(
                limited.rows,
                all.rows
                    .iter()
                    .skip(1)
                    .take(cli_limit.unwrap_or(2) as usize)
                    .cloned()
                    .collect::<Vec<_>>()
            );
        }
    }
    for (table, key) in [
        ("methods", "method_idx"),
        ("classes", "class_def_idx"),
        ("fields", "field_idx"),
    ] {
        let all = execute_query(
            &parse(&format!("SELECT {key} FROM {table}")),
            &ds,
            Some(&ds),
            &caches,
            None,
            false,
        )
        .unwrap();
        for row in &all.rows {
            let sql = format!("SELECT {key} FROM {table} WHERE {key}={} LIMIT 1", row[0]);
            let result = execute_query(&parse(&sql), &ds, Some(&ds), &caches, None, false).unwrap();
            assert_eq!(result.rows, vec![row.clone()], "{sql}");
        }
        let query = parse(&format!("SELECT {key} FROM {table} WHERE {key}=1 LIMIT 1"));
        let source = scan_factor(
            &select(&query).from[0].relation,
            &ds,
            Some(&[simple_push_predicate(select(&query).selection.as_ref().unwrap()).unwrap()]),
            None,
            false,
            &caches,
            Some(&ds),
            Some(1),
            None,
        )
        .unwrap();
        assert_eq!(source.len(), 1, "direct scanner {table}");
        assert_eq!(
            source[0].get(key),
            Some(&Scalar::Int(1)),
            "direct scanner {table}"
        );
    }
    let query = parse("SELECT count(name) FROM methods LIMIT 1");
    let result = execute_query(&query, &ds, Some(&ds), &caches, None, false).unwrap();
    assert_eq!(
        result.rows,
        vec![vec![ds.files[0].methods.len().to_string()]]
    );
}
