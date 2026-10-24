//! End-to-end tests for the `param_types_match` predicate and the canonical
//! `param_count` range form, including fast-path/generic parity.
//!
//! The fixture DEX files are shared with the metadata API tests: `alpha.dex`
//! defines a handful of methods with varied parameter lists and `beta.dex` only
//! references them.

use std::path::{Path, PathBuf};

use dexsql::Engine;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/dex")
        .join(name)
}

fn engine() -> Engine {
    Engine::open([fixture("alpha.dex"), fixture("beta.dex")]).expect("open fixture DEX files")
}

fn query_descriptors(engine: &Engine, sql: &str) -> Vec<String> {
    engine
        .query(sql)
        .unwrap_or_else(|error| panic!("query failed: {error}\n{sql}"))
        .rows
        .into_iter()
        .map(|row| row[0].clone())
        .collect()
}

/// Force the generic executor by appending a constant conjunct that the
/// descriptor-lookup fast path does not recognize.
fn force_generic(sql: &str) -> String {
    match sql.find(" ORDER BY") {
        Some(position) => format!("{} AND 1 = 1{}", &sql[..position], &sql[position..]),
        None => format!("{sql} AND 1 = 1"),
    }
}

fn assert_fast_and_generic_agree(engine: &Engine, sql: &str) -> Vec<String> {
    let fast = engine
        .query(sql)
        .unwrap_or_else(|error| panic!("fast query failed: {error}\n{sql}"));
    let generic_sql = force_generic(sql);
    let generic = engine
        .query(&generic_sql)
        .unwrap_or_else(|error| panic!("generic query failed: {error}\n{generic_sql}"));
    assert_eq!(fast.columns, generic.columns, "columns differ for {sql}");
    assert_eq!(
        fast.rows, generic.rows,
        "fast and generic rows differ for {sql}\nfast: {fast:?}\ngeneric: {generic:?}"
    );
    fast.rows.into_iter().map(|row| row[0].clone()).collect()
}

const FIXTURE_METHODS: &str = "m.class_descriptor LIKE 'Lfixtures/%'";

#[test]
fn pattern_matches_wildcards_at_any_position() {
    let engine = engine();
    let added = ["Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I".to_owned()];
    for pattern in [
        // Wildcard in the middle.
        "I,?,Ljava/lang/String;,[I",
        // Wildcards at the end.
        "I,J,?,?",
        // Wildcards at the start.
        "?,?,Ljava/lang/String;,[I",
        // Wildcard at every position with exact object/array tokens kept.
        "I,?,?,?",
    ] {
        let sql = format!(
            "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
             WHERE {FIXTURE_METHODS} \
               AND param_types_match(m.param_descriptors, '{pattern}') \
             ORDER BY m.descriptor"
        );
        assert_eq!(
            assert_fast_and_generic_agree(&engine, &sql),
            added,
            "pattern {pattern:?}"
        );
    }
}

#[test]
fn pattern_is_case_sensitive_and_arity_exact() {
    let engine = engine();
    for pattern in [
        // Lowercase primitive/object descriptors do not match.
        "i,j,Ljava/lang/String;,[I",
        // Wrong arity.
        "I,?",
        "I,?,Ljava/lang/String;",
        "I,?,Ljava/lang/String;,[I,?",
        // Empty parameter list does not match any parameterised method.
        "",
    ] {
        let sql = format!(
            "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
             WHERE {FIXTURE_METHODS} \
               AND param_types_match(m.param_descriptors, '{pattern}') \
             ORDER BY m.descriptor"
        );
        let rows = assert_fast_and_generic_agree(&engine, &sql);
        if pattern.is_empty() {
            // Empty matches only zero-parameter methods, which the next test
            // checks explicitly; here just make sure the parameterised method
            // is not included.
            assert!(!rows.contains(&"Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I".to_owned()));
        } else {
            assert!(
                rows.is_empty(),
                "pattern {pattern:?} unexpectedly matched {rows:?}"
            );
        }
    }
}

#[test]
fn empty_pattern_matches_zero_parameter_methods() {
    let engine = engine();
    let sql = format!(
        "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
         WHERE {FIXTURE_METHODS} \
           AND param_types_match(m.param_descriptors, '') \
         ORDER BY m.descriptor"
    );
    assert_eq!(
        assert_fast_and_generic_agree(&engine, &sql),
        [
            "Lfixtures/Alpha;-><clinit>()V",
            "Lfixtures/Alpha;-><init>()V",
            "Lfixtures/Alpha;->doIt()V",
            "Lfixtures/Alpha;->duplicateInvokes()I",
            "Lfixtures/Alpha;->duplicateStrings()I",
            "Lfixtures/Alpha;->fieldTraffic()I",
            "Lfixtures/Alpha;->helper()I",
            "Lfixtures/Alpha;->locked()V",
            "Lfixtures/Alpha;->numbers()J",
            "Lfixtures/Beta;-><init>()V",
            "Lfixtures/Beta;->run()V",
            "Lfixtures/Gamma;->doIt()V",
        ]
    );

    // The existing equality form stays equivalent.
    let equality = format!(
        "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
         WHERE {FIXTURE_METHODS} AND m.param_descriptors = '' ORDER BY m.descriptor"
    );
    assert_eq!(
        query_descriptors(&engine, &equality),
        query_descriptors(&engine, &sql)
    );
}

#[test]
fn inclusive_param_count_range_is_canonical() {
    let engine = engine();
    for (minimum, maximum, expected) in [
        (
            1,
            1,
            vec!["Lfixtures/Alpha;->greet(Ljava/lang/String;)Ljava/lang/String;".to_owned()],
        ),
        (
            4,
            4,
            vec!["Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I".to_owned()],
        ),
        (2, 3, Vec::new()),
    ] {
        let sql = format!(
            "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
             WHERE {FIXTURE_METHODS} \
               AND m.param_count >= {minimum} AND m.param_count <= {maximum} \
             ORDER BY m.descriptor"
        );
        assert_eq!(
            assert_fast_and_generic_agree(&engine, &sql),
            expected,
            "range {minimum}..={maximum}"
        );
    }

    // A zero..=zero range matches the same methods as the empty pattern.
    let zero_range = format!(
        "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
         WHERE {FIXTURE_METHODS} \
           AND m.param_count >= 0 AND m.param_count <= 0 \
         ORDER BY m.descriptor"
    );
    let empty_pattern = format!(
        "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
         WHERE {FIXTURE_METHODS} \
           AND param_types_match(m.param_descriptors, '') \
         ORDER BY m.descriptor"
    );
    assert_eq!(
        query_descriptors(&engine, &zero_range),
        query_descriptors(&engine, &empty_pattern)
    );
}

#[test]
fn strict_bounds_are_normalized_for_the_fast_path() {
    let engine = engine();
    let sql = format!(
        "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
         WHERE {FIXTURE_METHODS} \
           AND m.param_count > 3 AND m.param_count < 5 \
         ORDER BY m.descriptor"
    );
    assert_eq!(
        assert_fast_and_generic_agree(&engine, &sql),
        ["Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I"]
    );
}

#[test]
fn equals_one_form_matches_the_bare_predicate() {
    let engine = engine();
    let bare = format!(
        "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
         WHERE {FIXTURE_METHODS} \
           AND param_types_match(m.param_descriptors, 'I,?,?,?') \
         ORDER BY m.descriptor"
    );
    let wrapped = format!(
        "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
         WHERE {FIXTURE_METHODS} \
           AND param_types_match(m.param_descriptors, 'I,?,?,?') = 1 \
         ORDER BY m.descriptor"
    );
    assert_eq!(
        query_descriptors(&engine, &bare),
        query_descriptors(&engine, &wrapped)
    );
    assert_eq!(
        query_descriptors(&engine, &bare),
        ["Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I"]
    );
}

#[test]
fn null_and_malformed_inputs_match_nothing() {
    let engine = engine();
    for predicate in [
        "param_types_match(NULL, 'I')",
        "param_types_match(m.param_descriptors, NULL)",
        // Malformed patterns match nothing (documented behaviour).
        "param_types_match(m.param_descriptors, 'I,,J')",
        "param_types_match(m.param_descriptors, '??')",
        "param_types_match(m.param_descriptors, 'Lx?;')",
    ] {
        let sql = format!(
            "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
             WHERE {predicate} ORDER BY m.descriptor"
        );
        assert!(
            query_descriptors(&engine, &sql).is_empty(),
            "predicate {predicate:?} should match nothing"
        );
    }
}

#[test]
fn class_level_param_pattern_constraints() {
    let engine = engine();

    // declaredClass { paramTypes(...) } shape: an existential methods unit on
    // the projected class.
    let class_unit = "SELECT DISTINCT cm.class_descriptor AS descriptor FROM methods cm          JOIN methods ccm0 ON ccm0.class_descriptor = cm.class_descriptor          WHERE ccm0.file_id = cm.file_id AND ccm0.class_idx = cm.class_idx            AND param_types_match(ccm0.param_descriptors, 'I,?,?,?')            AND cm.class_descriptor LIKE 'Lfixtures/%'          ORDER BY cm.class_descriptor";
    assert_eq!(
        assert_fast_and_generic_agree(&engine, class_unit),
        ["Lfixtures/Alpha;"]
    );

    // Bare class query with a nested method constraint.
    let bare_class = "SELECT DISTINCT c.descriptor AS descriptor FROM classes c          JOIN methods ccm0 ON ccm0.class_descriptor = c.descriptor          WHERE param_types_match(ccm0.param_descriptors, 'I,J,?,?')            AND c.descriptor LIKE 'Lfixtures/%'          ORDER BY c.descriptor";
    assert_eq!(
        assert_fast_and_generic_agree(&engine, bare_class),
        ["Lfixtures/Alpha;"]
    );
}
