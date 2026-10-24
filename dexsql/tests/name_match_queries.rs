//! End-to-end tests for case-sensitive name-match modes on class/return/
//! superclass descriptors (DexKit StringMatchType Contains/StartsWith/EndsWith),
//! including fast-path/generic parity.
//!
//! Fixtures: `alpha.dex` defines `fixtures.Alpha` (fields + methods with varied
//! return/parameter types) and `fixtures.Gamma`; `beta.dex` defines
//! `fixtures.Beta extends fixtures.Alpha`.

use std::path::{Path, PathBuf};

use dexsql::Engine;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/dex")
        .join(name)
}

fn engine() -> Engine {
    // Default options retain class definitions.
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

/// Force the generic executor with a constant conjunct the fast path rejects.
fn force_generic(sql: &str) -> String {
    let position = sql.find(" ORDER BY").unwrap_or(sql.len());
    let (head, tail) = sql.split_at(position);
    if head.to_ascii_lowercase().contains(" where ") {
        format!("{head} AND 1 = 1{tail}")
    } else {
        format!("{head} WHERE 1 = 1{tail}")
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
    assert_eq!(
        fast.rows, generic.rows,
        "fast and generic rows differ for {sql}"
    );
    fast.rows.into_iter().map(|row| row[0].clone()).collect()
}

fn class_projection(predicate: &str) -> String {
    format!(
        "SELECT DISTINCT cm.class_descriptor AS descriptor FROM methods cm \
         WHERE {predicate} ORDER BY cm.class_descriptor"
    )
}

#[test]
fn class_descriptor_starts_with() {
    let engine = engine();
    assert_eq!(
        assert_fast_and_generic_agree(
            &engine,
            &class_projection("instr(cm.class_descriptor, 'Lfixtures/') = 1")
        ),
        ["Lfixtures/Alpha;", "Lfixtures/Beta;", "Lfixtures/Gamma;"]
    );
    // Prefix boundary: startsWith must match the literal exactly, not as a
    // looser "contains" or with extra letters.
    assert_eq!(
        assert_fast_and_generic_agree(
            &engine,
            &class_projection("instr(cm.class_descriptor, 'Lfixtures/Alph') = 1")
        ),
        ["Lfixtures/Alpha;"]
    );
    assert!(assert_fast_and_generic_agree(
        &engine,
        &class_projection("instr(cm.class_descriptor, 'Lfixtures/AlphaX') = 1")
    )
    .is_empty());
}

#[test]
fn class_descriptor_contains() {
    let engine = engine();
    assert_eq!(
        assert_fast_and_generic_agree(
            &engine,
            &class_projection("instr(cm.class_descriptor, 'fixtures/Al') > 0")
        ),
        ["Lfixtures/Alpha;"]
    );
    assert!(assert_fast_and_generic_agree(
        &engine,
        &class_projection("instr(cm.class_descriptor, 'Alpha;L') > 0")
    )
    .is_empty());
}

#[test]
fn class_descriptor_ends_with_includes_the_semicolon() {
    let engine = engine();
    // Canonical dotted form: literal "fixtures.Alpha" -> "fixtures/Alpha" and
    // substr(..., -(len + 1)) = 'fixtures/Alpha;'.
    assert_eq!(
        assert_fast_and_generic_agree(
            &engine,
            &class_projection("substr(cm.class_descriptor, -15) = 'fixtures/Alpha;'")
        ),
        ["Lfixtures/Alpha;"]
    );
    // A literal name suffix still needs the trailing ';' in the SQL literal.
    assert_eq!(
        assert_fast_and_generic_agree(
            &engine,
            &class_projection("substr(cm.class_descriptor, -5) = 'lpha;'")
        ),
        ["Lfixtures/Alpha;"]
    );
    assert!(assert_fast_and_generic_agree(
        &engine,
        &class_projection("substr(cm.class_descriptor, -5) = 'Alpha'")
    )
    .is_empty());
}

#[test]
fn return_descriptor_match_modes() {
    let engine = engine();
    let returns = |predicate: &str| {
        format!(
            "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
             WHERE {predicate} AND m.class_descriptor LIKE 'Lfixtures/%' \
             ORDER BY m.descriptor"
        )
    };
    assert_eq!(
        assert_fast_and_generic_agree(
            &engine,
            &returns("instr(m.return_descriptor, 'Ljava/lang/String') = 1")
        ),
        ["Lfixtures/Alpha;->greet(Ljava/lang/String;)Ljava/lang/String;"]
    );
    assert_eq!(
        assert_fast_and_generic_agree(
            &engine,
            &returns("instr(m.return_descriptor, 'lang/String') > 0")
        ),
        ["Lfixtures/Alpha;->greet(Ljava/lang/String;)Ljava/lang/String;"]
    );
    // Literal "String" (6 chars) -> suffix 'String;' at -(len + 1).
    assert_eq!(
        assert_fast_and_generic_agree(
            &engine,
            &returns("substr(m.return_descriptor, -7) = 'String;'")
        ),
        ["Lfixtures/Alpha;->greet(Ljava/lang/String;)Ljava/lang/String;"]
    );
    // Primitive descriptors are bare ('I') and do not carry a trailing ';',
    // so an endsWith suffix built for object types matches nothing.
    assert!(assert_fast_and_generic_agree(
        &engine,
        &returns("substr(m.return_descriptor, -2) = 'I;'")
    )
    .is_empty());
    // Primitive startsWith/contains compare against the raw descriptor.
    assert_eq!(
        assert_fast_and_generic_agree(&engine, &returns("instr(m.return_descriptor, 'I') = 1")),
        [
            "Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I",
            "Lfixtures/Alpha;->duplicateInvokes()I",
            "Lfixtures/Alpha;->duplicateStrings()I",
            "Lfixtures/Alpha;->fieldTraffic()I",
            "Lfixtures/Alpha;->helper()I",
        ]
    );
}

#[test]
fn superclass_descriptor_match_modes() {
    let engine = engine();
    let class_unit = |predicate: &str| {
        format!(
            "SELECT DISTINCT cm.class_descriptor AS descriptor FROM methods cm \
             JOIN classes cc ON cc.descriptor = cm.class_descriptor \
             WHERE {predicate} AND cm.class_descriptor LIKE 'Lfixtures/%' \
             ORDER BY cm.class_descriptor"
        )
    };
    for predicate in [
        "instr(cc.superclass_descriptor, 'Lfixtures/Alpha') = 1",
        "instr(cc.superclass_descriptor, 'fixtures/Al') > 0",
        "substr(cc.superclass_descriptor, -15) = 'fixtures/Alpha;'",
    ] {
        assert_eq!(
            assert_fast_and_generic_agree(&engine, &class_unit(predicate)),
            ["Lfixtures/Beta;"],
            "predicate {predicate}"
        );
    }

    let bare_class = |predicate: &str| {
        format!(
            "SELECT DISTINCT c.descriptor AS descriptor FROM classes c \
             WHERE {predicate} AND c.descriptor LIKE 'Lfixtures/%' \
             ORDER BY c.descriptor"
        )
    };
    for predicate in [
        "instr(c.superclass_descriptor, 'Lfixtures/Alpha') = 1",
        "instr(c.superclass_descriptor, 'Alpha') > 0",
        "substr(c.superclass_descriptor, -6) = 'Alpha;'",
    ] {
        assert_eq!(
            assert_fast_and_generic_agree(&engine, &bare_class(predicate)),
            ["Lfixtures/Beta;"],
            "predicate {predicate}"
        );
    }
}

#[test]
fn name_modes_inside_class_constraint_units() {
    let engine = engine();
    // declaredClass { methods { name-mode className } } shape.
    let sql = "SELECT DISTINCT cm.class_descriptor AS descriptor FROM methods cm \
         JOIN methods ccm0 ON ccm0.class_descriptor = cm.class_descriptor \
         WHERE ccm0.file_id = cm.file_id AND ccm0.class_idx = cm.class_idx \
           AND instr(ccm0.class_descriptor, 'fixtures/Al') > 0 \
         ORDER BY cm.class_descriptor";
    assert_eq!(
        assert_fast_and_generic_agree(&engine, sql),
        ["Lfixtures/Alpha;"]
    );
}

#[test]
fn field_class_descriptor_match_modes() {
    let engine = engine();
    let fields = |predicate: &str| {
        format!(
            "SELECT DISTINCT f.descriptor AS descriptor FROM fields f \
             WHERE {predicate} ORDER BY f.descriptor"
        )
    };
    assert_eq!(
        assert_fast_and_generic_agree(
            &engine,
            &fields("substr(f.class_descriptor, -15) = 'fixtures/Alpha;'")
        ),
        [
            "Lfixtures/Alpha;->TAG:Ljava/lang/String;",
            "Lfixtures/Alpha;->byteArray:[B",
            "Lfixtures/Alpha;->longField:J",
            "Lfixtures/Alpha;->matrix:[[I",
            "Lfixtures/Alpha;->name:Ljava/lang/String;",
            "Lfixtures/Alpha;->staticField:I",
        ]
    );
    assert_eq!(
        assert_fast_and_generic_agree(
            &engine,
            &fields("instr(f.class_descriptor, 'Lfixtures/Bet') = 1")
        )
        .len(),
        0
    );
}

#[test]
fn class_projection_without_predicates_matches_generic() {
    let engine = engine();
    // Includes classes that the fixture DEX only references (framework types),
    // exactly like the generic methods scan; this guards the candidate
    // enumeration fix for class-projected lookups with no unit predicates.
    let sql = "SELECT DISTINCT m.class_descriptor AS descriptor FROM methods m \
         ORDER BY m.class_descriptor LIMIT 8";
    let rows = assert_fast_and_generic_agree(&engine, sql);
    assert!(!rows.is_empty());
    assert!(rows.iter().any(|row| row.starts_with("Ljava/lang/")));
}
