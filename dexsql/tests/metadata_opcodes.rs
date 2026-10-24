//! Tests for the opcode projection on top-level metadata method documents.
//!
//! The fixture `fixtures/dex/annotated.dex` has methods with known instruction
//! streams. Opcode data requires a full-code-items load; metadata-only loads
//! render null/empty opcode fields instead of erroring.

use std::path::{Path, PathBuf};

use dexsql::{Engine, EngineOptions, IndexNeeds, MetaQuery};
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/dex")
        .join(name)
}

fn open_engine(full_code_items: bool) -> Engine {
    let options = EngineOptions {
        index_needs: IndexNeeds::all(),
        eager_code_items: full_code_items,
        full_code_items,
        retain_classes: true,
        threads: Some(1),
    };
    Engine::open_with_options([fixture("annotated.dex")], options).expect("open fixture DEX")
}

fn metadata(engine: &Engine, descriptor: &str) -> Value {
    engine
        .metadata(&MetaQuery::method(descriptor))
        .unwrap_or_else(|error| panic!("metadata failed for {descriptor}: {error}"))
}

fn strings(document: &Value, key: &str) -> Vec<String> {
    document
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|value| value.as_str().expect("opcode name").to_owned())
                .collect()
        })
        .unwrap_or_else(|| panic!("missing array key {key} in {document}"))
}

#[test]
fn opcodes_match_the_decoded_instruction_stream() {
    let engine = open_engine(true);

    let make = metadata(&engine, "Lfixtures/Annotated;->make()Ljava/lang/Object;");
    assert_eq!(make.get("opcode_count").and_then(Value::as_u64), Some(3));
    assert_eq!(
        strings(&make, "opcodes"),
        ["new-instance", "invoke-direct", "return-object"]
    );

    let add_one = metadata(&engine, "Lfixtures/Annotated;->addOne(I)I");
    assert_eq!(add_one.get("opcode_count").and_then(Value::as_u64), Some(2));
    assert_eq!(strings(&add_one, "opcodes"), ["add-int/lit8", "return"]);

    let copy = metadata(&engine, "Lfixtures/Annotated;->copy([I)[I");
    assert_eq!(copy.get("opcode_count").and_then(Value::as_u64), Some(4));
    assert_eq!(
        strings(&copy, "opcodes"),
        [
            "invoke-virtual",
            "move-result-object",
            "check-cast",
            "return-object"
        ]
    );

    let generic = metadata(
        &engine,
        "Lfixtures/Annotated;->genericList(Ljava/util/List;)Ljava/util/List;",
    );
    assert_eq!(generic.get("opcode_count").and_then(Value::as_u64), Some(1));
    assert_eq!(strings(&generic, "opcodes"), ["return-object"]);
}

#[test]
fn opcode_count_matches_the_methods_relation() {
    let engine = open_engine(true);
    for descriptor in [
        "Lfixtures/Annotated;->make()Ljava/lang/Object;",
        "Lfixtures/Annotated;->addOne(I)I",
        "Lfixtures/Annotated;->copy([I)[I",
        "Lfixtures/Annotated;->copyMetas([Lfixtures/Meta;)[Lfixtures/Meta;",
        "Lfixtures/Annotated;->genericList(Ljava/util/List;)Ljava/util/List;",
    ] {
        let document = metadata(&engine, descriptor);
        let json_count = document
            .get("opcode_count")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("missing opcode_count for {descriptor}"));
        let sql = format!("SELECT opcode_count FROM methods WHERE descriptor = '{descriptor}'");
        let result = engine.query(&sql).expect("methods query");
        let sql_count = result.rows[0][0]
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("non-numeric opcode_count for {descriptor}"));
        assert_eq!(
            json_count, sql_count,
            "opcode_count mismatch for {descriptor}"
        );
        assert_eq!(
            document
                .get("opcodes")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(json_count as usize),
            "opcode list length mismatch for {descriptor}"
        );
    }
}

#[test]
fn method_without_code_renders_null_opcodes() {
    let engine = open_engine(true);
    let document = metadata(&engine, "Lfixtures/Meta;->value()[Ljava/lang/String;");
    assert!(document.get("opcode_count").is_some_and(Value::is_null));
    assert_eq!(strings(&document, "opcodes"), Vec::<String>::new());
}

#[test]
fn metadata_only_load_renders_empty_opcode_fields() {
    let engine = open_engine(false);
    let document = metadata(&engine, "Lfixtures/Annotated;->make()Ljava/lang/Object;");
    assert!(document.get("opcode_count").is_some_and(Value::is_null));
    assert_eq!(strings(&document, "opcodes"), Vec::<String>::new());
    // The rest of the method document still renders normally.
    assert_eq!(document.get("name").and_then(Value::as_str), Some("make"));
}
