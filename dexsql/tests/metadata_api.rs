//! Integration tests for the typed metadata JSON API.
//!
//! Fixtures live in `fixtures/dex` and are described in its README: `alpha.dex`
//! defines `fixtures.Alpha` / `fixtures.Gamma`, and `beta.dex` only references
//! them, which exercises cross-DEX resolution and DexKit-compatible caller
//! import order.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dexsql::{Engine, EngineOptions, IndexNeeds, MetaQuery};
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/dex")
        .join(name)
}

fn open_engine(with_relations: bool) -> Engine {
    let options = EngineOptions {
        index_needs: if with_relations {
            IndexNeeds::all()
        } else {
            IndexNeeds::default()
        },
        eager_code_items: with_relations,
        full_code_items: false,
        retain_classes: true,
        threads: Some(1),
    };
    Engine::open_with_options([fixture("alpha.dex"), fixture("beta.dex")], options)
        .expect("open fixture DEX files")
}

fn metadata(engine: &Engine, query: MetaQuery) -> Value {
    engine.metadata(&query).expect("metadata query")
}

fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string key {key} in {value}"))
        .to_owned()
}

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing numeric key {key} in {value}"))
}

fn bool_at(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("missing bool key {key} in {value}"))
}

fn string_list(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing array key {key} in {value}"))
        .iter()
        .map(|item| item.as_str().expect("string array item").to_owned())
        .collect()
}

fn member_descriptors(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing array key {key} in {value}"))
        .iter()
        .map(|item| string(item, "descriptor"))
        .collect()
}

#[test]
fn class_document_shape_and_members() {
    let engine = open_engine(true);
    let class = metadata(&engine, MetaQuery::class("Lfixtures/Alpha;"));
    assert_eq!(string(&class, "kind"), "class");
    assert_eq!(string(&class, "descriptor"), "Lfixtures/Alpha;");
    assert_eq!(string(&class, "name"), "fixtures.Alpha");
    assert_eq!(string(&class, "simple_name"), "Alpha");
    assert_eq!(string(&class, "source_file"), "Alpha.java");
    assert_eq!(number(&class, "access_flags"), 1);
    assert_eq!(number(&class, "modifiers"), 1);
    assert!(!bool_at(&class, "is_array"));

    let super_class = class.get("super_class").expect("super_class key");
    assert_eq!(string(super_class, "descriptor"), "Ljava/lang/Object;");
    assert_eq!(string(super_class, "name"), "java.lang.Object");

    let interfaces = class
        .get("interfaces")
        .and_then(Value::as_array)
        .expect("interfaces array");
    assert_eq!(interfaces.len(), 1);
    assert_eq!(string(&interfaces[0], "descriptor"), "Lfixtures/Gamma;");
    assert_eq!(string(&interfaces[0], "name"), "fixtures.Gamma");

    // DexKit reports declared members in DEX id order.
    assert_eq!(
        member_descriptors(&class, "methods"),
        [
            "Lfixtures/Alpha;-><clinit>()V",
            "Lfixtures/Alpha;-><init>()V",
            "Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I",
            "Lfixtures/Alpha;->doIt()V",
            "Lfixtures/Alpha;->duplicateInvokes()I",
            "Lfixtures/Alpha;->duplicateStrings()I",
            "Lfixtures/Alpha;->fieldTraffic()I",
            "Lfixtures/Alpha;->greet(Ljava/lang/String;)Ljava/lang/String;",
            "Lfixtures/Alpha;->helper()I",
            "Lfixtures/Alpha;->locked()V",
            "Lfixtures/Alpha;->numbers()J",
        ]
    );
    assert_eq!(
        member_descriptors(&class, "fields"),
        [
            "Lfixtures/Alpha;->TAG:Ljava/lang/String;",
            "Lfixtures/Alpha;->byteArray:[B",
            "Lfixtures/Alpha;->longField:J",
            "Lfixtures/Alpha;->matrix:[[I",
            "Lfixtures/Alpha;->name:Ljava/lang/String;",
            "Lfixtures/Alpha;->staticField:I",
        ]
    );
}

#[test]
fn method_member_ref_shape_sign_and_modifiers() {
    let engine = open_engine(true);
    let method = metadata(
        &engine,
        MetaQuery::method("Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I"),
    );
    assert_eq!(string(&method, "kind"), "method");
    assert_eq!(
        string(&method, "descriptor"),
        "Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I"
    );
    assert_eq!(string(&method, "name"), "add");
    assert_eq!(string(&method, "declared_class_name"), "fixtures.Alpha");
    assert_eq!(number(&method, "access_flags"), 1);
    assert_eq!(number(&method, "modifiers"), 1);
    assert!(bool_at(&method, "defined"));
    assert_eq!(string(&method, "return_type"), "I");
    assert_eq!(string(&method, "return_type_name"), "int");
    assert_eq!(
        string_list(&method, "param_type_names"),
        ["int", "long", "java.lang.String", "int[]"]
    );
    assert_eq!(number(&method, "param_count"), 4);
    // DexKit methodSign is the proto sign without the method name.
    assert_eq!(string(&method, "method_sign"), "(IJLjava/lang/String;[I)I");
    assert!(!bool_at(&method, "is_constructor"));
    assert!(!bool_at(&method, "is_static_initializer"));
    assert!(bool_at(&method, "is_method"));

    let constructor = metadata(&engine, MetaQuery::method("Lfixtures/Alpha;-><init>()V"));
    assert!(bool_at(&constructor, "is_constructor"));
    assert_eq!(number(&constructor, "access_flags"), 65_537);
    // ACC_CONSTRUCTOR is a DEX-only bit and is stripped from modifiers.
    assert_eq!(number(&constructor, "modifiers"), 1);
    assert_eq!(string(&constructor, "method_sign"), "()V");

    let initializer = metadata(&engine, MetaQuery::method("Lfixtures/Alpha;-><clinit>()V"));
    assert!(bool_at(&initializer, "is_static_initializer"));
    assert_eq!(number(&initializer, "access_flags"), 65_544);
    assert_eq!(number(&initializer, "modifiers"), 8);

    // ACC_DECLARED_SYNCHRONIZED maps to Java Modifier.SYNCHRONIZED.
    let locked = metadata(&engine, MetaQuery::method("Lfixtures/Alpha;->locked()V"));
    assert_eq!(number(&locked, "access_flags"), 131_073);
    assert_eq!(number(&locked, "modifiers"), 33);
}

#[test]
fn field_member_ref_shape() {
    let engine = open_engine(true);
    let field = metadata(
        &engine,
        MetaQuery::field("Lfixtures/Alpha;->name:Ljava/lang/String;"),
    );
    assert_eq!(string(&field, "kind"), "field");
    assert_eq!(
        string(&field, "descriptor"),
        "Lfixtures/Alpha;->name:Ljava/lang/String;"
    );
    assert_eq!(string(&field, "name"), "name");
    assert_eq!(string(&field, "declared_class_name"), "fixtures.Alpha");
    assert_eq!(number(&field, "access_flags"), 2);
    assert_eq!(number(&field, "modifiers"), 2);
    assert!(bool_at(&field, "defined"));
    assert_eq!(string(&field, "type"), "Ljava/lang/String;");
    assert_eq!(string(&field, "type_name"), "java.lang.String");
}

#[test]
fn array_and_primitive_type_names() {
    let engine = open_engine(true);
    let class = metadata(&engine, MetaQuery::class("Lfixtures/Alpha;"));
    let fields = class
        .get("fields")
        .and_then(Value::as_array)
        .expect("fields array");
    let by_name = |name: &str| -> Value {
        fields
            .iter()
            .find(|field| string(field, "name") == name)
            .cloned()
            .unwrap_or_else(|| panic!("field {name}"))
    };
    assert_eq!(string(&by_name("byteArray"), "type_name"), "byte[]");
    assert_eq!(string(&by_name("matrix"), "type_name"), "int[][]");
    assert_eq!(string(&by_name("longField"), "type_name"), "long");
    assert_eq!(string(&by_name("staticField"), "type_name"), "int");
}

#[test]
fn invokes_keep_instruction_order_and_duplicates() {
    let engine = open_engine(true);
    let method = metadata(&engine, MetaQuery::method("Lfixtures/Alpha;->doIt()V"));
    assert_eq!(
        member_descriptors(&method, "invokes"),
        [
            "Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I",
            "Lfixtures/Alpha;->greet(Ljava/lang/String;)Ljava/lang/String;",
            "Lfixtures/Alpha;->greet(Ljava/lang/String;)Ljava/lang/String;",
            "Ljava/io/PrintStream;->println(Ljava/lang/String;)V",
        ]
    );
    let invokes = method
        .get("invokes")
        .and_then(Value::as_array)
        .expect("invokes array");
    // Methods defined in this file carry class-data flags.
    assert!(bool_at(&invokes[0], "defined"));
    assert_eq!(number(&invokes[0], "access_flags"), 1);
    // Framework references that no input DEX defines stay external.
    assert!(!bool_at(&invokes[3], "defined"));
    assert_eq!(number(&invokes[3], "access_flags"), 0);
    assert_eq!(number(&invokes[3], "modifiers"), 0);

    let duplicated = metadata(
        &engine,
        MetaQuery::method("Lfixtures/Alpha;->duplicateInvokes()I"),
    );
    assert_eq!(
        member_descriptors(&duplicated, "invokes"),
        ["Lfixtures/Alpha;->helper()I", "Lfixtures/Alpha;->helper()I"]
    );
}

#[test]
fn using_strings_keep_order_and_duplicates() {
    let engine = open_engine(true);
    let method = metadata(
        &engine,
        MetaQuery::method("Lfixtures/Alpha;->duplicateStrings()I"),
    );
    assert_eq!(
        string_list(&method, "using_strings"),
        ["alpha-one", "alpha-two", "alpha-one"]
    );
    let do_it = metadata(&engine, MetaQuery::method("Lfixtures/Alpha;->doIt()V"));
    assert_eq!(
        string_list(&do_it, "using_strings"),
        ["call-one", "call-two", "call-three"]
    );
}

#[test]
fn using_fields_keep_order_and_read_write() {
    let engine = open_engine(true);
    let method = metadata(
        &engine,
        MetaQuery::method("Lfixtures/Alpha;->fieldTraffic()I"),
    );
    let accesses = method
        .get("using_fields")
        .and_then(Value::as_array)
        .expect("using_fields array");
    let observed = accesses
        .iter()
        .map(|access| {
            let field = access.get("field").expect("field key");
            (
                string(field, "descriptor"),
                string(access, "using_type"),
                bool_at(field, "defined"),
                number(field, "access_flags"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        observed,
        [
            (
                "Lfixtures/Alpha;->staticField:I".to_owned(),
                "read".to_owned(),
                true,
                9
            ),
            (
                "Lfixtures/Alpha;->staticField:I".to_owned(),
                "write".to_owned(),
                true,
                9
            ),
            (
                "Lfixtures/Alpha;->name:Ljava/lang/String;".to_owned(),
                "read".to_owned(),
                true,
                2
            ),
            (
                "Lfixtures/Alpha;->name:Ljava/lang/String;".to_owned(),
                "write".to_owned(),
                true,
                2
            ),
        ]
    );
}

#[test]
fn using_numbers_report_long_and_double_literals() {
    let engine = open_engine(true);
    let method = metadata(&engine, MetaQuery::method("Lfixtures/Alpha;->numbers()J"));
    let numbers = method
        .get("using_numbers")
        .and_then(Value::as_array)
        .expect("using_numbers array");
    let observed = numbers
        .iter()
        .map(|number| (string(number, "kind"), string(number, "value")))
        .collect::<Vec<_>>();
    assert_eq!(
        observed,
        [
            ("double".to_owned(), "3.5".to_owned()),
            ("long".to_owned(), "1234567890123".to_owned()),
            ("long".to_owned(), "42".to_owned()),
        ]
    );
}

#[test]
fn cross_dex_member_references_resolve_to_the_defining_dex() {
    let engine = open_engine(true);
    let beta = metadata(&engine, MetaQuery::class("Lfixtures/Beta;"));
    let super_class = beta.get("super_class").expect("super_class key");
    assert_eq!(string(super_class, "descriptor"), "Lfixtures/Alpha;");
    assert_eq!(string(super_class, "name"), "fixtures.Alpha");
    assert_eq!(
        member_descriptors(&beta, "methods"),
        ["Lfixtures/Beta;-><init>()V", "Lfixtures/Beta;->run()V"]
    );

    let run = metadata(&engine, MetaQuery::method("Lfixtures/Beta;->run()V"));
    let invokes = run
        .get("invokes")
        .and_then(Value::as_array)
        .expect("invokes array");
    let alpha_constructor = &invokes[0];
    assert_eq!(
        string(alpha_constructor, "descriptor"),
        "Lfixtures/Alpha;-><init>()V"
    );
    assert!(bool_at(alpha_constructor, "defined"));
    assert_eq!(number(alpha_constructor, "access_flags"), 65_537);
    let alpha_add = &invokes[1];
    assert_eq!(
        string(alpha_add, "descriptor"),
        "Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I"
    );
    assert!(bool_at(alpha_add, "defined"));
    assert_eq!(number(alpha_add, "access_flags"), 1);
    // Unbound framework references keep the external view.
    let println = invokes
        .iter()
        .find(|invoke| string(invoke, "name") == "println")
        .expect("println invoke");
    assert!(!bool_at(println, "defined"));
    assert_eq!(number(println, "access_flags"), 0);

    let using_fields = run
        .get("using_fields")
        .and_then(Value::as_array)
        .expect("using_fields array");
    let static_write = &using_fields[0];
    assert_eq!(string(static_write, "using_type"), "write");
    let static_field = static_write.get("field").expect("field key");
    assert_eq!(
        string(static_field, "descriptor"),
        "Lfixtures/Alpha;->staticField:I"
    );
    assert!(bool_at(static_field, "defined"));
    assert_eq!(number(static_field, "access_flags"), 9);
}

#[test]
fn callers_are_available_through_the_explicit_api_only() {
    let engine = open_engine(true);
    // The default document intentionally omits caller lists: some host methods
    // have tens of thousands of callers.
    let add = metadata(
        &engine,
        MetaQuery::method("Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I"),
    );
    assert!(add.get("callers").is_none());
    assert_eq!(member_descriptors(&add, "invokes").len(), 1);

    // DexKit order: the defining DEX's own callers first, then cross-DEX imports.
    let callers = engine
        .metadata_callers("Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I")
        .expect("callers");
    let callers = callers.as_array().expect("callers array");
    let descriptors = callers
        .iter()
        .map(|caller| string(caller, "descriptor"))
        .collect::<Vec<_>>();
    assert_eq!(
        descriptors,
        ["Lfixtures/Alpha;->doIt()V", "Lfixtures/Beta;->run()V"]
    );
    assert_eq!(
        engine
            .metadata_callers("Lfixtures/Alpha;->numbers()J")
            .expect("callers")
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        engine
            .metadata_callers("Ldoes/Not/Exist;->run()V")
            .expect("callers"),
        Value::Null
    );
    assert!(engine.metadata_callers("not a descriptor").is_err());
}

#[test]
fn missing_descriptors_return_null_and_malformed_descriptors_fail() {
    let engine = open_engine(true);
    assert_eq!(
        metadata(&engine, MetaQuery::class("Ldoes/Not/Exist;")),
        Value::Null
    );
    assert_eq!(
        metadata(&engine, MetaQuery::method("Ldoes/Not/Exist;->run()V")),
        Value::Null
    );
    assert_eq!(
        metadata(&engine, MetaQuery::field("Ldoes/Not/Exist;->value:I")),
        Value::Null
    );
    // An external reference without a definition is still reported (defined=false).
    let external = metadata(&engine, MetaQuery::method("Ljava/lang/String;->length()I"));
    assert_eq!(
        string(&external, "descriptor"),
        "Ljava/lang/String;->length()I"
    );
    assert!(!bool_at(&external, "defined"));
    assert_eq!(number(&external, "access_flags"), 0);

    assert!(engine
        .metadata(&MetaQuery::method("not a descriptor"))
        .is_err());
    assert!(engine
        .metadata(&MetaQuery::field("Lfixtures/Alpha;->name"))
        .is_err());
    assert!(engine
        .metadata(&MetaQuery::class("fixtures.Alpha"))
        .is_err());
    assert!(engine
        .metadata(&MetaQuery::method(
            "Lfixtures/Alpha;->add(ILjava/lang/String;"
        ))
        .is_err());
}

#[test]
fn metadata_without_relation_indexes_returns_empty_lists() {
    let engine = open_engine(false);
    let method = metadata(
        &engine,
        MetaQuery::method("Lfixtures/Alpha;->fieldTraffic()I"),
    );
    for key in ["invokes", "using_strings", "using_numbers", "using_fields"] {
        assert_eq!(
            method.get(key).and_then(Value::as_array).map(Vec::len),
            Some(0),
            "{key} must be an empty array without relation indexes"
        );
    }
    assert_eq!(
        engine
            .metadata_callers("Lfixtures/Alpha;->fieldTraffic()I")
            .expect("callers")
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    // Metadata itself is still available.
    assert_eq!(string(&method, "declared_class_name"), "fixtures.Alpha");
    let class = metadata(&engine, MetaQuery::class("Lfixtures/Alpha;"));
    assert_eq!(string(&class, "name"), "fixtures.Alpha");
}

#[test]
fn repeated_concurrent_reads_are_stable() {
    let engine = Arc::new(open_engine(true));
    let queries = [
        MetaQuery::class("Lfixtures/Alpha;"),
        MetaQuery::class("Lfixtures/Beta;"),
        MetaQuery::method("Lfixtures/Beta;->run()V"),
        MetaQuery::method("Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I"),
        MetaQuery::field("Lfixtures/Alpha;->staticField:I"),
    ];
    let expected = queries
        .iter()
        .map(|query| engine.metadata(query).expect("metadata"))
        .collect::<Vec<_>>();
    let mut handles = Vec::new();
    for _ in 0..4 {
        let engine = Arc::clone(&engine);
        let queries = queries.clone();
        let expected = expected.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..20 {
                for (query, expected) in queries.iter().zip(&expected) {
                    assert_eq!(&engine.metadata(query).expect("metadata"), expected);
                }
            }
        }));
    }
    for handle in handles {
        handle.join().expect("metadata reader thread");
    }
}
