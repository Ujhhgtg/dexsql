//! Tests for class/method annotations on metadata documents.
//!
//! The fixture `fixtures/dex/annotated.dex` has a runtime annotation
//! (`@fixtures.Meta({"alpha","beta"})` on `fixtures.Annotated` and
//! `@fixtures.Meta({"gamma"})` on `genericList`) plus compiler-generated
//! `@dalvik/annotation/Signature` system annotations for the generic class and
//! its generic method.

use std::path::{Path, PathBuf};

use dexsql::{Engine, EngineOptions, IndexNeeds, MetaQuery};
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/dex")
        .join(name)
}

fn open_engine(full_code_items: bool) -> Engine {
    Engine::open_with_options(
        [fixture("annotated.dex")],
        EngineOptions {
            index_needs: IndexNeeds::all(),
            eager_code_items: full_code_items,
            full_code_items,
            retain_classes: true,
            threads: Some(1),
        },
    )
    .expect("open fixture DEX")
}

fn metadata(engine: &Engine, query: MetaQuery) -> Value {
    engine
        .metadata(&query)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"))
}

fn annotations(document: &Value) -> &[Value] {
    document
        .get("annotations")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("missing annotations in {document}"))
}

fn annotation<'a>(document: &'a Value, type_descriptor: &str) -> &'a Value {
    annotations(document)
        .iter()
        .find(|annotation| annotation.get("type").and_then(Value::as_str) == Some(type_descriptor))
        .unwrap_or_else(|| panic!("missing annotation {type_descriptor} in {document}"))
}

fn element_value<'a>(annotation: &'a Value, name: &str) -> &'a Value {
    annotation
        .get("elements")
        .and_then(Value::as_array)
        .and_then(|elements| {
            elements
                .iter()
                .find(|element| element.get("name").and_then(Value::as_str) == Some(name))
        })
        .and_then(|element| element.get("value"))
        .unwrap_or_else(|| panic!("missing annotation element {name} in {annotation}"))
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected string array, got {value}"))
        .iter()
        .map(|element| {
            element
                .as_str()
                .unwrap_or_else(|| panic!("expected string array element, got {element}"))
                .to_owned()
        })
        .collect()
}

#[test]
fn class_annotations_include_runtime_and_signature_annotations() {
    let engine = open_engine(true);
    let document = metadata(&engine, MetaQuery::class("Lfixtures/Annotated;"));

    let meta = annotation(&document, "Lfixtures/Meta;");
    assert_eq!(
        meta.get("type_name").and_then(Value::as_str),
        Some("fixtures.Meta")
    );
    assert_eq!(
        meta.get("visibility").and_then(Value::as_str),
        Some("runtime")
    );
    assert_eq!(
        string_array(element_value(meta, "value")),
        ["alpha", "beta"]
    );

    let signature = annotation(&document, "Ldalvik/annotation/Signature;");
    assert_eq!(
        signature.get("type_name").and_then(Value::as_str),
        Some("dalvik.annotation.Signature")
    );
    assert_eq!(
        signature.get("visibility").and_then(Value::as_str),
        Some("system")
    );
    // The DEX signature annotation splits the generic signature into string
    // tokens; concatenating them restores the full class signature.
    let tokens = string_array(element_value(signature, "value"));
    assert_eq!(tokens.concat(), "<T:Ljava/lang/Object;>Ljava/lang/Object;");
}

#[test]
fn method_annotations_include_runtime_and_signature_annotations() {
    let engine = open_engine(true);
    let generic = metadata(
        &engine,
        MetaQuery::method("Lfixtures/Annotated;->genericList(Ljava/util/List;)Ljava/util/List;"),
    );

    let meta = annotation(&generic, "Lfixtures/Meta;");
    assert_eq!(
        meta.get("visibility").and_then(Value::as_str),
        Some("runtime")
    );
    assert_eq!(string_array(element_value(meta, "value")), ["gamma"]);

    let signature = annotation(&generic, "Ldalvik/annotation/Signature;");
    assert_eq!(
        signature.get("visibility").and_then(Value::as_str),
        Some("system")
    );
    let signature_text = string_array(element_value(signature, "value")).concat();
    assert!(
        signature_text.starts_with("<E:") && signature_text.contains("(Ljava/util/List<"),
        "unexpected method signature tokens {signature_text:?}"
    );
}

#[test]
fn methods_without_annotations_render_an_empty_array() {
    let engine = open_engine(true);
    for descriptor in [
        "Lfixtures/Annotated;->make()Ljava/lang/Object;",
        "Lfixtures/Annotated;->addOne(I)I",
        "Lfixtures/Annotated;->copy([I)[I",
    ] {
        let document = metadata(&engine, MetaQuery::method(descriptor));
        assert!(
            annotations(&document).is_empty(),
            "unexpected annotations for {descriptor}"
        );
    }
}

#[test]
fn metadata_only_load_renders_empty_annotations() {
    let engine = open_engine(false);
    let document = metadata(&engine, MetaQuery::class("Lfixtures/Annotated;"));
    assert!(annotations(&document).is_empty());
    let method = metadata(
        &engine,
        MetaQuery::method("Lfixtures/Annotated;->genericList(Ljava/util/List;)Ljava/util/List;"),
    );
    assert!(annotations(&method).is_empty());
}

/// Sample real-APK annotation owners and assert their metadata documents render
/// the annotation lists without errors.
///
/// Ignored by default because it needs a host APK:
/// ```sh
/// DEXSQL_META_ANNOTATION_APK=/home/ujhhgtg/coding/wechat_8079_3180.apk /// cargo test -p dexsql --release --test metadata_annotations -- --ignored --nocapture
/// ```
#[test]
#[ignore = "needs a real WeChat APK"]
fn real_apk_annotations_render_without_errors() {
    let apk = PathBuf::from(
        std::env::var("DEXSQL_META_ANNOTATION_APK")
            .expect("set DEXSQL_META_ANNOTATION_APK to a DEX/APK file"),
    );
    let engine = Engine::open_with_options(
        [&apk],
        EngineOptions {
            index_needs: IndexNeeds::all(),
            eager_code_items: true,
            full_code_items: true,
            retain_classes: true,
            threads: Some(1),
        },
    )
    .expect("open sample engine");

    let class_rows = engine
        .query(
            "SELECT DISTINCT owner_descriptor FROM annotation_values              WHERE owner_kind = 'class' LIMIT 300",
        )
        .expect("class annotation owners");
    assert!(
        !class_rows.rows.is_empty(),
        "no class annotations in sample APK"
    );
    for row in &class_rows.rows {
        let descriptor = &row[0];
        let document = engine
            .metadata(&MetaQuery::class(descriptor))
            .unwrap_or_else(|error| panic!("class metadata failed for {descriptor}: {error}"));
        assert!(
            document
                .get("annotations")
                .and_then(Value::as_array)
                .is_some_and(|annotations| !annotations.is_empty()),
            "missing class annotations for {descriptor}"
        );
    }

    let method_rows = engine
        .query(
            "SELECT DISTINCT owner_descriptor FROM annotation_values              WHERE owner_kind = 'method' LIMIT 300",
        )
        .expect("method annotation owners");
    let mut rendered_methods = 0usize;
    for row in &method_rows.rows {
        let descriptor = &row[0];
        let document = engine
            .metadata(&MetaQuery::method(descriptor))
            .unwrap_or_else(|error| panic!("method metadata failed for {descriptor}: {error}"));
        assert!(
            !document.is_null(),
            "missing method metadata for {descriptor}"
        );
        if document
            .get("annotations")
            .and_then(Value::as_array)
            .is_some_and(|annotations| !annotations.is_empty())
        {
            rendered_methods += 1;
        }
    }
    println!(
        "annotation regression: {} class owners, {} method owners, {} methods rendered annotations",
        class_rows.rows.len(),
        method_rows.rows.len(),
        rendered_methods
    );
    assert!(rendered_methods > 0);
}
