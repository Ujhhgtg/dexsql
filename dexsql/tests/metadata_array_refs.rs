//! Regression tests for metadata references whose declaring class is an array
//! type (for example `[I->clone()Ljava/lang/Object;` emitted for
//! `array.clone()`). Such references must be rendered instead of failing the
//! whole metadata document.

use std::path::{Path, PathBuf};

use dexsql::{Engine, EngineOptions, IndexNeeds, MetaQuery};
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/dex")
        .join(name)
}

fn open_engine() -> Engine {
    let options = EngineOptions {
        index_needs: IndexNeeds::all(),
        eager_code_items: true,
        full_code_items: false,
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

fn array_ref<'a>(document: &'a Value, descriptor: &str) -> &'a Value {
    document
        .get("invokes")
        .and_then(Value::as_array)
        .and_then(|invokes| {
            invokes.iter().find(|reference| {
                reference.get("descriptor").and_then(Value::as_str) == Some(descriptor)
            })
        })
        .unwrap_or_else(|| panic!("missing invoke {descriptor} in {document}"))
}

#[test]
fn primitive_array_class_ref_is_rendered() {
    let engine = open_engine();
    let document = metadata(&engine, "Lfixtures/Annotated;->copy([I)[I");
    let reference = array_ref(&document, "[I->clone()Ljava/lang/Object;");
    assert_eq!(
        reference.get("declared_class").and_then(Value::as_str),
        Some("[I")
    );
    assert_eq!(
        reference.get("declared_class_name").and_then(Value::as_str),
        Some("int[]")
    );
    assert_eq!(reference.get("name").and_then(Value::as_str), Some("clone"));
    assert_eq!(
        reference.get("method_sign").and_then(Value::as_str),
        Some("()Ljava/lang/Object;")
    );
    assert_eq!(
        reference.get("access_flags").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(reference.get("modifiers").and_then(Value::as_u64), Some(0));
    assert_eq!(
        reference.get("defined").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        reference.get("is_method").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn object_array_class_ref_is_rendered() {
    let engine = open_engine();
    let document = metadata(
        &engine,
        "Lfixtures/Annotated;->copyMetas([Lfixtures/Meta;)[Lfixtures/Meta;",
    );
    let reference = array_ref(&document, "[Lfixtures/Meta;->clone()Ljava/lang/Object;");
    assert_eq!(
        reference.get("declared_class").and_then(Value::as_str),
        Some("[Lfixtures/Meta;")
    );
    assert_eq!(
        reference.get("declared_class_name").and_then(Value::as_str),
        Some("fixtures.Meta[]")
    );
}

#[test]
fn class_document_containing_array_refs_is_ok() {
    let engine = open_engine();
    let document = engine
        .metadata(&MetaQuery::class("Lfixtures/Annotated;"))
        .expect("class metadata");
    assert_eq!(document.get("kind").and_then(Value::as_str), Some("class"));
    assert!(document
        .get("methods")
        .and_then(Value::as_array)
        .is_some_and(|methods| methods.len() >= 5));
}

/// Sample real-APK methods whose invoke list references methods on array
/// classes and assert their metadata documents render instead of erroring.
///
/// Ignored by default because it needs a host APK:
/// ```sh
/// DEXSQL_META_REGRESSION_APK=/home/ujhhgtg/coding/wechat_8079_3180.apk \
/// cargo test -p dexsql --release --test metadata_array_refs -- --ignored --nocapture
/// ```
#[test]
#[ignore = "needs a real WeChat APK"]
fn real_apk_method_documents_with_array_refs_are_ok() {
    let apk = PathBuf::from(
        std::env::var("DEXSQL_META_REGRESSION_APK")
            .expect("set DEXSQL_META_REGRESSION_APK to a DEX/APK file"),
    );
    let dataset = dexsql_cache::Dataset::load_paths_with_requirements(
        std::slice::from_ref(&apk),
        IndexNeeds::all(),
        true,
        false,
        true,
    )
    .expect("open sample dataset");
    let mut samples = Vec::new();
    'files: for file in &dataset.files {
        for method_idx in 0..file.methods.len() as u32 {
            let references_array_class = file.invokes_for_method(method_idx).iter().any(|row| {
                file.method_parts(row.callee_method_idx)
                    .is_some_and(|parts| parts.class_descriptor.starts_with('['))
            });
            if references_array_class {
                samples.push(file.method_descriptor(method_idx));
                if samples.len() >= 500 {
                    break 'files;
                }
            }
        }
    }
    assert!(
        samples.len() >= 100,
        "expected at least 100 array-reference samples, found {}",
        samples.len()
    );
    let engine = Engine::open_with_options(
        [&apk],
        EngineOptions {
            index_needs: IndexNeeds::all(),
            eager_code_items: true,
            full_code_items: false,
            retain_classes: true,
            threads: Some(1),
        },
    )
    .expect("open sample engine");
    let mut rendered_array_refs = 0usize;
    for descriptor in &samples {
        let document = engine
            .metadata(&MetaQuery::method(descriptor))
            .unwrap_or_else(|error| panic!("metadata failed for {descriptor}: {error}"));
        assert!(!document.is_null(), "missing metadata for {descriptor}");
        if document
            .get("invokes")
            .and_then(Value::as_array)
            .is_some_and(|invokes| {
                invokes.iter().any(|reference| {
                    reference
                        .get("declared_class")
                        .and_then(Value::as_str)
                        .is_some_and(|class| class.starts_with('['))
                })
            })
        {
            rendered_array_refs += 1;
        }
    }
    println!(
        "metadata array-ref regression: {} method documents rendered, {} contain array-class invokes",
        samples.len(),
        rendered_array_refs
    );
    assert!(rendered_array_refs > 0);
}
