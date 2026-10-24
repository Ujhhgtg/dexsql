//! Manual benchmark for case-sensitive name-match fast paths (T3).
//!
//! Ignored by default: it needs a real WeChat APK. Run in release mode:
//!
//! ```sh
//! DEXSQL_NAME_BENCH_APK=/home/ujhhgtg/coding/wechat_8079_3180.apk \
//! cargo test -p dexsql --release --test name_match_perf -- --ignored --nocapture
//! ```
//!
//! Each query runs once against the descriptor-lookup fast path and once against
//! the generic relation executor (forced by appending a constant conjunct). Both
//! must return identical rows.

use std::path::PathBuf;
use std::time::Instant;

use dexsql_cache::{Dataset, IndexNeeds};
use dexsql_query::{execute_statement, NamedCaches};

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing environment variable {name}"))
}

fn force_generic(sql: &str) -> String {
    match sql.find(" ORDER BY") {
        Some(position) => format!("{} AND 1 = 1{}", &sql[..position], &sql[position..]),
        None => format!("{sql} AND 1 = 1"),
    }
}

fn timed(
    dataset: &Dataset,
    caches: &NamedCaches,
    sql: &str,
    iterations: usize,
) -> (Vec<Vec<String>>, f64) {
    let warmup = execute_statement(sql, Some(dataset), caches, None).expect("warmup query");
    let mut samples = Vec::with_capacity(iterations);
    let mut rows = warmup.rows;
    for _ in 0..iterations {
        let started = Instant::now();
        let result = execute_statement(sql, Some(dataset), caches, None).expect("benchmark query");
        samples.push(started.elapsed().as_secs_f64() * 1000.0);
        rows = result.rows;
    }
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    (rows, mean)
}

#[test]
#[ignore = "manual benchmark: needs a real WeChat APK"]
fn name_match_fast_path_perf() {
    let apk = PathBuf::from(required_env("DEXSQL_NAME_BENCH_APK"));
    let started = Instant::now();
    // Class definitions are needed for the superclass lookups; the class-name
    // cases also run fine on a metadata-only load.
    let dataset =
        Dataset::load_paths_with_requirements(&[apk], IndexNeeds::default(), false, false, true)
            .expect("open benchmark APK");
    let load_ms = started.elapsed().as_secs_f64() * 1000.0;
    let caches = NamedCaches::default();

    // Canonical T3 shapes (case-sensitive DexKit default).
    let class_starts_with = "SELECT DISTINCT cm.class_descriptor AS descriptor \
         FROM methods cm \
         WHERE instr(cm.class_descriptor, 'Lcom/tencent/mm/plugin/appbrand/menu') = 1 \
         ORDER BY cm.class_descriptor LIMIT 1";
    let class_ends_with = "SELECT DISTINCT cm.class_descriptor AS descriptor \
         FROM methods cm \
         WHERE substr(cm.class_descriptor, -6) = 'Popup;' \
         ORDER BY cm.class_descriptor LIMIT 1";
    let return_contains = "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
         WHERE instr(m.return_descriptor, 'Ljava/util/List') > 0 \
         ORDER BY m.descriptor LIMIT 1";
    let superclass_starts_with = "SELECT DISTINCT cm.class_descriptor AS descriptor \
         FROM methods cm JOIN classes cc ON cc.descriptor = cm.class_descriptor \
         WHERE instr(cc.superclass_descriptor, 'Landroid/app/Activity') = 1 \
         ORDER BY cm.class_descriptor LIMIT 1";

    for (name, sql) in [
        ("class-startsWith", class_starts_with),
        ("class-endsWith", class_ends_with),
        ("returnType-contains", return_contains),
        ("superclass-startsWith", superclass_starts_with),
    ] {
        let generic_sql = force_generic(sql);
        let (fast_rows, fast_ms) = timed(&dataset, &caches, sql, 3);
        let (generic_rows, generic_ms) = timed(&dataset, &caches, &generic_sql, 2);
        assert_eq!(
            fast_rows, generic_rows,
            "{name}: fast and generic rows differ"
        );
        println!(
            "name-match perf: query={name} load_ms={load_ms:.1} \
             fast_mean_ms={fast_ms:.2} generic_mean_ms={generic_ms:.2} speedup={:.1}x",
            generic_ms / fast_ms.max(f64::MIN_POSITIVE)
        );
        assert!(
            fast_ms < generic_ms,
            "{name}: the fast path should beat the generic executor"
        );
    }
}
