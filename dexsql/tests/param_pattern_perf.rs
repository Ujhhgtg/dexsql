//! Manual benchmark for the `param_types_match` predicate fast path.
//!
//! Ignored by default: it needs a real WeChat APK. Run in release mode:
//!
//! ```sh
//! DEXSQL_PARAM_BENCH_APK=/home/ujhhgtg/coding/wechat_8079_3180.apk \
//! cargo test -p dexsql --release --test param_pattern_perf -- --ignored --nocapture
//! ```
//!
//! The fast path is the descriptor-lookup executor in `dexsql-query`; the
//! generic variant appends a constant conjunct (`AND 1 = 1`) so the same query
//! falls back to the generic relation executor. Both forms must return the same
//! rows.

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
    // Warm up outside the measurement (page cache, lazy indexes).
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
fn param_pattern_fast_path_perf() {
    let apk = PathBuf::from(required_env("DEXSQL_PARAM_BENCH_APK"));
    let started = Instant::now();
    let dataset =
        Dataset::load_paths_with_needs(&[apk], IndexNeeds::default()).expect("open benchmark APK");
    let load_ms = started.elapsed().as_secs_f64() * 1000.0;
    let caches = NamedCaches::default();

    // Representative DexKit paramTypes()/paramCount() selectors on the host
    // APK. The filtered shape has a class + name pushdown; the full-scan shape
    // has no indexable predicate at all.
    let filtered = "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
         WHERE m.class_descriptor = 'Lcom/tencent/mm/storage/l4;' AND m.name = 'Q' \
           AND param_types_match(m.param_descriptors, '?,Ljava/lang/String;,?,?') \
         ORDER BY m.descriptor LIMIT 5";
    let range = "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
         WHERE m.class_descriptor = 'Lcom/tencent/mm/storage/l4;' AND m.name = 'Q' \
           AND m.param_count >= 4 AND m.param_count <= 4 \
         ORDER BY m.descriptor LIMIT 5";
    let full_scan = "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
         WHERE param_types_match(m.param_descriptors, '?,?,Ljava/lang/String;,?') \
         ORDER BY m.descriptor LIMIT 1";

    for (name, sql, iterations) in [
        ("filtered-pattern", filtered, 5usize),
        ("filtered-range", range, 5),
        ("full-scan-pattern", full_scan, 3),
    ] {
        let generic_sql = force_generic(sql);
        let (fast_rows, fast_ms) = timed(&dataset, &caches, sql, iterations);
        let (generic_rows, generic_ms) = timed(&dataset, &caches, &generic_sql, iterations);
        assert_eq!(
            fast_rows, generic_rows,
            "{name}: fast and generic rows differ"
        );
        println!(
            "param-pattern perf: query={name} load_ms={load_ms:.1} iterations={iterations} \
             fast_mean_ms={fast_ms:.2} generic_mean_ms={generic_ms:.2} speedup={:.1}x",
            generic_ms / fast_ms.max(f64::MIN_POSITIVE)
        );
        if name == "full-scan-pattern" {
            assert!(
                fast_ms < generic_ms,
                "the fast path should beat the generic executor on a full scan"
            );
        }
    }
}
