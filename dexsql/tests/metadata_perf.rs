//! Manual benchmark for the metadata API against a real host APK.
//!
//! Ignored by default because it needs a WeChat APK and a descriptor list on
//! disk. Run in release mode:
//!
//! ```sh
//! DEXSQL_META_BENCH_APK=/home/ujhhgtg/coding/wechat_8079_3180.apk \
//! DEXSQL_META_BENCH_DESCRIPTORS=/tmp/dex_meta_verify/descriptors/wechat_8079_3180.txt \
//! cargo test -p dexsql --release --test metadata_perf -- --ignored --nocapture
//! ```
//!
//! The descriptor file is the Phase 0 DexKit snapshot descriptor list, one
//! `kind|descriptor` entry per line (the same format `dexsql meta
//! --descriptor-file` accepts). Every document includes `invokes`, `callers`,
//! `using_strings`, `using_numbers` and `using_fields`, so the measurement
//! covers the worst-case eager document (all lazy relation and cross-DEX
//! indexes built).
//!
//! Reported values: load time, VmRSS after load and after metadata indexes are
//! built, p50/p99/max per-document latency. The release-mode run asserts the
//! spec gate of p99 < 1 ms.

use std::path::PathBuf;
use std::time::Instant;

use dexsql::{Engine, EngineOptions, IndexNeeds, MetaQuery};
use serde_json::Value;

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing environment variable {name}"))
}

fn parse_descriptor_line(line: &str) -> Option<MetaQuery> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (kind, descriptor) = match line.split_once('|') {
        Some((kind, descriptor)) => (kind.trim(), descriptor.trim()),
        None => (
            if line.contains("->") {
                if line.contains('(') {
                    "method"
                } else {
                    "field"
                }
            } else {
                "class"
            },
            line,
        ),
    };
    let descriptor =
        if kind == "class" && !(descriptor.starts_with('L') && descriptor.ends_with(';')) {
            format!("L{};", descriptor.replace('.', "/"))
        } else {
            descriptor.to_owned()
        };
    Some(match kind {
        "class" => MetaQuery::class(descriptor),
        "method" => MetaQuery::method(descriptor),
        "field" => MetaQuery::field(descriptor),
        other => panic!("unknown kind {other:?} in descriptor line {line:?}"),
    })
}

fn vm_rss_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kib = rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse::<f64>()
                .ok()?;
            return Some(kib / 1024.0);
        }
    }
    None
}

fn vm_hwm_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kib = rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse::<f64>()
                .ok()?;
            return Some(kib / 1024.0);
        }
    }
    None
}

fn percentile(sorted: &[f64], percentile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((sorted.len() - 1) as f64 * percentile).round() as usize;
    sorted[rank]
}

#[test]
#[ignore = "manual benchmark: needs a real WeChat APK and descriptor list"]
fn metadata_perf_on_real_apk() {
    let apk = PathBuf::from(required_env("DEXSQL_META_BENCH_APK"));
    let descriptors_path = PathBuf::from(required_env("DEXSQL_META_BENCH_DESCRIPTORS"));
    let text = std::fs::read_to_string(&descriptors_path).expect("read descriptor list");
    let mut queries = text
        .lines()
        .filter_map(parse_descriptor_line)
        .collect::<Vec<_>>();
    assert!(!queries.is_empty(), "descriptor list is empty");
    if queries.len() > 1000 {
        // Deterministic shuffle so the sample is stable across runs.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for index in (1..queries.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let swap = (state as usize) % (index + 1);
            queries.swap(index, swap);
        }
        queries.truncate(1000);
    }

    let started = Instant::now();
    let engine = Engine::open_with_options(
        [apk],
        EngineOptions {
            index_needs: IndexNeeds::all(),
            eager_code_items: true,
            full_code_items: false,
            retain_classes: true,
            threads: Some(1),
        },
    )
    .expect("open benchmark APK");
    let load_ms = started.elapsed().as_secs_f64() * 1000.0;
    let rss_after_load = vm_rss_mib();
    let hwm_after_load = vm_hwm_mib();

    // Warm up: the first pass builds lazy relation indexes and the cross-DEX
    // binding cache, which must not count toward per-document latency.
    for query in &queries {
        let document = engine.metadata(query).expect("metadata");
        assert!(
            !document.is_null(),
            "descriptor {} not found",
            query.descriptor()
        );
    }
    let rss_after_indexes = vm_rss_mib();
    let hwm_after_indexes = vm_hwm_mib();

    let mut durations = Vec::with_capacity(queries.len() * 3);
    let mut per_kind = std::collections::BTreeMap::<&str, Vec<f64>>::new();
    for _ in 0..3 {
        for query in &queries {
            let begin = Instant::now();
            let document: Value = engine.metadata(query).expect("metadata");
            let elapsed = begin.elapsed().as_secs_f64() * 1000.0;
            durations.push(elapsed);
            per_kind.entry(query.kind()).or_default().push(elapsed);
            std::hint::black_box(&document);
        }
    }
    durations.sort_by(|left, right| left.partial_cmp(right).expect("finite durations"));
    let p50 = percentile(&durations, 0.50);
    let p99 = percentile(&durations, 0.99);
    let max = durations.last().copied().unwrap_or(0.0);
    println!(
        "metadata bench: documents={} rounds=3 load_ms={load_ms:.1} p50_ms={p50:.4} p99_ms={p99:.4} max_ms={max:.4}",
        queries.len()
    );
    for (kind, mut values) in per_kind {
        values.sort_by(|left, right| left.partial_cmp(right).expect("finite durations"));
        println!(
            "metadata bench: kind={kind} samples={} p50_ms={:.4} p99_ms={:.4} max_ms={:.4}",
            values.len(),
            percentile(&values, 0.50),
            percentile(&values, 0.99),
            values.last().copied().unwrap_or(0.0)
        );
    }
    if let (Some(before), Some(after)) = (rss_after_load, rss_after_indexes) {
        println!(
            "metadata bench: rss_after_load_mib={before:.1} rss_after_indexes_mib={after:.1} \
             rss_delta_mib={delta:.1} hwm_after_load_mib={hwm_after_load:?} hwm_after_indexes_mib={hwm_after_indexes:?}",
            delta = after - before
        );
    }
    if !cfg!(debug_assertions) {
        assert!(
            p99 < 1.0,
            "p99 metadata latency {p99:.4} ms exceeds the 1 ms release gate"
        );
    }
}
