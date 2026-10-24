//! Small standalone probe for the execution kernels.
//!
//! Run with `cargo run -p dexsql-exec --example batch_probe --release`.
//! It compares the integer-key batch index and top-k selection that the SQL
//! executor can use in place of allocating one hash map per `RelRow`.

use std::hint::black_box;
use std::time::Instant;

use dexsql_exec::{top_k_indices, BatchKeyIndex};

fn main() {
    let rows = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000_000);
    let distinct = std::env::args()
        .nth(2)
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(100_000)
        .max(1);
    let top_k = std::env::args()
        .nth(3)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10);

    let start = Instant::now();
    let mut index = BatchKeyIndex::with_capacity(distinct as usize);
    for row in 0..rows as u32 {
        // A stable, deterministic distribution keeps repeated probes
        // comparable without relying on a random-number generator.
        index.insert(row.wrapping_mul(2_654_435_761) % distinct, row);
    }
    let build = start.elapsed();

    let start = Instant::now();
    let mut hits = 0usize;
    for key in 0..distinct {
        hits += index.probe(&key).map_or(0, <[u32]>::len);
    }
    let probe = start.elapsed();

    let values: Vec<u32> = (0..rows as u32)
        .map(|row| row.wrapping_mul(1_103_515_245).wrapping_add(12_345))
        .collect();
    let start = Instant::now();
    let selected = top_k_indices(values.len(), top_k, |left, right| {
        values[left].cmp(&values[right])
    });
    let topk = start.elapsed();

    println!(
        "rows={rows} distinct_keys={} indexed_rows={} hits={hits} build_ms={:.3} probe_ms={:.3} topk_ms={:.3} selected_checksum={}",
        index.distinct_keys(),
        index.rows(),
        build.as_secs_f64() * 1000.0,
        probe.as_secs_f64() * 1000.0,
        topk.as_secs_f64() * 1000.0,
        black_box(selected.iter().fold(0usize, |sum, row| sum ^ row)),
    );
}
