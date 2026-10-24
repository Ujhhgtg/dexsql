//! Release benchmark for the columnar filter/group/top-k kernels.
//!
//! Usage: cargo run -p dexsql-exec --example batch_ops_probe --release -- 1000000

use std::hint::black_box;
use std::time::Instant;

use dexsql_exec::{filter_batch, group_counts, top_k_indices};
use dexsql_ir::{ColumnBatch, ColumnType, StringId, TypedScalar};

fn main() {
    let rows = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000_000);
    let mut batch = ColumnBatch::with_capacity(&[ColumnType::Int64, ColumnType::TextId], rows);
    for row in 0..rows {
        batch.push_row(&[
            TypedScalar::Int(row as i64),
            TypedScalar::Text(StringId((row as u32).wrapping_mul(2_654_435_761) % 100_003)),
        ]);
    }

    let start = Instant::now();
    let kept = filter_batch(&mut batch, |batch, row| {
        batch
            .get(0, row)
            .and_then(TypedScalar::as_i64)
            .is_some_and(|value| value % 3 == 0)
    });
    let filter_ms = start.elapsed().as_secs_f64() * 1000.0;

    let start = Instant::now();
    let groups = group_counts(&batch, 1).expect("text column");
    let group_ms = start.elapsed().as_secs_f64() * 1000.0;

    let values: Vec<u32> = (0..batch.len() as u32)
        .map(|row| row.wrapping_mul(1_103_515_245).wrapping_add(12_345))
        .collect();
    let start = Instant::now();
    let top = top_k_indices(values.len(), 10, |left, right| {
        values[left].cmp(&values[right])
    });
    let topk_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!(
        "rows={} kept={} groups={} filter_ms={filter_ms:.3} group_ms={group_ms:.3} topk_ms={topk_ms:.3} checksum={}",
        black_box(rows),
        black_box(kept),
        black_box(groups.distinct_keys()),
        black_box(top.iter().fold(0usize, |sum, row| sum ^ row)),
    );
}
