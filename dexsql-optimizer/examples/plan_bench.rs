//! End-to-end lowering and logical optimization benchmark.
//!
//! Usage: cargo run -p dexsql-optimizer --example plan_bench --release -- 1000

use std::hint::black_box;
use std::time::Instant;

use dexsql_lower::lower_sql;
use dexsql_optimizer::optimize_plan;

fn main() {
    let count = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000);
    let sql = "SELECT m.descriptor FROM methods m JOIN method_numbers n ON m.file_id = n.file_id AND m.method_idx = n.method_idx WHERE m.param_count = 0 ORDER BY m.descriptor LIMIT 10";
    let start = Instant::now();
    let mut rewrites = 0usize;
    let mut passes = 0usize;
    for _ in 0..count {
        let plan = lower_sql(sql).expect("known query");
        let optimized = optimize_plan(plan);
        rewrites += optimized.rewrites;
        passes = optimized.passes;
        black_box(optimized.plan);
    }
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    println!(
        "queries={count} passes={passes} rewrites={rewrites} total_ms={elapsed:.3} per_query_us={:.3}",
        elapsed * 1000.0 / count as f64
    );
}
