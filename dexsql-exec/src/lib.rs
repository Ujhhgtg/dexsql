//! Physical execution kernel inventory recovered from EXPLAIN_RESOLVED output.

use std::collections::HashMap;
use std::hash::Hash;

/// A reusable hash index for typed batches.
///
/// The query executor can build this over a `u32` DEX string index (or any
/// other copy/hash key) and probe it with no `String` allocation.  Row ids are
/// `u32` because a single physical batch is bounded by the input row count;
/// callers that need more than 4G rows should partition the batch first.
#[derive(Debug, Clone)]
pub struct BatchKeyIndex<K> {
    map: HashMap<K, Vec<u32>>,
}

impl<K: Eq + Hash> BatchKeyIndex<K> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
        }
    }

    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    pub fn insert(&mut self, key: K, row: u32) {
        self.map.entry(key).or_default().push(row);
    }

    pub fn insert_many<I>(&mut self, key: K, rows: I)
    where
        I: IntoIterator<Item = u32>,
    {
        self.map.entry(key).or_default().extend(rows);
    }

    pub fn probe(&self, key: &K) -> Option<&[u32]> {
        self.map.get(key).map(Vec::as_slice)
    }

    pub fn get(&self, key: &K) -> Option<&Vec<u32>> {
        self.map.get(key)
    }

    pub fn distinct_keys(&self) -> usize {
        self.map.len()
    }

    pub fn rows(&self) -> usize {
        self.map.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl<K: Eq + Hash> Default for BatchKeyIndex<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// Return the first `k` row indexes according to `compare`, in sorted order.
///
/// `sort_unstable` on a million methods is needlessly expensive when the SQL
/// query has `LIMIT 10`.  This uses an `nth` partition and only sorts the
/// selected prefix.  The comparator has the same ordering contract as
/// `slice::sort_unstable_by`: `compare(a, b) == Less` means `a` comes first.
pub fn top_k_indices<F>(len: usize, k: usize, mut compare: F) -> Vec<usize>
where
    F: FnMut(usize, usize) -> std::cmp::Ordering,
{
    if k == 0 || len == 0 {
        return Vec::new();
    }
    let take = k.min(len);
    let mut indices: Vec<usize> = (0..len).collect();
    if take < len {
        // `select_nth_unstable_by(take)` leaves the first `take` values before
        // the pivot.  The pivot itself belongs to the suffix for this use.
        indices.select_nth_unstable_by(take, |left, right| compare(*left, *right));
        indices.truncate(take);
    }
    indices.sort_unstable_by(|left, right| compare(*left, *right));
    indices
}

/// A sorted merge of two already sorted row-id streams.
///
/// This is the low-level primitive used by parallel range scans and merge
/// joins.  Equal values are retained from both streams, matching SQL join
/// multiplicity.
pub fn merge_sorted<T: Ord + Copy>(left: &[T], right: &[T]) -> Vec<T> {
    let mut out = Vec::with_capacity(left.len() + right.len());
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        if left[i] <= right[j] {
            out.push(left[i]);
            i += 1;
        } else {
            out.push(right[j]);
            j += 1;
        }
    }
    out.extend_from_slice(&left[i..]);
    out.extend_from_slice(&right[j..]);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kernel {
    RawEdgeScan,
    MethodViewScan,
    NormalizedEntityScan,
    SimpleNativeProjection,
    RichNativeProjection,
    ComplexNativeProjection,
    SortedRangeScan,
    StreamingGroupBy,
    StreamingJoin,
    ParallelMerge,
    ScalarCount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    Strings,
    Numbers,
    Calls,
    FieldAccesses,
    UsedTypes,
}

#[derive(Debug, Clone)]
pub struct PhysicalPlan {
    pub kernel: Kernel,
    pub edge: Option<EdgeKind>,
    pub pushed_columns: usize,
    pub limit: Option<usize>,
}

impl PhysicalPlan {
    pub fn raw_edge(edge: EdgeKind, pushed_columns: usize) -> Self {
        Self {
            kernel: Kernel::RawEdgeScan,
            edge: Some(edge),
            pushed_columns,
            limit: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{merge_sorted, top_k_indices, BatchKeyIndex};

    #[test]
    fn key_index_keeps_duplicate_row_ids() {
        let mut index = BatchKeyIndex::with_capacity(2);
        index.insert(11u32, 3);
        index.insert(11, 8);
        index.insert(4, 2);
        assert_eq!(index.probe(&11), Some([3, 8].as_slice()));
        assert_eq!(index.distinct_keys(), 2);
        assert_eq!(index.rows(), 3);
    }

    #[test]
    fn top_k_partitions_before_sorting() {
        let values = [9, 1, 7, 2, 8, 3];
        let rows = top_k_indices(values.len(), 3, |a, b| values[a].cmp(&values[b]));
        assert_eq!(rows, [1, 3, 5]);
    }

    #[test]
    fn merge_keeps_multiplicity() {
        assert_eq!(merge_sorted(&[1, 2, 2, 9], &[2, 3]), [1, 2, 2, 2, 3, 9]);
    }
}

use dexsql_ir::{ColumnBatch, ColumnType, TypedScalar};

/// Evaluate a row predicate over a typed batch and compact matching rows in
/// place. The predicate receives the batch and row index, allowing callers to
/// fuse several column reads without allocating a relation map per row.
pub fn filter_batch<F>(batch: &mut ColumnBatch, mut predicate: F) -> usize
where
    F: FnMut(&ColumnBatch, usize) -> bool,
{
    let keep = (0..batch.len())
        .map(|row| predicate(batch, row))
        .collect::<Vec<_>>();
    let count = keep.iter().filter(|&&value| value).count();
    batch.retain(&keep);
    count
}

/// Materialize a row subset while retaining the source column physical types.
/// This is used after top-k selection and keeps text as StringId values until
/// final rendering.
pub fn take_rows(batch: &ColumnBatch, rows: &[usize]) -> Result<ColumnBatch, &'static str> {
    let types = (0..batch.width())
        .map(|column| {
            batch
                .column(column)
                .map_or(ColumnType::Scalar, |value| value.column_type())
        })
        .collect::<Vec<_>>();
    let mut output = ColumnBatch::with_capacity(&types, rows.len());
    for &row in rows {
        let mut values = Vec::with_capacity(batch.width());
        for column in 0..batch.width() {
            values.push(batch.get(column, row).ok_or("row index out of bounds")?);
        }
        output.push_row(&values);
    }
    Ok(output)
}

/// Count groups using copy-only scalar keys. Null is a valid SQL group key and
/// therefore remains in the index instead of being discarded as a join key.
pub fn group_counts(
    batch: &ColumnBatch,
    key_column: usize,
) -> Result<BatchKeyIndex<TypedScalar>, &'static str> {
    if key_column >= batch.width() {
        return Err("group column out of bounds");
    }
    let mut groups = BatchKeyIndex::with_capacity(batch.len());
    for row in 0..batch.len() {
        let key = batch
            .get(key_column, row)
            .ok_or("row index out of bounds")?;
        groups.insert(key, row as u32);
    }
    Ok(groups)
}

#[cfg(test)]
mod batch_operator_tests {
    use super::{filter_batch, group_counts, take_rows};
    use dexsql_ir::{ColumnBatch, ColumnType, StringId, TypedScalar};

    fn sample() -> ColumnBatch {
        let mut batch = ColumnBatch::with_capacity(&[ColumnType::Int64, ColumnType::TextId], 4);
        for (number, text) in [(1, 9), (2, 9), (3, 4), (4, 9)] {
            batch.push_row(&[TypedScalar::Int(number), TypedScalar::Text(StringId(text))]);
        }
        batch
    }

    #[test]
    fn filter_compacts_all_columns_without_row_maps() {
        let mut batch = sample();
        let kept = filter_batch(&mut batch, |batch, row| {
            batch.get(0, row).and_then(TypedScalar::as_i64).unwrap_or(0) % 2 == 0
        });
        assert_eq!(kept, 2);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.get(0, 0), Some(TypedScalar::Int(2)));
        assert_eq!(batch.get(1, 1), Some(TypedScalar::Text(StringId(9))));
    }

    #[test]
    fn take_rows_preserves_order_and_physical_types() {
        let batch = sample();
        let selected = take_rows(&batch, &[3, 1]).unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected.column(0).unwrap().column_type(), ColumnType::Int64);
        assert_eq!(selected.get(0, 0), Some(TypedScalar::Int(4)));
        assert_eq!(selected.get(1, 1), Some(TypedScalar::Text(StringId(9))));
    }

    #[test]
    fn group_counts_keeps_duplicate_and_null_keys() {
        let mut batch = ColumnBatch::new(&[ColumnType::TextId]);
        batch.push_row(&[TypedScalar::Text(StringId(7))]);
        batch.push_row(&[TypedScalar::Null]);
        batch.push_row(&[TypedScalar::Text(StringId(7))]);
        let groups = group_counts(&batch, 0).unwrap();
        assert_eq!(
            groups.probe(&TypedScalar::Text(StringId(7))),
            Some([0, 2].as_slice())
        );
        assert_eq!(groups.probe(&TypedScalar::Null), Some([1].as_slice()));
    }
}

/// Classify an optimized logical plan into the scan kernel that should own the
/// hot path. This is intentionally independent of the SQL parser: the CLI can
/// call it after lowering and use the returned gate decision before selecting
/// a specialized relation executor.
pub fn classify_plan(plan: &dexsql_ir::PlanNode, disable_scan_top_k: bool) -> PhysicalPlan {
    use dexsql_ir::{PlanNode, ScanKind};
    let mut node = plan;
    let mut limit = None;
    let mut pushed_columns = 0;
    let mut has_sort = false;
    loop {
        match node {
            PlanNode::Limit {
                input,
                limit: bound,
                ..
            } => {
                limit = Some(*bound);
                node = input;
            }
            PlanNode::Sort { input, .. } => {
                has_sort = true;
                node = input;
            }
            PlanNode::Project { input, expressions } => {
                pushed_columns = expressions.len();
                node = input;
            }
            PlanNode::Filter { input, .. } | PlanNode::Aggregate { input, .. } => node = input,
            PlanNode::Scan { kind, .. } => {
                let (kernel, edge) = match kind {
                    ScanKind::RawEdge { table, .. } => (
                        if has_sort && limit.is_some() && !disable_scan_top_k {
                            Kernel::SortedRangeScan
                        } else {
                            Kernel::RawEdgeScan
                        },
                        edge_kind(table),
                    ),
                    ScanKind::MethodView { .. } => (
                        if has_sort && limit.is_some() && !disable_scan_top_k {
                            Kernel::SimpleNativeProjection
                        } else {
                            Kernel::MethodViewScan
                        },
                        None,
                    ),
                    ScanKind::Table { .. } => (Kernel::NormalizedEntityScan, None),
                };
                return PhysicalPlan {
                    kernel,
                    edge,
                    pushed_columns,
                    limit,
                };
            }
            PlanNode::Join { .. } => {
                return PhysicalPlan {
                    kernel: Kernel::StreamingJoin,
                    edge: None,
                    pushed_columns,
                    limit,
                };
            }
        }
    }
}

fn edge_kind(table: &str) -> Option<EdgeKind> {
    if table.eq_ignore_ascii_case("method_strings") {
        Some(EdgeKind::Strings)
    } else if table.eq_ignore_ascii_case("method_numbers")
        || table.eq_ignore_ascii_case("method_using_numbers")
    {
        Some(EdgeKind::Numbers)
    } else if table.eq_ignore_ascii_case("method_calls") {
        Some(EdgeKind::Calls)
    } else if table.eq_ignore_ascii_case("method_field_accesses") {
        Some(EdgeKind::FieldAccesses)
    } else if table.eq_ignore_ascii_case("method_used_types") {
        Some(EdgeKind::UsedTypes)
    } else {
        None
    }
}

#[cfg(test)]
mod classify_tests {
    use super::{classify_plan, EdgeKind, Kernel};
    use dexsql_ir::{PlanNode, ScanKind, Schema};

    fn edge(table: &str) -> PlanNode {
        PlanNode::Scan {
            kind: ScanKind::RawEdge {
                table: table.into(),
                alias: "e".into(),
            },
            schema: Schema::default(),
        }
    }

    #[test]
    fn selects_sorted_edge_kernel_for_bounded_order() {
        let plan = PlanNode::Limit {
            input: Box::new(PlanNode::Sort {
                input: Box::new(edge("method_numbers")),
                keys: vec!["e.method".into()],
            }),
            limit: 10,
            offset: 0,
        };
        let physical = classify_plan(&plan, false);
        assert_eq!(physical.kernel, Kernel::SortedRangeScan);
        assert_eq!(physical.edge, Some(EdgeKind::Numbers));
        assert_eq!(physical.limit, Some(10));
    }

    #[test]
    fn top_k_gate_falls_back_to_raw_edge_scan() {
        let plan = PlanNode::Limit {
            input: Box::new(PlanNode::Sort {
                input: Box::new(edge("method_strings")),
                keys: vec!["e.method".into()],
            }),
            limit: 10,
            offset: 0,
        };
        assert_eq!(classify_plan(&plan, true).kernel, Kernel::RawEdgeScan);
    }
}
