//! Small typed relational IR used as the common boundary between lowering,
//! optimizer and execution.  It mirrors the names visible in the release
//! binary (frames, bindings and physical scan leaves) without pretending that
//! all optimizer rules are recovered yet.

use std::fmt;

/// An index into a query-local string pool.
///
/// DEX metadata already keeps strings in an indexed pool.  Passing those
/// indexes through the relational layer avoids cloning descriptor text for
/// every edge row and makes equality/hash joins integer operations.  `0` has
/// no special meaning; callers may use it for an empty string or a sentinel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StringId(pub u32);

impl From<u32> for StringId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<StringId> for u32 {
    fn from(value: StringId) -> Self {
        value.0
    }
}

/// Scalar representation used by [`ColumnBatch`].  It is deliberately copy
/// based: text is represented by a [`StringId`] and real values by their IEEE
/// bits so that grouping and hash joins do not allocate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TypedScalar {
    #[default]
    Null,
    Int(i64),
    Real(u64),
    Text(StringId),
}

impl TypedScalar {
    pub fn real(value: f64) -> Self {
        Self::Real(value.to_bits())
    }

    pub fn as_i64(self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_text_id(self) -> Option<StringId> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_f64(self) -> Option<f64> {
        match self {
            Self::Real(bits) => Some(f64::from_bits(bits)),
            _ => None,
        }
    }
}

/// Physical type of a column in a [`ColumnBatch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColumnType {
    Int64,
    TextId,
    RealBits,
    Scalar,
}

/// A compact columnar row set.
///
/// The SQL compatibility layer can still expose rows as maps at its boundary,
/// while scans and joins use this structure internally.  `Int64`, `TextId`,
/// and `RealBits` columns store values and a validity bitmap separately; a
/// null therefore costs one bit-like byte and does not require an enum or heap
/// allocation.  The `Scalar` variant is available for expressions whose type
/// cannot be inferred during lowering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ColumnData {
    Int64 {
        values: Vec<i64>,
        valid: Vec<u8>,
    },
    TextId {
        values: Vec<StringId>,
        valid: Vec<u8>,
    },
    RealBits {
        values: Vec<u64>,
        valid: Vec<u8>,
    },
    Scalar(Vec<TypedScalar>),
}

impl ColumnData {
    pub fn with_capacity(ty: ColumnType, capacity: usize) -> Self {
        match ty {
            ColumnType::Int64 => Self::Int64 {
                values: Vec::with_capacity(capacity),
                valid: Vec::with_capacity(capacity),
            },
            ColumnType::TextId => Self::TextId {
                values: Vec::with_capacity(capacity),
                valid: Vec::with_capacity(capacity),
            },
            ColumnType::RealBits => Self::RealBits {
                values: Vec::with_capacity(capacity),
                valid: Vec::with_capacity(capacity),
            },
            ColumnType::Scalar => Self::Scalar(Vec::with_capacity(capacity)),
        }
    }

    pub fn column_type(&self) -> ColumnType {
        match self {
            Self::Int64 { .. } => ColumnType::Int64,
            Self::TextId { .. } => ColumnType::TextId,
            Self::RealBits { .. } => ColumnType::RealBits,
            Self::Scalar(_) => ColumnType::Scalar,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Int64 { values, .. } => values.len(),
            Self::TextId { values, .. } => values.len(),
            Self::RealBits { values, .. } => values.len(),
            Self::Scalar(values) => values.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn push(&mut self, value: TypedScalar) {
        match self {
            Self::Int64 { values, valid } => match value {
                TypedScalar::Int(value) => {
                    values.push(value);
                    valid.push(1);
                }
                TypedScalar::Null => {
                    values.push(0);
                    valid.push(0);
                }
                _ => panic!("typed scalar does not match Int64 column"),
            },
            Self::TextId { values, valid } => match value {
                TypedScalar::Text(value) => {
                    values.push(value);
                    valid.push(1);
                }
                TypedScalar::Null => {
                    values.push(StringId::default());
                    valid.push(0);
                }
                _ => panic!("typed scalar does not match TextId column"),
            },
            Self::RealBits { values, valid } => match value {
                TypedScalar::Real(value) => {
                    values.push(value);
                    valid.push(1);
                }
                TypedScalar::Null => {
                    values.push(0);
                    valid.push(0);
                }
                _ => panic!("typed scalar does not match RealBits column"),
            },
            Self::Scalar(values) => values.push(value),
        }
    }

    pub fn get(&self, row: usize) -> Option<TypedScalar> {
        match self {
            Self::Int64 { values, valid } => {
                let value = *values.get(row)?;
                Some(if valid.get(row) == Some(&1) {
                    TypedScalar::Int(value)
                } else {
                    TypedScalar::Null
                })
            }
            Self::TextId { values, valid } => {
                let value = *values.get(row)?;
                Some(if valid.get(row) == Some(&1) {
                    TypedScalar::Text(value)
                } else {
                    TypedScalar::Null
                })
            }
            Self::RealBits { values, valid } => {
                let value = *values.get(row)?;
                Some(if valid.get(row) == Some(&1) {
                    TypedScalar::Real(value)
                } else {
                    TypedScalar::Null
                })
            }
            Self::Scalar(values) => values.get(row).copied(),
        }
    }

    fn retain(&mut self, keep: &[bool]) {
        match self {
            Self::Int64 { values, valid } => {
                compact(values, keep);
                compact(valid, keep);
            }
            Self::TextId { values, valid } => {
                compact(values, keep);
                compact(valid, keep);
            }
            Self::RealBits { values, valid } => {
                compact(values, keep);
                compact(valid, keep);
            }
            Self::Scalar(values) => compact(values, keep),
        }
    }
}

fn compact<T>(values: &mut Vec<T>, keep: &[bool]) {
    let mut write = 0;
    for read in 0..values.len() {
        if keep.get(read).copied().unwrap_or(false) {
            if write != read {
                values.swap(write, read);
            }
            write += 1;
        }
    }
    values.truncate(write);
}

/// A set of equal-length typed columns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnBatch {
    columns: Vec<ColumnData>,
    len: usize,
}

#[cfg(test)]
mod batch_tests {
    use super::{ColumnBatch, ColumnType, StringId, TypedScalar};

    #[test]
    fn typed_batch_round_trip_and_nulls() {
        let mut batch = ColumnBatch::with_capacity(
            &[ColumnType::Int64, ColumnType::TextId, ColumnType::RealBits],
            4,
        );
        batch.push_row(&[
            TypedScalar::Int(7),
            TypedScalar::Text(StringId(12)),
            TypedScalar::real(1.5),
        ]);
        batch.push_row(&[TypedScalar::Null, TypedScalar::Null, TypedScalar::Null]);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.get(0, 0), Some(TypedScalar::Int(7)));
        assert_eq!(batch.get(1, 0), Some(TypedScalar::Text(StringId(12))));
        assert_eq!(batch.get(2, 0).and_then(TypedScalar::as_f64), Some(1.5));
        assert_eq!(batch.get(0, 1), Some(TypedScalar::Null));
    }

    #[test]
    fn retain_compacts_all_columns_with_one_mask() {
        let mut batch = ColumnBatch::new(&[ColumnType::Int64, ColumnType::TextId]);
        for index in 0..4 {
            batch.push_row(&[
                TypedScalar::Int(index),
                TypedScalar::Text(StringId(index as u32 + 10)),
            ]);
        }
        batch.retain(&[false, true, false, true]);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.get(0, 0), Some(TypedScalar::Int(1)));
        assert_eq!(batch.get(1, 1), Some(TypedScalar::Text(StringId(13))));
    }

    #[test]
    fn from_columns_wraps_without_requiring_row_materialization() {
        let batch = ColumnBatch::from_columns(vec![
            super::ColumnData::Int64 {
                values: vec![1, 2, 3],
                valid: vec![1, 1, 1],
            },
            super::ColumnData::TextId {
                values: vec![StringId(4), StringId(5), StringId(6)],
                valid: vec![1, 1, 1],
            },
        ])
        .unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(batch.width(), 2);
    }
}

impl ColumnBatch {
    pub fn with_capacity(types: &[ColumnType], capacity: usize) -> Self {
        Self {
            columns: types
                .iter()
                .copied()
                .map(|ty| ColumnData::with_capacity(ty, capacity))
                .collect(),
            len: 0,
        }
    }

    pub fn new(types: &[ColumnType]) -> Self {
        Self::with_capacity(types, 0)
    }

    /// Wraps prebuilt columns without copying.  This is the preferred path
    /// for a scan that already owns typed vectors; `push_row` is mainly for
    /// expression operators and small batches.
    pub fn from_columns(columns: Vec<ColumnData>) -> Result<Self, &'static str> {
        let len = columns.first().map_or(0, ColumnData::len);
        if columns.iter().any(|column| column.len() != len) {
            return Err("column lengths differ");
        }
        Ok(Self { columns, len })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn width(&self) -> usize {
        self.columns.len()
    }

    pub fn column(&self, index: usize) -> Option<&ColumnData> {
        self.columns.get(index)
    }

    pub fn column_mut(&mut self, index: usize) -> Option<&mut ColumnData> {
        self.columns.get_mut(index)
    }

    /// Appends one row.  The slice must have exactly `width()` values.
    pub fn push_row(&mut self, values: &[TypedScalar]) {
        assert_eq!(
            values.len(),
            self.width(),
            "column batch row width mismatch"
        );
        for (column, value) in self.columns.iter_mut().zip(values.iter().copied()) {
            column.push(value);
        }
        self.len += 1;
    }

    pub fn get(&self, column: usize, row: usize) -> Option<TypedScalar> {
        self.columns.get(column)?.get(row)
    }

    /// Filters rows in place using a byte-per-row mask.  The byte mask keeps
    /// this operation branch-predictable and allows callers to reuse a SIMD
    /// predicate result without converting it to a second representation.
    pub fn retain(&mut self, keep: &[bool]) {
        let new_len = keep.iter().take(self.len).filter(|&&value| value).count();
        for column in &mut self.columns {
            column.retain(keep);
        }
        self.len = new_len;
    }

    pub fn into_columns(self) -> Vec<ColumnData> {
        self.columns
    }
}

impl fmt::Display for StringId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub nullable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Schema {
    pub columns: Vec<Column>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanKind {
    Table { name: String, alias: String },
    RawEdge { table: String, alias: String },
    MethodView { alias: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanNode {
    Scan {
        kind: ScanKind,
        schema: Schema,
    },
    Filter {
        input: Box<PlanNode>,
        predicate: String,
    },
    Project {
        input: Box<PlanNode>,
        expressions: Vec<String>,
    },
    Aggregate {
        input: Box<PlanNode>,
        groups: Vec<String>,
        aggregates: Vec<String>,
    },
    Join {
        left: Box<PlanNode>,
        right: Box<PlanNode>,
        on: String,
    },
    Sort {
        input: Box<PlanNode>,
        keys: Vec<String>,
    },
    Limit {
        input: Box<PlanNode>,
        limit: usize,
        offset: usize,
    },
}

impl PlanNode {
    pub fn schema(&self) -> &Schema {
        match self {
            Self::Scan { schema, .. } => schema,
            Self::Filter { input, .. }
            | Self::Project { input, .. }
            | Self::Aggregate { input, .. }
            | Self::Sort { input, .. }
            | Self::Limit { input, .. } => input.schema(),
            Self::Join { left, .. } => left.schema(),
        }
    }
}
