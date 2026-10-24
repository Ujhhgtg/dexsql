//! Indexed metadata lookups for typed class/method/field reads.
//!
//! The SQL engine answers arbitrary queries by scanning relations. WeKit's
//! DexKit replacement instead needs the DexKit *Data view of one descriptor
//! per delegate, so this module keeps the same immutable dataset and adds
//! per-file lazy indexes for descriptor lookups and code-reference slices.
//!
//! Everything here is derived from data the loader already retains:
//!
//! * classes and members come from the existing type/class indexes,
//! * relation slices are addressed by the existing per-file reference vectors,
//! * the only new allocations are the lazy indexes stored in
//!   [MetadataIndexes], built on first use and shared through OnceLock.
//!
//! The final JSON contract lives in the dexsql facade; this module only
//! exposes resolver-friendly pieces (descriptor parsing, dataset lookups, and
//! relation slices) so the CLI, the facade, and tests agree on one
//! implementation.

use std::sync::{Arc, OnceLock};

use rustc_hash::FxHashMap;

use crate::{
    ClassInfo, Dataset, DexFile, MethodCallRef, MethodFieldRef, MethodNumberRef, MethodStringRef,
};

/// One metadata read request.
///
/// All descriptors use DEX descriptor form: Lpkg/Class;,
/// Lpkg/Class;->name(ILjava/lang/String;)V, or
/// Lpkg/Class;->field:Ljava/lang/String;. Class names are never accepted in
/// place of class descriptors; callers that hold dotted names must convert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaQuery {
    Class { descriptor: String },
    Method { descriptor: String },
    Field { descriptor: String },
}

impl MetaQuery {
    pub fn class(descriptor: impl Into<String>) -> Self {
        Self::Class {
            descriptor: descriptor.into(),
        }
    }

    pub fn method(descriptor: impl Into<String>) -> Self {
        Self::Method {
            descriptor: descriptor.into(),
        }
    }

    pub fn field(descriptor: impl Into<String>) -> Self {
        Self::Field {
            descriptor: descriptor.into(),
        }
    }

    /// Lowercase JSON kind discriminator for this query.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Class { .. } => "class",
            Self::Method { .. } => "method",
            Self::Field { .. } => "field",
        }
    }

    pub fn descriptor(&self) -> &str {
        match self {
            Self::Class { descriptor }
            | Self::Method { descriptor }
            | Self::Field { descriptor } => descriptor,
        }
    }
}

// ---------------------------------------------------------------------------
// Descriptor parsing and Java-name conversion
// ---------------------------------------------------------------------------

/// Parsed method descriptor components borrowed from the input string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodDescriptorParts<'a> {
    pub class_descriptor: &'a str,
    pub name: &'a str,
    pub param_descriptors: Vec<&'a str>,
    pub return_descriptor: &'a str,
}

impl MethodDescriptorParts<'_> {
    /// Rebuild the canonical full descriptor.
    pub fn to_descriptor(&self) -> String {
        let mut out = String::with_capacity(
            self.class_descriptor.len()
                + self.name.len()
                + 3
                + self
                    .param_descriptors
                    .iter()
                    .map(|p| p.len())
                    .sum::<usize>()
                + self.return_descriptor.len(),
        );
        out.push_str(self.class_descriptor);
        out.push_str("->");
        out.push_str(self.name);
        push_method_sign(&mut out, &self.param_descriptors, self.return_descriptor);
        out
    }
}

/// Parsed field descriptor components borrowed from the input string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescriptorParts<'a> {
    pub class_descriptor: &'a str,
    pub name: &'a str,
    pub type_descriptor: &'a str,
}

impl FieldDescriptorParts<'_> {
    pub fn to_descriptor(&self) -> String {
        format!(
            "{}->{}:{}",
            self.class_descriptor, self.name, self.type_descriptor
        )
    }
}

/// Append DexKit's proto sign "(<params>)<return>" to out.
pub fn push_method_sign(out: &mut String, params: &[&str], return_descriptor: &str) {
    out.push('(');
    for param in params {
        out.push_str(param);
    }
    out.push(')');
    out.push_str(return_descriptor);
}

/// Validate a class descriptor and return its body (the part between L and ;).
pub fn class_descriptor_body(descriptor: &str) -> Result<&str, String> {
    if !descriptor.starts_with('L') || !descriptor.ends_with(';') || descriptor.len() < 3 {
        return Err(format!(
            "malformed class descriptor {descriptor:?}: expected Lpkg/Class;"
        ));
    }
    let body = &descriptor[1..descriptor.len() - 1];
    if body.is_empty()
        || body.contains(['.', '[', ';'])
        || body.contains("->")
        || body.contains(':')
    {
        return Err(format!(
            "malformed class descriptor {descriptor:?}: invalid class body"
        ));
    }
    Ok(body)
}

/// Convert any DEX type descriptor to its Java type name.
///
/// Arrays become type[] suffixes, primitives / void use their Java keywords,
/// and object types become dotted names.
pub fn descriptor_to_type_name(descriptor: &str) -> Result<String, String> {
    if descriptor.is_empty() {
        return Err("malformed type descriptor: empty".into());
    }
    let mut rest = descriptor;
    let mut dimensions = 0usize;
    while let Some(tail) = rest.strip_prefix('[') {
        dimensions += 1;
        rest = tail;
    }
    if dimensions > 255 {
        return Err(format!("malformed type descriptor {descriptor:?}"));
    }
    let mut name = if rest.starts_with('L') {
        let body = class_descriptor_body(rest)?;
        if body.contains('/') && body.starts_with('/') {
            return Err(format!("malformed type descriptor {descriptor:?}"));
        }
        body.replace('/', ".")
    } else {
        let primitive = match rest {
            "Z" => "boolean",
            "B" => "byte",
            "C" => "char",
            "S" => "short",
            "I" => "int",
            "F" => "float",
            "J" => "long",
            "D" => "double",
            "V" if dimensions == 0 => "void",
            _ => {
                return Err(format!(
                    "malformed type descriptor {descriptor:?}: unknown type code"
                ))
            }
        };
        primitive.to_owned()
    };
    for _ in 0..dimensions {
        name.push_str("[]");
    }
    Ok(name)
}

/// Convert a class descriptor to its dotted Java name.
pub fn class_descriptor_to_name(descriptor: &str) -> Result<String, String> {
    class_descriptor_body(descriptor)?;
    descriptor_to_type_name(descriptor)
}

/// DexKit's simpleName: everything after the last dot.
pub fn simple_type_name(java_name: &str) -> &str {
    java_name.rsplit('.').next().unwrap_or(java_name)
}

/// Parse a method descriptor into its components.
pub fn parse_method_descriptor(descriptor: &str) -> Result<MethodDescriptorParts<'_>, String> {
    let Some((class_descriptor, rest)) = descriptor.split_once("->") else {
        return Err(format!(
            "malformed method descriptor {descriptor:?}: missing ->"
        ));
    };
    class_descriptor_body(class_descriptor)?;
    let Some(open) = rest.find('(') else {
        return Err(format!(
            "malformed method descriptor {descriptor:?}: missing ("
        ));
    };
    let Some(close) = rest[open..].find(')').map(|offset| open + offset) else {
        return Err(format!(
            "malformed method descriptor {descriptor:?}: missing )"
        ));
    };
    let name = &rest[..open];
    if name.is_empty() || name.contains(['(', ')', ';', ':']) {
        return Err(format!(
            "malformed method descriptor {descriptor:?}: invalid method name"
        ));
    }
    let return_descriptor = &rest[close + 1..];
    if return_descriptor.is_empty() {
        return Err(format!(
            "malformed method descriptor {descriptor:?}: missing return type"
        ));
    }
    let param_descriptors = split_type_descriptors(&rest[open + 1..close])
        .map_err(|error| format!("malformed method descriptor {descriptor:?}: {error}"))?;
    descriptor_to_type_name(return_descriptor)
        .map_err(|error| format!("malformed method descriptor {descriptor:?}: {error}"))?;
    Ok(MethodDescriptorParts {
        class_descriptor,
        name,
        param_descriptors,
        return_descriptor,
    })
}

/// Parse a field descriptor into its components.
pub fn parse_field_descriptor(descriptor: &str) -> Result<FieldDescriptorParts<'_>, String> {
    let Some((class_descriptor, rest)) = descriptor.split_once("->") else {
        return Err(format!(
            "malformed field descriptor {descriptor:?}: missing ->"
        ));
    };
    class_descriptor_body(class_descriptor)?;
    let Some((name, type_descriptor)) = rest.split_once(':') else {
        return Err(format!(
            "malformed field descriptor {descriptor:?}: missing :"
        ));
    };
    if name.is_empty() || name.contains(['(', ')', ';', ':']) {
        return Err(format!(
            "malformed field descriptor {descriptor:?}: invalid field name"
        ));
    }
    if type_descriptor == "V" {
        return Err(format!(
            "malformed field descriptor {descriptor:?}: void field type"
        ));
    }
    descriptor_to_type_name(type_descriptor)
        .map_err(|error| format!("malformed field descriptor {descriptor:?}: {error}"))?;
    Ok(FieldDescriptorParts {
        class_descriptor,
        name,
        type_descriptor,
    })
}

/// Split a DEX type-list string (ILjava/lang/String;[I) into descriptors.
fn split_type_descriptors(mut input: &str) -> Result<Vec<&str>, String> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let bytes = input.as_bytes();
        let mut index = 0;
        while index < bytes.len() && bytes[index] == b'[' {
            index += 1;
        }
        if index >= bytes.len() {
            return Err("unterminated array type".into());
        }
        if bytes[index] == b'L' {
            let Some(end) = input[index..].find(';').map(|offset| index + offset) else {
                return Err("unterminated object type".into());
            };
            index = end;
        }
        let length = index + 1;
        let descriptor = &input[..length];
        if descriptor == "V" {
            return Err("void is not a valid parameter type".into());
        }
        descriptor_to_type_name(descriptor)?;
        out.push(descriptor);
        input = &input[length..];
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Per-file lazy indexes
// ---------------------------------------------------------------------------

/// Lazy relation indexes attached to one [DexFile].
///
/// The relation vectors themselves keep their load order (code order); each
/// index maps an owning method index to a contiguous row range. Indexes are
/// built on the first metadata read that needs them and are shared by all
/// threads afterwards.
#[derive(Debug, Default, Clone)]
pub struct MetadataIndexes {
    invokes: OnceLock<Arc<RangeIndex>>,
    callers: OnceLock<Arc<CallerIndex>>,
    using_strings: OnceLock<Arc<RangeIndex>>,
    using_numbers: OnceLock<Arc<RangeIndex>>,
    using_fields: OnceLock<Arc<RangeIndex>>,
}

impl MetadataIndexes {
    fn invokes(&self, rows: &[MethodCallRef]) -> &RangeIndex {
        self.invokes.get_or_init(|| {
            Arc::new(RangeIndex::build(rows.len(), |index| {
                rows[index].method_idx
            }))
        })
    }

    fn callers(&self, rows: &[MethodCallRef], method_count: usize) -> &CallerIndex {
        self.callers
            .get_or_init(|| Arc::new(CallerIndex::build(rows, method_count)))
    }

    fn using_strings(&self, rows: &[MethodStringRef]) -> &RangeIndex {
        self.using_strings.get_or_init(|| {
            Arc::new(RangeIndex::build(rows.len(), |index| {
                rows[index].method_idx
            }))
        })
    }

    fn using_numbers(&self, rows: &[MethodNumberRef]) -> &RangeIndex {
        self.using_numbers.get_or_init(|| {
            Arc::new(RangeIndex::build(rows.len(), |index| {
                rows[index].method_idx
            }))
        })
    }

    fn using_fields(&self, rows: &[MethodFieldRef]) -> &RangeIndex {
        self.using_fields.get_or_init(|| {
            Arc::new(RangeIndex::build(rows.len(), |index| {
                rows[index].method_idx
            }))
        })
    }
}

/// Where the rows for one method live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeSpan {
    Missing,
    /// Rows start here and continue while the key matches; used by the compact
    /// representation, which stores only the first row of each run.
    Start(usize),
    /// Explicit range; only used when a relation is not contiguous per method.
    Range(usize, usize),
}

/// Sorted (method_idx, row_start) index over a relation vector.
///
/// Rows produced by the official loaders are contiguous per method, so storing
/// only the first row of each run is enough: the lookup walks forward while the
/// row still belongs to the same method. A compact entry costs 8 bytes. If a
/// relation ever interleaves a method's rows (not produced by DexSQL today)
/// the builder falls back to explicit (method_idx, start, end) triples so the
/// result stays correct.
#[derive(Debug, Default)]
struct RangeIndex {
    entries: Vec<(u32, u32)>,
    fallback: Option<Vec<(u32, u32, u32)>>,
}

impl RangeIndex {
    fn build(row_count: usize, key_of: impl Fn(usize) -> u32) -> Self {
        let mut runs: Vec<(u32, u32, u32)> = Vec::new();
        for index in 0..row_count {
            let key = key_of(index);
            match runs.last_mut() {
                Some(run) if run.0 == key => run.2 = index as u32 + 1,
                _ => runs.push((key, index as u32, index as u32 + 1)),
            }
        }
        let mut order: Vec<u32> = (0..runs.len() as u32).collect();
        order.sort_unstable_by_key(|&index| runs[index as usize].0);
        let interleaved = order
            .windows(2)
            .any(|pair| runs[pair[0] as usize].0 == runs[pair[1] as usize].0);
        if interleaved {
            let fallback = order
                .into_iter()
                .map(|index| runs[index as usize])
                .collect();
            return Self {
                entries: Vec::new(),
                fallback: Some(fallback),
            };
        }
        let entries = order
            .into_iter()
            .map(|index| {
                let run = runs[index as usize];
                (run.0, run.1)
            })
            .collect();
        Self {
            entries,
            fallback: None,
        }
    }

    fn span(&self, key: u32, row_count: usize) -> RangeSpan {
        if let Some(fallback) = &self.fallback {
            return match fallback.binary_search_by_key(&key, |entry| entry.0) {
                Ok(index) => {
                    let entry = fallback[index];
                    RangeSpan::Range(entry.1 as usize, entry.2 as usize)
                }
                Err(_) => RangeSpan::Missing,
            };
        }
        match self.entries.binary_search_by_key(&key, |entry| entry.0) {
            Ok(index) => {
                let start = self.entries[index].1 as usize;
                if start >= row_count {
                    RangeSpan::Missing
                } else {
                    RangeSpan::Start(start)
                }
            }
            Err(_) => RangeSpan::Missing,
        }
    }
}

/// Inverted callee -> callers index for the callers metadata field.
///
/// Stores caller method ids grouped by callee as compact u16 ids (a DEX file
/// cannot hold more than 65536 method ids, because invoke instructions use a
/// 16-bit reference) and falls back to u32 for defensive support of
/// non-conformant inputs. Caller lists keep the relation row order, which is
/// DexKit's caller-list order (class-definition walk order, instruction order
/// inside a method, duplicates preserved because one caller can invoke the same
/// callee more than once).
#[derive(Debug, Default)]
struct CallerIndex {
    /// Sorted by callee: (callee_method_idx, start_row).
    entries: Vec<(u32, u32)>,
    rows: CallerRows,
}

#[derive(Debug, Default)]
enum CallerRows {
    #[default]
    Empty,
    U16(Vec<u16>),
    U32(Vec<u32>),
}

impl CallerRows {
    fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::U16(rows) => rows.len(),
            Self::U32(rows) => rows.len(),
        }
    }

    fn slice(&self, start: usize, end: usize) -> CallerIds<'_> {
        match self {
            Self::Empty => CallerIds::Empty,
            Self::U16(rows) => CallerIds::U16(&rows[start..end]),
            Self::U32(rows) => CallerIds::U32(&rows[start..end]),
        }
    }
}

/// Iterator over caller method indices for one callee.
#[derive(Debug)]
pub enum CallerIds<'a> {
    Empty,
    U16(&'a [u16]),
    U32(&'a [u32]),
}

impl Iterator for CallerIds<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        match self {
            Self::Empty => None,
            Self::U16(rows) => {
                let (first, rest) = rows.split_first()?;
                *self = Self::U16(rest);
                Some(*first as u32)
            }
            Self::U32(rows) => {
                let (first, rest) = rows.split_first()?;
                *self = Self::U32(rest);
                Some(*first)
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = match self {
            Self::Empty => 0,
            Self::U16(rows) => rows.len(),
            Self::U32(rows) => rows.len(),
        };
        (len, Some(len))
    }
}

impl ExactSizeIterator for CallerIds<'_> {}

impl CallerIndex {
    fn build(rows: &[MethodCallRef], method_count: usize) -> Self {
        if rows.is_empty() {
            return Self::default();
        }
        // Counting pass: callee -> edge count.
        let mut counts: FxHashMap<u32, u32> = FxHashMap::default();
        for row in rows {
            *counts.entry(row.callee_method_idx).or_insert(0) += 1;
        }
        let mut keys: Vec<(u32, u32)> = counts.iter().map(|(&key, &count)| (key, count)).collect();
        keys.sort_unstable_by_key(|entry| entry.0);
        let mut total = 0u32;
        let mut entries = Vec::with_capacity(keys.len());
        for (callee, count) in &keys {
            entries.push((*callee, total));
            total = total.saturating_add(*count);
        }
        debug_assert_eq!(total as usize, rows.len());
        // Reuse the counts map as callee -> rank for the filling pass.
        for (rank, (callee, _)) in keys.iter().enumerate() {
            counts.insert(*callee, rank as u32);
        }
        drop(keys);
        let mut cursor: Vec<u32> = entries.iter().map(|entry| entry.1).collect();
        let mut index = Self {
            entries,
            rows: if method_count <= u16::MAX as usize + 1 {
                CallerRows::U16(vec![0; rows.len()])
            } else {
                CallerRows::U32(vec![0; rows.len()])
            },
        };
        for row in rows {
            let rank = counts[&row.callee_method_idx] as usize;
            let position = cursor[rank] as usize;
            cursor[rank] += 1;
            match &mut index.rows {
                CallerRows::U16(values) => values[position] = row.method_idx as u16,
                CallerRows::U32(values) => values[position] = row.method_idx,
                CallerRows::Empty => unreachable!("caller index rows must be allocated"),
            }
        }
        // Keep relation order inside each callee's list: the reference rows are
        // appended while walking class definitions and instruction streams, which
        // is exactly DexKit's caller-list order (local callers first, then
        // cross-DEX imports in source DEX order).
        index
    }

    fn callers(&self, callee: u32) -> CallerIds<'_> {
        let row_count = self.rows.len();
        match self.entries.binary_search_by_key(&callee, |entry| entry.0) {
            Ok(position) => {
                let start = self.entries[position].1 as usize;
                let end = self
                    .entries
                    .get(position + 1)
                    .map(|entry| entry.1 as usize)
                    .unwrap_or(row_count);
                self.rows.slice(start, end)
            }
            Err(_) => CallerIds::Empty,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-file lookups
// ---------------------------------------------------------------------------

impl DexFile {
    /// Resolve a type descriptor to its DEX type id.
    ///
    /// DEX type_ids are sorted by descriptor string, so this is a binary
    /// search. Rust scalar-value ordering and DEX UTF-16 ordering only differ
    /// for descriptors containing characters outside the BMP; those are
    /// handled by a linear fallback so correctness never depends on the
    /// ordering assumption.
    pub fn type_idx_for_descriptor(&self, descriptor: &str) -> Option<u32> {
        let binary = self
            .types
            .binary_search_by(|info| self.string(info.descriptor_idx).cmp(descriptor));
        if let Ok(index) = binary {
            return Some(index as u32);
        }
        if descriptor.is_ascii() {
            return None;
        }
        self.types
            .iter()
            .position(|info| self.string(info.descriptor_idx) == descriptor)
            .map(|index| index as u32)
    }

    /// Class definition for a type id, if this file defines that class.
    pub fn class_for_type_idx(&self, type_idx: u32) -> Option<&ClassInfo> {
        let class_index = *self.classes_by_descriptor.get(&type_idx)?.first()?;
        self.classes.get(class_index as usize)
    }

    /// Class definition for a class descriptor, if this file defines it.
    pub fn class_for_descriptor(&self, descriptor: &str) -> Option<&ClassInfo> {
        self.class_for_type_idx(self.type_idx_for_descriptor(descriptor)?)
    }

    /// Method id table entry as resolver-friendly parts.
    pub fn method_parts(&self, method_idx: u32) -> Option<MethodRefParts<'_>> {
        let method = self.methods.get(method_idx as usize)?;
        let proto = self.protos.get(method.proto_idx as usize)?;
        Some(MethodRefParts {
            class_descriptor: self.type_descriptor(method.class_idx as u32),
            name: self.string(method.name_idx),
            return_descriptor: self.type_descriptor(proto.return_type_idx),
            param_descriptors: proto
                .parameters
                .iter()
                .map(|&param| self.type_descriptor(param as u32))
                .collect(),
        })
    }

    /// Field id table entry as resolver-friendly parts.
    pub fn field_parts(&self, field_idx: u32) -> Option<FieldRefParts<'_>> {
        let field = self.fields.get(field_idx as usize)?;
        Some(FieldRefParts {
            class_descriptor: self.type_descriptor(field.class_idx as u32),
            name: self.string(field.name_idx),
            type_descriptor: self.type_descriptor(field.type_idx as u32),
        })
    }

    /// Find the defined method matching parts in class.
    pub fn defined_method_in_class(
        &self,
        class: &ClassInfo,
        parts: &MethodDescriptorParts<'_>,
    ) -> Option<u32> {
        class
            .methods
            .iter()
            .map(|method| method.method_idx)
            .find(|&method_idx| self.method_matches(method_idx, parts))
    }

    /// Find any method id (defined in this file or an external reference)
    /// matching parts for a class type id.
    pub fn method_reference_for_type(
        &self,
        type_idx: u32,
        parts: &MethodDescriptorParts<'_>,
    ) -> Option<u32> {
        self.methods_by_class
            .get(&type_idx)?
            .iter()
            .copied()
            .find(|&method_idx| self.method_matches(method_idx, parts))
    }

    fn method_matches(&self, method_idx: u32, parts: &MethodDescriptorParts<'_>) -> bool {
        let Some(method) = self.methods.get(method_idx as usize) else {
            return false;
        };
        if self.string(method.name_idx) != parts.name {
            return false;
        }
        if self.type_descriptor(method.class_idx as u32) != parts.class_descriptor {
            return false;
        }
        let Some(proto) = self.protos.get(method.proto_idx as usize) else {
            return false;
        };
        if self.type_descriptor(proto.return_type_idx) != parts.return_descriptor {
            return false;
        }
        proto.parameters.len() == parts.param_descriptors.len()
            && proto
                .parameters
                .iter()
                .zip(&parts.param_descriptors)
                .all(|(&type_idx, &descriptor)| self.type_descriptor(type_idx as u32) == descriptor)
    }

    /// Find the defined field matching parts in class.
    pub fn defined_field_in_class(
        &self,
        class: &ClassInfo,
        parts: &FieldDescriptorParts<'_>,
    ) -> Option<u32> {
        class
            .fields
            .iter()
            .map(|field| field.field_idx)
            .find(|&field_idx| self.field_matches(field_idx, parts))
    }

    /// Find any field id (defined in this file or an external reference)
    /// matching parts for a class type id.
    pub fn field_reference_for_type(
        &self,
        type_idx: u32,
        parts: &FieldDescriptorParts<'_>,
    ) -> Option<u32> {
        let name_idx = self.find_string_idx(parts.name)?;
        self.fields_by_name
            .get(&name_idx)?
            .iter()
            .copied()
            .find(|&field_idx| {
                let Some(field) = self.fields.get(field_idx as usize) else {
                    return false;
                };
                field.class_idx as u32 == type_idx
                    && self.type_descriptor(field.type_idx as u32) == parts.type_descriptor
            })
    }

    fn field_matches(&self, field_idx: u32, parts: &FieldDescriptorParts<'_>) -> bool {
        let Some(field) = self.fields.get(field_idx as usize) else {
            return false;
        };
        self.string(field.name_idx) == parts.name
            && self.type_descriptor(field.class_idx as u32) == parts.class_descriptor
            && self.type_descriptor(field.type_idx as u32) == parts.type_descriptor
    }

    /// Access flags of a field defined in this file.
    pub fn defined_field_flags(&self, field_idx: u32) -> Option<u32> {
        let field = self.fields.get(field_idx as usize)?;
        let class = self.class_for_type_idx(field.class_idx as u32)?;
        class
            .fields
            .iter()
            .find(|entry| entry.field_idx == field_idx)
            .map(|entry| entry.access_flags)
    }

    /// Invoked methods in code order (duplicates preserved).
    pub fn invokes_for_method(&self, method_idx: u32) -> &[MethodCallRef] {
        let rows = &self.method_calls;
        match self.meta.invokes(rows).span(method_idx, rows.len()) {
            RangeSpan::Missing => &[],
            RangeSpan::Range(start, end) => &rows[start..end],
            RangeSpan::Start(start) => {
                let mut end = start;
                while end < rows.len() && rows[end].method_idx == method_idx {
                    end += 1;
                }
                &rows[start..end]
            }
        }
    }

    /// Caller method ids, sorted ascending, duplicates preserved.
    pub fn callers_for_method(&self, method_idx: u32) -> CallerIds<'_> {
        self.meta
            .callers(&self.method_calls, self.methods.len())
            .callers(method_idx)
    }

    /// Referenced string constants in code order (duplicates preserved).
    pub fn using_string_refs(&self, method_idx: u32) -> &[MethodStringRef] {
        let rows = &self.method_strings;
        match self.meta.using_strings(rows).span(method_idx, rows.len()) {
            RangeSpan::Missing => &[],
            RangeSpan::Range(start, end) => &rows[start..end],
            RangeSpan::Start(start) => {
                let mut end = start;
                while end < rows.len() && rows[end].method_idx == method_idx {
                    end += 1;
                }
                &rows[start..end]
            }
        }
    }

    /// Numeric literals in code order (duplicates preserved).
    pub fn using_number_refs(&self, method_idx: u32) -> &[MethodNumberRef] {
        let rows = &self.method_numbers;
        match self.meta.using_numbers(rows).span(method_idx, rows.len()) {
            RangeSpan::Missing => &[],
            RangeSpan::Range(start, end) => &rows[start..end],
            RangeSpan::Start(start) => {
                let mut end = start;
                while end < rows.len() && rows[end].method_idx == method_idx {
                    end += 1;
                }
                &rows[start..end]
            }
        }
    }

    /// Field reads/writes in code order (duplicates preserved).
    pub fn using_field_refs(&self, method_idx: u32) -> &[MethodFieldRef] {
        let rows = &self.method_field_accesses;
        match self.meta.using_fields(rows).span(method_idx, rows.len()) {
            RangeSpan::Missing => &[],
            RangeSpan::Range(start, end) => &rows[start..end],
            RangeSpan::Start(start) => {
                let mut end = start;
                while end < rows.len() && rows[end].method_idx == method_idx {
                    end += 1;
                }
                &rows[start..end]
            }
        }
    }
}

/// Method reference view over one DEX file's id table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRefParts<'a> {
    pub class_descriptor: &'a str,
    pub name: &'a str,
    pub return_descriptor: &'a str,
    pub param_descriptors: Vec<&'a str>,
}

impl MethodRefParts<'_> {
    pub fn descriptor(&self) -> String {
        MethodDescriptorParts {
            class_descriptor: self.class_descriptor,
            name: self.name,
            param_descriptors: self.param_descriptors.clone(),
            return_descriptor: self.return_descriptor,
        }
        .to_descriptor()
    }

    pub fn method_sign(&self) -> String {
        let mut out = String::new();
        push_method_sign(&mut out, &self.param_descriptors, self.return_descriptor);
        out
    }
}

/// Field reference view over one DEX file's id table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRefParts<'a> {
    pub class_descriptor: &'a str,
    pub name: &'a str,
    pub type_descriptor: &'a str,
}

impl FieldRefParts<'_> {
    pub fn descriptor(&self) -> String {
        format!(
            "{}->{}:{}",
            self.class_descriptor, self.name, self.type_descriptor
        )
    }
}

// ---------------------------------------------------------------------------
// Dataset lookups
// ---------------------------------------------------------------------------

/// A class defined by one file in the dataset.
#[derive(Debug, Clone, Copy)]
pub struct ClassLocation<'a> {
    pub file: &'a DexFile,
    pub class: &'a ClassInfo,
}

/// A method id found in the dataset.
#[derive(Debug, Clone, Copy)]
pub struct MethodLocation<'a> {
    pub file: &'a DexFile,
    pub method_idx: u32,
    /// True when the method is defined by a class in the dataset. False means
    /// the descriptor only names an external method reference.
    pub defined: bool,
}

/// A field id found in the dataset.
#[derive(Debug, Clone, Copy)]
pub struct FieldLocation<'a> {
    pub file: &'a DexFile,
    pub field_idx: u32,
    /// True when the field is defined by a class in the dataset.
    pub defined: bool,
}

impl Dataset {
    /// Find the file and class definition for a class descriptor.
    pub fn locate_class(&self, descriptor: &str) -> Result<Option<ClassLocation<'_>>, String> {
        class_descriptor_body(descriptor)?;
        for file in &self.files {
            let Some(type_idx) = file.type_idx_for_descriptor(descriptor) else {
                continue;
            };
            if let Some(class) = file.class_for_type_idx(type_idx) {
                return Ok(Some(ClassLocation { file, class }));
            }
        }
        Ok(None)
    }

    /// Find a defined method for descriptor, or an external reference when no
    /// file defines it.
    pub fn locate_method(&self, descriptor: &str) -> Result<Option<MethodLocation<'_>>, String> {
        let parts = parse_method_descriptor(descriptor)?;
        for file in &self.files {
            let Some(class) = file.class_for_descriptor(parts.class_descriptor) else {
                continue;
            };
            if let Some(method_idx) = file.defined_method_in_class(class, &parts) {
                return Ok(Some(MethodLocation {
                    file,
                    method_idx,
                    defined: true,
                }));
            }
        }
        for file in &self.files {
            let Some(type_idx) = file.type_idx_for_descriptor(parts.class_descriptor) else {
                continue;
            };
            if let Some(method_idx) = file.method_reference_for_type(type_idx, &parts) {
                return Ok(Some(MethodLocation {
                    file,
                    method_idx,
                    defined: file.method_access_flags(method_idx).is_some(),
                }));
            }
        }
        Ok(None)
    }

    /// Find a defined field for descriptor, or an external reference when no
    /// file defines it.
    pub fn locate_field(&self, descriptor: &str) -> Result<Option<FieldLocation<'_>>, String> {
        let parts = parse_field_descriptor(descriptor)?;
        for file in &self.files {
            let Some(class) = file.class_for_descriptor(parts.class_descriptor) else {
                continue;
            };
            if let Some(field_idx) = file.defined_field_in_class(class, &parts) {
                return Ok(Some(FieldLocation {
                    file,
                    field_idx,
                    defined: true,
                }));
            }
        }
        for file in &self.files {
            let Some(type_idx) = file.type_idx_for_descriptor(parts.class_descriptor) else {
                continue;
            };
            if let Some(field_idx) = file.field_reference_for_type(type_idx, &parts) {
                return Ok(Some(FieldLocation {
                    file,
                    field_idx,
                    defined: file.defined_field_flags(field_idx).is_some(),
                }));
            }
        }
        Ok(None)
    }

    /// Find the defining file for an already-parsed method descriptor, if any.
    ///
    /// Used to resolve the declared/access-flag view of cross-DEX invoke and
    /// using-field references, mirroring DexKit's cross-DEX bean resolution.
    pub fn locate_defined_method_parts(
        &self,
        parts: &MethodDescriptorParts<'_>,
    ) -> Option<MethodLocation<'_>> {
        for file in &self.files {
            let Some(class) = file.class_for_descriptor(parts.class_descriptor) else {
                continue;
            };
            if let Some(method_idx) = file.defined_method_in_class(class, parts) {
                return Some(MethodLocation {
                    file,
                    method_idx,
                    defined: true,
                });
            }
        }
        None
    }

    /// Find the defining file for an already-parsed field descriptor, if any.
    pub fn locate_defined_field_parts(
        &self,
        parts: &FieldDescriptorParts<'_>,
    ) -> Option<FieldLocation<'_>> {
        for file in &self.files {
            let Some(class) = file.class_for_descriptor(parts.class_descriptor) else {
                continue;
            };
            if let Some(field_idx) = file.defined_field_in_class(class, parts) {
                return Some(FieldLocation {
                    file,
                    field_idx,
                    defined: true,
                });
            }
        }
        None
    }
}

/// DexKit JavaModifiers / JavaMethodModifiers equivalents.
///
/// DexKit exposes the Java reflection modifier view of DEX access flags:
///
/// * classes and fields: raw flags masked to the low 16 bits,
/// * methods: mask to 16 bits, hide NATIVE on abstract methods, and rebuild
///   SYNCHRONIZED from the DEX-only ACC_DECLARED_SYNCHRONIZED bit.
///
/// The ACC_CONSTRUCTOR bit and other DEX-only high bits are therefore not part
/// of modifiers; see [method_modifiers], [field_modifiers] and
/// [class_modifiers].
pub fn method_modifiers(access_flags: u32) -> i32 {
    let mut flags = access_flags;
    if flags & 0x0400 != 0 {
        flags &= !0x0100;
    }
    flags &= !0x0020;
    if flags & 0x2_0000 != 0 {
        flags |= 0x0020;
    }
    (flags & 0xffff) as i32
}

pub fn field_modifiers(access_flags: u32) -> i32 {
    (access_flags & 0xffff) as i32
}

/// Class modifiers.
///
/// Known divergence: DexKit replaces class-definition access flags with the
/// dalvik.annotation.InnerClass annotation flags when that system annotation
/// is present (Android's Class.getModifiers behavior). The metadata snapshot
/// of WeKit delegates contains no such class, and WeKit resolution does not
/// consume class modifiers, so this implementation only masks the class-def
/// flags. Callers that need Android's exact inner-class modifier view should
/// keep using the annotation relations.
pub fn class_modifiers(access_flags: u32) -> i32 {
    (access_flags & 0xffff) as i32
}

/// True for the DEX field-access opcodes that read a field.
///
/// method_field_accesses rows loaded from a native DEXSQL cache use the
/// compact 0/1 sentinel instead of the source opcode (0 = read, 1 = write).
pub fn field_access_is_read(opcode: u8) -> bool {
    matches!(opcode, 0x52..=0x58 | 0x60..=0x66 | 0)
}

// ---------------------------------------------------------------------------
// DexKit-compatible cross-DEX reference binding
// ---------------------------------------------------------------------------

/// Lazily computed cross-DEX bindings for nested references.
///
/// DexKit renders nested `invokes` / `using_fields` beans through a per-file
/// identity binding built by `DexItem::PutCrossRef`: for a class that the
/// referencing DEX does not define, local method/field ids are matched against
/// the defining DEX's sorted member ids by a greedy two-pointer walk. Ids that
/// the walk does not match keep the file-local (missing) bean view, i.e. access
/// flags 0 and `defined = false`. Reproducing the walk, rather than resolving
/// every reference independently, is required to match the DexKit snapshot: the
/// greedy walk skips some references whose ordering differs between the two DEX
/// files' id tables.
///
/// The index is built per (file, class) on first use; each entry only stores the
/// matching local -> defining member ids.
#[derive(Debug)]
pub struct CrossRefCache {
    files: Vec<std::sync::Mutex<CrossFileCache>>,
}

#[derive(Debug, Default)]
struct CrossFileCache {
    methods: FxHashMap<u32, Option<Arc<MethodBinding>>>,
    fields: FxHashMap<u32, Option<Arc<FieldBinding>>>,
}

/// Local -> defining-DEX method binding for one class reference.
#[derive(Debug, Default)]
pub struct MethodBinding {
    pub origin_file_index: u32,
    local_to_origin: FxHashMap<u32, u32>,
}

impl MethodBinding {
    /// Defining method id for a local reference id, when DexKit would bind it.
    pub fn origin_method(&self, local_method_idx: u32) -> Option<u32> {
        self.local_to_origin.get(&local_method_idx).copied()
    }

    /// Local reference ids bound to one defining method id.
    pub fn local_methods(&self, origin_method_idx: u32) -> impl Iterator<Item = u32> + '_ {
        self.local_to_origin
            .iter()
            .filter_map(move |(&local, &origin)| (origin == origin_method_idx).then_some(local))
    }
}

/// Local -> defining-DEX field binding for one class reference.
#[derive(Debug, Default)]
pub struct FieldBinding {
    pub origin_file_index: u32,
    local_to_origin: FxHashMap<u32, u32>,
}

impl FieldBinding {
    pub fn origin_field(&self, local_field_idx: u32) -> Option<u32> {
        self.local_to_origin.get(&local_field_idx).copied()
    }
}

impl Default for CrossRefCache {
    fn default() -> Self {
        Self { files: Vec::new() }
    }
}

impl CrossRefCache {
    pub fn new(file_count: usize) -> Self {
        Self {
            files: (0..file_count)
                .map(|_| std::sync::Mutex::new(CrossFileCache::default()))
                .collect(),
        }
    }

    fn file_cache(&self, file_index: usize) -> std::sync::MutexGuard<'_, CrossFileCache> {
        self.files[file_index]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// DexKit-compatible binding for a nested method reference in a file.
    ///
    /// Returns `None` when the referencing file defines the class itself (then
    /// the normal class-data access flags apply) or when no input DEX defines
    /// the class at all (the reference stays an external `defined = false` ref).
    pub fn method_binding(
        &self,
        dataset: &Dataset,
        file_index: usize,
        local_method_idx: u32,
    ) -> Option<Arc<MethodBinding>> {
        let file = dataset.files.get(file_index)?;
        let method = file.methods.get(local_method_idx as usize)?;
        let type_idx = method.class_idx as u32;
        if file.class_for_type_idx(type_idx).is_some() {
            return None;
        }
        {
            let cache = self.file_cache(file_index);
            if let Some(cached) = cache.methods.get(&type_idx) {
                return cached.clone();
            }
        }
        let computed = compute_method_binding(dataset, file_index, type_idx).map(Arc::new);
        let mut cache = self.file_cache(file_index);
        cache.methods.insert(type_idx, computed.clone());
        computed
    }

    /// DexKit-compatible binding for a nested field reference in a file.
    pub fn field_binding(
        &self,
        dataset: &Dataset,
        file_index: usize,
        local_field_idx: u32,
    ) -> Option<Arc<FieldBinding>> {
        let file = dataset.files.get(file_index)?;
        let field = file.fields.get(local_field_idx as usize)?;
        let type_idx = field.class_idx as u32;
        if file.class_for_type_idx(type_idx).is_some() {
            return None;
        }
        {
            let cache = self.file_cache(file_index);
            if let Some(cached) = cache.fields.get(&type_idx) {
                return cached.clone();
            }
        }
        let computed = compute_field_binding(dataset, file_index, type_idx).map(Arc::new);
        let mut cache = self.file_cache(file_index);
        cache.fields.insert(type_idx, computed.clone());
        computed
    }
}

fn compute_method_binding(
    dataset: &Dataset,
    file_index: usize,
    type_idx: u32,
) -> Option<MethodBinding> {
    let file = &dataset.files[file_index];
    let descriptor = file.type_descriptor(type_idx);
    let (origin_file_index, origin_class) =
        dataset
            .files
            .iter()
            .enumerate()
            .find_map(|(index, candidate)| {
                candidate
                    .class_for_descriptor(descriptor)
                    .map(|class| (index, class))
            })?;
    let origin_file = &dataset.files[origin_file_index];
    let local_range = file.methods_by_class.get(&type_idx)?;
    let mut origin_ids = origin_class
        .methods
        .iter()
        .map(|method| method.method_idx)
        .collect::<Vec<_>>();
    origin_ids.sort_unstable();
    let mut binding = MethodBinding {
        origin_file_index: origin_file_index as u32,
        local_to_origin: FxHashMap::default(),
    };
    // Greedy identity walk, exactly like DexKit's PutCrossRef.
    let mut current = 0usize;
    let mut origin = 0usize;
    while current < local_range.len() && origin < origin_ids.len() {
        let local_idx = local_range[current];
        let origin_idx = origin_ids[origin];
        if same_method_identity(file, local_idx, origin_file, origin_idx) {
            binding.local_to_origin.insert(local_idx, origin_idx);
            current += 1;
        }
        origin += 1;
    }
    Some(binding)
}

fn compute_field_binding(
    dataset: &Dataset,
    file_index: usize,
    type_idx: u32,
) -> Option<FieldBinding> {
    let file = &dataset.files[file_index];
    let descriptor = file.type_descriptor(type_idx);
    let (origin_file_index, _origin_class) =
        dataset
            .files
            .iter()
            .enumerate()
            .find_map(|(index, candidate)| {
                candidate
                    .class_for_descriptor(descriptor)
                    .map(|class| (index, class))
            })?;
    let origin_file = &dataset.files[origin_file_index];
    let local_range = file.field_range_for_type(type_idx);
    // Type ids are per-DEX: resolve the class again in the defining file.
    let origin_type_idx = origin_file.type_idx_for_descriptor(descriptor)?;
    let origin_range = origin_file.field_range_for_type(origin_type_idx);
    let mut binding = FieldBinding {
        origin_file_index: origin_file_index as u32,
        local_to_origin: FxHashMap::default(),
    };
    let mut current = 0usize;
    let mut origin = 0usize;
    while current < local_range.len() && origin < origin_range.len() {
        let local_idx = local_range.start + current as u32;
        let origin_idx = origin_range.start + origin as u32;
        if same_field_identity(file, local_idx, origin_file, origin_idx) {
            binding.local_to_origin.insert(local_idx, origin_idx);
            current += 1;
        }
        origin += 1;
    }
    Some(binding)
}

fn same_method_identity(left: &DexFile, left_idx: u32, right: &DexFile, right_idx: u32) -> bool {
    let (Some(left_method), Some(right_method)) = (
        left.methods.get(left_idx as usize),
        right.methods.get(right_idx as usize),
    ) else {
        return false;
    };
    if left.string(left_method.name_idx) != right.string(right_method.name_idx) {
        return false;
    }
    if left.type_descriptor(left_method.class_idx as u32)
        != right.type_descriptor(right_method.class_idx as u32)
    {
        return false;
    }
    let (Some(left_proto), Some(right_proto)) = (
        left.protos.get(left_method.proto_idx as usize),
        right.protos.get(right_method.proto_idx as usize),
    ) else {
        return false;
    };
    if left.type_descriptor(left_proto.return_type_idx)
        != right.type_descriptor(right_proto.return_type_idx)
    {
        return false;
    }
    left_proto.parameters.len() == right_proto.parameters.len()
        && left_proto
            .parameters
            .iter()
            .zip(&right_proto.parameters)
            .all(|(&left_param, &right_param)| {
                left.type_descriptor(left_param as u32) == right.type_descriptor(right_param as u32)
            })
}

fn same_field_identity(left: &DexFile, left_idx: u32, right: &DexFile, right_idx: u32) -> bool {
    let (Some(left_field), Some(right_field)) = (
        left.fields.get(left_idx as usize),
        right.fields.get(right_idx as usize),
    ) else {
        return false;
    };
    left.string(left_field.name_idx) == right.string(right_field.name_idx)
        && left.type_descriptor(left_field.class_idx as u32)
            == right.type_descriptor(right_field.class_idx as u32)
        && left.type_descriptor(left_field.type_idx as u32)
            == right.type_descriptor(right_field.type_idx as u32)
}

impl Dataset {
    /// Dataset position of one file (pointer identity).
    pub fn file_index(&self, file: &DexFile) -> Option<usize> {
        self.files
            .iter()
            .position(|candidate| std::ptr::eq(candidate, file))
    }
}

impl DexFile {
    /// Contiguous field id range for one class.
    ///
    /// DEX field_ids are sorted by class_idx, so all field ids that reference a
    /// class form one contiguous range. DexKit uses that range (not class_data
    /// order) as the field side of its cross-DEX identity walk.
    pub fn field_range_for_type(&self, type_idx: u32) -> std::ops::Range<u32> {
        let start = self
            .fields
            .partition_point(|field| (field.class_idx as u32) < type_idx);
        let end = self
            .fields
            .partition_point(|field| (field.class_idx as u32) <= type_idx);
        start as u32..end as u32
    }
}

impl Dataset {
    /// DEX order used by the DexKit bridge.
    ///
    /// DexKit indexes multidex archives as classes.dex, classes2.dex, ... by
    /// numeric suffix, while the ZIP central directory (and therefore
    /// [Dataset::files]) uses lexicographic entry order. Cross-DEX caller lists
    /// follow DexKit's numeric order; single-file inputs keep their input order.
    pub fn dexkit_file_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.files.len()).collect();
        order.sort_by_key(|&index| dexkit_entry_rank(&self.files[index].entry_name, index));
        order
    }
}

fn dexkit_entry_rank(entry_name: &str, index: usize) -> (u32, usize) {
    let stem = entry_name.strip_suffix(".dex").unwrap_or(entry_name);
    if let Some(suffix) = stem.strip_prefix("classes") {
        if suffix.is_empty() {
            return (0, index);
        }
        if let Ok(number) = suffix.parse::<u32>() {
            if number >= 1 {
                return (number - 1, index);
            }
        }
    }
    (u32::MAX, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_method_descriptors() {
        let parsed = parse_method_descriptor("Lpkg/Class;->name(ILjava/lang/String;[I)V").unwrap();
        assert_eq!(parsed.class_descriptor, "Lpkg/Class;");
        assert_eq!(parsed.name, "name");
        assert_eq!(parsed.param_descriptors, ["I", "Ljava/lang/String;", "[I"]);
        assert_eq!(parsed.return_descriptor, "V");
        assert_eq!(
            parsed.to_descriptor(),
            "Lpkg/Class;->name(ILjava/lang/String;[I)V"
        );
        let constructor = parse_method_descriptor("Lpkg/Class;-><init>()V").unwrap();
        assert!(constructor.param_descriptors.is_empty());
        let initializer = parse_method_descriptor("Lpkg/Class;-><clinit>()V").unwrap();
        assert_eq!(initializer.name, "<clinit>");
    }

    #[test]
    fn rejects_malformed_method_descriptors() {
        for descriptor in [
            "",
            "Lpkg/Class;",
            "Lpkg/Class;->",
            "Lpkg/Class;->name",
            "Lpkg/Class;->name()",
            "pkg.Class;->name()V",
            "Lpkg/Class;->na;me()V",
            "Lpkg/Class;->name(Ljava/lang/String)V",
            "Lpkg/Class;->name(V)V",
            "Lpkg/Class;->name([)V",
        ] {
            assert!(
                parse_method_descriptor(descriptor).is_err(),
                "descriptor {descriptor:?} must be rejected"
            );
        }
    }

    #[test]
    fn parses_field_descriptors() {
        let parsed = parse_field_descriptor("Lpkg/Class;->field:Ljava/lang/String;").unwrap();
        assert_eq!(parsed.class_descriptor, "Lpkg/Class;");
        assert_eq!(parsed.name, "field");
        assert_eq!(parsed.type_descriptor, "Ljava/lang/String;");
        assert_eq!(
            parsed.to_descriptor(),
            "Lpkg/Class;->field:Ljava/lang/String;"
        );
        for descriptor in [
            "Lpkg/Class;->field",
            "Lpkg/Class;->field:",
            "pkg.Class;->field:I",
            "Lpkg/Class;->field:V",
            "Lpkg/Class;->field:Q",
        ] {
            assert!(
                parse_field_descriptor(descriptor).is_err(),
                "descriptor {descriptor:?} must be rejected"
            );
        }
    }

    #[test]
    fn converts_descriptors_to_java_names() {
        assert_eq!(
            descriptor_to_type_name("Ljava/lang/String;").unwrap(),
            "java.lang.String"
        );
        assert_eq!(descriptor_to_type_name("I").unwrap(), "int");
        assert_eq!(descriptor_to_type_name("Z").unwrap(), "boolean");
        assert_eq!(descriptor_to_type_name("V").unwrap(), "void");
        assert_eq!(descriptor_to_type_name("[I").unwrap(), "int[]");
        assert_eq!(
            descriptor_to_type_name("[[Ljava/lang/String;").unwrap(),
            "java.lang.String[][]"
        );
        assert_eq!(
            class_descriptor_to_name("Lpkg/Outer$Inner;").unwrap(),
            "pkg.Outer$Inner"
        );
        assert_eq!(simple_type_name("pkg.Outer$Inner"), "Outer$Inner");
        assert_eq!(simple_type_name("Alpha"), "Alpha");
        assert!(descriptor_to_type_name("").is_err());
        assert!(descriptor_to_type_name("[V").is_err());
        assert!(descriptor_to_type_name("Lpkg/Class").is_err());
        assert!(class_descriptor_body("pkg.Class").is_err());
    }

    #[test]
    fn computes_dexkit_modifier_views() {
        // Plain public method.
        assert_eq!(method_modifiers(0x0001), 1);
        // ACC_CONSTRUCTOR is DEX-only and stripped.
        assert_eq!(method_modifiers(0x1_0001), 1);
        // ACC_DECLARED_SYNCHRONIZED maps to Java SYNCHRONIZED.
        assert_eq!(method_modifiers(0x2_0001), 0x21);
        // Raw SYNCHRONIZED is cleared before the mapping.
        assert_eq!(method_modifiers(0x0021), 0x01);
        // NATIVE is hidden on abstract methods (abstract | native | public).
        assert_eq!(method_modifiers(0x0501), 0x0401);
        assert_eq!(field_modifiers(0x1_0019), 0x19);
        assert_eq!(class_modifiers(0x1_0001), 1);
        // Field access direction, including native-cache sentinels.
        assert!(field_access_is_read(0x52));
        assert!(field_access_is_read(0x53));
        assert!(field_access_is_read(0x60));
        assert!(field_access_is_read(0x66));
        assert!(!field_access_is_read(0x59));
        assert!(!field_access_is_read(0x67));
        assert!(field_access_is_read(0));
        assert!(!field_access_is_read(1));
    }

    #[test]
    fn range_index_handles_contiguous_runs() {
        // Rows: method 7 x2, method 3 x1, method 9 x3.
        let keys = [7u32, 7, 3, 9, 9, 9];
        let index = RangeIndex::build(keys.len(), |row| keys[row]);
        match index.span(7, keys.len()) {
            RangeSpan::Start(start) => assert_eq!(start, 0),
            other => panic!("unexpected span {other:?}"),
        }
        match index.span(3, keys.len()) {
            RangeSpan::Start(start) => assert_eq!(start, 2),
            other => panic!("unexpected span {other:?}"),
        }
        match index.span(9, keys.len()) {
            RangeSpan::Start(start) => assert_eq!(start, 3),
            other => panic!("unexpected span {other:?}"),
        }
        assert_eq!(index.span(8, keys.len()), RangeSpan::Missing);
    }

    #[test]
    fn range_index_falls_back_for_interleaved_runs() {
        // Method 1 appears in two non-adjacent runs; the compact form cannot
        // represent that, so the fallback triples must stay correct.
        let keys = [1u32, 2, 1];
        let index = RangeIndex::build(keys.len(), |row| keys[row]);
        match index.span(1, keys.len()) {
            RangeSpan::Range(start, end) => {
                assert_eq!((start, end), (2, 3));
            }
            other => panic!("unexpected span {other:?}"),
        }
        match index.span(2, keys.len()) {
            RangeSpan::Range(start, end) => assert_eq!((start, end), (1, 2)),
            other => panic!("unexpected span {other:?}"),
        }
        assert_eq!(index.span(3, keys.len()), RangeSpan::Missing);
    }

    #[test]
    fn caller_index_preserves_row_order_and_duplicates() {
        let rows = [
            MethodCallRef {
                method_idx: 5,
                callee_method_idx: 11,
            },
            MethodCallRef {
                method_idx: 2,
                callee_method_idx: 11,
            },
            MethodCallRef {
                method_idx: 5,
                callee_method_idx: 11,
            },
            MethodCallRef {
                method_idx: 9,
                callee_method_idx: 4,
            },
        ];
        let index = CallerIndex::build(&rows, 16);
        assert_eq!(index.callers(11).collect::<Vec<_>>(), [5, 2, 5]);
        assert_eq!(index.callers(4).collect::<Vec<_>>(), [9]);
        assert_eq!(index.callers(3).collect::<Vec<_>>(), Vec::<u32>::new());
        // Empty relations produce an empty index.
        let empty = CallerIndex::build(&[], 0);
        assert_eq!(empty.callers(0).collect::<Vec<_>>(), Vec::<u32>::new());
    }

    #[test]
    fn caller_index_supports_non_u16_method_tables() {
        let rows = [MethodCallRef {
            method_idx: 70_000,
            callee_method_idx: 3,
        }];
        let index = CallerIndex::build(&rows, 70_001);
        assert_eq!(index.callers(3).collect::<Vec<_>>(), [70_000]);
    }
}
