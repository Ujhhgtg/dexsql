//! DEX/APK loading and compact derived indexes.
//!
//! The original engine keeps DEX metadata in column-oriented stores.  This
//! first implementation keeps the same important boundary: all references are
//! numeric IDs into per-file pools, and strings/descriptors are materialized
//! only when a query asks for them.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use dexsql_mutf8::decode as decode_mutf8;
use memmap2::MmapOptions;
use rustc_hash::FxHashMap;
use sha2::{Digest, Sha256};

pub mod decode;
pub mod annotations;
pub mod metadata;

pub use metadata::MetaQuery;
use metadata::MetadataIndexes;

#[derive(Debug, Clone)]
pub struct LoadError(pub String);

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for LoadError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberType {
    Int,
    Long,
}

#[derive(Debug, Clone)]
pub struct MethodNumberRef {
    pub method_idx: u32,
    pub opcode: u8,
    pub number_type: NumberType,
    pub long_value: i64,
    pub double_value: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
pub struct MethodStringRef {
    pub method_idx: u32,
    pub string_idx: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct MethodCallRef {
    pub method_idx: u32,
    pub callee_method_idx: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct MethodFieldRef {
    pub method_idx: u32,
    pub field_idx: u32,
    pub opcode: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct MethodTypeRef {
    pub method_idx: u32,
    pub type_idx: u32,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub descriptor_idx: u32,
}

#[derive(Debug, Clone)]
pub struct ProtoInfo {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters: Vec<u16>,
}

#[derive(Debug, Clone, Copy)]
pub struct FieldInfo {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct MethodInfo {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct DefinedField {
    pub field_idx: u32,
    pub access_flags: u32,
    pub is_static: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct DefinedMethod {
    pub method_idx: u32,
    pub access_flags: u32,
    pub code_off: u32,
    pub is_direct: bool,
}

#[derive(Debug, Clone)]
pub struct ClassInfo {
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: Option<u32>,
    pub interfaces: Vec<u16>,
    pub source_file_idx: Option<u32>,
    pub class_data_off: u32,
    pub fields: Vec<DefinedField>,
    pub methods: Vec<DefinedMethod>,
}

#[derive(Debug, Clone)]
pub struct CodeItem {
    pub code_off: u32,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns: Vec<u16>,
    pub opcode_count: u32,
    /// The encoded try table, in code-unit addresses relative to `insns[0]`.
    pub tries: Vec<TryItem>,
    /// Decoded catch-handler lists. `TryItem::handler_off` indexes this by the
    /// byte offset used in the DEX encoded_catch_handler_list.
    pub catch_handlers: Vec<CatchHandlerSet>,
}

#[derive(Debug, Clone)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u32,
    pub handler_off: u16,
}

#[derive(Debug, Clone)]
pub struct CatchHandlerSet {
    pub offset: u32,
    pub handlers: Vec<CatchHandler>,
}

#[derive(Debug, Clone)]
pub struct CatchHandler {
    pub type_idx: Option<u32>,
    pub addr: u32,
}

#[derive(Debug, Clone)]
pub struct DebugInfoRow {
    pub debug_info_off: u32,
    pub line_start: u32,
    pub parameters_size: u32,
}

#[derive(Debug, Clone)]
pub struct DebugParameterRow {
    pub ordinal: u32,
    pub name_idx: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DebugPositionRow {
    pub ordinal: u32,
    pub address: u32,
    pub line: i32,
    pub source_file_idx: Option<u32>,
    pub prologue_end: bool,
    pub epilogue_begin: bool,
}

#[derive(Debug, Clone)]
pub struct DebugLocalRow {
    pub ordinal: u32,
    pub address: u32,
    pub event: String,
    pub register_num: u32,
    pub name_idx: Option<u32>,
    pub type_idx: Option<u32>,
    pub signature_idx: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DebugOpcodeRow {
    pub ordinal: u32,
    pub opcode_off: u32,
    pub opcode_end_off: u32,
    pub opcode: u32,
    pub address: u32,
    pub line: i32,
    pub address_diff: Option<u32>,
    pub line_diff: Option<i32>,
    pub register_num: Option<u32>,
    pub name_idx: Option<u32>,
    pub type_idx: Option<u32>,
    pub signature_idx: Option<u32>,
    pub source_file_idx: Option<u32>,
    pub emits_position: bool,
    pub emits_local: bool,
}

#[derive(Debug, Clone)]
pub struct DebugRows {
    pub info: DebugInfoRow,
    pub parameters: Vec<DebugParameterRow>,
    pub positions: Vec<DebugPositionRow>,
    pub locals: Vec<DebugLocalRow>,
    pub opcodes: Vec<DebugOpcodeRow>,
}

#[derive(Debug, Clone)]
pub struct DexFile {
    pub file_id: u32,
    pub source_path: PathBuf,
    pub entry_name: String,
    /// Raw DEX payload. Dropped after parsing when no lazy consumer
    /// (code items, debug info, decode views) can touch it, mirroring the
    /// reference's mmap-backed lifetime.
    pub bytes: Option<Arc<Vec<u8>>>,
    /// Original payload length; kept after the payload is dropped because
    /// the dex_files relation exposes it.
    pub byte_len: u64,
    pub dex_version: String,
    pub checksum: u32,
    pub signature_hex: String,
    pub header_size: u32,
    pub endian_tag: u32,
    pub map_off: u32,
    pub string_ids_off: u32,
    pub type_ids_off: u32,
    pub proto_ids_off: u32,
    pub field_ids_off: u32,
    pub method_ids_off: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
    pub strings: Vec<String>,
    pub string_lookup: HashMap<String, u32>,
    pub types: Vec<TypeInfo>,
    pub protos: Vec<ProtoInfo>,
    pub fields: Vec<FieldInfo>,
    pub methods: Vec<MethodInfo>,
    /// Access flags of defined methods indexed by method id; u32::MAX when
    /// the method id is not defined by this DEX (external reference).
    pub method_access_flags: Vec<u32>,
    pub methods_by_name: FxHashMap<u32, Vec<u32>>,
    pub methods_by_param_count: FxHashMap<u32, Vec<u32>>,
    pub methods_by_class: FxHashMap<u32, Vec<u32>>,
    pub methods_by_return: FxHashMap<u32, Vec<u32>>,
    pub fields_by_name: FxHashMap<u32, Vec<u32>>,
    /// Precomputed canonical descriptors used by query scans. Building these once
    /// avoids formatting a descriptor for every row of every repeated query.
    pub method_descriptors: Arc<OnceLock<Vec<String>>>,
    pub field_descriptors: Arc<OnceLock<Vec<String>>>,
    /// Cached debug streams make debug relations available from a compact
    /// query cache without retaining the original DEX byte payload.
    pub debug_rows_cache: Arc<OnceLock<Vec<Option<DebugRows>>>>,
    /// Zero for methods without code; built once from class data when a lazy
    /// code/debug/opcode consumer first needs a method's code offset.
    pub method_code_offsets: Arc<OnceLock<Vec<u32>>>,
    pub classes: Vec<ClassInfo>,
    /// Method indices ordered by composed method descriptor using the
    /// dialect's UTF-16 code-unit text order; built lazily for
    /// ORDER BY descriptor top-k queries.
    pub method_descriptor_order: Arc<OnceLock<Vec<u32>>>,
    /// String-pool ranks under the UTF-16 text order: rank[s] is the
    /// position of string s among the sorted pool.
    pub string_utf16_ranks: Arc<OnceLock<Vec<u32>>>,
    /// Indices into `classes` ordered by ascending `class_idx`; the
    /// class-data relations report rows in this order (not class_def order).
    pub classes_by_idx_order: Vec<u32>,
    pub classes_by_superclass: FxHashMap<u32, Vec<u32>>,
    pub classes_by_descriptor: FxHashMap<u32, Vec<u32>>,
    /// Eager code items indexed by method id. Empty for lazy/index-only
    /// loads; absence of eager code must be resolved through
    /// [`DexFile::decode_code_item`] when raw bytes were retained.
    pub code_items: Vec<Option<CodeItem>>,
    pub method_strings: Vec<MethodStringRef>,
    pub method_strings_by_string: FxHashMap<u32, Vec<u32>>,
    pub method_numbers: Vec<MethodNumberRef>,
    pub method_numbers_by_value: HashMap<i64, Vec<u32>>,
    pub method_number_rows_by_value: FxHashMap<i64, Vec<usize>>,
    pub method_calls: Vec<MethodCallRef>,
    pub method_field_accesses: Vec<MethodFieldRef>,
    pub method_used_types: Vec<MethodTypeRef>,
    /// Lazily-built metadata indexes over the relation vectors above.
    pub meta: MetadataIndexes,
}

impl DexFile {
    /// Raw DEX bytes; empty after a parse-only load dropped the payload.
    pub fn raw(&self) -> &[u8] {
        self.bytes.as_deref().map(|b| b.as_slice()).unwrap_or(&[])
    }

    /// Drop the raw DEX payload. Only valid when no lazy byte consumer
    /// (code items, debug info, decode rendering) remains possible.
    pub fn drop_raw_bytes(&mut self) {
        self.bytes = None;
    }

    /// Method indices ordered by composed descriptor using the dialect's
    /// UTF-16 code-unit text order; built lazily for ORDER BY descriptor
    /// top-k queries.
    pub fn ordered_method_descriptors(&self) -> &Vec<u32> {
        self.method_descriptor_order.get_or_init(|| {
            // The composed "class->name(params)ret" order equals the
            // (class, name, params..., return) pool-string-rank tuple order
            // for well-formed descriptors, so sorting never materializes a
            // descriptor string.
            let ranks = self.utf16_string_ranks();
            let mut order: Vec<u32> = (0..self.methods.len() as u32).collect();
            order.sort_by(|&a, &b| self.method_order_key_cmp(a, b, ranks));
            order
        })
    }

    fn utf16_string_ranks(&self) -> &Vec<u32> {
        self.string_utf16_ranks.get_or_init(|| {
            // Well-formed DEX files sort string_ids by UTF-16 code units, so
            // the identity is the rank map; only fall back to a full sort for
            // inputs that violate the spec.
            let sorted = self
                .strings
                .windows(2)
                .all(|pair| utf16_cmp(&pair[0], &pair[1]) != std::cmp::Ordering::Greater);
            if sorted {
                return (0..self.strings.len() as u32).collect();
            }
            let mut order: Vec<u32> = (0..self.strings.len() as u32).collect();
            order.sort_by(|&a, &b| utf16_cmp(&self.strings[a as usize], &self.strings[b as usize]));
            let mut ranks = vec![0u32; self.strings.len()];
            for (position, &string_idx) in order.iter().enumerate() {
                ranks[string_idx as usize] = position as u32;
            }
            ranks
        })
    }

    /// Compare two methods by their composed descriptor order using
    /// pool-string ranks (allocation-free).
    fn method_order_key_cmp(&self, a: u32, b: u32, ranks: &[u32]) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let rank = |string_idx: u32| ranks.get(string_idx as usize).copied().unwrap_or(0);
        let method_a = &self.methods[a as usize];
        let method_b = &self.methods[b as usize];
        let class_a = rank(self.types[method_a.class_idx as usize].descriptor_idx);
        let class_b = rank(self.types[method_b.class_idx as usize].descriptor_idx);
        if class_a != class_b {
            return class_a.cmp(&class_b);
        }
        let name_a = rank(method_a.name_idx);
        let name_b = rank(method_b.name_idx);
        if name_a != name_b {
            return name_a.cmp(&name_b);
        }
        let proto_a = &self.protos[method_a.proto_idx as usize];
        let proto_b = &self.protos[method_b.proto_idx as usize];
        for (&ta, &tb) in proto_a.parameters.iter().zip(proto_b.parameters.iter()) {
            let ra = rank(self.types[ta as usize].descriptor_idx);
            let rb = rank(self.types[tb as usize].descriptor_idx);
            if ra != rb {
                return ra.cmp(&rb);
            }
        }
        match proto_a.parameters.len().cmp(&proto_b.parameters.len()) {
            Ordering::Equal => {}
            other => return other,
        }
        let ret_a = rank(self.types[proto_a.return_type_idx as usize].descriptor_idx);
        let ret_b = rank(self.types[proto_b.return_type_idx as usize].descriptor_idx);
        ret_a.cmp(&ret_b)
    }

    pub fn string(&self, idx: u32) -> &str {
        self.strings
            .get(idx as usize)
            .map(String::as_str)
            .unwrap_or("")
    }

    /// Resolve a string-pool value without allocating a second `String` for
    /// every DEX string.  DEX string ids are sorted, so the common path is a
    /// binary search; the linear fallback preserves correctness for pools
    /// whose UTF-16 ordering differs from Rust scalar ordering.
    pub fn find_string_idx(&self, value: &str) -> Option<u32> {
        self.strings
            .binary_search_by(|item| item.as_str().cmp(value))
            .ok()
            .map(|idx| idx as u32)
            .or_else(|| {
                self.strings
                    .iter()
                    .position(|item| item == value)
                    .map(|idx| idx as u32)
            })
    }

    pub fn type_descriptor(&self, idx: u32) -> &str {
        self.types
            .get(idx as usize)
            .map(|t| self.string(t.descriptor_idx))
            .unwrap_or("")
    }

    pub fn method_class(&self, method_idx: u32) -> &str {
        self.methods
            .get(method_idx as usize)
            .map(|m| self.type_descriptor(m.class_idx as u32))
            .unwrap_or("")
    }

    pub fn method_name(&self, method_idx: u32) -> &str {
        self.methods
            .get(method_idx as usize)
            .map(|m| self.string(m.name_idx))
            .unwrap_or("")
    }

    pub fn method_descriptor_ref(&self, method_idx: u32) -> &str {
        self.method_descriptors
            .get_or_init(|| {
                (0..self.methods.len() as u32)
                    .map(|idx| build_method_descriptor(self, idx))
                    .collect()
            })
            .get(method_idx as usize)
            .map(String::as_str)
            .unwrap_or("")
    }

    pub fn method_descriptor(&self, method_idx: u32) -> String {
        self.method_descriptor_ref(method_idx).to_owned()
    }

    /// Build one descriptor without populating the cache for every method in
    /// the DEX.  Top-k query paths use this after a selective predicate has
    /// reduced the candidate set to a handful of rows.
    pub fn method_descriptor_direct(&self, method_idx: u32) -> String {
        build_method_descriptor(self, method_idx)
    }

    /// Return the reference CLI's compact opcode projection for a defined
    /// method.  `None` means the method has no code item (external/abstract),
    /// which is rendered as SQL NULL in the methods relation.
    pub fn method_opcode_count(&self, method_idx: u32) -> Option<usize> {
        // A full prepare load materializes at least one code item and uses
        // `None` to represent external/abstract methods.  Do not fall back to
        // the O(classes × methods) lookup for those None slots; that fallback
        // remains necessary only for lazy query loads.
        if self.code_items.iter().any(Option::is_some) {
            return self
                .code_items
                .get(method_idx as usize)
                .and_then(Option::as_ref)
                .map(|code| code.opcode_count as usize);
        }
        self.decode_code_item(method_idx)
            .ok()
            .flatten()
            .map(|code| code.opcode_count as usize)
    }

    /// Access flags of a method defined in this DEX, or None for an external
    /// method id that has no class_data entry.
    pub fn method_access_flags(&self, method_idx: u32) -> Option<u32> {
        self.method_access_flags
            .get(method_idx as usize)
            .copied()
            .filter(|flags| *flags != u32::MAX)
    }

    pub fn method_opcode_summary(&self, method_idx: u32) -> Option<(usize, String)> {
        let decoded;
        let code = match self
            .code_items
            .get(method_idx as usize)
            .and_then(Option::as_ref)
        {
            Some(code) => code,
            None => {
                decoded = self.decode_code_item(method_idx).ok().flatten()?;
                &decoded
            }
        };
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut pc = 0usize;
        let mut count = 0usize;
        let mut hex = String::with_capacity(code.opcode_count as usize * 3);
        while pc < code.insns.len() {
            let opcode = (code.insns[pc] & 0xff) as u8;
            let width = opcode_width(opcode, &code.insns, pc).max(1);
            if !is_payload_opcode(&code.insns, pc) {
                if count != 0 {
                    hex.push(' ');
                }
                hex.push(HEX[(opcode >> 4) as usize] as char);
                hex.push(HEX[(opcode & 15) as usize] as char);
                count += 1;
            }
            pc = pc.saturating_add(width);
        }
        Some((count, hex))
    }

    pub fn field_descriptor_ref(&self, field_idx: u32) -> &str {
        self.field_descriptors
            .get_or_init(|| {
                (0..self.fields.len() as u32)
                    .map(|idx| build_field_descriptor(self, idx))
                    .collect()
            })
            .get(field_idx as usize)
            .map(String::as_str)
            .unwrap_or("")
    }

    pub fn field_descriptor(&self, field_idx: u32) -> String {
        self.field_descriptor_ref(field_idx).to_owned()
    }

    /// Build one field descriptor without populating the cache for every
    /// field in the DEX.
    pub fn field_descriptor_direct(&self, field_idx: u32) -> String {
        build_field_descriptor(self, field_idx)
    }

    pub fn class_for_method(&self, method_idx: u32) -> Option<&ClassInfo> {
        self.classes
            .iter()
            .find(|c| c.methods.iter().any(|m| m.method_idx == method_idx))
    }

    /// Parse one code item on demand. Decode mode leaves the `code_items`
    /// vector empty so selecting a single method does not walk every method's
    /// instruction stream during APK startup.
    pub fn decode_code_item(&self, method_idx: u32) -> Result<Option<CodeItem>, LoadError> {
        let offsets = self.method_code_offsets.get_or_init(|| {
            let mut offsets = vec![0; self.methods.len()];
            for class in &self.classes {
                for method in &class.methods {
                    if let Some(offset) = offsets.get_mut(method.method_idx as usize) {
                        *offset = method.code_off;
                    }
                }
            }
            offsets
        });
        let code_off = offsets.get(method_idx as usize).copied().unwrap_or(0);
        if code_off == 0 {
            return Ok(None);
        }
        parse_code_item(self.raw(), code_off as usize, true).map(Some)
    }

    /// Decode one DEX `debug_info_item` into the five query-facing debug
    /// relations. Debug opcodes are retained as raw byte offsets so callers
    /// can audit malformed/partial streams without reparsing the bytes.
    pub fn debug_rows(&self, method_idx: u32) -> Result<Option<DebugRows>, LoadError> {
        if let Some(cached) = self
            .debug_rows_cache
            .get()
            .and_then(|rows| rows.get(method_idx as usize))
        {
            return Ok(cached.clone());
        }
        self.decode_debug_rows_uncached(method_idx)
    }

    fn decode_debug_rows_uncached(&self, method_idx: u32) -> Result<Option<DebugRows>, LoadError> {
        let code_owned = match self
            .code_items
            .get(method_idx as usize)
            .and_then(Option::as_ref)
        {
            Some(code) => code.clone(),
            None => match self.decode_code_item(method_idx)? {
                Some(code) => code,
                None => return Ok(None),
            },
        };
        if code_owned.debug_info_off == 0 {
            return Ok(None);
        }
        parse_debug_info(self.raw(), code_owned.debug_info_off)
            .map(Some)
            .map_err(|e| LoadError(format!("invalid debug info for method {method_idx}: {e}")))
    }

    /// Return the row count for a metadata table whose rows are represented by
    /// the compact parser, or can be counted directly from the DEX map/list
    /// structures.  Query's `count(*)` fast path uses this without materializing
    /// relation rows, so exposing these counts is cheap even for large APKs.
    pub fn table_count(&self, table: &str) -> Option<usize> {
        let direct = match table {
            "dex_files" => return Some(1),
            "strings" => Some(self.strings.len()),
            "type_ids" | "types" => Some(self.types.len()),
            "proto_ids" | "protos" => Some(self.protos.len()),
            "proto_params" => Some(self.protos.iter().map(|p| p.parameters.len()).sum()),
            "field_ids" | "fields" => Some(self.fields.len()),
            "method_ids" | "methods" | "method_opcodes" => Some(self.methods.len()),
            "class_defs" | "classes" => Some(self.classes.len()),
            "map_items" => Some(self.map_item_count()),
            "id_items" => Some(self.map_sum(0x0001, 0x0008)),
            "type_lists" => Some(self.map_count(0x1001)),
            "type_list_entries" => Some(self.type_list_entry_count()),
            "class_interfaces" => Some(self.classes.iter().map(|c| c.interfaces.len()).sum()),
            "class_data_items" => Some(
                self.classes
                    .iter()
                    .filter(|c| c.class_data_off != 0)
                    .count(),
            ),
            "class_fields" | "class_data_fields" => {
                Some(self.classes.iter().map(|c| c.fields.len()).sum())
            }
            "class_methods" | "class_data_methods" => {
                Some(self.classes.iter().map(|c| c.methods.len()).sum())
            }
            "class_static_values" => Some(self.class_static_value_count()),
            "code_items" => Some(self.code_items.iter().filter(|c| c.is_some()).count()),
            "try_items" => Some(
                self.code_items
                    .iter()
                    .flatten()
                    .map(|c| c.tries.len())
                    .sum(),
            ),
            "catch_handlers" => Some(
                self.code_items
                    .iter()
                    .flatten()
                    .flat_map(|c| c.catch_handlers.iter())
                    .map(|s| s.handlers.len())
                    .sum(),
            ),
            "method_handles" => Some(self.map_count(0x0008)),
            "call_sites" => Some(self.map_count(0x0007)),
            "encoded_arrays" => Some(self.map_count(0x2005)),
            "encoded_array_values" => Some(self.encoded_array_value_count()),
            "encoded_array_owners" => Some(self.encoded_array_owner_count()),
            "call_site_args" => Some(self.call_site_arg_count()),
            "annotation_directories" => Some(self.annotation_directory_count()),
            "annotation_directory_entries" => Some(self.annotation_directory_entry_count()),
            "annotation_sets" => Some(self.annotation_set_count()),
            "annotation_set_entries" => Some(self.annotation_set_entry_count()),
            "annotation_set_ref_lists" => Some(self.map_count(0x1002)),
            "annotation_set_refs" => Some(self.annotation_set_ref_count()),
            "annotations" => Some(self.map_count(0x2004)),
            "annotation_elements" => Some(self.annotation_element_count()),
            "annotation_values" => Some(self.annotation_value_count()),
            "annotation_elements_resolved" => Some(self.annotation_resolved_element_count()),
            "debug_info" => Some(self.debug_table_count(table)),
            "debug_parameters" => Some(self.debug_table_count(table)),
            "debug_positions" => Some(self.debug_table_count(table)),
            "debug_opcodes" => Some(self.debug_table_count(table)),
            "debug_locals" => Some(self.debug_table_count(table)),
            "hiddenapi_flags" => Some(self.map_count(0xf000)),
            "method_refs" => Some(
                self.method_calls.len()
                    + self.method_strings.len()
                    + self.method_field_accesses.len()
                    + self.method_used_types.len(),
            ),
            "method_numbers" | "method_using_numbers" => Some(self.method_numbers.len()),
            "method_strings" => Some(self.method_strings.len()),
            "method_calls" => Some(self.method_calls.len()),
            "method_field_accesses" => Some(self.method_field_accesses.len()),
            "method_used_types" => Some(self.method_used_types.len()),
            _ => None,
        };
        direct
    }

    fn debug_table_count(&self, table: &str) -> usize {
        if let Some(rows) = self.debug_rows_cache.get() {
            return rows
                .iter()
                .flatten()
                .map(|debug| match table {
                    "debug_info" => 1,
                    "debug_parameters" => debug.parameters.len(),
                    "debug_positions" => debug.positions.len(),
                    "debug_opcodes" => debug.opcodes.len(),
                    "debug_locals" => debug.locals.len(),
                    _ => 0,
                })
                .sum();
        }
        match table {
            "debug_info" => self
                .code_items
                .iter()
                .flatten()
                .filter(|c| c.debug_info_off != 0)
                .count(),
            "debug_parameters" => self.debug_parameter_count(),
            "debug_positions" => self.debug_event_count(true),
            "debug_opcodes" => self.debug_event_count(false),
            "debug_locals" => self.debug_local_count(),
            _ => 0,
        }
    }

    fn map_count(&self, type_code: u16) -> usize {
        let bytes = self.raw();
        let Some(size) = read_u32(bytes, self.map_off as usize).ok() else {
            return 0;
        };
        let mut count = 0usize;
        for i in 0..size as usize {
            let off = self.map_off as usize + 4 + i * 12;
            let Some(code) = read_u16(bytes, off).ok() else {
                break;
            };
            if code == type_code {
                count = read_u32(bytes, off + 4).unwrap_or(0) as usize;
                break;
            }
        }
        count
    }

    fn map_item_count(&self) -> usize {
        read_u32(self.raw(), self.map_off as usize)
            .map(|n| n as usize)
            .unwrap_or(0)
    }

    fn map_sum(&self, first: u16, last: u16) -> usize {
        let bytes = self.raw();
        let size = read_u32(bytes, self.map_off as usize).unwrap_or(0) as usize;
        (0..size)
            .filter_map(|i| {
                let off = self.map_off as usize + 4 + i * 12;
                let code = read_u16(bytes, off).ok()?;
                (code >= first && code <= last)
                    .then(|| read_u32(bytes, off + 4).unwrap_or(0) as usize)
            })
            .sum()
    }

    fn type_list_entry_count(&self) -> usize {
        let bytes = self.raw();
        let size = read_u32(bytes, self.map_off as usize).unwrap_or(0) as usize;
        let mut total = 0;
        for i in 0..size {
            let off = self.map_off as usize + 4 + i * 12;
            if read_u16(bytes, off).ok() == Some(0x1001) {
                let n = read_u32(bytes, off + 4).unwrap_or(0) as usize;
                let mut pos = read_u32(bytes, off + 8).unwrap_or(0) as usize;
                for _ in 0..n {
                    let len = read_u32(bytes, pos).unwrap_or(0) as usize;
                    total += len;
                    pos = pos.saturating_add(4 + ((len * 2 + 3) & !3));
                }
            }
        }
        total
    }

    fn map_offsets(&self, type_code: u16) -> Vec<usize> {
        let bytes = self.raw();
        let size = read_u32(bytes, self.map_off as usize).unwrap_or(0) as usize;
        let mut out = Vec::new();
        for i in 0..size {
            let off = self.map_off as usize + 4 + i * 12;
            if read_u16(bytes, off).ok() == Some(type_code) {
                let n = read_u32(bytes, off + 4).unwrap_or(0) as usize;
                let base = read_u32(bytes, off + 8).unwrap_or(0) as usize;
                if matches!(type_code, 0x1002 | 0x1003) {
                    let mut pos = base;
                    for _ in 0..n {
                        out.push(pos);
                        let len = read_u32(bytes, pos).unwrap_or(0) as usize;
                        pos = pos.saturating_add(4 + len * 4);
                    }
                } else if matches!(type_code, 0x2004 | 0x2005) {
                    let mut pos = base;
                    for _ in 0..n {
                        out.push(pos);
                        pos = if type_code == 0x2005 {
                            Self::encoded_array_end(bytes, pos)
                        } else {
                            Self::annotation_end(bytes, pos)
                        };
                    }
                } else if type_code == 0x2006 {
                    // annotation_directory_item has a fixed 16-byte header
                    // followed by variable entry arrays.  Its actual row
                    // count is derived from class_defs below; this map walk is
                    // retained for any direct users of map offsets.
                    out.extend((0..n).map(|j| base + j * 16));
                } else {
                    out.extend((0..n).map(|j| base + j));
                }
            }
        }
        out
    }

    fn class_static_value_count(&self) -> usize {
        let bytes = self.raw();
        let mut total = 0;
        for i in 0..self.classes.len() {
            let off = self.class_defs_off as usize + i * 32 + 28;
            let Some(array_off) = read_u32(bytes, off).ok().filter(|v| *v != 0) else {
                continue;
            };
            total += read_uleb(bytes, array_off as usize)
                .map(|(n, _)| n as usize)
                .unwrap_or(0);
        }
        total
    }

    fn encoded_array_owner_count(&self) -> usize {
        // The current DEX model's encoded-array owners are class static-value
        // arrays.  Call-site owners are added from the call-site map when
        // present; both references are one row per owner.
        let mut total = 0;
        for i in 0..self.classes.len() {
            let off = self.class_defs_off as usize + i * 32 + 28;
            if read_u32(self.raw(), off).ok().is_some_and(|v| v != 0) {
                total += 1;
            }
        }
        total + self.map_count(0x0007)
    }

    fn encoded_value_count(bytes: &[u8], mut pos: usize, include_root: bool) -> (usize, usize) {
        let Some(header) = bytes.get(pos).copied() else {
            return (0, pos);
        };
        pos += 1;
        let value_type = header & 0x1f;
        let value_arg = (header >> 5) as usize;
        let mut count = usize::from(include_root);
        match value_type {
            0x1c => {
                let Ok((n, mut next)) = read_uleb(bytes, pos) else {
                    return (count, pos);
                };
                for _ in 0..n {
                    let (nested, end) = Self::encoded_value_count(bytes, next, true);
                    count += nested;
                    next = end;
                }
                (count, next)
            }
            0x1d => {
                let Ok((_, mut next)) = read_uleb(bytes, pos) else {
                    return (count, pos);
                };
                let Ok((n, end)) = read_uleb(bytes, next) else {
                    return (count, next);
                };
                next = end;
                for _ in 0..n {
                    let Ok((_, end_name)) = read_uleb(bytes, next) else {
                        break;
                    };
                    let (nested, end_value) = Self::encoded_value_count(bytes, end_name, true);
                    count += nested;
                    next = end_value;
                }
                (count, next)
            }
            0x1e | 0x1f => (count, pos),
            _ => {
                // All scalar encoded values carry value_arg+1 little-endian
                // bytes, except the zero-width boolean/null forms handled
                // above.  The parser only needs to advance to the next value.
                (count, pos.saturating_add(value_arg + 1))
            }
        }
    }

    fn encoded_array_end(bytes: &[u8], base: usize) -> usize {
        let Ok((n, mut pos)) = read_uleb(bytes, base) else {
            return base;
        };
        for _ in 0..n {
            let (_, end) = Self::encoded_value_count(bytes, pos, false);
            pos = end;
        }
        pos
    }

    fn annotation_end(bytes: &[u8], base: usize) -> usize {
        let mut pos = base.saturating_add(1); // visibility byte
        let Ok((_, next)) = read_uleb(bytes, pos) else {
            return pos;
        };
        pos = next;
        let Ok((n, next)) = read_uleb(bytes, pos) else {
            return pos;
        };
        pos = next;
        for _ in 0..n {
            let Ok((_, next)) = read_uleb(bytes, pos) else {
                return pos;
            };
            pos = next;
            let (_, next) = Self::encoded_value_count(bytes, pos, false);
            pos = next;
        }
        pos
    }

    fn encoded_array_value_count(&self) -> usize {
        let mut total = 0;
        for base in self.map_offsets(0x2005) {
            let Ok((n, mut pos)) = read_uleb(self.raw(), base) else {
                continue;
            };
            for _ in 0..n {
                let (count, end) = Self::encoded_value_count(self.raw(), pos, true);
                total += count;
                pos = end;
            }
        }
        total
    }

    fn call_site_arg_count(&self) -> usize {
        let bytes = self.raw();
        let size = self.map_count(0x0007);
        if size == 0 {
            return 0;
        }
        // Locate the call_site_id map entry and decode each encoded-array
        // offset (one u32 per call site).
        let map_size = read_u32(bytes, self.map_off as usize).unwrap_or(0) as usize;
        for i in 0..map_size {
            let m = self.map_off as usize + 4 + i * 12;
            if read_u16(bytes, m).ok() != Some(0x0007) {
                continue;
            }
            let base = read_u32(bytes, m + 8).unwrap_or(0) as usize;
            return (0..size)
                .map(|j| {
                    let off = read_u32(bytes, base + j * 4).unwrap_or(0) as usize;
                    read_uleb(bytes, off).map(|(n, _)| n as usize).unwrap_or(0)
                })
                .sum();
        }
        0
    }

    fn annotation_directory_count(&self) -> usize {
        // class_def_item.annotations_off is at byte offset +20.  DexSQL's
        // annotation_directories relation is keyed by owning class, so its
        // row count follows non-zero class offsets rather than the map's raw
        // annotation_directory_item count.
        (0..self.classes.len())
            .filter(|i| {
                read_u32(self.raw(), self.class_defs_off as usize + *i * 32 + 20)
                    .ok()
                    .is_some_and(|v| v != 0)
            })
            .count()
    }

    fn annotation_directory_entry_count(&self) -> usize {
        let bytes = self.raw();
        let mut total = 0;
        for i in 0..self.classes.len() {
            let m = self.class_defs_off as usize + i * 32 + 20;
            let Some(base) = read_u32(bytes, m).ok().filter(|v| *v != 0) else {
                continue;
            };
            let fields = read_u32(bytes, base as usize + 4).unwrap_or(0) as usize;
            let methods = read_u32(bytes, base as usize + 8).unwrap_or(0) as usize;
            let params = read_u32(bytes, base as usize + 12).unwrap_or(0) as usize;
            total += fields + methods + params;
        }
        total
    }

    fn annotation_set_count(&self) -> usize {
        let bytes = self.raw();
        let mut offsets = Vec::new();
        for class in &self.classes {
            let class_def = self.class_defs_off as usize + class.class_def_idx as usize * 32;
            let Some(dir_off) = read_u32(bytes, class_def + 20).ok().filter(|v| *v != 0) else {
                continue;
            };
            let dir = dir_off as usize;
            let push = |offsets: &mut Vec<usize>, value: u32| {
                if value != 0 {
                    offsets.push(value as usize);
                }
            };
            push(&mut offsets, read_u32(bytes, dir).unwrap_or(0));
            let fields = read_u32(bytes, dir + 4).unwrap_or(0) as usize;
            let methods = read_u32(bytes, dir + 8).unwrap_or(0) as usize;
            let params = read_u32(bytes, dir + 12).unwrap_or(0) as usize;
            let mut pos = dir + 16;
            for _ in 0..fields {
                pos = pos.saturating_add(4);
                push(&mut offsets, read_u32(bytes, pos).unwrap_or(0));
                pos = pos.saturating_add(4);
            }
            for _ in 0..methods {
                pos = pos.saturating_add(4);
                push(&mut offsets, read_u32(bytes, pos).unwrap_or(0));
                pos = pos.saturating_add(4);
            }
            for _ in 0..params {
                pos = pos.saturating_add(4);
                let refs = read_u32(bytes, pos).unwrap_or(0) as usize;
                pos = pos.saturating_add(4);
                let n = read_u32(bytes, refs).unwrap_or(0) as usize;
                for j in 0..n {
                    push(&mut offsets, read_u32(bytes, refs + 4 + j * 4).unwrap_or(0));
                }
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets.len()
    }

    fn annotation_set_entry_count(&self) -> usize {
        self.map_offsets(0x1003)
            .into_iter()
            .map(|off| read_u32(self.raw(), off).unwrap_or(0) as usize)
            .sum()
    }

    fn annotation_set_ref_count(&self) -> usize {
        self.map_offsets(0x1002)
            .into_iter()
            .map(|off| read_u32(self.raw(), off).unwrap_or(0) as usize)
            .sum()
    }

    fn append_annotation_set(bytes: &[u8], set_off: usize, out: &mut Vec<usize>) {
        if set_off == 0 {
            return;
        }
        let n = read_u32(bytes, set_off).unwrap_or(0) as usize;
        for i in 0..n {
            if let Ok(off) = read_u32(bytes, set_off + 4 + i * 4) {
                out.push(off as usize);
            }
        }
    }

    fn annotation_instance_offsets(&self) -> Vec<usize> {
        let bytes = self.raw();
        let mut out = Vec::new();
        for i in 0..self.classes.len() {
            let class_def = self.class_defs_off as usize + i * 32;
            let Some(dir_off) = read_u32(bytes, class_def + 20).ok().filter(|v| *v != 0) else {
                continue;
            };
            let dir = dir_off as usize;
            Self::append_annotation_set(
                bytes,
                read_u32(bytes, dir).unwrap_or(0) as usize,
                &mut out,
            );
            let fields = read_u32(bytes, dir + 4).unwrap_or(0) as usize;
            let methods = read_u32(bytes, dir + 8).unwrap_or(0) as usize;
            let params = read_u32(bytes, dir + 12).unwrap_or(0) as usize;
            let mut pos = dir + 16;
            for _ in 0..fields {
                pos += 4;
                let set = read_u32(bytes, pos).unwrap_or(0) as usize;
                pos += 4;
                Self::append_annotation_set(bytes, set, &mut out);
            }
            for _ in 0..methods {
                pos += 4;
                let set = read_u32(bytes, pos).unwrap_or(0) as usize;
                pos += 4;
                Self::append_annotation_set(bytes, set, &mut out);
            }
            for _ in 0..params {
                pos += 4;
                let refs = read_u32(bytes, pos).unwrap_or(0) as usize;
                pos += 4;
                let n = read_u32(bytes, refs).unwrap_or(0) as usize;
                for j in 0..n {
                    let set = read_u32(bytes, refs + 4 + j * 4).unwrap_or(0) as usize;
                    Self::append_annotation_set(bytes, set, &mut out);
                }
            }
        }
        out
    }

    fn annotation_value_count(&self) -> usize {
        let bytes = self.raw();
        self.annotation_instance_offsets()
            .into_iter()
            .map(|base| {
                let pos = base.saturating_add(1);
                let Ok((_, pos)) = read_uleb(bytes, pos) else {
                    return 0;
                };
                let Ok((n, mut pos)) = read_uleb(bytes, pos) else {
                    return 0;
                };
                let mut total = 0;
                for _ in 0..n {
                    let Ok((_, name_end)) = read_uleb(bytes, pos) else {
                        break;
                    };
                    let (count, end) = Self::encoded_value_count(bytes, name_end, true);
                    total += count;
                    pos = end;
                }
                total
            })
            .sum()
    }

    fn annotation_resolved_element_count(&self) -> usize {
        let bytes = self.raw();
        self.annotation_instance_offsets()
            .into_iter()
            .map(|base| {
                let pos = base.saturating_add(1);
                let Ok((_, pos)) = read_uleb(bytes, pos) else {
                    return 0;
                };
                read_uleb(bytes, pos)
                    .map(|(n, _)| if n == 0 { 1 } else { n as usize })
                    .unwrap_or(0)
            })
            .sum()
    }

    fn annotation_element_count(&self) -> usize {
        let bytes = self.raw();
        let mut total = 0;
        for base in self.map_offsets(0x2004) {
            let Some(pos) = base.checked_add(1) else {
                continue;
            };
            let Ok((_, pos)) = read_uleb(bytes, pos) else {
                continue;
            };
            let Ok((n, mut pos)) = read_uleb(bytes, pos) else {
                continue;
            };
            for _ in 0..n {
                let Ok((_, name_end)) = read_uleb(bytes, pos) else {
                    break;
                };
                let (count, end) = Self::encoded_value_count(bytes, name_end, true);
                total += count;
                pos = end;
            }
        }
        total
    }

    fn debug_relation_counts(&self) -> [usize; 5] {
        let bytes = self.raw();
        let mut counts = [0usize; 5];
        for code in self.code_items.iter().flatten() {
            if code.debug_info_off == 0 {
                continue;
            }
            counts[0] += 1;
            let Ok((_, mut pos)) = read_uleb(bytes, code.debug_info_off as usize) else {
                continue;
            };
            let Ok((parameters, next)) = read_uleb(bytes, pos) else {
                continue;
            };
            counts[1] += parameters as usize;
            pos = next;
            let mut valid = true;
            for _ in 0..parameters {
                let Ok((_, next)) = read_uleb(bytes, pos) else {
                    valid = false;
                    break;
                };
                pos = next;
            }
            if !valid {
                continue;
            }
            loop {
                let Some(opcode) = bytes.get(pos).copied() else {
                    break;
                };
                pos += 1;
                counts[3] += 1;
                if opcode >= 0x0a {
                    counts[2] += 1;
                }
                if matches!(opcode, 0x03..=0x06) {
                    counts[4] += 1;
                }
                match opcode {
                    0x00 => break,
                    0x01 | 0x05 | 0x06 | 0x09 => {
                        let Ok((_, next)) = read_uleb(bytes, pos) else {
                            break;
                        };
                        pos = next;
                    }
                    0x02 => {
                        let Ok((_, next)) = read_sleb(bytes, pos) else {
                            break;
                        };
                        pos = next;
                    }
                    0x03 => {
                        let mut ok = true;
                        for _ in 0..3 {
                            let Ok((_, next)) = read_uleb(bytes, pos) else {
                                ok = false;
                                break;
                            };
                            pos = next;
                        }
                        if !ok {
                            break;
                        }
                    }
                    0x04 => {
                        let mut ok = true;
                        for _ in 0..4 {
                            let Ok((_, next)) = read_uleb(bytes, pos) else {
                                ok = false;
                                break;
                            };
                            pos = next;
                        }
                        if !ok {
                            break;
                        }
                    }
                    0x07 | 0x08 => {}
                    _ if opcode >= 0x0a => {}
                    _ => break,
                }
            }
        }
        counts
    }

    fn debug_parameter_count(&self) -> usize {
        self.code_items
            .iter()
            .flatten()
            .filter_map(|code| {
                if code.debug_info_off == 0 {
                    return None;
                }
                let (_, pos) = read_uleb(self.raw(), code.debug_info_off as usize).ok()?;
                let (n, _) = read_uleb(self.raw(), pos).ok()?;
                Some(n as usize)
            })
            .sum()
    }

    fn debug_event_count(&self, positions_only: bool) -> usize {
        let bytes = self.raw();
        let mut total = 0;
        for code in self.code_items.iter().flatten() {
            if code.debug_info_off == 0 {
                continue;
            }
            let Ok((_, mut pos)) = read_uleb(bytes, code.debug_info_off as usize) else {
                continue;
            };
            let Ok((params, next)) = read_uleb(bytes, pos) else {
                continue;
            };
            pos = next;
            let mut valid = true;
            for _ in 0..params {
                let Ok((_, next)) = read_uleb(bytes, pos) else {
                    valid = false;
                    break;
                };
                pos = next;
            }
            if !valid {
                continue;
            }
            loop {
                let Some(opcode) = bytes.get(pos).copied() else {
                    break;
                };
                pos += 1;
                let is_position = opcode >= 0x0a;
                // The reference debug_opcodes relation includes END_SEQUENCE;
                // debug_positions only includes explicit line positions.
                if !positions_only || is_position {
                    total += 1;
                }
                match opcode {
                    0x00 => break,
                    0x01 | 0x09 => {
                        let Ok((_, next)) = read_uleb(bytes, pos) else {
                            break;
                        };
                        pos = next;
                    }
                    0x02 => {
                        let Ok((_, next)) = read_sleb(bytes, pos) else {
                            break;
                        };
                        pos = next;
                    }
                    0x03 => {
                        let Ok((_, next)) = read_uleb(bytes, pos) else {
                            break;
                        };
                        pos = next;
                        let Ok((_, next)) = read_uleb(bytes, pos) else {
                            break;
                        };
                        pos = next;
                        let Ok((_, next)) = read_uleb(bytes, pos) else {
                            break;
                        };
                        pos = next;
                    }
                    0x04 => {
                        for _ in 0..4 {
                            let Ok((_, next)) = read_uleb(bytes, pos) else {
                                valid = false;
                                break;
                            };
                            pos = next;
                        }
                        if !valid {
                            break;
                        }
                    }
                    0x05 | 0x06 => {
                        let Ok((_, next)) = read_uleb(bytes, pos) else {
                            break;
                        };
                        pos = next;
                    }
                    0x07 | 0x08 => {}
                    _ if opcode >= 0x0a => {}
                    _ => break,
                }
            }
        }
        total
    }

    fn debug_local_count(&self) -> usize {
        let bytes = self.raw();
        let mut total = 0;
        for code in self.code_items.iter().flatten() {
            if code.debug_info_off == 0 {
                continue;
            }
            let Ok((_, mut pos)) = read_uleb(bytes, code.debug_info_off as usize) else {
                continue;
            };
            let Ok((params, next)) = read_uleb(bytes, pos) else {
                continue;
            };
            pos = next;
            let mut valid = true;
            for _ in 0..params {
                let Ok((_, next)) = read_uleb(bytes, pos) else {
                    valid = false;
                    break;
                };
                pos = next;
            }
            if !valid {
                continue;
            }
            loop {
                let Some(opcode) = bytes.get(pos).copied() else {
                    break;
                };
                pos += 1;
                if matches!(opcode, 0x03..=0x06) {
                    total += 1;
                }
                match opcode {
                    0x00 => break,
                    0x01 | 0x05 | 0x06 | 0x09 => {
                        let Ok((_, next)) = read_uleb(bytes, pos) else {
                            break;
                        };
                        pos = next;
                    }
                    0x02 => {
                        let Ok((_, next)) = read_sleb(bytes, pos) else {
                            break;
                        };
                        pos = next;
                    }
                    0x03 => {
                        for _ in 0..3 {
                            let Ok((_, next)) = read_uleb(bytes, pos) else {
                                valid = false;
                                break;
                            };
                            pos = next;
                        }
                        if !valid {
                            break;
                        }
                    }
                    0x04 => {
                        for _ in 0..4 {
                            let Ok((_, next)) = read_uleb(bytes, pos) else {
                                valid = false;
                                break;
                            };
                            pos = next;
                        }
                        if !valid {
                            break;
                        }
                    }
                    0x07 | 0x08 => {}
                    _ if opcode >= 0x0a => {}
                    _ => break,
                }
            }
        }
        total
    }
}

#[derive(Debug, Default, Clone)]
pub struct Dataset {
    pub files: Vec<DexFile>,
}

/// Derived instruction-reference columns requested by a query.
///
/// Parsing DEX metadata is useful for every relation, but walking every code
/// item and decoding all five reference families is needlessly expensive for
/// metadata-only statements.  Keep this as a small copyable value so the
/// loader can carry the exact requirements through APK inflation and the
/// parallel DEX parsers without a global mode or per-query branching.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexNeeds {
    /// Build method name/parameter/class/return lookup maps. Metadata-only
    /// class loads can omit these large side indexes.
    pub method_lookup: bool,
    pub method_strings: bool,
    pub method_numbers: bool,
    pub method_calls: bool,
    pub method_field_accesses: bool,
    pub method_used_types: bool,
}

/// Configure the shared Rayon pool before any archive work starts.  The CLI's
/// `--threads` flag is intentionally process-wide because archive inflation,
/// DEX parsing, and derived-index scans use the same pool.
pub fn configure_thread_pool(threads: Option<usize>) {
    let Some(threads) = threads.filter(|&value| value > 0) else {
        return;
    };
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global();
}

impl IndexNeeds {
    pub const fn all() -> Self {
        Self {
            method_lookup: true,
            method_strings: true,
            method_numbers: true,
            method_calls: true,
            method_field_accesses: true,
            method_used_types: true,
        }
    }

    pub const fn any(self) -> bool {
        self.method_strings
            || self.method_numbers
            || self.method_calls
            || self.method_field_accesses
            || self.method_used_types
    }
}

const NATIVE_BASE_COUNT_TABLES: &[&str] = &[
    "class_data_methods",
    "class_fields",
    "map_items",
    "type_list_entries",
];

const CACHE_FLAG_NATIVE: u32 = 8;
const MAX_CACHE_VECTOR: usize = 16_000_000;

/// Container family detected from the DXC2 header. Only the native release
/// container is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheFormat {
    NativeV2,
}

impl Dataset {
    /// Count tables whose cardinality is encoded in the DEX header/map without
    /// constructing the full metadata/reference index.  Query uses this for
    /// standalone `SELECT count(*)` statements, avoiding code-item decoding
    /// and derived opcode scans when the result needs only a header counter.
    pub fn count_paths_fast(paths: &[PathBuf], table: &str) -> Result<Option<u64>, LoadError> {
        if paths.is_empty() {
            return Ok(None);
        }
        let mut dex_bytes = Vec::new();
        for path in paths {
            let ext = path
                .extension()
                .and_then(|v| v.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            match ext.as_str() {
                "dex" => {
                    dex_bytes.push(std::fs::read(path).map_err(|e| {
                        LoadError(format!("failed to read {}: {e}", path.display()))
                    })?)
                }
                "apk" | "jar" | "zip" => {
                    // Reuse the mmap + central-directory scanner used by the
                    // normal loader.  The previous count-only path reopened
                    // and reparsed the ZIP once per DEX member, so even a
                    // header-only count paid the full archive setup cost.
                    let extracted = dexsql_inflate::inflate_dex_entries(path).map_err(|e| {
                        LoadError(format!("invalid ZIP/APK {}: {e}", path.display()))
                    })?;
                    dex_bytes.extend(extracted.into_iter().map(|(_, bytes)| bytes));
                }
                _ => return Ok(None),
            }
        }
        if table == "dex_files" {
            return Ok(Some(dex_bytes.len() as u64));
        }
        let mut total = 0u64;
        for bytes in &dex_bytes {
            let Some(value) = fast_dex_header_count(bytes, table) else {
                return Ok(None);
            };
            total = total.saturating_add(value as u64);
        }
        Ok(Some(total))
    }

    pub fn load_paths(paths: &[PathBuf]) -> Result<Self, LoadError> {
        Self::load_paths_with_requirements(paths, IndexNeeds::all(), true, true, true)
    }

    /// Load a query dataset while deriving only the requested instruction
    /// reference indexes.  This is the normal query entry point; callers that
    /// need code-derived rows should set the corresponding need, which also
    /// causes code items to be parsed eagerly.
    pub fn load_paths_with_needs(paths: &[PathBuf], needs: IndexNeeds) -> Result<Self, LoadError> {
        Self::load_paths_with_options(paths, needs, needs.any())
    }

    /// Variant of [`load_paths_with_needs`] that makes code-item eagerness
    /// explicit.  Metadata queries can leave code lazy, while methods queries
    /// that project opcode summaries can request eager code without building
    /// any reference index.
    pub fn load_paths_with_options(
        paths: &[PathBuf],
        needs: IndexNeeds,
        eager_code_items: bool,
    ) -> Result<Self, LoadError> {
        Self::load_paths_with_code_options(paths, needs, eager_code_items, eager_code_items)
    }

    /// Load with an explicit choice of whether eager code items should also
    /// decode their try/catch handler payloads.  Most query relations only
    /// need headers and instruction units; the two exception relations opt in
    /// to the full payload.
    pub fn load_paths_with_code_options(
        paths: &[PathBuf],
        needs: IndexNeeds,
        eager_code_items: bool,
        full_code_items: bool,
    ) -> Result<Self, LoadError> {
        Self::load_paths_with_requirements(paths, needs, eager_code_items, full_code_items, true)
    }

    /// Query-oriented loader with explicit class/member retention.  Reference
    /// scans over method IDs and code can omit the nested class-data vectors;
    /// relations that expose those vectors should use `retain_classes = true`.
    pub fn load_paths_with_requirements(
        paths: &[PathBuf],
        needs: IndexNeeds,
        eager_code_items: bool,
        full_code_items: bool,
        retain_classes: bool,
    ) -> Result<Self, LoadError> {
        // Preserve the original public loader contract: eager code and
        // decode-oriented loads keep a lazy byte source. Query planners that
        // know their complete relation requirements can opt out explicitly.
        Self::load_paths_with_retention(
            paths,
            needs,
            eager_code_items,
            full_code_items,
            retain_classes,
            eager_code_items || full_code_items,
        )
    }

    /// Load with an explicit raw-payload lifetime. `full_code_items` controls
    /// eager try/catch decoding; it does not describe whether later consumers
    /// need DEX bytes. Debug, annotation, encoded-value, map, and lazy opcode
    /// relations require `retain_raw_bytes = true`. Index-only queries can
    /// release each payload immediately after its derived indexes are built.
    pub fn load_paths_with_retention(
        paths: &[PathBuf],
        needs: IndexNeeds,
        eager_code_items: bool,
        full_code_items: bool,
        retain_classes: bool,
        retain_raw_bytes: bool,
    ) -> Result<Self, LoadError> {
        Self::load_paths_mode_for_file(
            paths,
            needs,
            eager_code_items,
            full_code_items,
            retain_classes,
            retain_raw_bytes,
            None,
        )
    }

    /// Load only the metadata and code items needed by `decode`. Query-derived
    /// opcode/reference indexes are intentionally omitted; building those for
    /// an APK just to render one method dominates startup time.
    pub fn load_paths_for_decode(paths: &[PathBuf]) -> Result<Self, LoadError> {
        Self::load_paths_mode_for_file(paths, IndexNeeds::default(), false, true, true, true, None)
    }

    /// Decode-only load restricted to one logical DEX file. This avoids
    /// inflating and parsing the other entries of a multi-dex APK when the
    /// caller supplied `--file-id`.
    pub fn load_paths_for_decode_file(paths: &[PathBuf], file_id: u32) -> Result<Self, LoadError> {
        Self::load_paths_mode_for_file(
            paths,
            IndexNeeds::default(),
            false,
            true,
            true,
            true,
            Some(file_id),
        )
    }

    fn load_paths_mode_for_file(
        paths: &[PathBuf],
        index_needs: IndexNeeds,
        eager_code_items: bool,
        full_code_items: bool,
        retain_classes: bool,
        retain_raw_bytes: bool,
        target_file_id: Option<u32>,
    ) -> Result<Self, LoadError> {
        if paths.is_empty() {
            return Err(LoadError("at least one DEX/APK input is required".into()));
        }
        let mut files = Vec::new();
        let mut logical_file_base = 0u32;
        for path in paths {
            let ext = path
                .extension()
                .and_then(|v| v.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            match ext.as_str() {
                "dex" => {
                    let file_id = logical_file_base;
                    logical_file_base = logical_file_base.saturating_add(1);
                    if target_file_id.is_some_and(|target| target != file_id) {
                        continue;
                    }
                    let bytes = std::fs::read(path).map_err(|e| {
                        LoadError(format!("failed to read {}: {e}", path.display()))
                    })?;
                    let mut file = parse_dex(
                        bytes,
                        file_id,
                        path.clone(),
                        path.file_name()
                            .and_then(|v| v.to_str())
                            .unwrap_or("classes.dex")
                            .into(),
                        index_needs,
                        eager_code_items,
                        full_code_items,
                        retain_classes,
                    )?;
                    // Index-only loads have no lazy consumer after parse.
                    // Release each DEX payload before the next input is
                    // inflated instead of retaining every archive member
                    // until Dataset construction finishes.
                    if !retain_raw_bytes {
                        file.drop_raw_bytes();
                    }
                    files.push(file);
                }
                "apk" | "jar" | "zip" => {
                    logical_file_base = load_archive(
                        path,
                        &mut files,
                        index_needs,
                        eager_code_items,
                        full_code_items,
                        retain_classes,
                        retain_raw_bytes,
                        logical_file_base,
                        target_file_id,
                    )?;
                }
                _ => {
                    return Err(LoadError(format!(
                        "unsupported input extension \"{}\"",
                        path.extension().and_then(|v| v.to_str()).unwrap_or("")
                    )))
                }
            }
        }
        if files.is_empty() && target_file_id.is_none() {
            return Err(LoadError("dataset has no DEX files".into()));
        }
        Ok(Self { files })
    }

    /// Build (once) and return each file's method indices ordered by
    /// composed descriptor under the dialect's UTF-16 code-unit text order.
    /// Files build in parallel; the result is cached per file.
    pub fn build_ordered_method_descriptors(&self) {
        use rayon::prelude::*;
        self.files.par_iter().for_each(|file| {
            let _ = file.ordered_method_descriptors();
        });
    }

    pub fn count(&self, table: &str) -> Option<u64> {
        let n = match table {
            "dex_files" => self.files.len(),
            "strings" => self.files.iter().map(|f| f.strings.len()).sum(),
            "type_ids" | "types" => self.files.iter().map(|f| f.types.len()).sum(),
            "proto_ids" | "protos" => self.files.iter().map(|f| f.protos.len()).sum(),
            "field_ids" | "fields" => self.files.iter().map(|f| f.fields.len()).sum(),
            "method_ids" | "methods" => self.files.iter().map(|f| f.methods.len()).sum(),
            "class_defs" | "classes" => self.files.iter().map(|f| f.classes.len()).sum(),
            "code_items" => self
                .files
                .iter()
                .map(|f| f.code_items.iter().filter(|x| x.is_some()).count())
                .sum(),
            "method_strings" => self.files.iter().map(|f| f.method_strings.len()).sum(),
            "method_using_numbers" | "method_numbers" => {
                self.files.iter().map(|f| f.method_numbers.len()).sum()
            }
            "method_calls" => self.files.iter().map(|f| f.method_calls.len()).sum(),
            "method_refs" => self
                .files
                .iter()
                .map(|f| {
                    f.method_calls.len()
                        + f.method_strings.len()
                        + f.method_field_accesses.len()
                        + f.method_used_types.len()
                })
                .sum(),
            "method_field_accesses" => self
                .files
                .iter()
                .map(|f| f.method_field_accesses.len())
                .sum(),
            "method_used_types" => self.files.iter().map(|f| f.method_used_types.len()).sum(),
            "class_methods" | "class_data_methods" => self
                .files
                .iter()
                .map(|f| f.classes.iter().map(|c| c.methods.len()).sum::<usize>())
                .sum(),
            "class_fields" | "class_data_fields" => self
                .files
                .iter()
                .map(|f| f.classes.iter().map(|c| c.fields.len()).sum::<usize>())
                .sum(),
            _ => {
                let total = self
                    .files
                    .iter()
                    .map(|file| file.table_count(table).unwrap_or(0))
                    .sum::<usize>();
                // Preserve unknown-table errors for names outside the fixed
                // schema.  `table_count` returning Some(0) is still a valid
                // empty relation (for example method_handles on a DEX without
                // invoke-custom data).
                if self
                    .files
                    .iter()
                    .any(|file| file.table_count(table).is_some())
                {
                    return Some(total as u64);
                }
                return None;
            }
        };
        Some(n as u64)
    }

    /// Count debug relations without materializing all debug rows at once.
    /// Query's `COUNT(*)` fast path uses this for large APKs; the ordinary
    /// relation scanner remains responsible for projecting individual rows.
    pub fn count_debug_rows(&self, table: &str) -> Result<Option<u64>, LoadError> {
        let mut total = 0u64;
        for file in &self.files {
            for method_idx in 0..file.methods.len() as u32 {
                let Some(debug) = file.debug_rows(method_idx)? else {
                    continue;
                };
                let count = match table {
                    "debug_info" => 1,
                    "debug_parameters" => debug.parameters.len(),
                    "debug_positions" => debug.positions.len(),
                    "debug_locals" => debug.locals.len(),
                    "debug_opcodes" => debug.opcodes.len(),
                    _ => return Ok(None),
                };
                total = total.saturating_add(count as u64);
            }
        }
        Ok(Some(total))
    }

    /// Write a small native-style DXC2 container used for interoperability
    /// probes. This sectioned writer emits the native metadata, counts,
    /// identities, and reference sidecars consumed by query-cache.
    pub fn write_native_cache<P: AsRef<Path>>(&self, path: P) -> Result<(), LoadError> {
        if self.files.is_empty() {
            return Err(LoadError(
                "cannot write an empty native cache dataset".into(),
            ));
        }
        let sections = vec![
            ("dex_files.native", native_dex_files_section(self)?),
            ("base_row_counts.native", native_base_counts_section(self)),
            (
                "method_opcode_stats.native",
                native_method_opcode_stats_section(self),
            ),
            (
                "method_opcode_arena.native",
                native_method_opcode_arena_section(self),
            ),
            (
                "method_identities.native",
                native_method_identities_section(self),
            ),
            ("method_refs.native", native_method_refs_section(self)),
            ("method_numbers.native", native_method_numbers_section(self)),
            ("manifest.txt", native_manifest(self).into_bytes()),
        ];
        let path = path.as_ref();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|e| {
            LoadError(format!(
                "failed to create cache directory {}: {e}",
                parent.display()
            ))
        })?;
        // Native DXC2 uses the section count at +8 (the value is eight for
        // the release layout); +0xc is reserved and must remain zero.  Keep
        // every payload page-aligned so mmap readers can jump directly to a
        // section while retaining deterministic offsets between writes.
        const SECTION_ALIGNMENT: usize = 0x1000;
        if sections.len() != 8 {
            return Err(LoadError(format!(
                "native DXC2 requires exactly eight top-level sections, got {}",
                sections.len()
            )));
        }
        let mut bytes = vec![0u8; 0x20];
        bytes[..4].copy_from_slice(b"DXC2");
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&(sections.len() as u32).to_le_bytes());
        // +0xc is reserved in the native v2 header.
        bytes[12..16].fill(0);
        let mut ranges = Vec::with_capacity(sections.len());
        for (_, section) in &sections {
            let aligned = (bytes.len() + SECTION_ALIGNMENT - 1) & !(SECTION_ALIGNMENT - 1);
            bytes.resize(aligned, 0);
            let offset = bytes.len();
            bytes.extend_from_slice(section);
            ranges.push((offset as u64, section.len() as u64));
        }
        let toc = bytes.len();
        bytes[16..24].copy_from_slice(&(toc as u64).to_le_bytes());
        for ((name, section), (offset, length)) in sections.iter().zip(ranges) {
            if name.len() > 0x100 {
                return Err(LoadError(format!(
                    "native DXC2 section name is too long: {name}"
                )));
            }
            bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(&native_section_metadata(section));
        }
        std::fs::write(path, bytes).map_err(|e| {
            LoadError(format!(
                "failed to write native cache {}: {e}",
                path.display()
            ))
        })
    }

    /// Read a cached table count in O(1) time. This is intentionally separate
    /// Aggregate count queries do not deserialize instruction/reference columns.
    pub fn cache_count<P: AsRef<Path>>(path: P, table: &str) -> Result<Option<u64>, LoadError> {
        let path = path.as_ref();
        let file = File::open(path)
            .map_err(|e| LoadError(format!("failed to open cache {}: {e}", path.display())))?;
        let mmap = unsafe {
            MmapOptions::new()
                .map(&file)
                .map_err(|e| LoadError(format!("failed to mmap cache {}: {e}", path.display())))?
        };
        Ok(native_cache_count(&mmap, table))
    }

    /// Identify the DXC2 container family from its fixed header without
    /// decoding any row sections. Native caches are count-readable through
    /// [`Dataset::cache_count`] and carry native sidecar row encodings.
    pub fn cache_format<P: AsRef<Path>>(path: P) -> Result<CacheFormat, LoadError> {
        let path = path.as_ref();
        let file = File::open(path)
            .map_err(|e| LoadError(format!("failed to open cache {}: {e}", path.display())))?;
        let mmap = unsafe {
            MmapOptions::new()
                .map(&file)
                .map_err(|e| LoadError(format!("failed to mmap cache {}: {e}", path.display())))?
        };
        let sections = parse_native_container(&mmap)?;
        let section_count = u32::from_le_bytes(mmap[8..12].try_into().unwrap());
        if section_count == CACHE_FLAG_NATIVE && sections.len() == section_count as usize {
            Ok(CacheFormat::NativeV2)
        } else {
            Err(LoadError(format!(
                "unsupported DXC2 native section count {section_count}"
            )))
        }
    }

    /// Load the method-numbers relation directly from native sidecars. This
    /// path does not reopen the recorded source input: MNS3 supplies the
    /// opcode/value columns and MIS1 supplies the method class identities.
    pub fn load_native_method_numbers<P: AsRef<Path>>(path: P) -> Result<Self, LoadError> {
        let path = path.as_ref();
        let file = File::open(path)
            .map_err(|e| LoadError(format!("failed to open cache {}: {e}", path.display())))?;
        let mmap = unsafe {
            MmapOptions::new()
                .map(&file)
                .map_err(|e| LoadError(format!("failed to mmap cache {}: {e}", path.display())))?
        };
        let numbers = NativeMethodNumbers::decode(
            native_section_bytes(&mmap, "method_numbers.native")
                .ok_or_else(|| LoadError("native cache is missing method_numbers.native".into()))?,
        )?;
        let identities = NativeMethodIdentities::decode(
            native_section_bytes(&mmap, "method_identities.native").ok_or_else(|| {
                LoadError("native cache is missing method_identities.native".into())
            })?,
        )?;
        let method_count = identities.class_idx.len();
        let edge_count = numbers.opcode.len();
        let mut methods = Vec::with_capacity(method_count);
        for &class_idx in &identities.class_idx {
            methods.push(MethodInfo {
                class_idx: class_idx as u16,
                proto_idx: 0,
                name_idx: 0,
            });
        }
        let mut method_numbers = Vec::new();
        // The compact MNS3 auxiliary column is a method-major CSR.  Its
        // terminal edge count is present even when the final zero-edge method
        // identities are omitted, so missing entries imply an empty range.
        for method_idx in 0..method_count {
            let start = numbers
                .forward_csr
                .get(method_idx)
                .copied()
                .unwrap_or(edge_count as u32) as usize;
            let end = numbers
                .forward_csr
                .get(method_idx + 1)
                .copied()
                .unwrap_or(edge_count as u32) as usize;
            if start > end || end > edge_count {
                return Err(LoadError(format!(
                    "native method_numbers CSR range {start}..{end} is invalid for method {method_idx}"
                )));
            }
            for row_idx in start..end {
                let opcode = numbers.opcode[row_idx];
                let long_value = numbers.values[row_idx];
                let number_type = if matches!(opcode, 0x16..=0x19) {
                    NumberType::Long
                } else {
                    NumberType::Int
                };
                let double_value = if matches!(opcode, 0x14 | 0x15) {
                    Some(f32::from_bits(long_value as u32) as f64)
                } else if matches!(opcode, 0x18 | 0x19) {
                    Some(f64::from_bits(long_value as u64))
                } else {
                    None
                };
                method_numbers.push(MethodNumberRef {
                    method_idx: method_idx as u32,
                    opcode,
                    number_type,
                    long_value,
                    double_value,
                });
            }
        }
        let mut method_numbers_by_value = HashMap::new();
        let mut method_number_rows_by_value = FxHashMap::default();
        for (row_idx, row) in method_numbers.iter().enumerate() {
            method_numbers_by_value
                .entry(row.long_value)
                .or_insert_with(Vec::new)
                .push(row.method_idx);
            method_number_rows_by_value
                .entry(row.long_value)
                .or_insert_with(Vec::new)
                .push(row_idx);
        }
        let mut dex = DexFile {
            file_id: 0,
            source_path: path.to_owned(),
            entry_name: "native-cache".into(),
            bytes: None,
            byte_len: 0,
            dex_version: String::new(),
            checksum: 0,
            signature_hex: String::new(),
            header_size: 0,
            endian_tag: 0,
            map_off: 0,
            string_ids_off: 0,
            type_ids_off: 0,
            proto_ids_off: 0,
            field_ids_off: 0,
            method_ids_off: 0,
            class_defs_off: 0,
            data_size: 0,
            data_off: 0,
            strings: Vec::new(),
            string_lookup: HashMap::new(),
            types: Vec::new(),
            protos: Vec::new(),
            fields: Vec::new(),
            methods,
            method_access_flags: Vec::new(),
            methods_by_name: FxHashMap::default(),
            methods_by_param_count: FxHashMap::default(),
            methods_by_class: FxHashMap::default(),
            methods_by_return: FxHashMap::default(),
            fields_by_name: FxHashMap::default(),
            method_descriptors: Arc::new(OnceLock::new()),
            field_descriptors: Arc::new(OnceLock::new()),
            debug_rows_cache: Arc::new(OnceLock::new()),
            method_code_offsets: Arc::new(OnceLock::new()),
            classes: Vec::new(),
            method_descriptor_order: Arc::new(OnceLock::new()),
            string_utf16_ranks: Arc::new(OnceLock::new()),
            classes_by_idx_order: Vec::new(),
            classes_by_superclass: FxHashMap::default(),
            classes_by_descriptor: FxHashMap::default(),
            code_items: Vec::new(),
            method_strings: Vec::new(),
            method_strings_by_string: FxHashMap::default(),
            method_numbers,
            method_numbers_by_value,
            method_number_rows_by_value,
            method_calls: Vec::new(),
            method_field_accesses: Vec::new(),
            method_used_types: Vec::new(),
            meta: MetadataIndexes::default(),
        };
        rebuild_method_lookup_indexes(&mut dex);
        if identities.file_ranges.len() <= 2 {
            return Ok(Self { files: vec![dex] });
        }
        let all_methods = dex.methods.clone();
        let all_numbers = dex.method_numbers.clone();
        let mut files = Vec::with_capacity(identities.file_ranges.len() - 1);
        for (file_id, range) in identities.file_ranges.windows(2).enumerate() {
            let start = range[0] as usize;
            let end = range[1] as usize;
            if start > end || end > all_methods.len() {
                return Err(LoadError(
                    "native method identity file range is invalid".into(),
                ));
            }
            let mut part = dex.clone();
            part.file_id = file_id as u32;
            part.methods = all_methods[start..end].to_vec();
            part.code_items = Vec::new();
            part.method_numbers.clear();
            // MNS3 method indices are global across all DEX files.  Select by
            // the identity directory and only then convert to the local index;
            // splitting each method's rows by file count silently discarded
            // rows whenever an APK had more than one DEX.
            for row in &all_numbers {
                let global_idx = row.method_idx as usize;
                if (start..end).contains(&global_idx) {
                    let mut row = row.clone();
                    row.method_idx = (global_idx - start) as u32;
                    part.method_numbers.push(row);
                }
            }
            part.method_numbers_by_value.clear();
            part.method_number_rows_by_value.clear();
            for (row_idx, row) in part.method_numbers.iter().enumerate() {
                part.method_numbers_by_value
                    .entry(row.long_value)
                    .or_default()
                    .push(row.method_idx);
                part.method_number_rows_by_value
                    .entry(row.long_value)
                    .or_default()
                    .push(row_idx);
            }
            part.methods_by_name.clear();
            part.methods_by_param_count.clear();
            part.methods_by_class.clear();
            part.methods_by_return.clear();
            part.meta = MetadataIndexes::default();
            rebuild_method_lookup_indexes(&mut part);
            files.push(part);
        }
        Ok(Self { files })
    }

    /// Load method_refs directly from an MRS5 sidecar plus method identities.
    pub fn load_native_method_refs<P: AsRef<Path>>(path: P) -> Result<Self, LoadError> {
        let path = path.as_ref();
        let file = File::open(path)
            .map_err(|e| LoadError(format!("failed to open cache {}: {e}", path.display())))?;
        let mmap = unsafe {
            MmapOptions::new()
                .map(&file)
                .map_err(|e| LoadError(format!("failed to mmap cache {}: {e}", path.display())))?
        };
        let refs = NativeMethodRefs::decode(
            native_section_bytes(&mmap, "method_refs.native")
                .ok_or_else(|| LoadError("native cache is missing method_refs.native".into()))?,
        )?;
        let identities = NativeMethodIdentities::decode(
            native_section_bytes(&mmap, "method_identities.native").ok_or_else(|| {
                LoadError("native cache is missing method_identities.native".into())
            })?,
        )?;
        let method_count = identities.class_idx.len();
        let methods = identities
            .class_idx
            .iter()
            .map(|&class_idx| MethodInfo {
                class_idx: class_idx as u16,
                proto_idx: 0,
                name_idx: 0,
            })
            .collect::<Vec<_>>();
        let rows = refs.rows()?;
        let mut method_strings = Vec::new();
        let mut method_used_types = Vec::new();
        let mut method_field_accesses = Vec::new();
        let mut method_calls = Vec::new();
        for row in rows {
            if row.method_idx as usize >= method_count {
                return Err(LoadError(
                    "native method-refs method index exceeds identities".into(),
                ));
            }
            match row.kind {
                0 => method_strings.push(MethodStringRef {
                    method_idx: row.method_idx,
                    string_idx: row.index,
                }),
                1 => method_used_types.push(MethodTypeRef {
                    method_idx: row.method_idx,
                    type_idx: row.index,
                }),
                2 => method_field_accesses.push(MethodFieldRef {
                    method_idx: row.method_idx,
                    field_idx: row.index,
                    opcode: 0,
                }),
                3 => method_field_accesses.push(MethodFieldRef {
                    method_idx: row.method_idx,
                    field_idx: row.index,
                    opcode: 1,
                }),
                4 => method_calls.push(MethodCallRef {
                    method_idx: row.method_idx,
                    callee_method_idx: row.index,
                }),
                _ => return Err(LoadError("native method-refs kind is invalid".into())),
            }
        }
        let mut dex = DexFile {
            file_id: 0,
            source_path: path.to_owned(),
            entry_name: "native-cache".into(),
            bytes: None,
            byte_len: 0,
            dex_version: String::new(),
            checksum: 0,
            signature_hex: String::new(),
            header_size: 0,
            endian_tag: 0,
            map_off: 0,
            string_ids_off: 0,
            type_ids_off: 0,
            proto_ids_off: 0,
            field_ids_off: 0,
            method_ids_off: 0,
            class_defs_off: 0,
            data_size: 0,
            data_off: 0,
            strings: Vec::new(),
            string_lookup: HashMap::new(),
            types: Vec::new(),
            protos: Vec::new(),
            fields: Vec::new(),
            methods,
            method_access_flags: Vec::new(),
            methods_by_name: FxHashMap::default(),
            methods_by_param_count: FxHashMap::default(),
            methods_by_class: FxHashMap::default(),
            methods_by_return: FxHashMap::default(),
            fields_by_name: FxHashMap::default(),
            method_descriptors: Arc::new(OnceLock::new()),
            field_descriptors: Arc::new(OnceLock::new()),
            debug_rows_cache: Arc::new(OnceLock::new()),
            method_code_offsets: Arc::new(OnceLock::new()),
            classes: Vec::new(),
            method_descriptor_order: Arc::new(OnceLock::new()),
            string_utf16_ranks: Arc::new(OnceLock::new()),
            classes_by_idx_order: Vec::new(),
            classes_by_superclass: FxHashMap::default(),
            classes_by_descriptor: FxHashMap::default(),
            code_items: Vec::new(),
            method_strings,
            method_strings_by_string: FxHashMap::default(),
            method_numbers: Vec::new(),
            method_numbers_by_value: HashMap::new(),
            method_number_rows_by_value: FxHashMap::default(),
            method_calls,
            method_field_accesses,
            method_used_types,
            meta: MetadataIndexes::default(),
        };
        rebuild_method_lookup_indexes(&mut dex);
        Ok(Self { files: vec![dex] })
    }

    /// Extract source inputs recorded by a native cache manifest. Native row
    /// sections use a compressed codec; reopening the recorded source keeps
    /// row queries useful while preserving the manifest's source identity.
    pub fn native_cache_source_paths<P: AsRef<Path>>(path: P) -> Result<Vec<PathBuf>, LoadError> {
        Ok(Self::native_cache_source_records(path)?
            .into_iter()
            .map(|(path, _)| path)
            .collect())
    }

    /// Validate the byte lengths recorded in a native manifest before a row
    /// query reopens its source inputs.
    pub fn validate_native_cache_sources<P: AsRef<Path>>(path: P) -> Result<(), LoadError> {
        let cache_path = path.as_ref();
        let cache_file = File::open(cache_path).map_err(|e| {
            LoadError(format!(
                "failed to open cache {}: {e}",
                cache_path.display()
            ))
        })?;
        let cache_mmap = unsafe {
            MmapOptions::new().map(&cache_file).map_err(|e| {
                LoadError(format!(
                    "failed to mmap cache {}: {e}",
                    cache_path.display()
                ))
            })?
        };
        let manifest = native_manifest_bytes(&cache_mmap)?;
        let mut aggregate = Sha256::new();
        let fingerprint = manifest.split(|byte| *byte == b'\n').find_map(|line| {
            line.strip_prefix(b"input_fingerprint=")
                .map(ToOwned::to_owned)
        });
        let records = Self::native_cache_manifest_records(cache_path)?;
        if records.is_empty() {
            return Err(LoadError("cache manifest missing input_source".into()));
        }
        for (source, expected_len, expected_mtime, expected_digest) in records {
            let metadata = std::fs::metadata(&source).map_err(|error| {
                LoadError(format!(
                    "cache is stale: cannot read source input {}: {error}",
                    source.display()
                ))
            })?;
            if metadata.len() != expected_len {
                return Err(LoadError(format!(
                    "cache is stale: source input {} byte length changed since cache build",
                    source.display()
                )));
            }
            let mtime = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
                .unwrap_or(0);
            if expected_mtime != 0 && mtime != expected_mtime {
                return Err(LoadError(format!(
                    "cache is stale: source input {} modified time changed since cache build",
                    source.display()
                )));
            }
            let mut input = File::open(&source).map_err(|error| {
                LoadError(format!(
                    "cache is stale: cannot read source input {}: {error}",
                    source.display()
                ))
            })?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 1024 * 1024];
            loop {
                let read = input.read(&mut buffer).map_err(|error| {
                    LoadError(format!(
                        "cache is stale: cannot read source input {}: {error}",
                        source.display()
                    ))
                })?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            let digest = hasher.finalize();
            if !expected_digest.is_empty() && expected_digest != native_hex(&digest) {
                return Err(LoadError(format!(
                    "cache is stale: source input {} content changed since cache build",
                    source.display()
                )));
            }
            aggregate.update(native_fingerprint_record(
                &source,
                metadata.len(),
                mtime,
                &digest,
            ));
        }
        if let Some(expected) = fingerprint {
            let expected = std::str::from_utf8(&expected)
                .map_err(|_| LoadError("cache manifest input_fingerprint is not UTF-8".into()))?;
            let actual = aggregate.finalize();
            let actual_hex = native_hex(&actual);
            if expected.trim() != actual_hex {
                return Err(LoadError(
                    "cache manifest input_fingerprint mismatch".into(),
                ));
            }
        }
        Ok(())
    }

    fn native_cache_source_records<P: AsRef<Path>>(
        path: P,
    ) -> Result<Vec<(PathBuf, u64)>, LoadError> {
        Ok(Self::native_cache_manifest_records(path)?
            .into_iter()
            .map(|(source, length, _, _)| (source, length))
            .collect())
    }

    fn native_cache_manifest_records<P: AsRef<Path>>(
        path: P,
    ) -> Result<Vec<(PathBuf, u64, u64, String)>, LoadError> {
        let path = path.as_ref();
        let file = File::open(path)
            .map_err(|e| LoadError(format!("failed to open cache {}: {e}", path.display())))?;
        let mmap = unsafe {
            MmapOptions::new()
                .map(&file)
                .map_err(|e| LoadError(format!("failed to mmap cache {}: {e}", path.display())))?
        };
        let manifest = native_manifest_bytes(&mmap)?;
        let mut paths = Vec::new();
        for line in manifest.split(|byte| *byte == b'\n') {
            let Some(value) = line.strip_prefix(b"input_source=") else {
                continue;
            };
            let mut fields = value.split(|byte| *byte == b',');
            let encoded = fields.next().unwrap_or_default();
            let Some(byte_len) = fields
                .next()
                .and_then(|field| std::str::from_utf8(field).ok()?.parse::<u64>().ok())
            else {
                continue;
            };
            let mtime = fields
                .next()
                .and_then(|field| std::str::from_utf8(field).ok()?.parse::<u64>().ok())
                .unwrap_or(0);
            let digest = fields
                .next()
                .and_then(|field| std::str::from_utf8(field).ok())
                .unwrap_or_default()
                .to_owned();
            if encoded.len() % 2 != 0 || encoded.is_empty() {
                continue;
            }
            let mut decoded = Vec::with_capacity(encoded.len() / 2);
            let mut index = 0;
            let mut valid = true;
            while index < encoded.len() {
                let Some(high) = hex_digit(encoded[index]) else {
                    valid = false;
                    break;
                };
                let Some(low) = hex_digit(encoded[index + 1]) else {
                    valid = false;
                    break;
                };
                decoded.push((high << 4) | low);
                index += 2;
            }
            if !valid {
                continue;
            }
            let source = String::from_utf8(decoded).map_err(|_| {
                LoadError("native cache manifest has a non-UTF-8 input path".into())
            })?;
            let source = PathBuf::from(source);
            if !paths.iter().any(|(existing, _, _, _)| existing == &source) {
                paths.push((source, byte_len, mtime, digest));
            }
        }
        Ok(paths)
    }
}

fn write_u32<W: Write>(out: &mut W, value: u32) -> std::io::Result<()> {
    out.write_all(&value.to_le_bytes())
}
fn write_u64<W: Write>(out: &mut W, value: u64) -> std::io::Result<()> {
    out.write_all(&value.to_le_bytes())
}
fn write_string<W: Write>(out: &mut W, value: &str) -> std::io::Result<()> {
    write_u32(out, value.len() as u32)?;
    out.write_all(value.as_bytes())
}
fn native_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn native_fingerprint_record(
    source: &Path,
    byte_len: u64,
    mtime_nanos: u64,
    digest: &[u8],
) -> Vec<u8> {
    let encoded = source
        .to_string_lossy()
        .as_bytes()
        .iter()
        .flat_map(|byte| format!("{byte:02x}").into_bytes())
        .collect::<Vec<_>>();
    let digest_hex = native_hex(digest);
    let mut record = Vec::with_capacity(encoded.len() + digest_hex.len() + 26);
    record.extend_from_slice(&encoded);
    record.push(0);
    record.extend_from_slice(&byte_len.to_le_bytes());
    record.extend_from_slice(b"sha256");
    record.push(0);
    record.extend_from_slice(&mtime_nanos.to_le_bytes());
    record.push(0);
    record.extend_from_slice(digest_hex.as_bytes());
    record.push(0xff);
    record
}

fn native_manifest(dataset: &Dataset) -> String {
    let mut out = String::from(
        "version=dexsql-cache-v52\ndecode_references=true\ndecode_opcode_hex=true\nreference_kinds=127\ndecode_numbers=true\n",
    );
    let mut aggregate = Sha256::new();
    // A ZIP/APK can contribute many logical DEX files but it is one source
    // input.  Fingerprinting the inflated member (the old writer did this)
    // made every archive cache stale immediately because validation hashes the
    // archive itself.  Preserve input order while emitting each source once.
    let mut seen_sources = HashSet::new();
    for file in &dataset.files {
        if !seen_sources.insert(file.source_path.clone()) {
            continue;
        }
        let (byte_len, mtime, digest) = source_identity(&file.source_path, file.raw());
        let encoded = native_hex(file.source_path.to_string_lossy().as_bytes());
        aggregate.update(native_fingerprint_record(
            &file.source_path,
            byte_len,
            mtime,
            &digest,
        ));
        out.push_str(&format!(
            "input_source={encoded},{byte_len},{mtime},{}\n",
            native_hex(&digest)
        ));
    }
    out.push_str("input_fingerprint=");
    out.push_str(&native_hex(&aggregate.finalize()));
    out.push('\n');
    out
}

fn source_identity(source: &Path, fallback: &[u8]) -> (u64, u64, Vec<u8>) {
    let metadata = std::fs::metadata(source).ok();
    let byte_len = metadata.as_ref().map(|meta| meta.len());
    let mtime = metadata
        .as_ref()
        .and_then(|meta| meta.modified().ok())
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
        .unwrap_or(0);
    if let Ok(mut input) = File::open(source) {
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 1024 * 1024];
        let mut read_ok = true;
        loop {
            match input.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => hasher.update(&buffer[..read]),
                Err(_) => {
                    read_ok = false;
                    break;
                }
            }
        }
        if read_ok {
            return (byte_len.unwrap_or(0), mtime, hasher.finalize().to_vec());
        }
    }
    (
        byte_len.unwrap_or(fallback.len() as u64),
        mtime,
        Sha256::digest(fallback).to_vec(),
    )
}

fn native_dex_files_section(dataset: &Dataset) -> Result<Vec<u8>, LoadError> {
    let mut out = b"DXR1".to_vec();
    out.extend_from_slice(&(dataset.files.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0u8; 8]);
    for file in &dataset.files {
        write_string(&mut out, &file.source_path.to_string_lossy())
            .map_err(|e| LoadError(format!("failed to encode native dex source: {e}")))?;
        write_string(&mut out, &file.entry_name)
            .map_err(|e| LoadError(format!("failed to encode native dex entry: {e}")))?;
        write_u64(&mut out, file.raw().len() as u64)
            .map_err(|e| LoadError(format!("failed to encode native dex length: {e}")))?;
        write_string(&mut out, &file.dex_version)
            .map_err(|e| LoadError(format!("failed to encode native dex version: {e}")))?;
        write_u32(&mut out, file.checksum)
            .map_err(|e| LoadError(format!("failed to encode native dex checksum: {e}")))?;
        write_string(&mut out, &file.signature_hex)
            .map_err(|e| LoadError(format!("failed to encode native dex signature: {e}")))?;
        // The twenty u32s mirror the native dex_files schema exactly:
        // file_size, header_size, endian_tag, link_size, link_off, map_off,
        // then count/offset pairs for strings, types, protos, fields,
        // methods, classes, followed by data_size/data_off.
        let mut fields = [0u32; 20];
        fields[0] = read_u32(file.raw(), 32).unwrap_or(file.raw().len() as u32);
        fields[1] = file.header_size;
        fields[2] = file.endian_tag;
        fields[3] = read_u32(file.raw(), 44).unwrap_or(0);
        fields[4] = read_u32(file.raw(), 48).unwrap_or(0);
        fields[5] = file.map_off;
        fields[6] = file.strings.len() as u32;
        fields[7] = file.string_ids_off;
        fields[8] = file.types.len() as u32;
        fields[9] = file.type_ids_off;
        fields[10] = file.protos.len() as u32;
        fields[11] = file.proto_ids_off;
        fields[12] = file.fields.len() as u32;
        fields[13] = file.field_ids_off;
        fields[14] = file.methods.len() as u32;
        fields[15] = file.method_ids_off;
        fields[16] = file.classes.len() as u32;
        fields[17] = file.class_defs_off;
        fields[18] = file.data_size;
        fields[19] = file.data_off;
        for value in fields {
            write_u32(&mut out, value)
                .map_err(|e| LoadError(format!("failed to encode native dex fields: {e}")))?;
        }
        // Multi-file native caches carry a boundary marker between adjacent
        // DEX records.  The release reader uses the repeated ordinal to
        // validate logical file ordering; the final record has no marker.
        if file.file_id + 1 < dataset.files.len() as u32 {
            write_u32(&mut out, file.file_id + 1)
                .map_err(|e| LoadError(format!("failed to encode native dex boundary: {e}")))?;
            write_u32(&mut out, file.file_id + 1)
                .map_err(|e| LoadError(format!("failed to encode native dex boundary: {e}")))?;
        }
    }
    Ok(out)
}

fn native_base_counts_section(dataset: &Dataset) -> Vec<u8> {
    let debug_counts = dataset
        .files
        .iter()
        .map(DexFile::debug_relation_counts)
        .collect::<Vec<_>>();
    let debug_count = |column: usize| -> u64 {
        debug_counts
            .iter()
            .map(|counts| counts[column] as u64)
            .sum()
    };
    let mut out = b"DXR1".to_vec();
    out.extend_from_slice(&(NATIVE_BASE_COUNT_TABLES.len() as u32).to_le_bytes());
    for table in NATIVE_BASE_COUNT_TABLES {
        let count = match *table {
            "debug_info" => debug_count(0),
            "debug_parameters" => debug_count(1),
            "debug_positions" => debug_count(2),
            "debug_opcodes" => debug_count(3),
            "debug_locals" => debug_count(4),
            _ => dataset.count(table).unwrap_or(0),
        };
        let _ = write_string(&mut out, table);
        let _ = write_u64(&mut out, count);
    }
    out
}

fn native_method_identities_section(dataset: &Dataset) -> Vec<u8> {
    let width = if dataset
        .files
        .iter()
        .flat_map(|file| file.methods.iter())
        .all(|method| method.class_idx <= u8::MAX as u16)
    {
        1usize
    } else {
        2usize
    };
    let mut out = b"MIS1".to_vec();
    out.push(width as u8);
    let method_count = dataset
        .files
        .iter()
        .map(|file| file.methods.len())
        .sum::<usize>();
    out.extend_from_slice(&(method_count as u32).to_le_bytes());
    for file in &dataset.files {
        for method in &file.methods {
            if width == 1 {
                out.push(method.class_idx as u8);
            } else {
                out.extend_from_slice(&method.class_idx.to_le_bytes());
            }
        }
    }
    out.extend_from_slice(&((dataset.files.len() + 1) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    let mut total = 0u32;
    for file in &dataset.files {
        total = total.saturating_add(file.methods.len() as u32);
        out.extend_from_slice(&total.to_le_bytes());
    }
    out
}

fn native_method_opcode_arena_section(dataset: &Dataset) -> Vec<u8> {
    let mut arena = Vec::new();
    let mut csr = vec![0u32];
    for file in &dataset.files {
        for method_idx in 0..file.methods.len() as u32 {
            if let Some(code) = file
                .code_items
                .get(method_idx as usize)
                .and_then(Option::as_ref)
            {
                let mut pc = 0usize;
                while pc < code.insns.len() {
                    let opcode = (code.insns[pc] & 0xff) as u8;
                    let width = opcode_width(opcode, &code.insns, pc).max(1);
                    if !is_payload_opcode(&code.insns, pc) {
                        arena.push(opcode);
                    }
                    pc = pc.saturating_add(width);
                }
            }
            csr.push(arena.len() as u32);
        }
    }
    let mut out = b"MOA1".to_vec();
    out.extend_from_slice(&(arena.len() as u32).to_le_bytes());
    out.extend_from_slice(&arena);
    out.extend_from_slice(&(csr.len() as u32).to_le_bytes());
    for value in csr {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

fn native_method_opcode_stats_section(dataset: &Dataset) -> Vec<u8> {
    let mut out = b"DXR1".to_vec();
    let count = dataset
        .files
        .iter()
        .map(|file| file.methods.len())
        .sum::<usize>();
    out.extend_from_slice(&(count as u32).to_le_bytes());
    for file in &dataset.files {
        let mut direct = vec![None; file.methods.len()];
        for class in &file.classes {
            for method in &class.methods {
                if let Some(slot) = direct.get_mut(method.method_idx as usize) {
                    *slot = Some(method.is_direct);
                }
            }
        }
        for method_idx in 0..file.methods.len() as u32 {
            let Some(is_direct) = direct
                .get(method_idx as usize)
                .and_then(Option::as_ref)
                .copied()
            else {
                out.extend_from_slice(&0u32.to_le_bytes());
                out.push(0);
                continue;
            };
            let opcode_count = file.method_opcode_count(method_idx).unwrap_or(0);
            let kind = if is_direct { "direct" } else { "virtual" };
            out.extend_from_slice(&(opcode_count as u32).to_le_bytes());
            out.push(1);
            out.extend_from_slice(&(kind.len() as u32).to_le_bytes());
            out.extend_from_slice(kind.as_bytes());
        }
    }
    out
}

fn native_method_numbers_section(dataset: &Dataset) -> Vec<u8> {
    let method_count = dataset
        .files
        .iter()
        .map(|file| file.methods.len())
        .max()
        .unwrap_or(0);
    let mut per_file = Vec::with_capacity(dataset.files.len());
    for file in &dataset.files {
        let mut rows = vec![Vec::<MethodNumberRef>::new(); file.methods.len()];
        for row in &file.method_numbers {
            if let Some(slot) = rows.get_mut(row.method_idx as usize) {
                slot.push(row.clone());
            }
        }
        per_file.push((file.file_id as u8, rows));
    }
    let mut rows = Vec::<(u8, MethodNumberRef)>::new();
    for method_idx in 0..method_count {
        for (file_id, file_rows) in &per_file {
            if let Some(method_rows) = file_rows.get(method_idx) {
                for row in method_rows {
                    rows.push((*file_id, row.clone()));
                }
            }
        }
    }
    let value_keys = rows
        .iter()
        .map(|(_, row)| row.long_value)
        .collect::<Vec<_>>();
    let reverse_perm = radix_permutation_i64(&value_keys);
    let mut out = b"MNS3".to_vec();
    out.push(1);
    out.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    out.extend(rows.iter().map(|(file_id, _)| *file_id));

    out.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    out.extend(rows.iter().map(|(_, row)| row.opcode));
    out.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    for (_, row) in &rows {
        out.extend_from_slice(&(row.long_value as u64).to_le_bytes());
    }
    // Auxiliary is the native method-major CSR without method zero: each
    // entry is the cumulative end offset for methods 1..N-1.  This is compact
    // (and matches the release sidecar's 3032-entry column for 3033 methods).
    let mut counts = vec![0u32; method_count];
    for (_, row) in &rows {
        if let Some(count) = counts.get_mut(row.method_idx as usize) {
            *count = count.saturating_add(1);
        }
    }
    let count_limit = counts
        .iter()
        .rposition(|count| *count != 0)
        .map(|index| index.saturating_add(1))
        .unwrap_or(0);
    let mut cumulative = 0u32;
    let mut aux = Vec::with_capacity(count_limit.saturating_add(1));
    aux.push(0);
    for count in counts.into_iter().take(count_limit) {
        cumulative = cumulative.saturating_add(count);
        aux.push(cumulative);
    }
    out.extend_from_slice(&(aux.len() as u32).to_le_bytes());
    for value in aux {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&(reverse_perm.len() as u32).to_le_bytes());
    for row in reverse_perm {
        out.extend_from_slice(&row.to_le_bytes());
    }
    out
}

fn native_method_refs_section(dataset: &Dataset) -> Vec<u8> {
    let mut packed = Vec::<u32>::new();
    let mut declarations = Vec::<u8>::new();
    let mut extra_declarations = Vec::<u8>::new();
    let mut extra_methods = Vec::<u32>::new();
    let mut extra_values = Vec::<u32>::new();
    let mut by_kind = vec![Vec::<(u8, u32, u32)>::new(); 5];
    let mut field_ties = vec![Vec::<u32>::new(); 5];
    let mut field_occurrences = HashMap::<(u8, u32), u32>::new();
    for file in &dataset.files {
        let file_id = file.file_id as u8;
        for row in &file.method_strings {
            if row.string_idx > u16::MAX as u32 {
                extra_declarations.push(file_id);
                extra_methods.push(row.method_idx);
                extra_values.push(row.string_idx);
            } else {
                by_kind[0].push((file_id, row.method_idx, row.string_idx));
            }
        }
        for row in &file.method_used_types {
            by_kind[1].push((file_id, row.method_idx, row.type_idx));
        }
        for row in &file.method_field_accesses {
            let is_get = matches!(row.opcode, 0x52..=0x58 | 0x60..=0x66);
            let kind = usize::from(!is_get) + 2;
            let method = row.method_idx;
            let occurrence = field_occurrences.entry((file_id, method)).or_default();
            by_kind[kind].push((file_id, method, row.field_idx));
            field_ties[kind].push(*occurrence);
            *occurrence = occurrence.saturating_add(1);
        }
        for row in &file.method_calls {
            by_kind[4].push((file_id, row.method_idx, row.callee_method_idx));
        }
    }
    let method_count = dataset
        .files
        .iter()
        .map(|file| file.methods.len())
        .max()
        .unwrap_or(0);
    let mut method_ranks = Vec::with_capacity(dataset.files.len());
    for file in &dataset.files {
        let mut ranks = vec![0u32; file.methods.len()];
        let mut rank = 0u32;
        for class in &file.classes {
            for method in &class.methods {
                if let Some(slot) = ranks.get_mut(method.method_idx as usize) {
                    *slot = rank;
                }
                rank = rank.saturating_add(1);
            }
        }
        method_ranks.push(ranks);
    }
    let string_count = dataset
        .files
        .iter()
        .flat_map(|file| {
            file.method_strings
                .iter()
                .map(|row| row.string_idx as usize + 1)
        })
        .max()
        .unwrap_or(0);
    let type_count = dataset
        .files
        .iter()
        .flat_map(|file| {
            file.method_used_types
                .iter()
                .map(|row| row.type_idx as usize + 1)
        })
        .max()
        .unwrap_or(0);
    let field_count = dataset
        .files
        .iter()
        .flat_map(|file| {
            file.method_field_accesses
                .iter()
                .map(|row| row.field_idx as usize + 1)
        })
        .max()
        .unwrap_or(0);
    let method_ref_count = dataset
        .files
        .iter()
        .flat_map(|file| {
            file.method_calls
                .iter()
                .flat_map(|row| [row.method_idx, row.callee_method_idx])
        })
        .map(|index| index as usize + 1)
        .max()
        .unwrap_or(0);
    let domain_counts = [string_count, type_count, field_count, method_ref_count];
    let mut domain_key_counts = domain_counts
        .iter()
        .map(|&count| vec![0u32; count])
        .collect::<Vec<_>>();
    for &index in &extra_values {
        if let Some(key_count) = domain_key_counts[0].get_mut(index as usize) {
            *key_count = key_count.saturating_add(1);
        }
    }
    let mut kind_start = vec![0u32];
    let mut forward = Vec::new();
    let mut bases = vec![0u32];
    let mut reverse_ties = Vec::<u64>::new();
    for (kind_index, kind) in by_kind.iter().enumerate() {
        let mut occurrences = HashMap::<(u8, u32), u32>::new();
        let mut rows = kind
            .iter()
            .enumerate()
            .map(|(source, &(file_id, method, index))| {
                let value = if matches!(kind_index, 2 | 3) {
                    ((method_ranks
                        .get(file_id as usize)
                        .and_then(|ranks| ranks.get(method as usize))
                        .copied()
                        .unwrap_or(method) as u64)
                        << 32)
                        | u64::from(
                            field_ties[kind_index]
                                .get(source)
                                .copied()
                                .unwrap_or(source as u32),
                        )
                } else {
                    let occurrence = occurrences.entry((file_id, method)).or_default();
                    let value = ((method_ranks
                        .get(file_id as usize)
                        .and_then(|ranks| ranks.get(method as usize))
                        .copied()
                        .unwrap_or(method) as u64)
                        << 32)
                        | u64::from(*occurrence);
                    *occurrence = occurrence.saturating_add(1);
                    value
                };
                (file_id, method, index, value)
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|(_, method, _, _)| *method);
        let mut counts = vec![0u32; method_count];
        let domain = match kind_index {
            0 => 0,
            1 => 1,
            2 | 3 => 2,
            4 => 3,
            _ => unreachable!(),
        };
        for (file_id, method, index, source) in rows {
            if let Some(slot) = counts.get_mut(method as usize) {
                *slot = slot.saturating_add(1);
                if let Some(key_count) = domain_key_counts[domain].get_mut(index as usize) {
                    *key_count = key_count.saturating_add(1);
                }
                declarations.push(file_id);
                packed.push(index);
                reverse_ties.push(source);
            }
        }
        let last = counts
            .iter()
            .rposition(|count| *count != 0)
            .map(|index| index + 1)
            .unwrap_or(0);
        let mut start = 0u32;
        let extra_terminal = 0usize;
        for count in counts.into_iter().take(last.saturating_add(extra_terminal)) {
            forward.push(start);
            start = start.saturating_add(count);
        }
        forward.push(start);
        kind_start.push(packed.len() as u32);
        bases.push(forward.len() as u32);
    }
    // Native MRS5 reserves twelve kind partitions. The final seven are empty
    // for ordinary reference rows, except that an out-of-width string index is
    // retained as a declaration-only jumbo-string kind (kind 10).
    let extra_count = extra_declarations.len() as u32;
    let has_extra_kind = extra_count != 0;
    while kind_start.len() < 12 {
        kind_start.push(packed.len() as u32);
    }
    while bases.len() < if has_extra_kind { 11 } else { 12 } {
        forward.push(0);
        bases.push(forward.len() as u32);
    }
    if has_extra_kind {
        let mut extra_counts = vec![0u32; method_count];
        for &method in &extra_methods {
            if let Some(count) = extra_counts.get_mut(method as usize) {
                *count = count.saturating_add(1);
            }
        }
        let extra_last = extra_counts
            .iter()
            .rposition(|count| *count != 0)
            .map(|index| index + 1)
            .unwrap_or(0);
        let mut extra_start = 0u32;
        for count in extra_counts.into_iter().take(extra_last) {
            forward.push(extra_start);
            extra_start = extra_start.saturating_add(count);
        }
        forward.push(extra_start);
        kind_start[11] = (declarations.len() + extra_declarations.len()) as u32;
        bases.push(forward.len() as u32);
    }
    let partition_start = vec![
        0,
        kind_start[1].saturating_add(extra_count),
        kind_start[2].saturating_add(extra_count),
        kind_start[4].saturating_add(extra_count),
        kind_start[5].saturating_add(extra_count),
        (packed.len() as u32).saturating_add(extra_count),
        (packed.len() as u32).saturating_add(extra_count),
        (packed.len() as u32).saturating_add(extra_count),
        (packed.len() as u32).saturating_add(extra_count),
        (packed.len() as u32).saturating_add(extra_count),
    ];
    let partition_offsets = vec![
        0,
        domain_counts[0] as u32 + 1,
        (domain_counts[0] + domain_counts[1]) as u32 + 2,
        (domain_counts[0] + domain_counts[1] + domain_counts[2]) as u32 + 3,
        (domain_counts.iter().sum::<usize>() + 4) as u32,
        (domain_counts.iter().sum::<usize>() + 4) as u32,
        (domain_counts.iter().sum::<usize>() + 4) as u32,
        (domain_counts.iter().sum::<usize>() + 4) as u32,
        (domain_counts.iter().sum::<usize>() + 4) as u32,
    ];
    let partition_counts = vec![
        domain_counts[0] as u32,
        domain_counts[1] as u32,
        domain_counts[2] as u32,
        domain_counts[3] as u32,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut storage_keys = Vec::with_capacity(partition_offsets[4] as usize);
    let mut storage_base = 0u32;
    for counts in domain_key_counts {
        storage_keys.push(storage_base);
        for count in counts {
            storage_base = storage_base.saturating_add(count);
            storage_keys.push(storage_base);
        }
    }
    let mut extra_reverse_ties = Vec::with_capacity(extra_methods.len());
    let mut extra_occurrences = HashMap::<(u8, u32), u32>::new();
    for (&file_id, &method) in extra_declarations.iter().zip(&extra_methods) {
        let occurrence = extra_occurrences.entry((file_id, method)).or_default();
        let rank = method_ranks
            .get(file_id as usize)
            .and_then(|ranks| ranks.get(method as usize))
            .copied()
            .unwrap_or(method);
        extra_reverse_ties.push((u64::from(rank) << 32) | u64::from(*occurrence));
        *occurrence = occurrence.saturating_add(1);
    }
    let mut reverse_keys = Vec::with_capacity(declarations.len() + extra_count as usize);
    let packed_partitions = [
        (kind_start[0], kind_start[1]),
        (kind_start[1], kind_start[2]),
        (kind_start[2], kind_start[4]),
        (kind_start[4], kind_start[5]),
    ];
    for (partition_index, &(start, end)) in packed_partitions.iter().enumerate() {
        let mut order: Vec<u32> = (start..end).collect();
        order.sort_by_key(|&index| {
            (
                packed[index as usize],
                declarations[index as usize],
                reverse_ties[index as usize],
            )
        });
        reverse_keys.extend(order);
        if partition_index == 0 && has_extra_kind {
            let mut extra_order: Vec<usize> = (0..extra_values.len()).collect();
            extra_order.sort_by_key(|&index| {
                (
                    extra_values[index],
                    extra_declarations[index],
                    extra_reverse_ties[index],
                )
            });
            reverse_keys.extend(
                extra_order
                    .into_iter()
                    .map(|index| packed.len() as u32 + index as u32),
            );
        }
    }
    let arrays: [&[u32]; 9] = [
        &extra_values,
        &kind_start,
        &forward,
        &bases,
        &partition_start,
        &partition_offsets,
        &partition_counts,
        &storage_keys,
        &reverse_keys,
    ];
    let mut out = b"MRS5".to_vec();
    out.push(1);
    out.extend_from_slice(&((declarations.len() + extra_declarations.len()) as u32).to_le_bytes());
    out.extend_from_slice(&declarations);
    out.extend_from_slice(&extra_declarations);
    // Reference MRS5 uses a two-byte packed index column for this dataset;
    // keep the declaration width independent from the packed storage width.
    out.push(2);
    out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    for index in packed {
        out.extend_from_slice(&(index as u16).to_le_bytes());
    }
    for values in arrays {
        out.extend_from_slice(&(values.len() as u32).to_le_bytes());
        for value in values {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    out
}

fn radix_permutation_i64(values: &[i64]) -> Vec<u32> {
    let mut order: Vec<u32> = (0..values.len() as u32).collect();
    let mut scratch = vec![0u32; order.len()];
    for shift in [0u32, 16, 32, 48] {
        let mut counts = vec![0usize; 1 << 16];
        for &index in &order {
            let key = (values[index as usize] as u64) ^ (1u64 << 63);
            counts[((key >> shift) & 0xffff) as usize] += 1;
        }
        let mut offset = 0usize;
        for count in &mut counts {
            let next = offset + *count;
            *count = offset;
            offset = next;
        }
        for &index in &order {
            let key = (values[index as usize] as u64) ^ (1u64 << 63);
            let bucket = ((key >> shift) & 0xffff) as usize;
            scratch[counts[bucket]] = index;
            counts[bucket] += 1;
        }
        std::mem::swap(&mut order, &mut scratch);
    }
    order
}

fn native_section_metadata(section: &[u8]) -> [u8; 32] {
    // v0.1.1 retains the section length but drops the CRC/tail descriptor
    // fields, matching the mmap cache layout used by the release binary.
    let mut metadata = [0u8; 32];
    metadata[4..12].copy_from_slice(&(section.len() as u64).to_le_bytes());
    metadata
}

fn native_crc32(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

/// Header of a native sidecar section.
///
/// Native sidecars currently use a compact, columnar payload after the
/// four-byte magic and count.  Keeping the header parser separate from the
/// column decoder lets callers validate a section before allocating any row
/// buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeSidecarHeader {
    pub magic: [u8; 4],
    pub count: u32,
    pub declaration_width: u8,
    pub payload_offset: usize,
}

impl NativeSidecarHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, LoadError> {
        if bytes.len() < 8 {
            return Err(LoadError("native sidecar is truncated".into()));
        }
        let magic = bytes[..4]
            .try_into()
            .map_err(|_| LoadError("native sidecar has an invalid header".into()))?;
        if !matches!(&magic, b"MRS5" | b"MNS3" | b"MIS1" | b"DXR1") {
            return Err(LoadError(
                "native sidecar has an unrecognized header".into(),
            ));
        }
        let (declaration_width, count, payload_offset) = if &magic == b"DXR1" {
            (
                0,
                u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
                8usize,
            )
        } else {
            if bytes.len() < 9 {
                return Err(LoadError("native sidecar declaration is truncated".into()));
            }
            let width = bytes[4];
            if width == 0 || width > 4 {
                return Err(LoadError(
                    "native sidecar declaration width is invalid".into(),
                ));
            }
            let count = u32::from_le_bytes(bytes[5..9].try_into().unwrap());
            let payload_offset = 9usize
                .checked_add(
                    (width as usize)
                        .checked_mul(count as usize)
                        .ok_or_else(|| LoadError("native sidecar declaration overflows".into()))?,
                )
                .ok_or_else(|| LoadError("native sidecar declaration overflows".into()))?;
            if payload_offset > bytes.len() {
                return Err(LoadError(
                    "native sidecar declaration exceeds section".into(),
                ));
            }
            (width, count, payload_offset)
        };
        Ok(Self {
            magic,
            count,
            declaration_width,
            payload_offset,
        })
    }
}

/// Bounds-checked cursor for the column/CSR payload after a native sidecar
/// header.  MRS5/MNS3 use bit-packed columns in the reference cache; this
/// cursor deliberately exposes only primitive reads, so malformed streams
/// cannot trigger an out-of-bounds slice while a higher-level decoder is
/// selecting a row.
#[derive(Debug, Clone, Copy)]
pub struct NativeCsrCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    header: NativeSidecarHeader,
}

impl<'a> NativeCsrCursor<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, LoadError> {
        let header = NativeSidecarHeader::parse(bytes)?;
        Ok(Self {
            bytes,
            pos: header.payload_offset,
            header,
        })
    }

    pub fn header(&self) -> NativeSidecarHeader {
        self.header
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    pub fn skip(&mut self, len: usize) -> Result<(), LoadError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| LoadError("native sidecar cursor overflow".into()))?;
        if end > self.bytes.len() {
            return Err(LoadError("native sidecar is truncated".into()));
        }
        self.pos = end;
        Ok(())
    }

    pub fn read_u32(&mut self) -> Result<u32, LoadError> {
        let end = self
            .pos
            .checked_add(4)
            .ok_or_else(|| LoadError("native sidecar cursor overflow".into()))?;
        let value = u32::from_le_bytes(
            self.bytes
                .get(self.pos..end)
                .ok_or_else(|| LoadError("native sidecar is truncated".into()))?
                .try_into()
                .unwrap(),
        );
        self.pos = end;
        Ok(value)
    }

    pub fn read_u64(&mut self) -> Result<u64, LoadError> {
        let end = self
            .pos
            .checked_add(8)
            .ok_or_else(|| LoadError("native sidecar cursor overflow".into()))?;
        let value = u64::from_le_bytes(
            self.bytes
                .get(self.pos..end)
                .ok_or_else(|| LoadError("native sidecar is truncated".into()))?
                .try_into()
                .unwrap(),
        );
        self.pos = end;
        Ok(value)
    }

    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], LoadError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| LoadError("native sidecar cursor overflow".into()))?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| LoadError("native sidecar is truncated".into()))?;
        self.pos = end;
        Ok(value)
    }
}

/// Decoded column payload of an `MNS3` method-numbers sidecar.
///
/// The reference format stores one opcode and one signed 64-bit value for
/// each edge, followed by a monotone forward CSR and a permutation of the
/// edge ordinals.  Method/class identity resolution is performed by the
/// companion method-identity sidecar, so this type intentionally exposes the
/// numeric columns without fabricating descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeMethodNumbers {
    pub opcode: Vec<u8>,
    pub values: Vec<i64>,
    pub forward_csr: Vec<u32>,
    pub reverse_perm: Vec<u32>,
}

/// Method-to-class identity column from the native `method_identities.native`
/// sidecar. The sidecar stores one little-endian u16 class index per method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeMethodIdentities {
    pub class_idx: Vec<u32>,
    pub file_ranges: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeMethodRefRow {
    pub method_idx: u32,
    pub kind: u8,
    pub index: u32,
}

/// Decode the packed index and CSR columns of an MRS5 method-reference
/// section. Kind partitions are string, type, field-get, field-put, and
/// method; rows within each partition are recovered through the forward CSR
/// and reverse permutation columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeMethodRefs {
    pub packed_index: Vec<u32>,
    pub kind_start: Vec<u32>,
    pub forward_csr: Vec<u32>,
    pub forward_csr_base: Vec<u32>,
    pub reverse_perm: Vec<u32>,
    /// Native storage-domain key starts (strings, types, fields, methods).
    pub storage_keys: Vec<u32>,
    pub partition_offsets: Vec<u32>,
    pub partition_counts: Vec<u32>,
}

impl NativeMethodRefs {
    pub fn decode(bytes: &[u8]) -> Result<Self, LoadError> {
        let header = NativeSidecarHeader::parse(bytes)?;
        if &header.magic != b"MRS5" {
            return Err(LoadError(
                "native method-refs section has the wrong header".into(),
            ));
        }
        let mut cursor = NativeCsrCursor::parse(bytes)?;
        let width = cursor.read_bytes(1)?[0] as usize;
        if !matches!(width, 1 | 2 | 4) {
            return Err(LoadError(
                "native method-refs packed width is invalid".into(),
            ));
        }
        let packed_len = cursor.read_u32()? as usize;
        if packed_len != header.count as usize {
            return Err(LoadError(
                "native method-refs packed length is inconsistent".into(),
            ));
        }
        let packed_bytes = cursor.read_bytes(
            packed_len
                .checked_mul(width)
                .ok_or_else(|| LoadError("native method-refs packed column overflows".into()))?,
        )?;
        let mut packed_index = Vec::with_capacity(packed_len);
        for chunk in packed_bytes.chunks_exact(width) {
            packed_index.push(match width {
                1 => chunk[0] as u32,
                2 => u16::from_le_bytes([chunk[0], chunk[1]]) as u32,
                4 => u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                _ => unreachable!(),
            });
        }
        let mut arrays = Vec::with_capacity(9);
        for _ in 0..9 {
            let len = cursor.read_u32()? as usize;
            if len > MAX_CACHE_VECTOR {
                return Err(LoadError("native method-refs array is too large".into()));
            }
            let mut values = Vec::with_capacity(len);
            for _ in 0..len {
                values.push(cursor.read_u32()?);
            }
            arrays.push(values);
        }
        if cursor.remaining() != 0 {
            return Err(LoadError(
                "native method-refs sidecar has trailing bytes".into(),
            ));
        }
        if header.count as usize > MAX_CACHE_VECTOR {
            return Err(LoadError(
                "native method-refs row count is too large".into(),
            ));
        }
        let kind_start = arrays.get(1).cloned().unwrap_or_default();
        let forward_csr = arrays.get(2).cloned().unwrap_or_default();
        let forward_csr_base = arrays.get(3).cloned().unwrap_or_default();
        let partition_offsets = arrays.get(5).cloned().unwrap_or_default();
        let partition_counts = arrays.get(6).cloned().unwrap_or_default();
        let storage_keys = arrays.get(7).cloned().unwrap_or_default();
        let reverse_perm = arrays.get(8).cloned().unwrap_or_default();
        if kind_start.len() < 2
            || forward_csr_base.len() != kind_start.len()
            || reverse_perm.len() != packed_index.len()
            || (!partition_offsets.is_empty()
                && (partition_offsets.len() != partition_counts.len()
                    || partition_offsets.len() < 4))
        {
            return Err(LoadError(
                "native method-refs CSR columns have inconsistent lengths".into(),
            ));
        }
        validate_monotone(
            "method_refs kind starts",
            &kind_start,
            packed_index.len() as u32,
        )?;
        validate_monotone(
            "method_refs CSR bases",
            &forward_csr_base,
            forward_csr.len() as u32,
        )?;
        if !partition_offsets.is_empty() {
            validate_monotone(
                "method_refs partition offsets",
                &partition_offsets,
                storage_keys.len() as u32,
            )?;
            if partition_offsets.len() != partition_counts.len()
                || partition_offsets
                    .iter()
                    .zip(partition_counts.iter())
                    .any(|(&offset, &count)| {
                        let width = if count == 0 { 0 } else { count as usize + 1 };
                        (offset as usize)
                            .checked_add(width)
                            .is_none_or(|end| end > storage_keys.len())
                    })
                || !is_permutation(&reverse_perm, packed_index.len())
            {
                return Err(LoadError(
                    "native method-refs storage domains are invalid".into(),
                ));
            }
            validate_monotone(
                "method_refs storage keys",
                &storage_keys,
                packed_index.len() as u32,
            )?;
        }
        for kind in 0..kind_start.len() - 1 {
            let q_start = kind_start[kind] as usize;
            let q_end = kind_start[kind + 1] as usize;
            let base_start = forward_csr_base[kind] as usize;
            let base_end = forward_csr_base[kind + 1] as usize;
            if q_start > q_end
                || q_end > packed_index.len()
                || base_start > base_end
                || base_end > forward_csr.len()
                || base_end - base_start == 0
            {
                return Err(LoadError(
                    "native method-refs CSR partition is invalid".into(),
                ));
            }
            let mut seen = vec![false; reverse_perm.len()];
            for q in q_start..q_end {
                let slot = reverse_perm[q] as usize;
                if slot >= seen.len() || seen[slot] {
                    return Err(LoadError(
                        "native method-refs reverse permutation is invalid".into(),
                    ));
                }
                seen[slot] = true;
            }
            let csr = &forward_csr[base_start..base_end];
            validate_monotone("method_refs forward CSR", csr, (q_end - q_start) as u32)?;
        }
        Ok(Self {
            packed_index,
            kind_start,
            forward_csr,
            forward_csr_base,
            reverse_perm,
            storage_keys,
            partition_offsets,
            partition_counts,
        })
    }

    pub fn rows(&self) -> Result<Vec<NativeMethodRefRow>, LoadError> {
        // Native MRS5 stores packed indices in query order while the CSR is
        // indexed in storage order.  reverse_perm[storage] gives the query
        // ordinal; invert that relationship by placing each decoded row at
        // its query slot.  Hand-built legacy payloads omit storage domains and
        // retain their historical direct traversal below.
        if !self.storage_keys.is_empty() {
            let mut ordered = vec![None; self.packed_index.len()];
            for kind in 0..self.kind_start.len() - 1 {
                let storage_start = self.kind_start[kind] as usize;
                let storage_end = self.kind_start[kind + 1] as usize;
                let base_start = self.forward_csr_base[kind] as usize;
                let base_end = self.forward_csr_base[kind + 1] as usize;
                let csr = &self.forward_csr[base_start..base_end];
                if csr.is_empty() {
                    continue;
                }
                for storage in storage_start..storage_end {
                    let local = storage - storage_start;
                    let mut lo = 0usize;
                    let mut hi = csr.len();
                    while lo < hi {
                        let mid = (lo + hi) / 2;
                        if csr[mid] <= local as u32 {
                            lo = mid + 1;
                        } else {
                            hi = mid;
                        }
                    }
                    let method_idx = lo.saturating_sub(1);
                    let start = csr[method_idx] as usize;
                    let end = csr
                        .get(method_idx + 1)
                        .copied()
                        .unwrap_or(storage_end as u32 - storage_start as u32)
                        as usize;
                    if local < start || local >= end {
                        return Err(LoadError("native method_refs CSR row is invalid".into()));
                    }
                    let query = self.reverse_perm[storage] as usize;
                    if query >= ordered.len() || ordered[query].is_some() {
                        return Err(LoadError(
                            "native method_refs reverse row is invalid".into(),
                        ));
                    }
                    ordered[query] = Some(NativeMethodRefRow {
                        method_idx: method_idx as u32,
                        kind: kind as u8,
                        index: self.packed_index[query],
                    });
                }
            }
            return ordered
                .into_iter()
                .map(|row| {
                    row.ok_or_else(|| {
                        LoadError("native method_refs reverse domain is incomplete".into())
                    })
                })
                .collect();
        }

        let mut rows = Vec::new();
        for kind in 0..self.kind_start.len() - 1 {
            let q_start = self.kind_start[kind] as usize;
            let q_end = self.kind_start[kind + 1] as usize;
            let base_start = self.forward_csr_base[kind] as usize;
            let base_end = self.forward_csr_base[kind + 1] as usize;
            let csr = &self.forward_csr[base_start..base_end];
            if csr.is_empty() {
                continue;
            }
            for q in q_start..q_end {
                let local = q - q_start;
                let mut lo = 0usize;
                let mut hi = csr.len();
                while lo < hi {
                    let mid = (lo + hi) / 2;
                    if (csr[mid] as usize) <= local {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                let method_idx = lo.saturating_sub(1);
                let start = csr[method_idx] as usize;
                let end = csr
                    .get(method_idx + 1)
                    .copied()
                    .map(|value| value as usize)
                    .unwrap_or(q_end - q_start);
                if local < start || local >= end {
                    return Err(LoadError("native method_refs CSR row is invalid".into()));
                }
                rows.push(NativeMethodRefRow {
                    method_idx: method_idx as u32,
                    kind: kind as u8,
                    index: self.packed_index[q],
                });
            }
        }
        Ok(rows)
    }
}

fn is_permutation(values: &[u32], domain: usize) -> bool {
    if values.len() != domain {
        return false;
    }
    let mut seen = vec![false; domain];
    for &value in values {
        let slot = value as usize;
        if slot >= domain || seen[slot] {
            return false;
        }
        seen[slot] = true;
    }
    true
}

fn validate_monotone(label: &str, values: &[u32], max: u32) -> Result<(), LoadError> {
    let mut previous = 0;
    for (index, &value) in values.iter().enumerate() {
        if index != 0 && value < previous {
            return Err(LoadError(format!("native {label} is not monotonic")));
        }
        if value > max {
            return Err(LoadError(format!(
                "native {label} entry exceeds its domain"
            )));
        }
        previous = value;
    }
    Ok(())
}

impl NativeMethodIdentities {
    pub fn decode(bytes: &[u8]) -> Result<Self, LoadError> {
        let header = NativeSidecarHeader::parse(bytes)?;
        if &header.magic != b"MIS1" || !matches!(header.declaration_width, 1 | 2 | 4) {
            return Err(LoadError(
                "native method-identities section has the wrong header".into(),
            ));
        }
        let mut class_idx = Vec::with_capacity(header.count as usize);
        let declarations = bytes.get(9..header.payload_offset).ok_or_else(|| {
            LoadError("native method-identities declarations are truncated".into())
        })?;
        let width = header.declaration_width as usize;
        for chunk in declarations.chunks_exact(width) {
            let value = match width {
                1 => chunk[0] as u32,
                2 => u16::from_le_bytes([chunk[0], chunk[1]]) as u32,
                4 => u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                _ => unreachable!(),
            };
            class_idx.push(value);
        }
        if class_idx.len() != header.count as usize {
            return Err(LoadError(
                "native method-identities count is inconsistent".into(),
            ));
        }
        let mut cursor = NativeCsrCursor::parse(bytes)?;
        let directory_len = cursor.read_u32()? as usize;
        if !(2..=4096).contains(&directory_len) {
            return Err(LoadError(
                "native method-identities file directory is invalid".into(),
            ));
        }
        let mut file_ranges = Vec::with_capacity(directory_len);
        for _ in 0..directory_len {
            file_ranges.push(cursor.read_u32()?);
        }
        if file_ranges.first().copied() != Some(0)
            || file_ranges.last().copied() != Some(header.count)
            || file_ranges.windows(2).any(|pair| pair[0] > pair[1])
            || cursor.remaining() != 0
        {
            return Err(LoadError(
                "native method-identities file directory is invalid".into(),
            ));
        }
        Ok(Self {
            class_idx,
            file_ranges,
        })
    }
}

impl NativeMethodNumbers {
    pub fn decode(bytes: &[u8]) -> Result<Self, LoadError> {
        let header = NativeSidecarHeader::parse(bytes)?;
        if &header.magic != b"MNS3" {
            return Err(LoadError(
                "native method-numbers section has the wrong header".into(),
            ));
        }
        if header.declaration_width != 1 {
            return Err(LoadError(
                "native method-numbers declaration width is invalid".into(),
            ));
        }
        let edge_count = header.count as usize;
        if edge_count > MAX_CACHE_VECTOR {
            return Err(LoadError(
                "native method-numbers row count is too large".into(),
            ));
        }
        let mut cursor = NativeCsrCursor::parse(bytes)?;
        let opcode_len = cursor.read_u32()? as usize;
        if opcode_len != edge_count {
            return Err(LoadError(format!(
                "method_numbers opcode length {opcode_len} != edge count {edge_count}"
            )));
        }
        let opcode = cursor.read_bytes(opcode_len)?.to_vec();

        let value_len = cursor.read_u32()? as usize;
        if value_len != edge_count {
            return Err(LoadError(format!(
                "method_numbers value length {value_len} != edge count {edge_count}"
            )));
        }
        let mut values = Vec::with_capacity(value_len);
        for _ in 0..value_len {
            values.push(cursor.read_u64()? as i64);
        }

        // Native MNS3 calls the remaining columns `aux` and `method_idx`.
        // The pre-native Rust writer called the same slots CSR and reverse;
        // accept both layouts, selecting the legacy interpretation only when
        // the third column is at least as large as the edge domain and is a
        // genuine CSR/permutation pair.
        let third_len = cursor.read_u32()? as usize;
        if third_len > MAX_CACHE_VECTOR {
            return Err(LoadError(
                "method_numbers auxiliary column is too large".into(),
            ));
        }
        let mut third = Vec::with_capacity(third_len);
        for _ in 0..third_len {
            third.push(cursor.read_u32()?);
        }
        let fourth_len = cursor.read_u32()? as usize;
        if fourth_len != edge_count {
            return Err(LoadError(format!(
                "method_numbers method-index length {fourth_len} != edge count {edge_count}"
            )));
        }
        let mut fourth = Vec::with_capacity(fourth_len);
        for _ in 0..fourth_len {
            fourth.push(cursor.read_u32()?);
        }
        if cursor.remaining() != 0 {
            return Err(LoadError(
                "method_numbers sidecar has trailing bytes".into(),
            ));
        }

        let legacy_csr = third_len >= edge_count
            && third.first().copied().unwrap_or(0) == 0
            && third.last().copied().unwrap_or(0) == edge_count as u32
            && third.windows(2).all(|pair| pair[0] <= pair[1])
            && is_permutation(&fourth, edge_count);
        if legacy_csr {
            Ok(Self {
                opcode,
                values,
                forward_csr: third,
                reverse_perm: fourth,
            })
        } else {
            if third.first().copied().unwrap_or(0) != 0
                || third.windows(2).any(|pair| pair[0] > pair[1])
                || third.last().copied().unwrap_or(0) > edge_count as u32
            {
                return Err(LoadError(
                    "method_numbers auxiliary CSR is not monotonic".into(),
                ));
            }
            // The release MNS3 sidecar stores the compact method-major CSR in
            // `aux`; the final column is a physical-row permutation used by
            // the native flat executor, not a method-index column.  Keep the
            // CSR as the public forward mapping so row reconstruction remains
            // compatible with both the official 3032-entry aux column and
            // legacy full-length CSR payloads.
            Ok(Self {
                opcode,
                values,
                forward_csr: third,
                reverse_perm: fourth,
            })
        }
    }
}

/// Read the small native DXC2 count sections emitted by the reference cache.
/// This keeps `query-cache SELECT count(*)` useful across the native container
/// without pretending that the current Rust row decoder understands every
/// native column section.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn native_manifest_bytes(bytes: &[u8]) -> Result<&[u8], LoadError> {
    if bytes.get(..4) == Some(b"DXC2") {
        let sections = parse_native_container(bytes)?;
        let section = sections
            .iter()
            .find(|section| section.name == "manifest.txt")
            .ok_or_else(|| LoadError("cache manifest section is missing".into()))?;
        bytes
            .get(section.offset..section.offset + section.length)
            .ok_or_else(|| LoadError("cache manifest section exceeds file".into()))
    } else {
        // Keep the small public helper useful for callers that persisted only
        // the manifest text before native containers gained a TOC.
        Ok(bytes)
    }
}

#[derive(Debug, Clone)]
struct NativeCacheSection {
    name: String,
    offset: usize,
    length: usize,
}

fn native_section_metadata_valid(
    bytes: &[u8],
    offset: usize,
    length: usize,
    metadata: &[u8],
) -> bool {
    if metadata.len() != 32 {
        return false;
    }
    // v0.1.1 metadata has a zero CRC and zero tail; only the encoded length is
    // authoritative. This intentionally accepts tampered CRC/tail bytes the
    // same way as the native reader.
    if metadata[..4].iter().all(|byte| *byte == 0) && metadata[12..].iter().all(|byte| *byte == 0) {
        let expected_len = u64::from_le_bytes(metadata[4..12].try_into().unwrap());
        return expected_len == length as u64;
    }
    let expected_crc = u32::from_le_bytes(metadata[..4].try_into().unwrap());
    let expected_len = u64::from_le_bytes(metadata[4..12].try_into().unwrap());
    let Some(end) = offset.checked_add(length) else {
        return false;
    };
    expected_len == length as u64
        && metadata[12..].iter().all(|byte| *byte == 0)
        && native_crc32(bytes.get(offset..end).unwrap_or_default()) == expected_crc
}

/// Parse and validate the DXC2 header and TOC exactly once.  All consumers
/// (format detection, count reads, and section decoders) share this validator;
/// this avoids a malformed TOC being accepted by one path and rejected by
/// another after a second, subtly different bounds walk.
fn parse_native_container(bytes: &[u8]) -> Result<Vec<NativeCacheSection>, LoadError> {
    if bytes.len() < 0x20 || &bytes[..4] != b"DXC2" {
        return Err(LoadError("invalid cache magic (expected DXC2)".into()));
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != 2 {
        return Err(LoadError(format!("unsupported cache version {version}")));
    }
    let section_count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if section_count == 0 || section_count > 4096 {
        return Err(LoadError("invalid DXC2 section count".into()));
    }
    if bytes[12..16].iter().any(|byte| *byte != 0) || bytes[24..32].iter().any(|byte| *byte != 0) {
        return Err(LoadError("invalid DXC2 reserved header bytes".into()));
    }
    let toc = usize::try_from(u64::from_le_bytes(bytes[16..24].try_into().unwrap()))
        .map_err(|_| LoadError("DXC2 TOC offset overflows host usize".into()))?;
    if toc < 0x20 || toc > bytes.len() {
        return Err(LoadError("DXC2 TOC offset is outside the cache".into()));
    }
    let mut cursor = toc;
    let mut names = HashSet::with_capacity(section_count);
    let mut sections = Vec::with_capacity(section_count);
    for _ in 0..section_count {
        let name_len_end = cursor
            .checked_add(4)
            .ok_or_else(|| LoadError("DXC2 TOC entry overflows".into()))?;
        let name_len = u32::from_le_bytes(
            bytes
                .get(cursor..name_len_end)
                .ok_or_else(|| LoadError("DXC2 TOC is truncated".into()))?
                .try_into()
                .unwrap(),
        ) as usize;
        if name_len == 0 || name_len > 0x100 {
            return Err(LoadError("invalid DXC2 section name length".into()));
        }
        let name_start = name_len_end;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(|| LoadError("DXC2 section name overflows".into()))?;
        let name = std::str::from_utf8(
            bytes
                .get(name_start..name_end)
                .ok_or_else(|| LoadError("DXC2 TOC section name is truncated".into()))?,
        )
        .map_err(|_| LoadError("DXC2 section name is not UTF-8".into()))?
        .to_owned();
        if !names.insert(name.clone()) {
            return Err(LoadError(format!("duplicate DXC2 section {name}")));
        }
        let offset_start = name_end;
        let length_start = offset_start
            .checked_add(8)
            .ok_or_else(|| LoadError("DXC2 section offset overflows".into()))?;
        let metadata_start = length_start
            .checked_add(8)
            .ok_or_else(|| LoadError("DXC2 section length overflows".into()))?;
        let entry_end = metadata_start
            .checked_add(32)
            .ok_or_else(|| LoadError("DXC2 TOC entry overflows".into()))?;
        let offset = usize::try_from(u64::from_le_bytes(
            bytes
                .get(offset_start..length_start)
                .ok_or_else(|| LoadError("DXC2 TOC offset is truncated".into()))?
                .try_into()
                .unwrap(),
        ))
        .map_err(|_| LoadError("DXC2 section offset overflows host usize".into()))?;
        let length = usize::try_from(u64::from_le_bytes(
            bytes
                .get(length_start..metadata_start)
                .ok_or_else(|| LoadError("DXC2 TOC length is truncated".into()))?
                .try_into()
                .unwrap(),
        ))
        .map_err(|_| LoadError("DXC2 section length overflows host usize".into()))?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| LoadError(format!("DXC2 section {name} range overflows")))?;
        if offset < 0x20 || end > toc || end > bytes.len() {
            return Err(LoadError(format!(
                "DXC2 section {name} exceeds file bounds"
            )));
        }
        let metadata = bytes
            .get(metadata_start..entry_end)
            .ok_or_else(|| LoadError("DXC2 TOC checksum is truncated".into()))?;
        if !native_section_metadata_valid(bytes, offset, length, metadata) {
            return Err(LoadError(format!(
                "DXC2 section checksum mismatch for {name}"
            )));
        }
        sections.push(NativeCacheSection {
            name,
            offset,
            length,
        });
        cursor = entry_end;
    }
    if cursor != bytes.len() {
        return Err(LoadError("DXC2 TOC does not end at EOF".into()));
    }
    let mut ranges = sections
        .iter()
        .map(|section| (section.offset, section.offset + section.length))
        .collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|(offset, _)| *offset);
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(LoadError("DXC2 sections overlap".into()));
    }
    Ok(sections)
}

fn native_section_bytes<'a>(bytes: &'a [u8], wanted: &str) -> Option<&'a [u8]> {
    let sections = parse_native_container(bytes).ok()?;
    let section = sections.iter().find(|section| section.name == wanted)?;
    bytes.get(section.offset..section.offset.checked_add(section.length)?)
}

fn native_cache_count(bytes: &[u8], table: &str) -> Option<u64> {
    let sections = parse_native_container(bytes).ok()?;
    let sidecar = match table.to_ascii_lowercase().as_str() {
        "dex_files" => Some(("dex_files.native", b"DXR1")),
        "id_items" => Some(("id_items.native", b"DXR1")),
        "proto_params" => Some(("proto_params.native", b"DXR1")),
        "type_lists" => Some(("type_lists.native", b"DXR1")),
        "type_list_entries" => Some(("type_list_entries.native", b"DXR1")),
        "method_opcodes" => Some(("method_opcode_stats.native", b"DXR1")),
        "method_handles" => Some(("method_handles.native", b"DXR1")),
        "call_sites" => Some(("call_sites.native", b"DXR1")),
        "call_site_args" => Some(("call_site_args.native", b"DXR1")),
        "encoded_arrays" => Some(("encoded_arrays.native", b"DXR1")),
        "encoded_array_values" => Some(("encoded_array_values.native", b"DXR1")),
        "encoded_array_owners" => Some(("encoded_array_owners.native", b"DXR1")),
        "class_data_items" => Some(("class_data_items.native", b"DXR1")),
        "class_static_values" => Some(("class_static_values.native", b"DXR1")),
        "class_interfaces" => Some(("class_interfaces.native", b"DXR1")),
        "class_fields" => Some(("class_fields.native", b"DXR1")),
        "class_methods" | "class_data_methods" => Some(("class_methods.native", b"DXR1")),
        "hiddenapi_flags" => Some(("hiddenapi_flags.native", b"DXR1")),
        "code_items" => Some(("code_items.native", b"DXR1")),
        "catch_handlers" => Some(("catch_handlers.native", b"DXR1")),
        "method_identities" => Some(("method_identities.native", b"MIS1")),
        "method_refs" => Some(("method_refs.native", b"MRS5")),
        "method_numbers" | "method_using_numbers" => Some(("method_numbers.native", b"MNS3")),
        "method_opcode_stats" => Some(("method_opcode_stats.native", b"DXR1")),
        _ => None,
    };
    if let Some((section_name, expected_magic)) = sidecar {
        let section = sections
            .iter()
            .find(|section| section.name == section_name)?;
        let data = bytes.get(section.offset..section.offset.checked_add(section.length)?)?;
        let header = NativeSidecarHeader::parse(data).ok()?;
        if &header.magic != expected_magic {
            return None;
        }
        return Some(header.count as u64);
    }
    let wanted = match table.to_ascii_lowercase().as_str() {
        "method_ids" | "methods" => Some(("method_count", 14usize)),
        "class_defs" | "classes" => Some(("class_count", 16usize)),
        "strings" => Some(("string_count", 6usize)),
        "types" | "type_ids" => Some(("type_count", 8usize)),
        "protos" | "proto_ids" => Some(("proto_count", 10usize)),
        "fields" | "field_ids" => Some(("field_count", 12usize)),
        _ => None,
    };
    if let Some((_, field)) = wanted {
        let section = sections
            .iter()
            .find(|section| section.name == "dex_files.native")?;
        let data = bytes.get(section.offset..section.offset.checked_add(section.length)?)?;
        if data.len() < 16 || &data[..4] != b"DXR1" {
            return None;
        }
        let count = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
        let mut p = 16usize;
        let mut total = 0u64;
        for _ in 0..count {
            let read_u32 = |p: &mut usize| -> Option<u32> {
                let value = u32::from_le_bytes(data.get(*p..*p + 4)?.try_into().ok()?);
                *p += 4;
                Some(value)
            };
            let read_u64 = |p: &mut usize| -> Option<u64> {
                let value = u64::from_le_bytes(data.get(*p..*p + 8)?.try_into().ok()?);
                *p += 8;
                Some(value)
            };
            let read_string = |p: &mut usize| -> Option<()> {
                let len = read_u32(p)? as usize;
                *p = p.checked_add(len)?;
                data.get(*p - len..*p)?;
                Some(())
            };
            read_string(&mut p)?;
            read_string(&mut p)?;
            read_u64(&mut p)?;
            read_string(&mut p)?;
            read_u32(&mut p)?;
            read_string(&mut p)?;
            let mut fields = [0u32; 20];
            for value in &mut fields {
                *value = read_u32(&mut p)?;
            }
            total = total.saturating_add(fields[field] as u64);
            // Two row-local identity fields follow the DEX header in the
            // native dex_files section.
            if p + 8 <= data.len() {
                read_u32(&mut p)?;
                read_u32(&mut p)?;
            }
        }
        return Some(total);
    }
    let section = sections
        .iter()
        .find(|section| section.name == "base_row_counts.native")?;
    let data = bytes.get(section.offset..section.offset.checked_add(section.length)?)?;
    if data.len() < 8 || &data[..4] != b"DXR1" {
        return None;
    }
    let count = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
    let mut p = 8usize;
    for _ in 0..count {
        let len = u32::from_le_bytes(data.get(p..p + 4)?.try_into().ok()?) as usize;
        p += 4;
        let name = std::str::from_utf8(data.get(p..p + len)?).ok()?;
        p += len;
        let value = u64::from_le_bytes(data.get(p..p + 8)?.try_into().ok()?);
        p += 8;
        if name == table {
            return Some(value);
        }
    }
    None
}

fn load_archive(
    path: &Path,
    files: &mut Vec<DexFile>,
    index_needs: IndexNeeds,
    eager_code_items: bool,
    full_code_items: bool,
    retain_classes: bool,
    retain_raw_bytes: bool,
    logical_file_base: u32,
    target_file_id: Option<u32>,
) -> Result<u32, LoadError> {
    let base = logical_file_base;
    // The inflater discovers the member count before dispatching workers. A
    // target file id can therefore be selected without inflating unrelated
    // multidex entries while the normal query path keeps parsing overlapped
    // with DEFLATE.
    let dex_count = dexsql_inflate::dex_entry_count(path)
        .map_err(|e| LoadError(format!("invalid ZIP/APK {}: {e}", path.display())))?
        as u32;
    if let Some(target) = target_file_id {
        if target < base || target >= base + dex_count {
            return Ok(base + dex_count);
        }
    }
    let parsed = dexsql_inflate::inflate_dex_entries_with(
        path,
        target_file_id.map(|target| target.saturating_sub(base) as usize),
        |index, name, bytes| {
            let mut file = parse_dex(
                bytes,
                base + index as u32,
                path.to_path_buf(),
                name,
                index_needs,
                eager_code_items,
                full_code_items,
                retain_classes,
            )
            .map_err(|e| dexsql_inflate::InflateError(e.to_string()))?;
            if !retain_raw_bytes {
                file.drop_raw_bytes();
            }
            Ok(file)
        },
    )
    .map_err(|e| LoadError(format!("invalid ZIP/APK {}: {e}", path.display())))?;
    files.extend(parsed);
    Ok(base + dex_count)
}

fn parse_dex(
    bytes: Vec<u8>,
    file_id: u32,
    source_path: PathBuf,
    entry_name: String,
    index_needs: IndexNeeds,
    eager_code_items: bool,
    full_code_items: bool,
    retain_classes: bool,
) -> Result<DexFile, LoadError> {
    if bytes.len() < 112 || &bytes[0..4] != b"dex\n" || bytes[7] != 0 {
        return Err(LoadError(format!("{} is not a DEX file", entry_name)));
    }
    let version = String::from_utf8_lossy(&bytes[4..7]).to_string();
    let read32 = |off| read_u32(&bytes, off);
    let checksum = read32(8)?;
    let signature_hex = bytes[12..32]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let header_size = read32(36)?;
    let endian_tag = read32(40)?;
    let map_off = read32(52)?;
    let string_count = read32(56)?;
    let string_ids_off = read32(60)?;
    let type_count = read32(64)?;
    let type_ids_off = read32(68)?;
    let proto_count = read32(72)?;
    let proto_ids_off = read32(76)?;
    let field_count = read32(80)?;
    let field_ids_off = read32(84)?;
    let method_count = read32(88)?;
    let method_ids_off = read32(92)?;
    let class_count = read32(96)?;
    let class_defs_off = read32(100)?;
    let data_size = read32(104)?;
    let data_off = read32(108)?;
    for (off, count, width, label) in [
        (string_ids_off, string_count, 4, "string_ids"),
        (type_ids_off, type_count, 4, "type_ids"),
        (proto_ids_off, proto_count, 12, "proto_ids"),
        (field_ids_off, field_count, 8, "field_ids"),
        (method_ids_off, method_count, 8, "method_ids"),
        (class_defs_off, class_count, 32, "class_defs"),
    ] {
        checked_range(&bytes, off, count, width)
            .map_err(|e| LoadError(format!("invalid {label}: {e}")))?;
    }
    checked_range(&bytes, data_off, data_size, 1)
        .map_err(|e| LoadError(format!("invalid data section: {e}")))?;

    let mut strings = Vec::with_capacity(string_count as usize);
    for i in 0..string_count {
        let off = read32(string_ids_off as usize + i as usize * 4)? as usize;
        let (utf16_len, mut pos) = read_uleb(&bytes, off)?;
        let start = pos;
        while pos < bytes.len() && bytes[pos] != 0 {
            pos += 1;
        }
        if pos >= bytes.len() {
            return Err(LoadError(format!("unterminated DEX string {i}")));
        }
        let decoded = decode_mutf8(&bytes[start..pos]).map_err(|e| {
            LoadError(format!(
                "invalid DEX string {i} (utf16_len={utf16_len}): {e}"
            ))
        })?;
        strings.push(decoded);
    }
    let types = (0..type_count)
        .map(|i| {
            Ok(TypeInfo {
                descriptor_idx: read32(type_ids_off as usize + i as usize * 4)?,
            })
        })
        .collect::<Result<Vec<_>, LoadError>>()?;
    let mut protos = Vec::with_capacity(proto_count as usize);
    for i in 0..proto_count {
        let off = proto_ids_off as usize + i as usize * 12;
        let shorty_idx = read32(off)?;
        let return_type_idx = read32(off + 4)?;
        let params_off = read32(off + 8)?; // proto_id layout: shorty, return_type, parameters
        let parameters = if params_off == 0 {
            Vec::new()
        } else {
            let size = read32(params_off as usize)? as usize;
            let mut values = Vec::with_capacity(size);
            for j in 0..size {
                values.push(read_u16(&bytes, params_off as usize + 4 + j * 2)?);
            }
            values
        };
        protos.push(ProtoInfo {
            shorty_idx,
            return_type_idx,
            parameters,
        });
    }
    let fields = if retain_classes {
        (0..field_count)
            .map(|i| {
                let off = field_ids_off as usize + i as usize * 8;
                Ok(FieldInfo {
                    class_idx: read_u16(&bytes, off)?,
                    type_idx: read_u16(&bytes, off + 2)?,
                    name_idx: read32(off + 4)?,
                })
            })
            .collect::<Result<Vec<_>, LoadError>>()?
    } else {
        Vec::new()
    };
    let mut methods = Vec::with_capacity(method_count as usize);
    // Class-only queries do not need the four method lookup maps. They are
    // sizeable on multidex APKs (one vector entry per method) and were the
    // largest avoidable part of the class relation's resident set. The query
    // planner sets `method_lookup` only when a methods relation is reachable.
    let build_method_lookups = index_needs.method_lookup;
    let mut methods_by_name = FxHashMap::default();
    let mut methods_by_class = FxHashMap::default();
    let mut methods_by_param_count = FxHashMap::default();
    let mut methods_by_return = FxHashMap::default();
    for i in 0..method_count {
        let off = method_ids_off as usize + i as usize * 8;
        let method = MethodInfo {
            class_idx: read_u16(&bytes, off)?,
            proto_idx: read_u16(&bytes, off + 2)?,
            name_idx: read32(off + 4)?,
        };
        if build_method_lookups {
            methods_by_name
                .entry(method.name_idx)
                .or_insert_with(Vec::new)
                .push(i);
            methods_by_class
                .entry(method.class_idx as u32)
                .or_insert_with(Vec::new)
                .push(i);
            if let Some(proto) = protos.get(method.proto_idx as usize) {
                methods_by_param_count
                    .entry(proto.parameters.len() as u32)
                    .or_insert_with(Vec::new)
                    .push(i);
                methods_by_return
                    .entry(proto.return_type_idx)
                    .or_insert_with(Vec::new)
                    .push(i);
            }
        }
        methods.push(method);
    }

    let mut classes = Vec::with_capacity(class_count as usize);
    // Option<CodeItem> contains several Vec headers even when it is None.
    // Reserving one for every referenced method cost over 100 MiB on large
    // multidex inputs although lazy loads never populate a single slot.
    let mut code_items = if eager_code_items && full_code_items {
        vec![None; method_count as usize]
    } else {
        Vec::new()
    };
    let mut code_offsets = Vec::new();
    let raw_bytes = Arc::new(bytes);
    let bytes = raw_bytes.clone();
    for class_def_idx in 0..class_count {
        let off = class_defs_off as usize + class_def_idx as usize * 32;
        let class_idx = read32_arc(&bytes, off)?;
        let access_flags = read32_arc(&bytes, off + 4)?;
        let superclass_idx = match read32_arc(&bytes, off + 8)? {
            u32::MAX => None,
            v => Some(v),
        };
        let interfaces_off = read32_arc(&bytes, off + 12)?;
        let source_file_idx = match read32_arc(&bytes, off + 16)? {
            u32::MAX => None,
            v => Some(v),
        };
        let class_data_off = read32_arc(&bytes, off + 24)?;
        if !retain_classes {
            if class_data_off != 0 {
                collect_code_offsets(&bytes, class_data_off as usize, &mut code_offsets)?;
            }
            continue;
        }
        let (fields_defined, methods_defined) = if class_data_off == 0 {
            (Vec::new(), Vec::new())
        } else {
            parse_class_data(
                &bytes,
                class_data_off as usize,
                &mut code_items,
                &mut code_offsets,
                eager_code_items,
                full_code_items,
            )?
        };
        let interfaces = if interfaces_off == 0 {
            Vec::new()
        } else {
            let size = read32_arc(&bytes, interfaces_off as usize)? as usize;
            (0..size)
                .map(|i| read_u16_arc(&bytes, interfaces_off as usize + 4 + i * 2))
                .collect::<Result<Vec<_>, _>>()?
        };
        classes.push(ClassInfo {
            class_def_idx,
            class_idx,
            access_flags,
            superclass_idx,
            interfaces,
            source_file_idx,
            class_data_off,
            fields: fields_defined,
            methods: methods_defined,
        });
    }
    let mut method_access_flags = vec![u32::MAX; method_count as usize];
    for class in &classes {
        for method in &class.methods {
            if let Some(slot) = method_access_flags.get_mut(method.method_idx as usize) {
                *slot = method.access_flags;
            }
        }
    }
    let mut dex = DexFile {
        file_id,
        source_path,
        entry_name,
        dex_version: version,
        checksum,
        signature_hex,
        header_size,
        endian_tag,
        map_off,
        string_ids_off,
        type_ids_off,
        proto_ids_off,
        field_ids_off,
        method_ids_off,
        class_defs_off,
        data_size,
        data_off,
        string_lookup: HashMap::new(),
        strings,
        types,
        protos,
        fields,
        methods,
        method_access_flags,
        methods_by_name,
        methods_by_param_count,
        methods_by_class,
        methods_by_return,
        fields_by_name: FxHashMap::default(),
        method_descriptors: Arc::new(OnceLock::new()),
        field_descriptors: Arc::new(OnceLock::new()),
        debug_rows_cache: Arc::new(OnceLock::new()),
        method_code_offsets: Arc::new(OnceLock::new()),
        bytes: Some(raw_bytes.clone()),
        byte_len: raw_bytes.len() as u64,
        method_descriptor_order: Arc::new(OnceLock::new()),
        string_utf16_ranks: Arc::new(OnceLock::new()),
        classes_by_idx_order: {
            let mut order: Vec<u32> = (0..classes.len() as u32).collect();
            order.sort_by_key(|&index| classes[index as usize].class_idx);
            order
        },
        classes,
        classes_by_superclass: FxHashMap::default(),
        classes_by_descriptor: FxHashMap::default(),
        code_items,
        method_strings: Vec::with_capacity(if index_needs.method_strings {
            method_count as usize / 4
        } else {
            0
        }),
        method_strings_by_string: FxHashMap::default(),
        method_numbers: Vec::with_capacity(if index_needs.method_numbers {
            method_count as usize / 2
        } else {
            0
        }),
        method_numbers_by_value: HashMap::new(),
        method_number_rows_by_value: FxHashMap::default(),
        method_calls: Vec::new(),
        method_field_accesses: Vec::new(),
        method_used_types: Vec::new(),
        meta: MetadataIndexes::default(),
    };
    rebuild_nonmethod_lookup_indexes(&mut dex);
    if index_needs.any() {
        if eager_code_items && !full_code_items {
            derive_code_indexes_from_offsets(&mut dex, &code_offsets, index_needs)?;
        } else {
            derive_code_indexes(&mut dex, index_needs);
        }
        if index_needs.method_strings {
            for row in &dex.method_strings {
                dex.method_strings_by_string
                    .entry(row.string_idx)
                    .or_default()
                    .push(row.method_idx);
            }
        }
        if index_needs.method_numbers {
            for (row_idx, row) in dex.method_numbers.iter().enumerate() {
                dex.method_number_rows_by_value
                    .entry(row.long_value)
                    .or_default()
                    .push(row_idx);
                dex.method_numbers_by_value
                    .entry(row.long_value)
                    .or_default()
                    .push(row.method_idx);
            }
        }
    }
    Ok(dex)
}

fn build_method_descriptor(dex: &DexFile, method_idx: u32) -> String {
    let Some(method) = dex.methods.get(method_idx as usize) else {
        return String::new();
    };
    let Some(proto) = dex.protos.get(method.proto_idx as usize) else {
        return String::new();
    };
    let mut out = String::new();
    out.push_str(dex.type_descriptor(method.class_idx as u32));
    out.push_str("->");
    out.push_str(dex.string(method.name_idx));
    out.push('(');
    for &param in &proto.parameters {
        out.push_str(dex.type_descriptor(param as u32));
    }
    out.push(')');
    out.push_str(dex.type_descriptor(proto.return_type_idx));
    out
}

fn build_field_descriptor(dex: &DexFile, field_idx: u32) -> String {
    let Some(field) = dex.fields.get(field_idx as usize) else {
        return String::new();
    };
    format!(
        "{}->{}:{}",
        dex.type_descriptor(field.class_idx as u32),
        dex.string(field.name_idx),
        dex.type_descriptor(field.type_idx as u32)
    )
}

fn rebuild_method_lookup_indexes(dex: &mut DexFile) {
    for (method_idx, method) in dex.methods.iter().enumerate() {
        dex.methods_by_name
            .entry(method.name_idx)
            .or_default()
            .push(method_idx as u32);
        dex.methods_by_class
            .entry(method.class_idx as u32)
            .or_default()
            .push(method_idx as u32);
        if let Some(proto) = dex.protos.get(method.proto_idx as usize) {
            dex.methods_by_param_count
                .entry(proto.parameters.len() as u32)
                .or_default()
                .push(method_idx as u32);
            dex.methods_by_return
                .entry(proto.return_type_idx)
                .or_default()
                .push(method_idx as u32);
        }
    }
}

fn rebuild_nonmethod_lookup_indexes(dex: &mut DexFile) {
    for (field_idx, field) in dex.fields.iter().enumerate() {
        dex.fields_by_name
            .entry(field.name_idx)
            .or_default()
            .push(field_idx as u32);
    }
    for (class_idx, class) in dex.classes.iter().enumerate() {
        if let Some(superclass_idx) = class.superclass_idx {
            dex.classes_by_superclass
                .entry(superclass_idx)
                .or_default()
                .push(class_idx as u32);
        }
        dex.classes_by_descriptor
            .entry(class.class_idx)
            .or_default()
            .push(class_idx as u32);
    }
}

/// Read only the class-data method records needed to locate code items.  The
/// compact query loader uses this when class/member relations are not part of
/// the requested batch, avoiding one allocation per defined field/method.
fn collect_code_offsets(
    bytes: &[u8],
    mut pos: usize,
    code_offsets: &mut Vec<(u32, u32)>,
) -> Result<(), LoadError> {
    let (static_fields, next) = read_uleb(bytes, pos)?;
    pos = next;
    let (instance_fields, next) = read_uleb(bytes, pos)?;
    pos = next;
    let (direct_methods, next) = read_uleb(bytes, pos)?;
    pos = next;
    let (virtual_methods, next) = read_uleb(bytes, pos)?;
    pos = next;
    for _ in 0..static_fields + instance_fields {
        pos = read_uleb(bytes, pos)?.1;
        pos = read_uleb(bytes, pos)?.1;
    }
    let mut method_idx = 0u32;
    for i in 0..direct_methods + virtual_methods {
        if i == direct_methods {
            method_idx = 0;
        }
        let (delta, next) = read_uleb(bytes, pos)?;
        method_idx = method_idx.wrapping_add(delta);
        pos = next;
        pos = read_uleb(bytes, pos)?.1;
        let (code_off, next) = read_uleb(bytes, pos)?;
        pos = next;
        if code_off != 0 {
            code_offsets.push((method_idx, code_off));
        }
    }
    Ok(())
}

fn parse_class_data(
    bytes: &[u8],
    mut pos: usize,
    code_items: &mut [Option<CodeItem>],
    code_offsets: &mut Vec<(u32, u32)>,
    eager_code_items: bool,
    full_code_items: bool,
) -> Result<(Vec<DefinedField>, Vec<DefinedMethod>), LoadError> {
    let (static_fields, next) = read_uleb(bytes, pos)?;
    pos = next;
    let (instance_fields, next) = read_uleb(bytes, pos)?;
    pos = next;
    let (direct_methods, next) = read_uleb(bytes, pos)?;
    pos = next;
    let (virtual_methods, next) = read_uleb(bytes, pos)?;
    pos = next;
    let mut fields = Vec::with_capacity((static_fields + instance_fields) as usize);
    let mut field_idx = 0u32;
    for i in 0..(static_fields + instance_fields) {
        if i == static_fields {
            field_idx = 0;
        }
        let delta = read_uleb(bytes, pos)?;
        field_idx = field_idx.wrapping_add(delta.0);
        pos = delta.1;
        let flags = read_uleb(bytes, pos)?;
        pos = flags.1;
        fields.push(DefinedField {
            field_idx,
            access_flags: flags.0,
            is_static: i < static_fields,
        });
    }
    let mut methods = Vec::with_capacity((direct_methods + virtual_methods) as usize);
    let mut method_idx = 0u32;
    for i in 0..(direct_methods + virtual_methods) {
        if i == direct_methods {
            method_idx = 0;
        }
        let delta = read_uleb(bytes, pos)?;
        method_idx = method_idx.wrapping_add(delta.0);
        pos = delta.1;
        let flags = read_uleb(bytes, pos)?;
        pos = flags.1;
        let code = read_uleb(bytes, pos)?;
        pos = code.1;
        if code.0 != 0 {
            code_offsets.push((method_idx, code.0));
        }
        if eager_code_items
            && full_code_items
            && code.0 != 0
            && (method_idx as usize) < code_items.len()
        {
            code_items[method_idx as usize] =
                Some(parse_code_item(bytes, code.0 as usize, full_code_items)?);
        }
        methods.push(DefinedMethod {
            method_idx,
            access_flags: flags.0,
            code_off: code.0,
            is_direct: i < direct_methods,
        });
    }
    Ok((fields, methods))
}

fn parse_code_item(bytes: &[u8], off: usize, full_code_items: bool) -> Result<CodeItem, LoadError> {
    let registers_size = read_u16(bytes, off)?;
    let ins_size = read_u16(bytes, off + 2)?;
    let outs_size = read_u16(bytes, off + 4)?;
    let tries_size = read_u16(bytes, off + 6)?;
    let debug_info_off = read_u32(bytes, off + 8)?;
    let insns_size = read_u32(bytes, off + 12)? as usize;
    let start = off + 16;
    checked_range(bytes, start as u32, insns_size as u32, 2).map_err(LoadError)?;
    let mut insns = Vec::with_capacity(insns_size);
    for i in 0..insns_size {
        insns.push(read_u16(bytes, start + i * 2)?);
    }
    // The tries array is four-byte aligned immediately after the instruction
    // units. The handler offsets in each try_item are relative to the start
    // of the encoded_catch_handler_list that follows the try array.
    let mut tries = Vec::new();
    let mut catch_handlers = Vec::new();
    if full_code_items && tries_size != 0 {
        let tries_off = (start + insns_size * 2 + 3) & !3;
        let tries_bytes = (tries_size as usize)
            .checked_mul(8)
            .ok_or_else(|| LoadError("try_item size overflow".into()))?;
        checked_range(bytes, tries_off as u32, tries_bytes as u32, 1).map_err(LoadError)?;
        for i in 0..tries_size as usize {
            let p = tries_off + i * 8;
            tries.push(TryItem {
                start_addr: read_u32(bytes, p)?,
                insn_count: read_u16(bytes, p + 4)? as u32,
                handler_off: read_u16(bytes, p + 6)?,
            });
        }
        let handlers_start = tries_off + tries_bytes;
        // A malformed handler list should make the DEX fail to load, just as
        // malformed string/class data does above. Decode every list so the
        // disassembler can render catches without touching raw bytes again.
        let (handler_count, mut pos) = read_uleb(bytes, handlers_start)?;
        for _ in 0..handler_count as usize {
            let offset = (pos - handlers_start) as u32;
            let (size, next) = read_sleb(bytes, pos)?;
            pos = next;
            let typed_count = size.unsigned_abs() as usize;
            let mut handlers = Vec::with_capacity(typed_count + usize::from(size <= 0));
            for _ in 0..typed_count {
                let (type_idx, next) = read_uleb(bytes, pos)?;
                pos = next;
                let (addr, next) = read_uleb(bytes, pos)?;
                pos = next;
                handlers.push(CatchHandler {
                    type_idx: Some(type_idx),
                    addr,
                });
            }
            if size <= 0 {
                let (addr, next) = read_uleb(bytes, pos)?;
                handlers.push(CatchHandler {
                    type_idx: None,
                    addr,
                });
                pos = next;
            }
            catch_handlers.push(CatchHandlerSet { offset, handlers });
        }
    }
    let mut opcode_count = 0u32;
    let mut opcode_pc = 0usize;
    while opcode_pc < insns.len() {
        let opcode = (insns[opcode_pc] & 0xff) as u8;
        if !is_payload_opcode(&insns, opcode_pc) {
            opcode_count = opcode_count.saturating_add(1);
        }
        opcode_pc = opcode_pc.saturating_add(opcode_width(opcode, &insns, opcode_pc).max(1));
    }
    Ok(CodeItem {
        code_off: off as u32,
        registers_size,
        ins_size,
        outs_size,
        tries_size,
        debug_info_off,
        insns,
        opcode_count,
        tries,
        catch_handlers,
    })
}

fn parse_debug_info(bytes: &[u8], debug_info_off: u32) -> Result<DebugRows, String> {
    let base = debug_info_off as usize;
    let (line_start, mut pos) = read_uleb(bytes, base).map_err(|e| e.to_string())?;
    let (parameters_size, next) = read_uleb(bytes, pos).map_err(|e| e.to_string())?;
    pos = next;
    let mut parameters = Vec::with_capacity(parameters_size as usize);
    for ordinal in 0..parameters_size {
        let (name_idx, next) = read_uleb(bytes, pos).map_err(|e| e.to_string())?;
        pos = next;
        parameters.push(DebugParameterRow {
            ordinal,
            // debug_info_item encodes string_idx + 1; zero means NO_INDEX.
            name_idx: debug_index(name_idx),
        });
    }
    let info = DebugInfoRow {
        debug_info_off,
        line_start,
        parameters_size,
    };
    let mut rows = DebugRows {
        info,
        parameters,
        positions: Vec::new(),
        locals: Vec::new(),
        opcodes: Vec::new(),
    };
    let mut address = 0u32;
    let mut line = line_start as i32;
    let mut source_file_idx = None;
    let mut prologue_end = false;
    let mut epilogue_begin = false;
    let mut position_ordinal = 0u32;
    let mut local_ordinal = 0u32;
    let mut opcode_ordinal = 0u32;
    loop {
        let opcode_off = pos;
        let opcode = *bytes
            .get(pos)
            .ok_or_else(|| "debug opcode stream ended before END_SEQUENCE".to_string())?
            as u32;
        pos += 1;
        let mut address_diff = None;
        let mut line_diff = None;
        let mut register_num = None;
        let mut name_idx = None;
        let mut type_idx = None;
        let mut signature_idx = None;
        let mut emits_position = false;
        let mut emits_local = false;
        match opcode {
            0x00 => {}
            0x01 => {
                let (diff, next) = read_uleb(bytes, pos).map_err(|e| e.to_string())?;
                pos = next;
                address = address.saturating_add(diff);
                address_diff = Some(diff);
            }
            0x02 => {
                let (diff, next) = read_sleb(bytes, pos).map_err(|e| e.to_string())?;
                pos = next;
                line = line.saturating_add(diff);
                line_diff = Some(diff);
            }
            0x03 => {
                let (register, next) = read_uleb(bytes, pos).map_err(|e| e.to_string())?;
                pos = next;
                let (name, next) = read_uleb(bytes, pos).map_err(|e| e.to_string())?;
                pos = next;
                let (ty, next) = read_uleb(bytes, pos).map_err(|e| e.to_string())?;
                pos = next;
                register_num = Some(register);
                name_idx = debug_index(name);
                type_idx = debug_index(ty);
                emits_local = true;
                rows.locals.push(DebugLocalRow {
                    ordinal: local_ordinal,
                    address,
                    event: "start".into(),
                    register_num: register,
                    name_idx,
                    type_idx,
                    signature_idx,
                });
                local_ordinal += 1;
            }
            0x04 => {
                let (register, next) = read_uleb(bytes, pos).map_err(|e| e.to_string())?;
                pos = next;
                let (name, next) = read_uleb(bytes, pos).map_err(|e| e.to_string())?;
                pos = next;
                let (ty, next) = read_uleb(bytes, pos).map_err(|e| e.to_string())?;
                pos = next;
                let (signature, next) = read_uleb(bytes, pos).map_err(|e| e.to_string())?;
                pos = next;
                register_num = Some(register);
                name_idx = debug_index(name);
                type_idx = debug_index(ty);
                signature_idx = debug_index(signature);
                emits_local = true;
                rows.locals.push(DebugLocalRow {
                    ordinal: local_ordinal,
                    address,
                    event: "start".into(),
                    register_num: register,
                    name_idx,
                    type_idx,
                    signature_idx,
                });
                local_ordinal += 1;
            }
            0x05 | 0x06 | 0x09 => {
                let (value, next) = read_uleb(bytes, pos).map_err(|e| e.to_string())?;
                pos = next;
                if opcode == 0x05 || opcode == 0x06 {
                    register_num = Some(value);
                    emits_local = true;
                    rows.locals.push(DebugLocalRow {
                        ordinal: local_ordinal,
                        address,
                        event: if opcode == 0x05 { "end" } else { "restart" }.into(),
                        register_num: value,
                        name_idx: None,
                        type_idx: None,
                        signature_idx: None,
                    });
                    local_ordinal += 1;
                } else {
                    source_file_idx = debug_index(value);
                }
            }
            0x07 => prologue_end = true,
            0x08 => epilogue_begin = true,
            0x0a..=0xff => {
                let adjusted = opcode - 0x0a;
                let addr_delta = adjusted / 15;
                let line_delta = (adjusted % 15) as i32 - 4;
                address = address.saturating_add(addr_delta);
                line = line.saturating_add(line_delta);
                address_diff = Some(addr_delta);
                line_diff = Some(line_delta);
                emits_position = true;
                rows.positions.push(DebugPositionRow {
                    ordinal: position_ordinal,
                    address,
                    line,
                    source_file_idx,
                    prologue_end,
                    epilogue_begin,
                });
                position_ordinal += 1;
                prologue_end = false;
                epilogue_begin = false;
            }
            _ => return Err(format!("invalid debug opcode {opcode}")),
        }
        let opcode_end_off = pos;
        rows.opcodes.push(DebugOpcodeRow {
            ordinal: opcode_ordinal,
            opcode_off: opcode_off as u32,
            opcode_end_off: opcode_end_off as u32,
            opcode,
            address,
            line,
            address_diff,
            line_diff,
            register_num,
            name_idx,
            type_idx,
            signature_idx,
            source_file_idx,
            emits_position,
            emits_local,
        });
        opcode_ordinal += 1;
        if opcode == 0x00 {
            break;
        }
    }
    Ok(rows)
}

fn debug_index(encoded: u32) -> Option<u32> {
    if encoded == 0 {
        None
    } else {
        Some(encoded - 1)
    }
}

fn derive_code_indexes(dex: &mut DexFile, needs: IndexNeeds) {
    if !needs.any() {
        return;
    }
    let code_items = std::mem::take(&mut dex.code_items);
    for (method_idx, code) in code_items.iter().enumerate() {
        let Some(code) = code else { continue };
        derive_code_indexes_for_method(dex, method_idx as u32, &code.insns, needs);
    }
    dex.code_items = code_items;
    finish_method_number_values(dex);
}

fn derive_code_indexes_from_offsets(
    dex: &mut DexFile,
    offsets: &[(u32, u32)],
    needs: IndexNeeds,
) -> Result<(), LoadError> {
    for &(method_idx, code_off) in offsets {
        let off = code_off as usize;
        let raw = dex.raw();
        let insns_size = read_u32(raw, off + 12)? as usize;
        let start = off + 16;
        checked_range(raw, start as u32, insns_size as u32, 2).map_err(LoadError)?;
        // DEX code items are four-byte aligned and encode little-endian
        // 16-bit code units.  The loader already rejects non-little-endian
        // DEX headers, so borrow the instruction stream directly instead of
        // allocating and copying a temporary Vec for every method.
        let insns: &[u16] = unsafe {
            std::slice::from_raw_parts(raw.as_ptr().add(start) as *const u16, insns_size)
        };
        derive_code_indexes_for_method(dex, method_idx, insns, needs);
    }
    finish_method_number_values(dex);
    Ok(())
}

#[inline(always)]
fn derive_code_indexes_for_method(
    dex: &mut DexFile,
    method_idx: u32,
    insns: &[u16],
    needs: IndexNeeds,
) {
    if needs.method_strings
        && !needs.method_numbers
        && !needs.method_calls
        && !needs.method_field_accesses
        && !needs.method_used_types
    {
        derive_method_strings_for_method(dex, method_idx, insns);
        return;
    }
    if needs.method_strings
        && needs.method_numbers
        && !needs.method_calls
        && !needs.method_field_accesses
        && !needs.method_used_types
    {
        derive_method_strings_numbers_for_method(dex, method_idx, insns);
        return;
    }
    derive_code_indexes_for_method_generic(dex, method_idx, insns, needs);
}

#[inline(always)]
fn derive_method_strings_for_method(dex: &mut DexFile, method_idx: u32, insns: &[u16]) {
    let mut pc = 0usize;
    while pc < insns.len() {
        let unit = insns[pc];
        match (unit & 0xff) as u8 {
            0x1a if pc + 1 < insns.len() => dex.method_strings.push(MethodStringRef {
                method_idx,
                string_idx: insns[pc + 1] as u32,
            }),
            0x1b if pc + 2 < insns.len() => dex.method_strings.push(MethodStringRef {
                method_idx,
                string_idx: insns[pc + 1] as u32 | ((insns[pc + 2] as u32) << 16),
            }),
            _ => {}
        }
        pc = pc.saturating_add(opcode_width((unit & 0xff) as u8, insns, pc).max(1));
    }
}

#[inline(always)]
fn derive_method_strings_numbers_for_method(dex: &mut DexFile, method_idx: u32, insns: &[u16]) {
    let mut pc = 0usize;
    while pc < insns.len() {
        let unit = insns[pc];
        let opcode = (unit & 0xff) as u8;
        match opcode {
            0x1a if pc + 1 < insns.len() => dex.method_strings.push(MethodStringRef {
                method_idx,
                string_idx: insns[pc + 1] as u32,
            }),
            0x1b if pc + 2 < insns.len() => dex.method_strings.push(MethodStringRef {
                method_idx,
                string_idx: insns[pc + 1] as u32 | ((insns[pc + 2] as u32) << 16),
            }),
            0x12 => dex.method_numbers.push(MethodNumberRef {
                method_idx,
                opcode,
                number_type: NumberType::Int,
                long_value: sign_extend((unit >> 12) as u64, 4),
                double_value: None,
            }),
            0x13 if pc + 1 < insns.len() => dex.method_numbers.push(MethodNumberRef {
                method_idx,
                opcode,
                number_type: NumberType::Int,
                long_value: insns[pc + 1] as i16 as i64,
                double_value: None,
            }),
            0x14 if pc + 2 < insns.len() => dex.method_numbers.push(MethodNumberRef {
                method_idx,
                opcode,
                number_type: NumberType::Int,
                long_value: (insns[pc + 1] as u32 | ((insns[pc + 2] as u32) << 16)) as i32 as i64,
                double_value: None,
            }),
            0x15 if pc + 1 < insns.len() => dex.method_numbers.push(MethodNumberRef {
                method_idx,
                opcode,
                number_type: NumberType::Int,
                long_value: ((insns[pc + 1] as i16 as i32) << 16) as i64,
                double_value: None,
            }),
            0x16 if pc + 1 < insns.len() => dex.method_numbers.push(MethodNumberRef {
                method_idx,
                opcode,
                number_type: NumberType::Long,
                long_value: insns[pc + 1] as i16 as i64,
                double_value: None,
            }),
            0x17 if pc + 2 < insns.len() => dex.method_numbers.push(MethodNumberRef {
                method_idx,
                opcode,
                number_type: NumberType::Long,
                long_value: (insns[pc + 1] as u32 | ((insns[pc + 2] as u32) << 16)) as i32 as i64,
                double_value: None,
            }),
            0x18 if pc + 4 < insns.len() => dex.method_numbers.push(MethodNumberRef {
                method_idx,
                opcode,
                number_type: NumberType::Long,
                long_value: (insns[pc + 1] as u64
                    | ((insns[pc + 2] as u64) << 16)
                    | ((insns[pc + 3] as u64) << 32)
                    | ((insns[pc + 4] as u64) << 48)) as i64,
                double_value: None,
            }),
            0x19 if pc + 1 < insns.len() => dex.method_numbers.push(MethodNumberRef {
                method_idx,
                opcode,
                number_type: NumberType::Long,
                long_value: (insns[pc + 1] as i16 as i64) << 48,
                double_value: None,
            }),
            0xd0..=0xd7 if pc + 1 < insns.len() => dex.method_numbers.push(MethodNumberRef {
                method_idx,
                opcode,
                number_type: NumberType::Int,
                long_value: insns[pc + 1] as i16 as i64,
                double_value: None,
            }),
            0xd8..=0xe2 if pc + 1 < insns.len() => dex.method_numbers.push(MethodNumberRef {
                method_idx,
                opcode,
                number_type: NumberType::Int,
                long_value: ((insns[pc + 1] >> 8) as i8) as i64,
                double_value: None,
            }),
            _ => {}
        }
        pc = pc.saturating_add(opcode_width(opcode, insns, pc).max(1));
    }
}

#[inline(always)]
fn derive_code_indexes_for_method_generic(
    dex: &mut DexFile,
    method_idx: u32,
    insns: &[u16],
    needs: IndexNeeds,
) {
    let mut pc = 0usize;
    while pc < insns.len() {
        let unit = insns[pc];
        let opcode = (unit & 0xff) as u8;
        let width = opcode_width(opcode, insns, pc).max(1);
        match opcode {
            0x1a if needs.method_strings && pc + 1 < insns.len() => {
                dex.method_strings.push(MethodStringRef {
                    method_idx,
                    string_idx: insns[pc + 1] as u32,
                })
            }
            0x1b if needs.method_strings && pc + 2 < insns.len() => {
                dex.method_strings.push(MethodStringRef {
                    method_idx,
                    string_idx: insns[pc + 1] as u32 | ((insns[pc + 2] as u32) << 16),
                })
            }
            0x6e..=0x72 | 0x74..=0x78 if needs.method_calls && pc + 1 < insns.len() => {
                dex.method_calls.push(MethodCallRef {
                    method_idx,
                    callee_method_idx: insns[pc + 1] as u32,
                })
            }
            0xfa | 0xfb if needs.method_calls && pc + 1 < insns.len() => {
                dex.method_calls.push(MethodCallRef {
                    method_idx,
                    callee_method_idx: insns[pc + 1] as u32,
                })
            }
            0x52..=0x6d if needs.method_field_accesses && pc + 1 < insns.len() => {
                dex.method_field_accesses.push(MethodFieldRef {
                    method_idx,
                    field_idx: insns[pc + 1] as u32,
                    opcode,
                })
            }
            0x1c | 0x1f | 0x20 | 0x22 | 0x23 | 0x24 | 0x25
                if needs.method_used_types && pc + 1 < insns.len() =>
            {
                dex.method_used_types.push(MethodTypeRef {
                    method_idx,
                    type_idx: insns[pc + 1] as u32,
                })
            }
            0x12 if needs.method_numbers => dex.method_numbers.push(MethodNumberRef {
                method_idx,
                opcode,
                number_type: NumberType::Int,
                long_value: sign_extend((unit >> 12) as u64, 4),
                double_value: None,
            }),
            0x13 if needs.method_numbers && pc + 1 < insns.len() => {
                dex.method_numbers.push(MethodNumberRef {
                    method_idx,
                    opcode,
                    number_type: NumberType::Int,
                    long_value: insns[pc + 1] as i16 as i64,
                    double_value: None,
                })
            }
            0x14 if needs.method_numbers && pc + 2 < insns.len() => {
                dex.method_numbers.push(MethodNumberRef {
                    method_idx,
                    opcode,
                    number_type: NumberType::Int,
                    long_value: (insns[pc + 1] as u32 | ((insns[pc + 2] as u32) << 16)) as i32
                        as i64,
                    double_value: None,
                })
            }
            0x15 if needs.method_numbers && pc + 1 < insns.len() => {
                dex.method_numbers.push(MethodNumberRef {
                    method_idx,
                    opcode,
                    number_type: NumberType::Int,
                    long_value: ((insns[pc + 1] as i16 as i32) << 16) as i64,
                    double_value: None,
                })
            }
            0x16 if needs.method_numbers && pc + 1 < insns.len() => {
                dex.method_numbers.push(MethodNumberRef {
                    method_idx,
                    opcode,
                    number_type: NumberType::Long,
                    long_value: insns[pc + 1] as i16 as i64,
                    double_value: None,
                })
            }
            0x17 if needs.method_numbers && pc + 2 < insns.len() => {
                dex.method_numbers.push(MethodNumberRef {
                    method_idx,
                    opcode,
                    number_type: NumberType::Long,
                    long_value: (insns[pc + 1] as u32 | ((insns[pc + 2] as u32) << 16)) as i32
                        as i64,
                    double_value: None,
                })
            }
            0x18 if needs.method_numbers && pc + 4 < insns.len() => {
                dex.method_numbers.push(MethodNumberRef {
                    method_idx,
                    opcode,
                    number_type: NumberType::Long,
                    long_value: (insns[pc + 1] as u64
                        | ((insns[pc + 2] as u64) << 16)
                        | ((insns[pc + 3] as u64) << 32)
                        | ((insns[pc + 4] as u64) << 48)) as i64,
                    double_value: None,
                })
            }
            0x19 if needs.method_numbers && pc + 1 < insns.len() => {
                dex.method_numbers.push(MethodNumberRef {
                    method_idx,
                    opcode,
                    number_type: NumberType::Long,
                    long_value: (insns[pc + 1] as i16 as i64) << 48,
                    double_value: None,
                })
            }
            0xd0..=0xd7 if needs.method_numbers && pc + 1 < insns.len() => {
                dex.method_numbers.push(MethodNumberRef {
                    method_idx,
                    opcode,
                    number_type: NumberType::Int,
                    long_value: insns[pc + 1] as i16 as i64,
                    double_value: None,
                })
            }
            0xd8..=0xe2 if needs.method_numbers && pc + 1 < insns.len() => {
                dex.method_numbers.push(MethodNumberRef {
                    method_idx,
                    opcode,
                    number_type: NumberType::Int,
                    long_value: ((insns[pc + 1] >> 8) as i8) as i64,
                    double_value: None,
                })
            }
            _ => {}
        }
        pc = pc.saturating_add(width);
    }
}

fn finish_method_number_values(dex: &mut DexFile) {
    // DexSQL exposes a floating interpretation for const/high16 and
    // const-wide values while retaining the integer bit pattern in
    // `long_value`.
    for reference in &mut dex.method_numbers {
        if matches!(reference.opcode, 0x14 | 0x15) {
            reference.double_value = Some(f32::from_bits(reference.long_value as u32) as f64);
        } else if matches!(reference.opcode, 0x18 | 0x19) {
            reference.double_value = Some(f64::from_bits(reference.long_value as u64));
        }
    }
}

#[inline(always)]
fn is_payload_opcode(insns: &[u16], pc: usize) -> bool {
    insns
        .get(pc)
        .is_some_and(|unit| unit & 0xff == 0 && matches!(unit >> 8, 1..=3))
}

#[inline(always)]
fn opcode_width(op: u8, insns: &[u16], pc: usize) -> usize {
    match op {
        0x00 => match insns.get(pc).map(|v| v >> 8).unwrap_or(0) {
            0x01 => 4 + insns.get(pc + 1).copied().unwrap_or(0) as usize * 2,
            0x02 => 2 + insns.get(pc + 1).copied().unwrap_or(0) as usize * 4,
            0x03 => {
                let element_width = insns.get(pc + 1).copied().unwrap_or(0) as usize;
                let size = insns.get(pc + 2).copied().unwrap_or(0) as usize
                    | ((insns.get(pc + 3).copied().unwrap_or(0) as usize) << 16);
                4 + element_width.saturating_mul(size).div_ceil(2)
            }
            _ => 1,
        },
        // 22x/22s/22b/21c/23x/22c and the other two-unit formats.
        0x02
        | 0x05
        | 0x08
        | 0x13
        | 0x15
        | 0x16
        | 0x19
        | 0x1a
        | 0x1c
        | 0x1f
        | 0x20
        | 0x22
        | 0x23
        | 0x29
        | 0x2d..=0x3d
        | 0x44..=0x6d
        | 0x90..=0xaf
        | 0xd0..=0xe9
        | 0xf3..=0xf9
        | 0xfe..=0xff => 2,
        // 32x/31i/31c/31t/35c/3rc and quick invoke/field formats.
        0x03
        | 0x06
        | 0x09
        | 0x14
        | 0x17
        | 0x1b
        | 0x24
        | 0x25
        | 0x26
        | 0x2a
        | 0x2b
        | 0x2c
        | 0x6e..=0x78
        | 0xf0..=0xf2
        | 0xfc
        | 0xfd => 3,
        0x18 => 5,
        0xfa | 0xfb => 4,
        _ => 1,
    }
}

fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn checked_range(bytes: &[u8], off: u32, count: u32, width: usize) -> Result<(), String> {
    let start = off as usize;
    let len = (count as usize)
        .checked_mul(width)
        .ok_or("range overflow")?;
    let end = start.checked_add(len).ok_or("range overflow")?;
    if end > bytes.len() {
        Err(format!("range 0x{start:x}..0x{end:x} outside file"))
    } else {
        Ok(())
    }
}

fn fast_annotation_set_count(
    bytes: &[u8],
    class_defs_off: usize,
    class_count: usize,
) -> Option<usize> {
    let read = |offset: usize| -> Option<u32> {
        let value = bytes.get(offset..offset + 4)?;
        Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
    };
    let mut offsets = Vec::new();
    for class_index in 0..class_count {
        let class_def = class_defs_off.checked_add(class_index.checked_mul(32)?)?;
        let directory = read(class_def + 20)? as usize;
        if directory == 0 {
            continue;
        }
        let push = |offsets: &mut Vec<u32>, value: u32| {
            if value != 0 && !offsets.contains(&value) {
                offsets.push(value);
            }
        };
        push(&mut offsets, read(directory)?);
        let fields = read(directory + 4)? as usize;
        let methods = read(directory + 8)? as usize;
        let parameters = read(directory + 12)? as usize;
        let mut position = directory.checked_add(16)?;
        for _ in 0..fields.saturating_add(methods) {
            position = position.checked_add(4)?;
            push(&mut offsets, read(position)?);
            position = position.checked_add(4)?;
        }
        for _ in 0..parameters {
            position = position.checked_add(4)?;
            let references = read(position)? as usize;
            position = position.checked_add(4)?;
            let count = read(references)? as usize;
            for ordinal in 0..count {
                push(
                    &mut offsets,
                    read(references.checked_add(4 + ordinal.checked_mul(4)?)?)?,
                );
            }
        }
    }
    Some(offsets.len())
}

fn fast_dex_header_count(bytes: &[u8], table: &str) -> Option<usize> {
    if bytes.len() < 112 || &bytes[0..4] != b"dex\n" {
        return None;
    }
    let read = |off: usize| -> Option<u32> {
        let v = bytes.get(off..off + 4)?;
        Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    };
    if table == "annotation_sets" {
        let class_count = read(96)? as usize;
        let class_defs_off = read(100)? as usize;
        return fast_annotation_set_count(bytes, class_defs_off, class_count);
    }
    let direct = match table {
        "strings" => read(56),
        "type_ids" | "types" => read(64),
        "proto_ids" | "protos" => read(72),
        "field_ids" | "fields" => read(80),
        "method_ids" | "methods" | "method_opcodes" => read(88),
        "class_defs" | "classes" => read(96),
        _ => None,
    };
    if let Some(value) = direct {
        return Some(value as usize);
    }
    let map_off = read(52)? as usize;
    let map_size = read(map_off)? as usize;
    let mut map_items = 0usize;
    let mut ids = 0usize;
    let mut wanted = None;
    for ordinal in 0..map_size {
        let off = map_off.checked_add(4 + ordinal * 12)?;
        let code = {
            let v = bytes.get(off..off + 2)?;
            u16::from_le_bytes([v[0], v[1]])
        };
        let size = read(off + 4)? as usize;
        if code == 0x1000 {
            map_items = map_size;
        }
        if (1..=8).contains(&code) {
            ids += size;
        }
        let table_code = match table {
            "type_lists" => Some(0x1001),
            "annotation_set_ref_lists" => Some(0x1002),
            "annotation_sets" => Some(0x1003),
            "class_data_items" => Some(0x2000),
            "code_items" => Some(0x2001),
            "annotations" => Some(0x2004),
            "encoded_arrays" => Some(0x2005),
            "method_handles" => Some(0x0008),
            "call_sites" => Some(0x0007),
            "hiddenapi_flags" => Some(0xf000),
            _ => None,
        };
        if table_code == Some(code) {
            wanted = Some(size);
        }
    }
    match table {
        "map_items" => Some(map_items),
        "id_items" => Some(ids),
        _ => wanted,
    }
}

fn read_u16(bytes: &[u8], off: usize) -> Result<u16, LoadError> {
    let v = bytes
        .get(off..off + 2)
        .ok_or_else(|| LoadError(format!("read u16 out of range at 0x{off:x}")))?;
    Ok(u16::from_le_bytes([v[0], v[1]]))
}
fn read_u32(bytes: &[u8], off: usize) -> Result<u32, LoadError> {
    let v = bytes
        .get(off..off + 4)
        .ok_or_else(|| LoadError(format!("read u32 out of range at 0x{off:x}")))?;
    Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

fn read_u16_arc(bytes: &[u8], off: usize) -> Result<u16, LoadError> {
    read_u16(bytes, off)
}
fn read32_arc(bytes: &[u8], off: usize) -> Result<u32, LoadError> {
    read_u32(bytes, off)
}
#[inline(always)]
fn read_uleb(bytes: &[u8], mut off: usize) -> Result<(u32, usize), LoadError> {
    let mut value = 0u32;
    for shift in (0..35).step_by(7) {
        let b = *bytes
            .get(off)
            .ok_or_else(|| LoadError(format!("read uleb out of range at 0x{off:x}")))?;
        off += 1;
        value |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            return Ok((value, off));
        }
    }
    Err(LoadError("invalid uleb128".into()))
}

fn read_sleb(bytes: &[u8], mut off: usize) -> Result<(i32, usize), LoadError> {
    let mut value = 0i32;
    let mut shift = 0u32;
    loop {
        let b = *bytes
            .get(off)
            .ok_or_else(|| LoadError(format!("read sleb out of range at 0x{off:x}")))?;
        off += 1;
        value |= ((b & 0x7f) as i32) << shift;
        let done = b & 0x80 == 0;
        shift += 7;
        if done {
            if shift < 32 && b & 0x40 != 0 {
                value |= !0i32 << shift;
            }
            return Ok((value, off));
        }
        if shift >= 35 {
            return Err(LoadError("invalid sleb128".into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        native_cache_count, native_section_bytes, CacheFormat, Dataset, IndexNeeds,
        NativeCsrCursor, NativeMethodNumbers, NativeMethodRefRow, NativeMethodRefs,
        NativeSidecarHeader,
    };
    use std::path::PathBuf;

    fn native_container(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x20];
        bytes[..4].copy_from_slice(b"DXC2");
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        let mut ranges = Vec::with_capacity(entries.len());
        for (_, payload) in entries {
            let offset = bytes.len();
            bytes.extend_from_slice(payload);
            ranges.push((offset as u64, payload.len() as u64));
        }
        let toc = bytes.len();
        bytes[16..24].copy_from_slice(&(toc as u64).to_le_bytes());
        for ((name, _), (offset, length)) in entries.iter().zip(ranges) {
            bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(&length.to_le_bytes());
            let mut metadata = [0u8; 32];
            metadata[4..12].copy_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(&metadata);
        }
        bytes
    }

    fn native_counts_payload(table: &str, count: u64) -> Vec<u8> {
        let mut payload = b"DXR1".to_vec();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&(table.len() as u32).to_le_bytes());
        payload.extend_from_slice(table.as_bytes());
        payload.extend_from_slice(&count.to_le_bytes());
        payload
    }

    #[test]
    fn native_count_parser_reads_base_counts() {
        let bytes = native_container(&[(
            "base_row_counts.native",
            &native_counts_payload("method_calls", 42),
        )]);
        assert_eq!(native_cache_count(&bytes, "method_calls"), Some(42));
    }

    #[test]
    fn native_sidecar_header_and_cursor_are_bounds_checked() {
        let mut payload = b"MRS5".to_vec();
        payload.push(1);
        payload.extend_from_slice(&7u32.to_le_bytes());
        payload.extend_from_slice(&[0u8; 7]);
        payload.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        payload.extend_from_slice(&0x5566_7788_99aau64.to_le_bytes());
        let header = NativeSidecarHeader::parse(&payload).expect("MRS5 header");
        assert_eq!(header.count, 7);
        assert_eq!(header.declaration_width, 1);
        assert_eq!(header.payload_offset, 16);
        let mut cursor = NativeCsrCursor::parse(&payload).expect("cursor");
        assert_eq!(cursor.read_u32().unwrap(), 0x1122_3344);
        assert_eq!(cursor.read_u64().unwrap(), 0x5566_7788_99aa);
        assert_eq!(cursor.remaining(), 0);
        assert!(cursor.read_u32().is_err());
        assert!(NativeSidecarHeader::parse(b"MNS").is_err());
        assert!(NativeSidecarHeader::parse(b"XXXX\0\0\0\0").is_err());
    }

    #[test]
    fn decodes_mns3_columns_and_csr() {
        let mut bytes = b"MNS3".to_vec();
        bytes.push(1); // declaration width
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0]); // declaration payload
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[0x12, 0x12, 0x13]);
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&(-2i64 as u64).to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let decoded = NativeMethodNumbers::decode(&bytes).expect("decode MNS3");
        assert_eq!(decoded.opcode, vec![0x12, 0x12, 0x13]);
        assert_eq!(decoded.values, vec![0, 1, -2]);
        assert_eq!(decoded.forward_csr, vec![0, 1, 3]);
        assert_eq!(decoded.reverse_perm, vec![2, 0, 1]);
    }

    #[test]
    fn mns3_decoder_rejects_nonmonotone_csr() {
        let mut bytes = b"MNS3".to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0]);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0x12);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert!(NativeMethodNumbers::decode(&bytes).is_err());
    }

    #[test]
    fn decodes_mrs5_kind_partitions_and_rows() {
        let mut bytes = b"MRS5".to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0]);
        bytes.push(1);
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[10, 11, 12]);
        let arrays: &[&[u32]] = &[
            &[],
            &[0, 2, 3],
            &[0, 2, 0],
            &[0, 2, 3],
            &[],
            &[],
            &[],
            &[],
            &[1, 0, 0],
        ];
        for values in arrays {
            bytes.extend_from_slice(&(values.len() as u32).to_le_bytes());
            for value in *values {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        let decoded = NativeMethodRefs::decode(&bytes).expect("decode MRS5");
        assert_eq!(
            decoded.rows().expect("rows"),
            vec![
                NativeMethodRefRow {
                    method_idx: 0,
                    kind: 0,
                    index: 10
                },
                NativeMethodRefRow {
                    method_idx: 0,
                    kind: 0,
                    index: 11
                },
                NativeMethodRefRow {
                    method_idx: 0,
                    kind: 1,
                    index: 12
                },
            ]
        );
    }

    #[test]
    fn native_count_parser_reads_mrs_and_mns_counts() {
        let mut refs = b"MRS5".to_vec();
        refs.push(1);
        refs.extend_from_slice(&29_996u32.to_le_bytes());
        refs.extend_from_slice(&[0u8; 29_996]);
        let mut numbers = b"MNS3".to_vec();
        numbers.push(1);
        numbers.extend_from_slice(&3_668u32.to_le_bytes());
        numbers.extend_from_slice(&[0u8; 3_668]);
        let bytes = native_container(&[
            ("method_refs.native", refs.as_slice()),
            ("method_numbers.native", numbers.as_slice()),
        ]);
        assert_eq!(native_cache_count(&bytes, "method_refs"), Some(29_996));
        assert_eq!(native_cache_count(&bytes, "method_numbers"), Some(3_668));
        assert_eq!(
            native_cache_count(&bytes, "method_using_numbers"),
            Some(3_668)
        );
    }

    #[test]
    fn cache_format_identifies_native_header() {
        let payload = b"DXR1";
        let entries = [
            ("section-0", &payload[..]),
            ("section-1", &payload[..]),
            ("section-2", &payload[..]),
            ("section-3", &payload[..]),
            ("section-4", &payload[..]),
            ("section-5", &payload[..]),
            ("section-6", &payload[..]),
            ("section-7", &payload[..]),
        ];
        let bytes = native_container(&entries);
        let path = std::env::temp_dir().join(format!(
            "dexsql-cache-native-format-{}-{}.dxc2",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(&path, bytes).expect("write native header");
        assert_eq!(
            Dataset::cache_format(&path).expect("read native format"),
            CacheFormat::NativeV2
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn native_manifest_extracts_input_source() {
        let path = std::env::temp_dir().join(format!(
            "dexsql-cache-native-manifest-{}-{}.dxc2",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(
            &path,
            b"manifest.txt\ninput_source=2f746d702f7061796c6f61642e646578,1\n",
        )
        .expect("write native manifest");
        assert_eq!(
            Dataset::native_cache_source_paths(&path).expect("read native input source"),
            vec![PathBuf::from("/tmp/payload.dex")]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn native_count_parser_rejects_duplicate_sections() {
        let payload = native_counts_payload("method_calls", 42);
        let bytes = native_container(&[
            ("base_row_counts.native", payload.as_slice()),
            ("base_row_counts.native", payload.as_slice()),
        ]);
        assert_eq!(native_cache_count(&bytes, "method_calls"), None);
    }

    #[test]
    fn native_count_parser_rejects_out_of_bounds_sections() {
        let mut bytes = native_container(&[("base_row_counts.native", b"DXR1")]);
        let toc = u64::from_le_bytes(bytes[16..24].try_into().unwrap()) as usize;
        // The section offset is the first u64 after the section name.
        let offset_pos = toc + 4 + "base_row_counts.native".len();
        bytes[offset_pos..offset_pos + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(native_cache_count(&bytes, "method_calls"), None);
    }

    #[test]
    fn native_count_parser_rejects_truncated_toc() {
        let payload = native_counts_payload("method_calls", 42);
        let mut bytes = native_container(&[("base_row_counts.native", payload.as_slice())]);
        bytes.pop();
        assert_eq!(native_cache_count(&bytes, "method_calls"), None);
    }

    #[test]
    fn parses_available_payload_dex() {
        let path = PathBuf::from("/home/ujhhgtg/Downloads/payload.dex");
        if !path.exists() {
            return;
        }
        let dataset = Dataset::load_paths(&[path]).expect("payload.dex should parse");
        assert!(dataset.count("classes").unwrap_or(0) > 0);
        assert!(dataset.count("methods").unwrap_or(0) > 0);
    }

    #[test]
    fn explicit_raw_retention_preserves_lazy_code_and_debug() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex");
        let full = Dataset::load_paths(std::slice::from_ref(&path)).expect("full fixture load");
        let lazy = Dataset::load_paths_with_retention(
            std::slice::from_ref(&path),
            IndexNeeds::default(),
            false,
            false,
            true,
            true,
        )
        .expect("lazy fixture load");
        assert!(!lazy.files[0].raw().is_empty());
        assert!(lazy.files[0].code_items.is_empty());
        let mut code_methods = 0;
        let mut debug_methods = 0;
        for method_idx in 0..full.files[0].methods.len() as u32 {
            let expected = full.files[0].method_opcode_summary(method_idx);
            code_methods += usize::from(expected.is_some());
            assert_eq!(lazy.files[0].method_opcode_summary(method_idx), expected);
            let expected_debug = full.files[0].debug_rows(method_idx).unwrap();
            debug_methods += usize::from(expected_debug.is_some());
            assert_eq!(
                format!("{:?}", lazy.files[0].debug_rows(method_idx).unwrap()),
                format!("{:?}", expected_debug),
            );
        }
        assert!(code_methods > 0);
        assert!(debug_methods > 0);

        let needs = IndexNeeds {
            method_lookup: true,
            method_strings: true,
            ..IndexNeeds::default()
        };
        let index_only = Dataset::load_paths_with_retention(
            std::slice::from_ref(&path),
            needs,
            true,
            false,
            true,
            false,
        )
        .expect("index-only fixture load");
        assert!(index_only.files[0].bytes.is_none());
        assert!(index_only.files[0].code_items.is_empty());
        assert!(!index_only.files[0].method_strings.is_empty());
        assert_eq!(
            index_only.files[0]
                .method_strings
                .iter()
                .map(|r| (r.method_idx, r.string_idx))
                .collect::<Vec<_>>(),
            full.files[0]
                .method_strings
                .iter()
                .map(|r| (r.method_idx, r.string_idx))
                .collect::<Vec<_>>(),
        );
        let legacy = Dataset::load_paths_with_requirements(&[path], needs, true, false, true)
            .expect("legacy fixture load");
        assert!(legacy.files[0].bytes.is_some());
    }

    #[test]
    fn native_writer_emits_count_readable_toc() {
        let path = PathBuf::from("/home/ujhhgtg/Downloads/payload.dex");
        if !path.exists() {
            return;
        }
        let dataset = Dataset::load_paths(std::slice::from_ref(&path)).expect("parse payload");
        let cache_path = std::env::temp_dir().join(format!(
            "dexsql-native-writer-{}-{}.dxc2",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        dataset
            .write_native_cache(&cache_path)
            .expect("write native cache");
        assert_eq!(
            Dataset::cache_format(&cache_path).expect("read native format"),
            CacheFormat::NativeV2
        );
        assert_eq!(
            Dataset::cache_count(&cache_path, "methods").expect("read native methods"),
            Some(dataset.count("methods").unwrap())
        );
        let cache_bytes = std::fs::read(&cache_path).expect("read native cache bytes");
        let manifest =
            native_section_bytes(&cache_bytes, "manifest.txt").expect("native manifest section");
        let manifest = std::str::from_utf8(manifest).expect("manifest utf8");
        assert!(manifest.contains(
            "input_fingerprint=5b73de55459c5ac9947c90762139b996f45ec1b1bfe256dc28bd65ceea84bf00"
        ));
        let _ = std::fs::remove_file(cache_path);
    }

    #[test]
    fn parses_debug_info_stream_rows() {
        let path = PathBuf::from("/home/ujhhgtg/Downloads/payload.dex");
        if !path.exists() {
            return;
        }
        let dataset = Dataset::load_paths(std::slice::from_ref(&path)).expect("parse payload");
        let rows = dataset.files[0]
            .debug_rows(889)
            .expect("debug stream should parse")
            .expect("method has debug info");
        assert_eq!(rows.info.line_start, 30);
        assert_eq!(rows.info.parameters_size, 2);
        assert_eq!(rows.parameters.len(), 2);
        assert_eq!(rows.positions.len(), 20);
        assert_eq!(rows.opcodes.len(), 23);
    }
}

/// Lexicographic UTF-16 code-unit comparison: the dialect's text order for
/// sorting (differs from UTF-8 byte order for supplementary characters).
pub fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let mut a = a.encode_utf16();
    let mut b = b.encode_utf16();
    loop {
        match (a.next(), b.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) => {
                if x != y {
                    return x.cmp(&y);
                }
            }
        }
    }
}
