//! Dalvik opcode mnemonics for the metadata method-document opcode projection.
//!
//! The metadata API exposes the same instruction stream as the SQL
//! `method_opcodes` relation (opcode_count and opcode_hex), but as ordered
//! mnemonic names so DexKit opNames-style consumers can inspect it directly.
//! Payload pseudo-instructions are skipped exactly like the SQL projection.

use dexsql_cache::DexFile;

const UNUSED: &str = "unused";

/// Dalvik opcode mnemonics indexed by opcode byte.
///
/// Slots for unused/optimized-only opcodes render as `unused`; DEX 038/039
/// invocation and method-handle opcodes retain their official names. The metadata
/// projection never exposes them for payload pseudo-instructions because those
/// are skipped before the mnemonic lookup.
const OPCODE_MNEMONICS: [&str; 256] = [
    "nop",
    "move",
    "move/from16",
    "move/16",
    "move-wide",
    "move-wide/from16",
    "move-wide/16",
    "move-object", // 0x00
    "move-object/from16",
    "move-object/16",
    "move-result",
    "move-result-wide",
    "move-result-object",
    "move-exception",
    "return-void",
    "return", // 0x08
    "return-wide",
    "return-object",
    "const/4",
    "const/16",
    "const",
    "const/high16",
    "const-wide/16",
    "const-wide/32", // 0x10
    "const-wide",
    "const-wide/high16",
    "const-string",
    "const-string/jumbo",
    "const-class",
    "monitor-enter",
    "monitor-exit",
    "check-cast", // 0x18
    "instance-of",
    "array-length",
    "new-instance",
    "new-array",
    "filled-new-array",
    "filled-new-array/range",
    "fill-array-data",
    "throw", // 0x20
    "goto",
    "goto/16",
    "goto/32",
    "packed-switch",
    "sparse-switch",
    "cmpl-float",
    "cmpg-float",
    "cmpl-double", // 0x28
    "cmpg-double",
    "cmp-long",
    "if-eq",
    "if-ne",
    "if-lt",
    "if-ge",
    "if-gt",
    "if-le", // 0x30
    "if-eqz",
    "if-nez",
    "if-ltz",
    "if-gez",
    "if-gtz",
    "if-lez",
    "unused",
    "unused", // 0x38
    "unused",
    "unused",
    "unused",
    "unused",
    "aget",
    "aget-wide",
    "aget-object",
    "aget-boolean", // 0x40
    "aget-byte",
    "aget-char",
    "aget-short",
    "aput",
    "aput-wide",
    "aput-object",
    "aput-boolean",
    "aput-byte", // 0x48
    "aput-char",
    "aput-short",
    "iget",
    "iget-wide",
    "iget-object",
    "iget-boolean",
    "iget-byte",
    "iget-char", // 0x50
    "iget-short",
    "iput",
    "iput-wide",
    "iput-object",
    "iput-boolean",
    "iput-byte",
    "iput-char",
    "iput-short", // 0x58
    "sget",
    "sget-wide",
    "sget-object",
    "sget-boolean",
    "sget-byte",
    "sget-char",
    "sget-short",
    "sput", // 0x60
    "sput-wide",
    "sput-object",
    "sput-boolean",
    "sput-byte",
    "sput-char",
    "sput-short",
    "invoke-virtual",
    "invoke-super", // 0x68
    "invoke-direct",
    "invoke-static",
    "invoke-interface",
    "unused",
    "invoke-virtual/range",
    "invoke-super/range",
    "invoke-direct/range",
    "invoke-static/range", // 0x70
    "invoke-interface/range",
    "unused",
    "unused",
    "neg-int",
    "not-int",
    "neg-long",
    "not-long",
    "neg-float", // 0x78
    "neg-double",
    "int-to-long",
    "int-to-float",
    "int-to-double",
    "long-to-int",
    "long-to-float",
    "long-to-double",
    "float-to-int", // 0x80
    "float-to-long",
    "float-to-double",
    "double-to-int",
    "double-to-long",
    "double-to-float",
    "int-to-byte",
    "int-to-char",
    "int-to-short", // 0x88
    "add-int",
    "sub-int",
    "mul-int",
    "div-int",
    "rem-int",
    "and-int",
    "or-int",
    "xor-int", // 0x90
    "shl-int",
    "shr-int",
    "ushr-int",
    "add-long",
    "sub-long",
    "mul-long",
    "div-long",
    "rem-long", // 0x98
    "and-long",
    "or-long",
    "xor-long",
    "shl-long",
    "shr-long",
    "ushr-long",
    "add-float",
    "sub-float", // 0xa0
    "mul-float",
    "div-float",
    "rem-float",
    "add-double",
    "sub-double",
    "mul-double",
    "div-double",
    "rem-double", // 0xa8
    "add-int/2addr",
    "sub-int/2addr",
    "mul-int/2addr",
    "div-int/2addr",
    "rem-int/2addr",
    "and-int/2addr",
    "or-int/2addr",
    "xor-int/2addr", // 0xb0
    "shl-int/2addr",
    "shr-int/2addr",
    "ushr-int/2addr",
    "add-long/2addr",
    "sub-long/2addr",
    "mul-long/2addr",
    "div-long/2addr",
    "rem-long/2addr", // 0xb8
    "and-long/2addr",
    "or-long/2addr",
    "xor-long/2addr",
    "shl-long/2addr",
    "shr-long/2addr",
    "ushr-long/2addr",
    "add-float/2addr",
    "sub-float/2addr", // 0xc0
    "mul-float/2addr",
    "div-float/2addr",
    "rem-float/2addr",
    "add-double/2addr",
    "sub-double/2addr",
    "mul-double/2addr",
    "div-double/2addr",
    "rem-double/2addr", // 0xc8
    "add-int/lit16",
    "rsub-int",
    "mul-int/lit16",
    "div-int/lit16",
    "rem-int/lit16",
    "and-int/lit16",
    "or-int/lit16",
    "xor-int/lit16", // 0xd0
    "add-int/lit8",
    "rsub-int/lit8",
    "mul-int/lit8",
    "div-int/lit8",
    "rem-int/lit8",
    "and-int/lit8",
    "or-int/lit8",
    "xor-int/lit8", // 0xd8
    "shl-int/lit8",
    "shr-int/lit8",
    "ushr-int/lit8",
    "unused",
    "unused",
    "unused",
    "unused",
    "unused", // 0xe0
    "unused",
    "unused",
    "unused",
    "unused",
    "unused",
    "unused",
    "unused",
    "unused", // 0xe8
    "unused",
    "unused",
    "unused",
    "unused",
    "unused",
    "unused",
    "unused",
    "unused", // 0xf0
    "unused",
    "unused",
    "invoke-polymorphic", // 0xfa
    "invoke-polymorphic/range",
    "invoke-custom",
    "invoke-custom/range",
    "const-method-handle",
    "const-method-type",
];

/// Mnemonic of one Dalvik opcode byte.
pub(crate) fn opcode_mnemonic(opcode: u8) -> &'static str {
    OPCODE_MNEMONICS[opcode as usize]
}

/// Opcodes of one defined method, in code-unit order.
///
/// Returns `None` when the dataset cannot provide a code item for the method
/// (external/abstract method, or a load that dropped raw DEX bytes without
/// retaining code items). The returned count matches
/// `method_opcodes.opcode_count` and excludes payload pseudo-instructions.
pub(crate) fn method_opcode_names(
    file: &DexFile,
    method_idx: u32,
) -> Option<(usize, Vec<&'static str>)> {
    // Metadata-only loads drop the raw DEX payload and keep no code items; do
    // not pay the lazy code-item lookup (a class-data scan) in that case.
    if file.bytes.is_none()
        && file
            .code_items
            .get(method_idx as usize)
            .and_then(Option::as_ref)
            .is_none()
    {
        return None;
    }
    let (count, hex) = file.method_opcode_summary(method_idx)?;
    let names = hex
        .split(' ')
        .filter(|opcode| !opcode.is_empty())
        .map(|opcode| {
            u8::from_str_radix(opcode, 16)
                .ok()
                .map(opcode_mnemonic)
                .unwrap_or(UNUSED)
        })
        .collect::<Vec<_>>();
    Some((count, names))
}

#[cfg(test)]
mod tests {
    use super::{method_opcode_names, opcode_mnemonic};
    use dexsql_cache::{CodeItem, Dataset};
    use std::path::PathBuf;

    #[test]
    fn exposes_known_dalvik_mnemonics() {
        assert_eq!(opcode_mnemonic(0x00), "nop");
        assert_eq!(opcode_mnemonic(0x0c), "move-result-object");
        assert_eq!(opcode_mnemonic(0x11), "return-object");
        assert_eq!(opcode_mnemonic(0x1f), "check-cast");
        assert_eq!(opcode_mnemonic(0x22), "new-instance");
        assert_eq!(opcode_mnemonic(0x70), "invoke-direct");
        assert_eq!(opcode_mnemonic(0x6e), "invoke-virtual");
        assert_eq!(opcode_mnemonic(0x78), "invoke-interface/range");
        assert_eq!(opcode_mnemonic(0xd8), "add-int/lit8");
        assert_eq!(opcode_mnemonic(0x0f), "return");
        assert_eq!(opcode_mnemonic(0xe3), "unused");
        assert_eq!(opcode_mnemonic(0xfa), "invoke-polymorphic");
        assert_eq!(opcode_mnemonic(0xfb), "invoke-polymorphic/range");
        assert_eq!(opcode_mnemonic(0xfc), "invoke-custom");
        assert_eq!(opcode_mnemonic(0xfd), "invoke-custom/range");
        assert_eq!(opcode_mnemonic(0xfe), "const-method-handle");
        assert_eq!(opcode_mnemonic(0xff), "const-method-type");
    }

    #[test]
    fn modern_opcodes_follow_code_widths_without_retained_raw_bytes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/annotated.dex");
        let mut file = Dataset::load_paths(&[path]).unwrap().files.remove(0);
        file.code_items[0] = Some(CodeItem {
            code_off: 0,
            registers_size: 0,
            ins_size: 0,
            outs_size: 0,
            tries_size: 0,
            debug_info_off: 0,
            insns: vec![
                0x00fa, 0, 0, 0, 0x00fb, 0, 0, 0, 0x00fc, 0, 0, 0x00fd, 0, 0, 0x00fe, 0, 0x00ff, 0,
                0x000e,
            ],
            opcode_count: 7,
            tries: Vec::new(),
            catch_handlers: Vec::new(),
        });
        file.drop_raw_bytes();
        let (count, names) = method_opcode_names(&file, 0).unwrap();
        assert_eq!(count, 7);
        assert_eq!(
            names,
            [
                "invoke-polymorphic",
                "invoke-polymorphic/range",
                "invoke-custom",
                "invoke-custom/range",
                "const-method-handle",
                "const-method-type",
                "return-void",
            ]
        );
    }
}
