//! Smali rendering for the `decode` command.
//!
//! This intentionally lives next to the DEX reader.  The decoder consumes the
//! same `CodeItem` and reference pools used by query, so a decode result cannot
//! silently come from a second, subtly different parser.

use std::collections::BTreeSet;

use crate::{CodeItem, DefinedMethod, DexFile, LoadError};

pub fn method_indices_for_class(dex: &DexFile, class: &str) -> Vec<u32> {
    dex.classes
        .iter()
        .filter(|c| dex.type_descriptor(c.class_idx) == class)
        .flat_map(|c| c.methods.iter().map(|m| m.method_idx))
        .collect()
}

/// Return class-data definitions directly so class decode does not perform a
/// full `classes` scan once per method. The access flags are carried alongside
/// the method index and are needed for the `.method` directive.
pub fn method_definitions_for_class(dex: &DexFile, class: &str) -> Vec<DefinedMethod> {
    dex.classes
        .iter()
        .filter(|c| dex.type_descriptor(c.class_idx) == class)
        .flat_map(|c| c.methods.iter().copied())
        .collect()
}

pub fn method_index_for_descriptor(dex: &DexFile, descriptor: &str) -> Option<u32> {
    dex.methods
        .iter()
        .enumerate()
        .find(|(idx, _)| method_descriptor_matches(dex, *idx as u32, descriptor))
        .map(|(idx, _)| idx as u32)
}

fn method_descriptor_matches(dex: &DexFile, method_idx: u32, target: &str) -> bool {
    let Some((class, rest)) = target.split_once("->") else {
        return false;
    };
    let Some((name, mut signature)) = rest.split_once('(') else {
        return false;
    };
    let Some(method) = dex.methods.get(method_idx as usize) else {
        return false;
    };
    if dex.type_descriptor(method.class_idx as u32) != class || dex.string(method.name_idx) != name
    {
        return false;
    }
    let Some(proto) = dex.protos.get(method.proto_idx as usize) else {
        return false;
    };
    for parameter in &proto.parameters {
        let descriptor = dex.type_descriptor(*parameter as u32);
        let Some(next) = signature.strip_prefix(descriptor) else {
            return false;
        };
        signature = next;
    }
    let Some(return_descriptor) = signature.strip_prefix(')') else {
        return false;
    };
    return_descriptor == dex.type_descriptor(proto.return_type_idx)
}

pub fn render_method(dex: &DexFile, method_idx: u32) -> Result<String, LoadError> {
    render_method_with_flags(dex, method_idx, None)
}

pub fn render_method_with_flags(
    dex: &DexFile,
    method_idx: u32,
    access_flags: Option<u32>,
) -> Result<String, LoadError> {
    let _method = dex
        .methods
        .get(method_idx as usize)
        .ok_or_else(|| LoadError("selected file, method, or class not found".into()))?;
    let code_owned = match dex
        .code_items
        .get(method_idx as usize)
        .and_then(Option::as_ref)
    {
        Some(code) => Some(code.clone()),
        None => dex.decode_code_item(method_idx)?,
    };
    let code = code_owned.as_ref();
    // A single decode should not initialize the million-entry descriptor
    // cache. Query benefits from that cache; decode can format only the
    // selected method and lazily format referenced invoke targets below.
    let descriptor_owned = dex
        .method_descriptors
        .get()
        .and_then(|all| all.get(method_idx as usize))
        .cloned()
        .unwrap_or_else(|| super::build_method_descriptor(dex, method_idx));
    let descriptor = descriptor_owned.as_str();
    let mut out = String::new();
    out.push_str(&format!(
        "# file_id={} method_idx={} source=\"{}\" entry=\"{}\" descriptor=\"{}\"\n",
        dex.file_id,
        method_idx,
        escape_header(&dex.source_path.to_string_lossy()),
        escape_header(&dex.entry_name),
        escape_header(descriptor),
    ));
    let (name, proto) = descriptor
        .split_once("->")
        .and_then(|(_, rest)| rest.split_once('('))
        .map(|(name, rest)| (name, format!("({rest}")))
        .unwrap_or((dex.method_name(method_idx), String::new()));
    let access_flags = access_flags.unwrap_or_else(|| {
        dex.class_for_method(method_idx)
            .and_then(|class| class.methods.iter().find(|m| m.method_idx == method_idx))
            .map(|m| m.access_flags)
            .unwrap_or(0)
    });
    out.push_str(".method");
    for flag in method_flags_for(access_flags, dex.method_name(method_idx)) {
        out.push(' ');
        out.push_str(flag);
    }
    out.push(' ');
    out.push_str(name);
    out.push_str(&proto);
    out.push('\n');
    if code.is_none() {
        out.push_str(".end method\n\n");
        return Ok(out);
    }
    let code = code.expect("checked above");
    out.push_str(&format!("    .registers {}\n\n", code.registers_size));

    let mut labels = BTreeSet::new();
    let mut payloads = Vec::new();
    collect_labels(code, &mut labels, &mut payloads);
    let mut pc = 0usize;
    while pc < code.insns.len() {
        if labels.contains(&(pc as u32)) {
            out.push_str(&format!("    :label_{:04x}\n", pc));
        }
        let op = (code.insns[pc] & 0xff) as u8;
        // Payloads are rendered in a separate block at the end, matching the
        // original renderer's layout.
        if op == 0 && matches!(code.insns[pc] >> 8, 1 | 2 | 3) {
            pc += payload_width(code, pc);
            continue;
        }
        let width = super::opcode_width(op, &code.insns, pc).max(1);
        out.push_str("    ");
        out.push_str(&format_instruction(dex, code, pc));
        out.push('\n');
        pc = pc.saturating_add(width);
    }
    for payload in payloads {
        render_payload(&mut out, code, &payload);
    }
    for tr in &code.tries {
        let start = tr.start_addr;
        let end = start.saturating_add(tr.insn_count);
        let Some(set) = code
            .catch_handlers
            .iter()
            .find(|set| set.offset == tr.handler_off as u32)
        else {
            continue;
        };
        for handler in &set.handlers {
            match handler.type_idx {
                Some(type_idx) => out.push_str(&format!(
                    "    .catch {} {{:label_{:04x} .. :label_{:04x}}} :label_{:04x}\n",
                    dex.type_descriptor(type_idx),
                    start,
                    end,
                    handler.addr
                )),
                None => out.push_str(&format!(
                    "    .catchall {{:label_{:04x} .. :label_{:04x}}} :label_{:04x}\n",
                    start, end, handler.addr
                )),
            }
        }
    }
    out.push_str(".end method\n\n");
    Ok(out)
}

pub fn render_selection(
    dex: &DexFile,
    method_indices: impl IntoIterator<Item = u32>,
) -> Result<String, LoadError> {
    let mut out = String::new();
    for idx in method_indices {
        out.push_str(&render_method(dex, idx)?);
    }
    Ok(out)
}

fn method_flags_for(access_flags: u32, name: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (bit, text) in [
        (0x1, "public"),
        (0x2, "private"),
        (0x4, "protected"),
        (0x8, "static"),
        (0x10, "final"),
        (0x20, "synchronized"),
        (0x40, "bridge"),
        (0x80, "varargs"),
        (0x100, "native"),
        (0x400, "abstract"),
        (0x800, "strictfp"),
        (0x1000, "synthetic"),
    ] {
        if access_flags & bit != 0 {
            out.push(text);
        }
    }
    if name == "<init>" || name == "<clinit>" || access_flags & 0x10000 != 0 {
        out.push("constructor");
    }
    out
}

fn escape_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[derive(Debug, Clone)]
enum Payload {
    Packed {
        pc: usize,
        target: usize,
        first_key: i32,
        targets: Vec<i32>,
    },
    Sparse {
        pc: usize,
        target: usize,
        keys: Vec<i32>,
        targets: Vec<i32>,
    },
    Array {
        target: usize,
        width: u16,
        size: usize,
        values: Vec<u16>,
    },
}

fn collect_labels(code: &CodeItem, labels: &mut BTreeSet<u32>, payloads: &mut Vec<Payload>) {
    for tr in &code.tries {
        labels.insert(tr.start_addr);
        labels.insert(tr.start_addr.saturating_add(tr.insn_count));
        if let Some(set) = code
            .catch_handlers
            .iter()
            .find(|s| s.offset == tr.handler_off as u32)
        {
            for h in &set.handlers {
                labels.insert(h.addr);
            }
        }
    }
    let mut pc = 0usize;
    while pc < code.insns.len() {
        let unit = code.insns[pc];
        let op = (unit & 0xff) as u8;
        match op {
            0x28 => {
                labels.insert(branch_target(code, pc, (unit >> 8) as i8 as i32) as u32);
            }
            0x29 => {
                labels.insert(branch_target(
                    code,
                    pc,
                    code.insns.get(pc + 1).copied().unwrap_or(0) as i16 as i32,
                ) as u32);
            }
            0x2a => {
                let off = read_i32(code, pc + 1);
                labels.insert(branch_target(code, pc, off) as u32);
            }
            0x32..=0x37 | 0x38..=0x3d => {
                let off = code.insns.get(pc + 1).copied().unwrap_or(0) as i16 as i32;
                labels.insert(branch_target(code, pc, off) as u32);
            }
            0x2b | 0x2c | 0x26 => {
                let off = match op {
                    0x26 => read_i32(code, pc + 1),
                    0x2b | 0x2c => read_i32(code, pc + 1),
                    _ => 0,
                };
                let target = branch_target(code, pc, off);
                if target >= 0 && (target as usize) < code.insns.len() {
                    match op {
                        0x2b => parse_packed(code, pc, target as usize, payloads),
                        0x2c => parse_sparse(code, pc, target as usize, payloads),
                        _ => parse_array(code, pc, target as usize, payloads),
                    }
                }
            }
            _ => {}
        }
        pc += super::opcode_width(op, &code.insns, pc).max(1);
    }
    for payload in payloads.iter() {
        match payload {
            Payload::Packed { pc, targets, .. } => {
                for off in targets {
                    labels.insert(branch_target(code, *pc, *off) as u32);
                }
            }
            Payload::Sparse { pc, targets, .. } => {
                for off in targets {
                    labels.insert(branch_target(code, *pc, *off) as u32);
                }
            }
            Payload::Array { .. } => {}
        }
    }
}

fn parse_packed(code: &CodeItem, switch_pc: usize, target: usize, out: &mut Vec<Payload>) {
    if code.insns.get(target).map(|x| x & 0xff00) != Some(0x0100) {
        return;
    }
    let size = code.insns.get(target + 1).copied().unwrap_or(0) as usize;
    let first = read_i32(code, target + 2);
    let mut targets = Vec::with_capacity(size);
    for i in 0..size {
        targets.push(read_i32(code, target + 4 + i * 2));
    }
    out.push(Payload::Packed {
        pc: switch_pc,
        target,
        first_key: first,
        targets,
    });
}
fn parse_sparse(code: &CodeItem, switch_pc: usize, target: usize, out: &mut Vec<Payload>) {
    if code.insns.get(target).map(|x| x & 0xff00) != Some(0x0200) {
        return;
    }
    let size = code.insns.get(target + 1).copied().unwrap_or(0) as usize;
    let mut keys = Vec::with_capacity(size);
    let mut targets = Vec::with_capacity(size);
    for i in 0..size {
        keys.push(read_i32(code, target + 2 + i * 2));
    }
    for i in 0..size {
        targets.push(read_i32(code, target + 2 + size * 2 + i * 2));
    }
    out.push(Payload::Sparse {
        pc: switch_pc,
        target,
        keys,
        targets,
    });
}
fn parse_array(code: &CodeItem, _pc: usize, target: usize, out: &mut Vec<Payload>) {
    if code.insns.get(target).map(|x| x & 0xff00) != Some(0x0300) {
        return;
    }
    let width = code.insns.get(target + 1).copied().unwrap_or(0);
    let size = read_u32(code, target + 2) as usize;
    let units = (size * width as usize).div_ceil(2);
    let values = code
        .insns
        .get(target + 4..target + 4 + units)
        .unwrap_or(&[])
        .to_vec();
    out.push(Payload::Array {
        target,
        width,
        size,
        values,
    });
}
fn payload_width(code: &CodeItem, pc: usize) -> usize {
    match code.insns.get(pc).map(|v| v >> 8) {
        Some(1) => 4 + code.insns.get(pc + 1).copied().unwrap_or(0) as usize * 2,
        Some(2) => 2 + code.insns.get(pc + 1).copied().unwrap_or(0) as usize * 4,
        Some(3) => {
            let width = code.insns.get(pc + 1).copied().unwrap_or(0) as usize;
            let size = read_u32(code, pc + 2) as usize;
            4 + (width * size).div_ceil(2)
        }
        _ => 1,
    }
}

fn render_payload(out: &mut String, code: &CodeItem, payload: &Payload) {
    match payload {
        Payload::Packed {
            pc,
            target,
            first_key,
            targets,
        } => {
            out.push_str(&format!("    :payload_{:04x}_{:04x}\n", target, pc));
            out.push_str(&format!("    .packed-switch 0x{:x}\n", *first_key as u32));
            for off in targets {
                out.push_str(&format!(
                    "        :label_{:04x}\n",
                    branch_target(code, *pc, *off)
                ));
            }
            out.push_str("    .end packed-switch\n");
        }
        Payload::Sparse {
            pc,
            target,
            keys,
            targets,
        } => {
            out.push_str(&format!("    :payload_{:04x}_{:04x}\n", target, pc));
            out.push_str("    .sparse-switch\n");
            for (key, off) in keys.iter().zip(targets) {
                out.push_str(&format!(
                    "        0x{:x} -> :label_{:04x}\n",
                    *key as u32,
                    branch_target(code, *pc, *off)
                ));
            }
            out.push_str("    .end sparse-switch\n");
        }
        Payload::Array {
            target,
            width,
            size,
            values,
        } => {
            out.push_str(&format!("    :payload_{:04x}_0000\n", target));
            out.push_str(&format!("    .array-data {}\n", width));
            let mut bytes = Vec::with_capacity(values.len() * 2);
            for value in values {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            for i in 0..*size {
                let text = match *width {
                    1 => format_typed(bytes.get(i).copied().unwrap_or(0) as i8 as i64, 't'),
                    2 => {
                        let j = i * 2;
                        format_typed(
                            i16::from_le_bytes([
                                bytes.get(j).copied().unwrap_or(0),
                                bytes.get(j + 1).copied().unwrap_or(0),
                            ]) as i64,
                            's',
                        )
                    }
                    4 => {
                        let j = i * 4;
                        let mut a = [0u8; 4];
                        for k in 0..4 {
                            a[k] = bytes.get(j + k).copied().unwrap_or(0);
                        }
                        format_typed(i32::from_le_bytes(a) as i64, '\0')
                    }
                    8 => {
                        let j = i * 8;
                        let mut a = [0u8; 8];
                        for k in 0..8 {
                            a[k] = bytes.get(j + k).copied().unwrap_or(0);
                        }
                        format_typed(i64::from_le_bytes(a), 'L')
                    }
                    _ => "0x0".into(),
                };
                out.push_str("        ");
                out.push_str(&text);
                out.push('\n');
            }
            out.push_str("    .end array-data\n");
        }
    }
}

fn branch_target(_code: &CodeItem, pc: usize, off: i32) -> i32 {
    pc as i32 + off
}
fn read_u32(code: &CodeItem, i: usize) -> u32 {
    (code.insns.get(i).copied().unwrap_or(0) as u32)
        | ((code.insns.get(i + 1).copied().unwrap_or(0) as u32) << 16)
}
fn read_i32(code: &CodeItem, i: usize) -> i32 {
    read_u32(code, i) as i32
}

fn reg(unit: u16, shift: u32) -> String {
    format!("v{}", (unit >> shift) & 0xf)
}
fn reg8(unit: u16) -> String {
    format!("v{}", unit >> 8)
}
fn reg16(v: u16) -> String {
    format!("v{}", v)
}
fn reg_b(unit: u16) -> String {
    format!("v{}", unit & 0xff)
}
fn reg_c(unit: u16) -> String {
    format!("v{}", unit >> 8)
}
fn label(code: &CodeItem, pc: usize, off: i32) -> String {
    format!(":label_{:04x}", branch_target(code, pc, off))
}
fn lit(v: i64) -> String {
    if v < 0 {
        format!("-0x{:x}", v.unsigned_abs())
    } else {
        format!("0x{:x}", v)
    }
}
fn sign_nibble(v: u16) -> i64 {
    let v = (v & 0xf) as i64;
    if v & 8 != 0 {
        v - 16
    } else {
        v
    }
}
fn lit_wide(v: i64) -> String {
    format!("{}L", lit(v))
}
fn format_typed(v: i64, suffix: char) -> String {
    let mut s = lit(v);
    if suffix != '\0' {
        s.push(suffix);
    }
    s
}
fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.encode_utf16() {
        match ch {
            0x0a => out.push_str("\\n"),
            0x0d => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            0x5c => out.push_str("\\\\"),
            0x22 => out.push_str("\\\""),
            0x20..=0x7e => out.push(ch as u8 as char),
            _ => out.push_str(&format!("\\u{:04x}", ch)),
        }
    }
    out.push('"');
    out
}

fn field_ref(dex: &DexFile, idx: usize) -> String {
    dex.fields
        .get(idx)
        .map(|f| {
            format!(
                "{}->{}:{}",
                dex.type_descriptor(f.class_idx as u32),
                dex.string(f.name_idx),
                dex.type_descriptor(f.type_idx as u32)
            )
        })
        .unwrap_or_else(|| format!("field@{}", idx))
}
fn method_ref(dex: &DexFile, idx: usize) -> String {
    dex.method_descriptors
        .get()
        .and_then(|all| all.get(idx))
        .cloned()
        .unwrap_or_else(|| super::build_method_descriptor(dex, idx as u32))
}
fn format_args(_unit: u16, regs: [u16; 5], count: usize) -> String {
    regs[..count.min(5)]
        .iter()
        .map(|r| reg16(*r))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_instruction(dex: &DexFile, code: &CodeItem, pc: usize) -> String {
    let u = code.insns[pc];
    let op = (u & 0xff) as u8;
    let next = |n| code.insns.get(pc + n).copied().unwrap_or(0);
    let bin = |name: &str| format!("{} {}, {}", name, reg(u, 8), reg(u, 12));
    let bin3 = |name: &str| {
        format!(
            "{} {}, {}, {}",
            name,
            reg8(u),
            reg_b(next(1)),
            reg_c(next(1))
        )
    };
    match op {
        0x00 => "nop".into(),
        0x01..=0x03 => format!(
            "move{} {}, {}",
            ["", "/from16", "/16"][usize::from(op - 1)],
            if op == 3 {
                reg16(next(1))
            } else if op == 1 {
                reg(u, 8)
            } else {
                reg8(u)
            },
            if op == 3 {
                reg16(next(2))
            } else if op == 2 {
                reg16(next(1))
            } else {
                reg(u, 12)
            }
        ),
        0x04..=0x06 => format!(
            "move-wide{} {}, {}",
            ["", "/from16", "/16"][usize::from(op - 4)],
            if op == 6 {
                reg16(next(1))
            } else if op == 4 {
                reg(u, 8)
            } else {
                reg8(u)
            },
            if op == 6 {
                reg16(next(2))
            } else if op == 5 {
                reg16(next(1))
            } else {
                reg(u, 12)
            }
        ),
        0x07..=0x09 => format!(
            "move-object{} {}, {}",
            ["", "/from16", "/16"][usize::from(op - 7)],
            if op == 9 {
                reg16(next(1))
            } else if op == 7 {
                reg(u, 8)
            } else {
                reg8(u)
            },
            if op == 9 {
                reg16(next(2))
            } else if op == 8 {
                reg16(next(1))
            } else {
                reg(u, 12)
            }
        ),
        0x0a..=0x0d => {
            let name = [
                "move-result",
                "move-result-wide",
                "move-result-object",
                "move-exception",
            ][usize::from(op - 0x0a)];
            format!("{} {}", name, reg8(u))
        }
        0x0e => "return-void".into(),
        0x0f..=0x11 => format!(
            "{} {}",
            ["return", "return-wide", "return-object"][usize::from(op - 0x0f)],
            reg8(u)
        ),
        0x12 => format!("const/4 {}, {}", reg(u, 8), lit(sign_nibble(u >> 12))),
        0x13 => format!("const/16 {}, {}", reg8(u), lit(next(1) as i16 as i64)),
        0x14 => format!(
            "const {}, {}",
            reg8(u),
            lit(read_u32(code, pc + 1) as i32 as i64)
        ),
        0x15 => format!(
            "const/high16 {}, {}",
            reg8(u),
            lit((next(1) as i16 as i64) << 16)
        ),
        0x16 => format!("const-wide/16 {}, {}", reg8(u), lit(next(1) as i16 as i64)),
        0x17 => format!(
            "const-wide/32 {}, {}",
            reg8(u),
            lit(read_u32(code, pc + 1) as i32 as i64)
        ),
        0x18 => format!(
            "const-wide {}, {}",
            reg8(u),
            lit_wide(read_u64(code, pc + 1))
        ),
        0x19 => format!(
            "const-wide/high16 {}, {}",
            reg8(u),
            lit((next(1) as i16 as i64) << 48)
        ),
        0x1a | 0x1b => {
            let idx = if op == 0x1a {
                next(1) as u32
            } else {
                read_u32(code, pc + 1)
            };
            format!(
                "const-string{} {}, {}",
                if op == 0x1b { "/jumbo" } else { "" },
                reg8(u),
                quote(dex.string(idx))
            )
        }
        0x1c => format!(
            "const-class {}, {}",
            reg8(u),
            dex.type_descriptor(next(1) as u32)
        ),
        0x1d => format!("monitor-enter {}", reg8(u)),
        0x1e => format!("monitor-exit {}", reg8(u)),
        0x1f => format!(
            "check-cast {}, {}",
            reg8(u),
            dex.type_descriptor(next(1) as u32)
        ),
        0x20 => format!(
            "instance-of {}, {}, {}",
            reg(u, 8),
            reg(u, 12),
            dex.type_descriptor(next(1) as u32)
        ),
        0x21 => format!("array-length {}, {}", reg(u, 8), reg(u, 12)),
        0x22 => format!(
            "new-instance {}, {}",
            reg8(u),
            dex.type_descriptor(next(1) as u32)
        ),
        0x23 => format!(
            "new-array {}, {}, {}",
            reg(u, 8),
            reg(u, 12),
            dex.type_descriptor(next(1) as u32)
        ),
        0x24 | 0x25 => {
            let count = if op == 0x25 {
                ((u >> 8) & 0xff) as usize
            } else {
                ((u >> 12) & 0xf) as usize
            };
            let idx = next(1);
            let args = if op == 0x24 {
                let x = next(2);
                format_args(
                    u,
                    [
                        x & 0xf,
                        (x >> 4) & 0xf,
                        (x >> 8) & 0xf,
                        (x >> 12) & 0xf,
                        ((u >> 8) & 0xf) as u16,
                    ],
                    count,
                )
            } else {
                let start = next(2);
                if count == 0 {
                    String::new()
                } else {
                    format!("{} .. {}", reg16(start), reg16(start + count as u16 - 1))
                }
            };
            format!(
                "filled-new-array{} {{{}}}, {}",
                if op == 0x25 { "/range" } else { "" },
                args,
                dex.type_descriptor(idx as u32)
            )
        }
        0x26 => {
            let target = branch_target(code, pc, read_i32(code, pc + 1));
            format!("fill-array-data {}, :payload_{:04x}_0000", reg8(u), target)
        }
        0x27 => format!("throw {}", reg8(u)),
        0x28 => format!("goto {}", label(code, pc, (u >> 8) as i8 as i32)),
        0x29 => format!("goto/16 {}", label(code, pc, next(1) as i16 as i32)),
        0x2a => format!("goto/32 {}", label(code, pc, read_i32(code, pc + 1))),
        0x2b | 0x2c => {
            let t = branch_target(code, pc, read_i32(code, pc + 1));
            format!(
                "{} {}, :payload_{:04x}_{:04x}",
                if op == 0x2b {
                    "packed-switch"
                } else {
                    "sparse-switch"
                },
                reg8(u),
                t,
                pc
            )
        }
        0x2d..=0x31 => format!(
            "{} {}, {}, {}",
            [
                "cmpl-float",
                "cmpg-float",
                "cmpl-double",
                "cmpg-double",
                "cmp-long"
            ][usize::from(op - 0x2d)],
            reg8(u),
            reg_b(next(1)),
            reg_c(next(1))
        ),
        0x32..=0x37 => format!(
            "{} {}, {}, {}",
            ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"][usize::from(op - 0x32)],
            reg(u, 8),
            reg(u, 12),
            label(code, pc, next(1) as i16 as i32)
        ),
        0x38..=0x3d => format!(
            "{} {}, {}",
            ["if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"][usize::from(op - 0x38)],
            reg8(u),
            label(code, pc, next(1) as i16 as i32)
        ),
        0x44..=0x51 => format!(
            "{} {}, {}, {}",
            [
                "aget",
                "aget-wide",
                "aget-object",
                "aget-boolean",
                "aget-byte",
                "aget-char",
                "aget-short",
                "aput",
                "aput-wide",
                "aput-object",
                "aput-boolean",
                "aput-byte",
                "aput-char",
                "aput-short"
            ][usize::from(op - 0x44)],
            reg8(u),
            reg_b(next(1)),
            reg_c(next(1))
        ),
        0x52..=0x5f => format!(
            "{} {}, {}, {}",
            [
                "iget",
                "iget-wide",
                "iget-object",
                "iget-boolean",
                "iget-byte",
                "iget-char",
                "iget-short",
                "iput",
                "iput-wide",
                "iput-object",
                "iput-boolean",
                "iput-byte",
                "iput-char",
                "iput-short"
            ][usize::from(op - 0x52)],
            reg(u, 8),
            reg(u, 12),
            field_ref(dex, next(1) as usize)
        ),
        0x60..=0x6d => format!(
            "{} {}, {}",
            [
                "sget",
                "sget-wide",
                "sget-object",
                "sget-boolean",
                "sget-byte",
                "sget-char",
                "sget-short",
                "sput",
                "sput-wide",
                "sput-object",
                "sput-boolean",
                "sput-byte",
                "sput-char",
                "sput-short"
            ][usize::from(op - 0x60)],
            reg8(u),
            field_ref(dex, next(1) as usize)
        ),
        0x6e..=0x72 | 0x74..=0x78 => format_invoke(dex, code, pc, op),
        0x7b..=0x8f => format!("{} {}, {}", unary_name(op), reg(u, 8), reg(u, 12)),
        0x90..=0xaf => bin3(bin_name(op)),
        0xb0..=0xcf => bin(bin_name(op)),
        0xd0..=0xe2 => format!(
            "{} {}, {}, {}",
            bin_name(op),
            reg(u, 8),
            if op >= 0xd8 {
                reg_b(next(1))
            } else {
                reg(u, 12)
            },
            lit(if op >= 0xd8 {
                ((next(1) >> 8) as i8) as i64
            } else {
                next(1) as i16 as i64
            })
        ),
        _ => format!("op_{:02x} 0x{:04x}", op, u),
    }
}

fn read_u64(code: &CodeItem, i: usize) -> i64 {
    let mut v = 0u64;
    for j in 0..4 {
        v |= (code.insns.get(i + j).copied().unwrap_or(0) as u64) << (j * 16);
    }
    v as i64
}
fn format_invoke(dex: &DexFile, code: &CodeItem, pc: usize, op: u8) -> String {
    let u = code.insns[pc];
    let count = if op >= 0x74 {
        ((u >> 8) & 0xff) as usize
    } else {
        ((u >> 12) & 0xf) as usize
    };
    let idx = code.insns.get(pc + 1).copied().unwrap_or(0) as usize;
    let names = [
        "invoke-virtual",
        "invoke-super",
        "invoke-direct",
        "invoke-static",
        "invoke-interface",
    ];
    let name = if op >= 0x74 {
        format!("{}/range", names[(op - 0x74) as usize])
    } else {
        names[(op - 0x6e) as usize].into()
    };
    let args = if op >= 0x74 {
        let start = code.insns.get(pc + 2).copied().unwrap_or(0);
        if count == 0 {
            String::new()
        } else {
            format!("{} .. {}", reg16(start), reg16(start + count as u16 - 1))
        }
    } else {
        let x = code.insns.get(pc + 2).copied().unwrap_or(0);
        format_args(
            u,
            [
                x & 0xf,
                (x >> 4) & 0xf,
                (x >> 8) & 0xf,
                (x >> 12) & 0xf,
                ((u >> 8) & 0xf) as u16,
            ],
            count,
        )
    };
    format!("{} {{{}}}, {}", name, args, method_ref(dex, idx))
}
fn unary_name(op: u8) -> &'static str {
    [
        "neg-int",
        "not-int",
        "neg-long",
        "not-long",
        "neg-float",
        "neg-double",
        "int-to-long",
        "int-to-float",
        "int-to-double",
        "long-to-int",
        "long-to-float",
        "long-to-double",
        "float-to-int",
        "float-to-long",
        "float-to-double",
        "double-to-int",
        "double-to-long",
        "double-to-float",
        "int-to-byte",
        "int-to-char",
        "int-to-short",
    ][usize::from(op - 0x7b)]
}
fn bin_name(op: u8) -> &'static str {
    const N: &[&str] = &[
        "add-int",
        "sub-int",
        "mul-int",
        "div-int",
        "rem-int",
        "and-int",
        "or-int",
        "xor-int",
        "shl-int",
        "shr-int",
        "ushr-int",
        "add-long",
        "sub-long",
        "mul-long",
        "div-long",
        "rem-long",
        "and-long",
        "or-long",
        "xor-long",
        "shl-long",
        "shr-long",
        "ushr-long",
        "add-float",
        "sub-float",
        "mul-float",
        "div-float",
        "rem-float",
        "add-double",
        "sub-double",
        "mul-double",
        "div-double",
        "rem-double",
        "add-int/2addr",
        "sub-int/2addr",
        "mul-int/2addr",
        "div-int/2addr",
        "rem-int/2addr",
        "and-int/2addr",
        "or-int/2addr",
        "xor-int/2addr",
        "shl-int/2addr",
        "shr-int/2addr",
        "ushr-int/2addr",
        "add-long/2addr",
        "sub-long/2addr",
        "mul-long/2addr",
        "div-long/2addr",
        "rem-long/2addr",
        "and-long/2addr",
        "or-long/2addr",
        "xor-long/2addr",
        "shl-long/2addr",
        "shr-long/2addr",
        "ushr-long/2addr",
        "add-float/2addr",
        "sub-float/2addr",
        "mul-float/2addr",
        "div-float/2addr",
        "rem-float/2addr",
        "add-double/2addr",
        "sub-double/2addr",
        "mul-double/2addr",
        "div-double/2addr",
        "rem-double/2addr",
        "add-int/lit16",
        "rsub-int",
        "mul-int/lit16",
        "div-int/lit16",
        "rem-int/lit16",
        "and-int/lit16",
        "or-int/lit16",
        "xor-int/lit16",
        "add-int/lit8",
        "rsub-int/lit8",
        "mul-int/lit8",
        "div-int/lit8",
        "rem-int/lit8",
        "and-int/lit8",
        "or-int/lit8",
        "xor-int/lit8",
        "shl-int/lit8",
        "shr-int/lit8",
        "ushr-int/lit8",
    ];
    N.get((op - 0x90) as usize).copied().unwrap_or("unknown-op")
}
