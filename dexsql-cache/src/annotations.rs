//! DEX annotation parsing for the metadata JSON API.
//!
//! The SQL schema exposes the same data through the `annotation_*` and
//! `encoded_*` relations, but those are query relations. The typed metadata API
//! resolves one class or method descriptor and renders the attached annotations
//! directly from the DEX bytes, in DexKit's `AnnotationData` shape:
//!
//! `[{ type, type_name, visibility, elements: [{ name, value }] }]`
//!
//! Element values are decoded from the DEX encoded-value encoding. String
//! arrays (for example `@dalvik/annotation/Signature` values) render as JSON
//! arrays of strings; integers/booleans/floats render as JSON scalars; type,
//! field, method, and enum values render as descriptor strings; nested
//! annotations render as objects. Visibility names follow DexKit's
//! `AnnotationVisibilityType`: `build`, `runtime`, `system` (unknown bytes
//! render as `"unknown"`).
//!
//! Annotation bytes are only available when the dataset retains the raw DEX
//! payload (same load requirement as the `annotation_*` relations and code
//! items). Loads that keep parsed metadata only render an empty annotation
//! list instead of erroring.

use crate::metadata::class_descriptor_to_name;
use crate::{ClassInfo, DexFile};
use serde_json::{Map, Value};

/// Annotations attached to a class definition.
pub fn class_annotations(file: &DexFile, class: &ClassInfo) -> Result<Value, String> {
    let Some(annotations_off) = class_annotations_off(file, class.class_def_idx)? else {
        return Ok(Value::Array(Vec::new()));
    };
    let mut cursor = Cursor::new(file)?;
    let class_set_off = cursor.read_u32_at(annotations_off as usize)?;
    if class_set_off == 0 {
        return Ok(Value::Array(Vec::new()));
    }
    annotation_set_json(file, class_set_off as usize)
}

/// Annotations attached to one method definition.
pub fn method_annotations(file: &DexFile, method_idx: u32) -> Result<Value, String> {
    let Some(method) = file.methods.get(method_idx as usize) else {
        return Ok(Value::Array(Vec::new()));
    };
    let Some(class) = file.class_for_type_idx(method.class_idx as u32) else {
        return Ok(Value::Array(Vec::new()));
    };
    let Some(annotations_off) = class_annotations_off(file, class.class_def_idx)? else {
        return Ok(Value::Array(Vec::new()));
    };
    let mut cursor = Cursor::new(file)?;
    let fields_size = cursor.read_u32_at(annotations_off as usize + 4)? as usize;
    let methods_start = annotations_off as usize + 16 + fields_size * 8;
    let methods_size = cursor.read_u32_at(annotations_off as usize + 8)? as usize;
    for index in 0..methods_size {
        let entry = methods_start + index * 8;
        let entry_method_idx = cursor.read_u32_at(entry)?;
        if entry_method_idx != method_idx {
            continue;
        }
        let set_off = cursor.read_u32_at(entry + 4)?;
        if set_off == 0 {
            return Ok(Value::Array(Vec::new()));
        }
        return annotation_set_json(file, set_off as usize);
    }
    Ok(Value::Array(Vec::new()))
}

/// Offset of the annotation directory for one class def, or None for none.
fn class_annotations_off(file: &DexFile, class_def_idx: u32) -> Result<Option<u32>, String> {
    if file.raw().is_empty() {
        return Ok(None);
    }
    let base = file.class_defs_off as usize + class_def_idx as usize * 32;
    let mut cursor = Cursor::new(file)?;
    let off = cursor.read_u32_at(base + 20)?;
    Ok((off != 0).then_some(off))
}

fn annotation_set_json(file: &DexFile, set_off: usize) -> Result<Value, String> {
    let mut cursor = Cursor::new(file)?;
    let size = cursor.read_u32_at(set_off)? as usize;
    cursor.check_count(set_off + 4, size, 4)?;
    let mut annotations = Vec::new();
    for index in 0..size {
        let item_off = cursor.read_u32_at(set_off + 4 + index * 4)? as usize;
        annotations.push(annotation_json(file, item_off)?);
    }
    Ok(Value::Array(annotations))
}

fn annotation_json(file: &DexFile, item_off: usize) -> Result<Value, String> {
    let mut cursor = Cursor::new(file)?;
    let visibility = cursor.read_u8(item_off)?;
    let mut annotation = encoded_annotation_json(file, &mut cursor, item_off + 1)?;
    let object = annotation
        .as_object_mut()
        .ok_or("encoded annotation is not an object")?;
    object.insert(
        "visibility".to_owned(),
        Value::from(visibility_name(visibility)),
    );
    Ok(annotation)
}

fn visibility_name(visibility: u8) -> &'static str {
    match visibility {
        0 => "build",
        1 => "runtime",
        2 => "system",
        _ => "unknown",
    }
}

fn encoded_annotation_json(
    file: &DexFile,
    cursor: &mut Cursor<'_>,
    start: usize,
) -> Result<Value, String> {
    cursor.seek(start);
    let type_idx = cursor.read_uleb128()? as usize;
    if type_idx >= file.types.len() {
        return Err(format!("annotation type index {type_idx} is out of range"));
    }
    let type_descriptor = file.type_descriptor(type_idx as u32).to_owned();
    let type_name = class_descriptor_to_name(&type_descriptor)?;
    let size = cursor.read_uleb128()? as usize;
    // Every element needs at least a one-byte name id and a value header.
    // Validate before allocating, and grow only as successfully decoded
    // elements arrive; a corrupt count must not reserve gigabytes first.
    cursor.check_count(cursor.pos, size, 2)?;
    let mut elements = Vec::new();
    for _ in 0..size {
        let name_idx = cursor.read_uleb128()? as usize;
        let name = file
            .strings
            .get(name_idx)
            .ok_or_else(|| format!("annotation element name index {name_idx} is out of range"))?
            .to_owned();
        let value = encoded_value_json(file, cursor)?;
        elements.push(Value::Object(Map::from_iter([
            ("name".to_owned(), Value::from(name)),
            ("value".to_owned(), value),
        ])));
    }
    Ok(Value::Object(Map::from_iter([
        ("type".to_owned(), Value::from(type_descriptor)),
        ("type_name".to_owned(), Value::from(type_name)),
        ("elements".to_owned(), Value::Array(elements)),
    ])))
}

#[cfg(test)]
mod tests {
    use super::{annotation_set_json, encoded_annotation_json, encoded_value_json, Cursor};
    use dexsql_cache::{Dataset, DexFile};
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn fixture_file(name: &str) -> DexFile {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/dex")
            .join(name);
        Dataset::load_paths(&[path]).unwrap().files.remove(0)
    }

    fn parse_value(file: &DexFile, bytes: &[u8]) -> Result<serde_json::Value, String> {
        let mut cursor = Cursor { bytes, pos: 0 };
        encoded_value_json(file, &mut cursor)
    }

    #[test]
    fn compressed_float_values_restore_low_zero_bits() {
        let file = fixture_file("annotated.dex");
        for (encoded, expected) in [
            (&[0x30, 0x80, 0x3f][..], 1.0),
            (&[0x10, 0x40][..], 2.0),
            (&[0x70, 0x00, 0x00, 0x80, 0x3f][..], 1.0),
            (&[0x31, 0xf0, 0x3f][..], 1.0),
            (&[0x11, 0x40][..], 2.0),
            (&[0xf1, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f][..], 1.0),
        ] {
            assert_eq!(
                parse_value(&file, encoded).unwrap().as_f64(),
                Some(expected)
            );
        }
        assert_eq!(parse_value(&file, &[0x04, 0xff]).unwrap(), json!(-1));
        assert_eq!(
            parse_value(&file, &[0x23, 0xff, 0xff]).unwrap(),
            json!(65535)
        );
    }

    #[test]
    fn malformed_sizes_and_value_arguments_fail_before_allocation() {
        let mut file = fixture_file("annotated.dex");
        // A six-byte array that claims 2^32 - 1 values used to reserve a
        // Vec<Value> of that length before discovering that it was truncated.
        assert!(parse_value(&file, &[0x1c, 0xff, 0xff, 0xff, 0xff, 0x0f]).is_err());
        assert!(parse_value(&file, &[0x1c, 0xff, 0xff, 0xff, 0xff, 0x1f]).is_err());
        assert!(parse_value(&file, &[0x90, 0, 0, 0, 0, 0]).is_err());
        assert!(parse_value(&file, &[0x3e]).is_err());

        let type_idx = file.type_idx_for_descriptor("Lfixtures/Meta;").unwrap();
        assert!(type_idx < 128);
        let bytes = [type_idx as u8, 0xff, 0xff, 0xff, 0xff, 0x0f];
        let mut cursor = Cursor {
            bytes: &bytes,
            pos: 0,
        };
        assert!(encoded_annotation_json(&file, &mut cursor, 0).is_err());

        file.bytes = Some(Arc::new(vec![0xff; 4]));
        assert!(annotation_set_json(&file, 0).is_err());
    }

    #[test]
    fn annotation_member_references_do_not_fill_whole_dex_descriptor_caches() {
        let file = fixture_file("alpha.dex");
        assert!(!file.fields.is_empty());
        assert!(!file.methods.is_empty());
        assert!(file.field_descriptors.get().is_none());
        assert!(file.method_descriptors.get().is_none());
        assert_eq!(
            parse_value(&file, &[0x19, 0]).unwrap(),
            json!(file.field_descriptor_direct(0)),
        );
        assert_eq!(
            parse_value(&file, &[0x1a, 0]).unwrap(),
            json!(file.method_descriptor_direct(0)),
        );
        assert!(file.field_descriptors.get().is_none());
        assert!(file.method_descriptors.get().is_none());
        assert!(parse_value(&file, &[0x19, 0xff]).is_err());
        assert!(parse_value(&file, &[0x1a, 0xff]).is_err());
    }
}

fn encoded_value_json(file: &DexFile, cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let header = cursor.read_u8(cursor.pos)?;
    cursor.pos += 1;
    let value_type = header & 0x1f;
    let value_arg = header >> 5;
    let max_arg = match value_type {
        0x00 | 0x1c..=0x1e => 0,
        0x02 | 0x03 | 0x1f => 1,
        0x04 | 0x10 | 0x15..=0x1b => 3,
        0x06 | 0x11 => 7,
        _ => return Err(format!("unknown annotation value type {value_type:#x}")),
    };
    if value_arg > max_arg {
        return Err(format!(
            "invalid annotation value argument {value_arg} for type {value_type:#x}"
        ));
    }
    match value_type {
        // byte, short, char, int, long
        0x00 | 0x02 | 0x03 | 0x04 | 0x06 => {
            let bytes = value_arg as usize + 1;
            let raw = cursor.read_unsigned_le(bytes)?;
            match value_type {
                0x03 => Ok(Value::from(raw)),
                _ => Ok(Value::from(sign_extend(raw, bytes * 8))),
            }
        }
        0x10 => {
            let width = value_arg as usize + 1;
            // encoded_value omits low zero bytes of floating-point values.
            // Restore those bits on the right, unlike integer zero extension.
            let bits = (cursor.read_unsigned_le(width)? as u32) << ((4 - width) * 8);
            Ok(Value::from(f32::from_bits(bits) as f64))
        }
        0x11 => {
            let width = value_arg as usize + 1;
            let bits = cursor.read_unsigned_le(width)? << ((8 - width) * 8);
            Ok(Value::from(f64::from_bits(bits)))
        }
        0x15 | 0x16 => {
            let index = cursor.read_unsigned_le(value_arg as usize + 1)?;
            Ok(Value::Object(Map::from_iter([
                (
                    "kind".to_owned(),
                    Value::from(if value_type == 0x15 {
                        "method_type"
                    } else {
                        "method_handle"
                    }),
                ),
                ("index".to_owned(), Value::from(index)),
            ])))
        }
        0x17 => {
            let index = cursor.read_unsigned_le(value_arg as usize + 1)? as usize;
            file.strings
                .get(index)
                .map(|value| Value::from(value.clone()))
                .ok_or_else(|| format!("annotation string index {index} is out of range"))
        }
        0x18 => {
            let index = cursor.read_unsigned_le(value_arg as usize + 1)? as usize;
            if index >= file.types.len() {
                return Err(format!("annotation type index {index} is out of range"));
            }
            Ok(Value::from(file.type_descriptor(index as u32).to_owned()))
        }
        0x19 | 0x1b => {
            let index = cursor.read_unsigned_le(value_arg as usize + 1)?;
            if index as usize >= file.fields.len() {
                return Err(format!("annotation field index {index} is out of range"));
            }
            // A single annotation reference must not populate the descriptor
            // cache for every field in this DEX.
            Ok(Value::from(file.field_descriptor_direct(index as u32)))
        }
        0x1a => {
            let index = cursor.read_unsigned_le(value_arg as usize + 1)?;
            if index as usize >= file.methods.len() {
                return Err(format!("annotation method index {index} is out of range"));
            }
            Ok(Value::from(file.method_descriptor_direct(index as u32)))
        }
        0x1c => {
            let size = cursor.read_uleb128()? as usize;
            cursor.check_count(cursor.pos, size, 1)?;
            let mut values = Vec::new();
            for _ in 0..size {
                values.push(encoded_value_json(file, cursor)?);
            }
            Ok(Value::Array(values))
        }
        0x1d => encoded_annotation_json(file, cursor, cursor.pos),
        0x1e => Ok(Value::Null),
        0x1f => Ok(Value::Bool(value_arg != 0)),
        _ => unreachable!("value type was validated above"),
    }
}

fn sign_extend(value: u64, bits: usize) -> i64 {
    if bits >= 64 {
        return value as i64;
    }
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

/// Checked little-endian reader over the raw DEX payload.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(file: &'a DexFile) -> Result<Self, String> {
        let bytes = file.raw();
        if bytes.is_empty() {
            return Err("annotation bytes are not retained by this dataset".into());
        }
        Ok(Self { bytes, pos: 0 })
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn read_u8(&mut self, pos: usize) -> Result<u8, String> {
        self.bytes
            .get(pos)
            .copied()
            .ok_or_else(|| format!("annotation read out of bounds at {pos:#x}"))
    }

    fn read_u32_at(&mut self, pos: usize) -> Result<u32, String> {
        self.check_count(pos, 1, 4)?;
        let slice = self
            .bytes
            .get(pos..pos + 4)
            .ok_or_else(|| format!("annotation read out of bounds at {pos:#x}"))?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn read_uleb128(&mut self) -> Result<u64, String> {
        let mut result = 0u64;
        // DEX ULEB128 values are u32, including annotation sizes and ids.
        for shift in (0..35).step_by(7) {
            let byte = self.read_u8(self.pos)?;
            self.pos += 1;
            if shift == 28 && byte > 0x0f {
                return Err("annotation uleb128 exceeds u32".into());
            }
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err("annotation uleb128 is too long".into())
    }

    fn check_count(&self, pos: usize, count: usize, width: usize) -> Result<(), String> {
        if pos > self.bytes.len() || count > (self.bytes.len() - pos) / width {
            return Err(format!(
                "annotation count {count} exceeds bytes at {pos:#x}"
            ));
        }
        Ok(())
    }

    fn read_unsigned_le(&mut self, bytes: usize) -> Result<u64, String> {
        if bytes == 0 || bytes > 8 {
            return Err(format!("invalid annotation value width {bytes}"));
        }
        let mut value = 0u64;
        for index in 0..bytes {
            value |= u64::from(self.read_u8(self.pos)?) << (index * 8);
            self.pos += 1;
        }
        Ok(value)
    }
}
