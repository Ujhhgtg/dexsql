//! Fast extraction of DEX members from APK/JAR ZIP containers.
//!
//! DexSQL's query path treats the archive as an immutable byte source: one
//! mmap is shared by the worker threads and each compressed DEX is inflated
//! directly into its final buffer. Keeping this separate from the metadata
//! parser avoids reopening and reparsing the ZIP central directory once per
//! member.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use memmap2::Mmap;
use rayon::prelude::*;

#[derive(Debug, Clone)]
pub struct InflateError(pub String);

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InflateError {}

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    method: u16,
    compressed_offset: usize,
    compressed_size: usize,
    uncompressed_size: usize,
}

/// Inflate all `classes*.dex` members from an archive in central-directory
/// order. Stored entries are copied; deflated entries use miniz_oxide's raw
/// DEFLATE decoder. The returned buffers own their bytes and can therefore be
/// parsed after the mmap is dropped.
pub fn inflate_dex_entries(path: &Path) -> Result<Vec<(String, Vec<u8>)>, InflateError> {
    inflate_dex_entries_with(path, None, |_, name, bytes| Ok((name, bytes)))
}

/// Return the number of `classes*.dex` members without inflating any bytes.
pub fn dex_entry_count(path: &Path) -> Result<usize, InflateError> {
    let file = File::open(path)
        .map_err(|e| InflateError(format!("failed to open {}: {e}", path.display())))?;
    let mmap = unsafe {
        Mmap::map(&file)
            .map_err(|e| InflateError(format!("failed to mmap {}: {e}", path.display())))?
    };
    Ok(find_dex_entries(&mmap)?.len())
}

/// Inflate entries and parse each one on the same worker that produced its
/// output.  This overlaps DEFLATE work with DEX parsing and matches the
/// original pipeline's per-entry worker ownership.  `target_index` is used by
/// decode to avoid inflating unrelated multidex members.
pub fn inflate_dex_entries_with<T, F>(
    path: &Path,
    target_index: Option<usize>,
    parser: F,
) -> Result<Vec<T>, InflateError>
where
    T: Send,
    F: Fn(usize, String, Vec<u8>) -> Result<T, InflateError> + Sync,
{
    let file = File::open(path)
        .map_err(|e| InflateError(format!("failed to open {}: {e}", path.display())))?;
    let mmap = unsafe {
        Mmap::map(&file)
            .map_err(|e| InflateError(format!("failed to mmap {}: {e}", path.display())))?
    };
    let entries = find_dex_entries(&mmap)?;
    entries
        .into_par_iter()
        .enumerate()
        .filter(|(index, _)| target_index.is_none_or(|target| target == *index))
        .map(|(index, entry)| {
            let name = entry.name.clone();
            let bytes = inflate_entry(&mmap, &entry)?;
            parser(index, name, bytes)
        })
        .collect()
}

fn inflate_entry(mmap: &[u8], entry: &Entry) -> Result<Vec<u8>, InflateError> {
    let end = entry
        .compressed_offset
        .checked_add(entry.compressed_size)
        .ok_or_else(|| InflateError(format!("ZIP entry {} overflows", entry.name)))?;
    let input = mmap
        .get(entry.compressed_offset..end)
        .ok_or_else(|| InflateError(format!("ZIP entry {} exceeds archive bounds", entry.name)))?;
    let bytes = match entry.method {
        0 => input.to_vec(),
        8 => {
            // The inflater writes every output byte before reading it as a
            // back-reference. Leave the exact-size buffer uninitialized so
            // the allocator/kernel do not perform a second 190 MiB memset;
            // this mirrors the original anonymous mmap output buffers.
            let mut output = Vec::with_capacity(entry.uncompressed_size);
            unsafe { output.set_len(entry.uncompressed_size) };
            let mut decoder = flate2::read::DeflateDecoder::new(input);
            decoder
                .read_exact(&mut output)
                .map_err(|e| InflateError(format!("failed to inflate {}: {e}", entry.name)))?;
            output
        }
        method => {
            return Err(InflateError(format!(
                "unsupported ZIP compression method {method} for {}",
                entry.name
            )))
        }
    };
    if bytes.len() != entry.uncompressed_size {
        return Err(InflateError(format!(
            "inflated {} to {} bytes, expected {}",
            entry.name,
            bytes.len(),
            entry.uncompressed_size
        )));
    }
    Ok(bytes)
}

fn find_dex_entries(bytes: &[u8]) -> Result<Vec<Entry>, InflateError> {
    let search_start = bytes.len().saturating_sub(65_557);
    let eocd = (search_start..bytes.len().saturating_sub(3))
        .rev()
        .find(|&off| bytes.get(off..off + 4) == Some(b"PK\x05\x06"))
        .ok_or_else(|| InflateError("ZIP end-of-central-directory is missing".into()))?;
    let count = u16_at(bytes, eocd + 10)? as usize;
    let central_size = u32_at(bytes, eocd + 12)? as usize;
    let central_offset = u32_at(bytes, eocd + 16)? as usize;
    let central_end = central_offset
        .checked_add(central_size)
        .ok_or_else(|| InflateError("ZIP central directory overflows".into()))?;
    if central_end > bytes.len() {
        return Err(InflateError("ZIP central directory exceeds archive".into()));
    }
    let mut out = Vec::with_capacity(count.min(64));
    let mut pos = central_offset;
    for _ in 0..count {
        if bytes.get(pos..pos + 4) != Some(b"PK\x01\x02") {
            return Err(InflateError("invalid ZIP central-directory entry".into()));
        }
        let method = u16_at(bytes, pos + 10)?;
        let compressed_size = u32_at(bytes, pos + 20)? as usize;
        let uncompressed_size = u32_at(bytes, pos + 24)? as usize;
        let name_len = u16_at(bytes, pos + 28)? as usize;
        let extra_len = u16_at(bytes, pos + 30)? as usize;
        let comment_len = u16_at(bytes, pos + 32)? as usize;
        let local_header_offset = u32_at(bytes, pos + 42)? as usize;
        let name_start = pos + 46;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(|| InflateError("ZIP name overflows".into()))?;
        let name = std::str::from_utf8(
            bytes
                .get(name_start..name_end)
                .ok_or_else(|| InflateError("ZIP name exceeds archive".into()))?,
        )
        .map_err(|_| InflateError("ZIP entry name is not UTF-8".into()))?
        .to_owned();
        pos = name_end
            .checked_add(extra_len)
            .and_then(|v| v.checked_add(comment_len))
            .ok_or_else(|| InflateError("ZIP central entry overflows".into()))?;
        if !is_dex_name(&name) {
            continue;
        }
        if bytes.get(local_header_offset..local_header_offset + 4) != Some(b"PK\x03\x04") {
            return Err(InflateError(format!("invalid local header for {name}")));
        }
        let local_name_len = u16_at(bytes, local_header_offset + 26)? as usize;
        let local_extra_len = u16_at(bytes, local_header_offset + 28)? as usize;
        let compressed_offset = local_header_offset
            .checked_add(30)
            .and_then(|v| v.checked_add(local_name_len))
            .and_then(|v| v.checked_add(local_extra_len))
            .ok_or_else(|| InflateError(format!("local header for {name} overflows")))?;
        let compressed_end = compressed_offset
            .checked_add(compressed_size)
            .ok_or_else(|| InflateError(format!("compressed entry {name} overflows")))?;
        if compressed_end > bytes.len() {
            return Err(InflateError(format!(
                "compressed entry {name} exceeds archive"
            )));
        }
        out.push(Entry {
            name,
            method,
            compressed_offset,
            compressed_size,
            uncompressed_size,
        });
    }
    Ok(out)
}

fn is_dex_name(name: &str) -> bool {
    if name == "classes.dex" {
        return true;
    }
    name.strip_prefix("classes")
        .and_then(|suffix| suffix.strip_suffix(".dex"))
        .is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn u16_at(bytes: &[u8], off: usize) -> Result<u16, InflateError> {
    let value = bytes
        .get(off..off + 2)
        .ok_or_else(|| InflateError(format!("ZIP read u16 out of range at 0x{off:x}")))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn u32_at(bytes: &[u8], off: usize) -> Result<u32, InflateError> {
    let value = bytes
        .get(off..off + 4)
        .ok_or_else(|| InflateError(format!("ZIP read u32 out of range at 0x{off:x}")))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}
