//! Decoder for the modified UTF-8 used by DEX string_data_item values.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    InvalidLead(u8),
    InvalidContinuation(u8),
    UnpairedSurrogate(u16),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated modified UTF-8 sequence"),
            Self::InvalidLead(b) => write!(f, "invalid modified UTF-8 lead byte 0x{b:02x}"),
            Self::InvalidContinuation(b) => {
                write!(f, "invalid modified UTF-8 continuation byte 0x{b:02x}")
            }
            Self::UnpairedSurrogate(u) => write!(f, "unpaired UTF-16 surrogate 0x{u:04x}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode bytes up to (but not including) the DEX string terminator.
pub fn decode(bytes: &[u8]) -> Result<String, DecodeError> {
    // DEX string pools are overwhelmingly ASCII.  Keep the hot path to one
    // copy and one UTF-8 validation instead of first materializing UTF-16
    // units and then transcoding them character by character.
    if bytes.iter().all(|&byte| byte.is_ascii() && byte != 0) {
        return String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::InvalidLead(0));
    }
    let mut units = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0 {
            break;
        }
        let (unit, width) = match b {
            0x01..=0x7f => (b as u16, 1),
            0xc0..=0xdf => {
                let b1 = *bytes.get(i + 1).ok_or(DecodeError::Truncated)?;
                if b1 & 0xc0 != 0x80 {
                    return Err(DecodeError::InvalidContinuation(b1));
                }
                ((((b & 0x1f) as u16) << 6) | (b1 & 0x3f) as u16, 2)
            }
            0xe0..=0xef => {
                let b1 = *bytes.get(i + 1).ok_or(DecodeError::Truncated)?;
                let b2 = *bytes.get(i + 2).ok_or(DecodeError::Truncated)?;
                if b1 & 0xc0 != 0x80 {
                    return Err(DecodeError::InvalidContinuation(b1));
                }
                if b2 & 0xc0 != 0x80 {
                    return Err(DecodeError::InvalidContinuation(b2));
                }
                (
                    (((b & 0x0f) as u16) << 12) | (((b1 & 0x3f) as u16) << 6) | (b2 & 0x3f) as u16,
                    3,
                )
            }
            _ => return Err(DecodeError::InvalidLead(b)),
        };
        units.push(unit);
        i += width;
    }

    let mut out = String::with_capacity(units.len());
    let mut i = 0;
    while i < units.len() {
        let unit = units[i];
        if (0xd800..=0xdbff).contains(&unit) {
            let Some(&next) = units.get(i + 1) else {
                out.push('\u{fffd}');
                i += 1;
                continue;
            };
            if !(0xdc00..=0xdfff).contains(&next) {
                out.push('\u{fffd}');
                i += 1;
                continue;
            }
            let scalar = 0x1_0000 + (((unit as u32 - 0xd800) << 10) | (next as u32 - 0xdc00));
            out.push(char::from_u32(scalar).expect("valid surrogate pair"));
            i += 2;
        } else if (0xdc00..=0xdfff).contains(&unit) {
            out.push('\u{fffd}');
            i += 1;
        } else {
            out.push(char::from_u32(unit as u32).expect("valid UTF-16 unit"));
            i += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn decodes_ascii_and_encoded_nul() {
        assert_eq!(decode(b"a\xc0\x80b\0").unwrap(), "a\0b");
    }

    #[test]
    fn decodes_surrogate_pair() {
        assert_eq!(decode(b"\xed\xa0\xbd\xed\xb8\x80\0").unwrap(), "😀");
    }
}
