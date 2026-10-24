//! Scalar function library for the DexSQL read-only dialect.
//!
//! Behavior is pinned to the reference binary (see `work/docs/sql_functions.md`
//! extracted from the release ELF): SQLite semantics with NULL propagation,
//! text coercion through the value's text representation, ASCII-only case
//! folding, and control-character-preserving `char`.

use crate::Scalar;

/// Format a finite float the way the reference renders REAL values:
/// Rust's shortest representation, with `.0` appended to integral results.
pub fn real_format(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Inf" } else { "-Inf" }.to_owned();
    }
    let mut text = format!("{value}");
    if !text.contains('.') && !text.contains('e') && !text.contains('E') {
        text.push_str(".0");
    }
    text
}

pub fn real_scalar(value: f64) -> Scalar {
    Scalar::Real(real_format(value))
}

/// Text representation used for coercion into string functions.
fn text_of(value: &Scalar) -> Option<String> {
    match value {
        Scalar::Null => None,
        Scalar::Text(text) => Some(text.to_string()),
        Scalar::Int(value) => Some(value.to_string()),
        Scalar::Real(value) => Some(value.clone()),
        Scalar::Blob(bytes) => Some(bytes.iter().map(|b| format!("{b:02x}")).collect()),
    }
}

fn numeric_of(value: &Scalar) -> Option<f64> {
    value.numeric()
}

/// Evaluate a whitelisted scalar function.  Returns `None` when `name` is
/// not a scalar function (aggregates are handled by the caller).
pub fn eval_scalar_function(name: &str, values: &[Scalar]) -> Option<Result<Scalar, String>> {
    match name {
        "length" => Some(Ok(match values {
            [value] => match value {
                Scalar::Null => Scalar::Null,
                Scalar::Text(text) => Scalar::Int(text.chars().count() as i64),
                Scalar::Int(value) => Scalar::Int(value.to_string().chars().count() as i64),
                Scalar::Real(value) => Scalar::Int(value.chars().count() as i64),
                Scalar::Blob(bytes) => Scalar::Int(bytes.len() as i64),
            },
            _ => Scalar::Null,
        })),
        "upper" => Some(Ok(match values.first() {
            Some(value) => match text_of(value) {
                Some(text) => Scalar::text(text.chars().map(ascii_upper).collect::<String>()),
                None => Scalar::Null,
            },
            None => Scalar::Null,
        })),
        "lower" => Some(Ok(match values.first() {
            Some(value) => match text_of(value) {
                Some(text) => Scalar::text(text.chars().map(ascii_lower).collect::<String>()),
                None => Scalar::Null,
            },
            None => Scalar::Null,
        })),
        "trim" | "ltrim" | "rtrim" => Some(trim(name, values)),
        "replace" => Some(Ok(match values {
            [Scalar::Null, ..] | [_, Scalar::Null, ..] | [_, _, Scalar::Null] => Scalar::Null,
            [haystack, needle, replacement] => {
                let (Some(haystack), Some(needle), Some(replacement)) =
                    (text_of(haystack), text_of(needle), text_of(replacement))
                else {
                    return Some(Ok(Scalar::Null));
                };
                if needle.is_empty() {
                    return Some(Ok(Scalar::text(haystack)));
                }
                Scalar::text(haystack.replace(&needle, &replacement))
            }
            _ => return Some(Err("replace requires three arguments".into())),
        })),
        "instr" => Some(Ok(match values {
            [Scalar::Null, ..] | [_, Scalar::Null] => Scalar::Null,
            [haystack, needle] => {
                let (Some(haystack), Some(needle)) = (text_of(haystack), text_of(needle)) else {
                    return Some(Ok(Scalar::Null));
                };
                let Some(index) = haystack.find(&needle) else {
                    return Some(Ok(Scalar::Int(0)));
                };
                Scalar::Int(haystack[..index].chars().count() as i64 + 1)
            }
            _ => return Some(Err("instr requires two arguments".into())),
        })),
        "hex" => Some(Ok(match values.first() {
            Some(Scalar::Null) | None => Scalar::text(""),
            Some(value) => {
                let bytes: Vec<u8> = match value {
                    Scalar::Blob(bytes) => bytes.clone(),
                    other => match text_of(other) {
                        Some(text) => text.into_bytes(),
                        None => return Some(Ok(Scalar::text(""))),
                    },
                };
                Scalar::text(
                    bytes
                        .iter()
                        .map(|byte| format!("{byte:02X}"))
                        .collect::<String>(),
                )
            }
        })),
        "quote" => Some(Ok(match values.first() {
            Some(Scalar::Null) | None => Scalar::Null,
            Some(Scalar::Text(text)) => {
                let escaped = text.replace('\'', "''");
                Scalar::text(format!("'{escaped}'"))
            }
            Some(Scalar::Int(value)) => Scalar::text(value.to_string()),
            Some(Scalar::Real(value)) => Scalar::text(value.clone()),
            Some(Scalar::Blob(bytes)) => Scalar::text(format!(
                "X'{}'",
                bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
            )),
        })),
        "unicode" => Some(Ok(match values.first() {
            Some(value) => match text_of(value) {
                Some(text) => match text.chars().next() {
                    Some(first) => Scalar::Int(first as u32 as i64),
                    None => Scalar::Null,
                },
                None => Scalar::Null,
            },
            None => Scalar::Null,
        })),
        "char" => Some(Ok(match values {
            [] => Scalar::text(""),
            values => {
                // NULL arguments contribute U+0000, matching the reference's
                // NUL-preserving char().
                let mut out = String::with_capacity(values.len());
                for value in values {
                    let code = match numeric_of(value) {
                        Some(code) => code as i64,
                        None => 0,
                    };
                    let code = if code < 0 { 0 } else { code };
                    out.push(char::from_u32(code as u32).unwrap_or('\u{fffd}'));
                }
                Scalar::text(out)
            }
        })),
        "abs" => Some(Ok(match values.first() {
            Some(Scalar::Int(value)) => Scalar::Int(value.wrapping_abs()),
            Some(Scalar::Real(value)) => match value.parse::<f64>() {
                Ok(number) => real_scalar(number.abs()),
                Err(_) => Scalar::Null,
            },
            Some(Scalar::Null) | None => Scalar::Null,
            // Text coerces through numeric conversion; non-numeric text is 0.
            Some(other) => real_scalar(other.numeric().unwrap_or(0.0).abs()),
        })),
        "coalesce" | "ifnull" => Some(Ok(values
            .iter()
            .find(|value| !matches!(value, Scalar::Null))
            .cloned()
            .unwrap_or(Scalar::Null))),
        "nullif" => Some(Ok(match values {
            [a, b] => {
                if matches!(a, Scalar::Null) {
                    Scalar::Null
                } else if a.sql_eq(b) {
                    Scalar::Null
                } else {
                    a.clone()
                }
            }
            _ => return Some(Err("nullif requires two arguments".into())),
        })),
        "iif" => Some(Ok(match values {
            [condition, yes, no] => {
                if condition.truthy() {
                    yes.clone()
                } else {
                    no.clone()
                }
            }
            _ => return Some(Err("iif requires three arguments".into())),
        })),
        "typeof" => Some(Ok(match values.first() {
            Some(Scalar::Null) | None => Scalar::text("null"),
            Some(Scalar::Int(_)) => Scalar::text("integer"),
            Some(Scalar::Real(_)) => Scalar::text("real"),
            Some(Scalar::Text(_)) => Scalar::text("text"),
            Some(Scalar::Blob(_)) => Scalar::text("blob"),
        })),
        "dex_java_name" => Some(Ok(match values.first() {
            Some(value) => match text_of(value) {
                Some(text) => Scalar::text(dex_java_name(&text)),
                None => Scalar::Null,
            },
            None => Scalar::Null,
        })),
        _ => None,
    }
}

fn ascii_upper(ch: char) -> char {
    if ch.is_ascii_lowercase() {
        ch.to_ascii_uppercase()
    } else {
        ch
    }
}

fn ascii_lower(ch: char) -> char {
    if ch.is_ascii_uppercase() {
        ch.to_ascii_lowercase()
    } else {
        ch
    }
}

fn trim(name: &str, values: &[Scalar]) -> Result<Scalar, String> {
    if values.len() != 1 && values.len() != 2 {
        return Err(format!("{name} requires one or two arguments"));
    }
    if matches!(values[0], Scalar::Null) {
        return Ok(Scalar::Null);
    }
    let Some(text) = text_of(&values[0]) else {
        return Ok(Scalar::Null);
    };
    let chars: Vec<char> = match values.get(1) {
        Some(Scalar::Null) => return Ok(Scalar::Null),
        None => vec![' '],
        Some(set) => match text_of(set) {
            Some(set) => set.chars().collect(),
            None => return Ok(Scalar::Null),
        },
    };
    let trimmed: String = match name {
        "trim" => text.trim_matches(|ch: char| chars.contains(&ch)).to_owned(),
        "ltrim" => text
            .trim_start_matches(|ch: char| chars.contains(&ch))
            .to_owned(),
        _ => text
            .trim_end_matches(|ch: char| chars.contains(&ch))
            .to_owned(),
    };
    Ok(Scalar::text(trimmed))
}

/// Render a DEX type descriptor as its Java-style name: `Lcom/f/B;` becomes
/// `com.f.B`, `[I` becomes `int[]`, and primitive/single-letter descriptors
/// map to their Java spellings.  Anything else passes through unchanged.
pub fn dex_java_name(descriptor: &str) -> String {
    let mut dims = 0usize;
    let mut rest = descriptor;
    while let Some(stripped) = rest.strip_prefix('[') {
        dims += 1;
        rest = stripped;
    }
    let base = match rest {
        "V" => "void".to_owned(),
        "Z" => "boolean".to_owned(),
        "B" => "byte".to_owned(),
        "C" => "char".to_owned(),
        "S" => "short".to_owned(),
        "I" => "int".to_owned(),
        "J" => "long".to_owned(),
        "F" => "float".to_owned(),
        "D" => "double".to_owned(),
        _ => {
            let Some(inner) = rest.strip_prefix('L').and_then(|s| s.strip_suffix(';')) else {
                return descriptor.to_owned();
            };
            inner.replace('/', ".")
        }
    };
    let brackets = "[]".repeat(dims);
    format!("{base}{brackets}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Scalar {
        Scalar::text(value.to_owned())
    }

    #[test]
    fn reference_semantics() {
        // hex(NULL) is empty text; hex uses the text representation.
        assert_eq!(
            eval_scalar_function("hex", &[Scalar::Null])
                .unwrap()
                .unwrap(),
            text("")
        );
        assert_eq!(
            eval_scalar_function("hex", &[text("ab")]).unwrap().unwrap(),
            text("6162")
        );
        assert_eq!(
            eval_scalar_function("hex", &[Scalar::Int(12)])
                .unwrap()
                .unwrap(),
            text("3132")
        );
        assert_eq!(
            eval_scalar_function("hex", &[Scalar::Real("1.5".into())])
                .unwrap()
                .unwrap(),
            text("312E35")
        );
        // quote wraps text in single quotes; numbers pass through.
        assert_eq!(
            eval_scalar_function("quote", &[text("a")])
                .unwrap()
                .unwrap(),
            text("'a'")
        );
        assert_eq!(
            eval_scalar_function("quote", &[Scalar::Real("1.5".into())])
                .unwrap()
                .unwrap(),
            text("1.5")
        );
        // unicode takes the first code point; empty text is NULL.
        assert_eq!(
            eval_scalar_function("unicode", &[text("ab")])
                .unwrap()
                .unwrap(),
            Scalar::Int(97)
        );
        assert_eq!(
            eval_scalar_function("unicode", &[text("")])
                .unwrap()
                .unwrap(),
            Scalar::Null
        );
        // char(NULL) contributes U+0000.
        assert_eq!(
            eval_scalar_function("char", &[Scalar::Int(65), Scalar::Null])
                .unwrap()
                .unwrap(),
            text("A\0")
        );
        // Scalar min/max propagate NULL and compare text binarily (dispatched
        // at the call site, covered by integration probes).
        // iif treats NULL conditions as false.
        assert_eq!(
            eval_scalar_function("iif", &[Scalar::Null, Scalar::Int(1), Scalar::Int(2)])
                .unwrap()
                .unwrap(),
            Scalar::Int(2)
        );
        // nullif: NULL never equals.
        assert_eq!(
            eval_scalar_function("nullif", &[Scalar::Int(1), Scalar::Null])
                .unwrap()
                .unwrap(),
            Scalar::Int(1)
        );
    }

    #[test]
    fn java_names() {
        assert_eq!(dex_java_name("Lcom/f/B;"), "com.f.B");
        assert_eq!(dex_java_name("[I"), "int[]");
        assert_eq!(dex_java_name("V"), "void");
        assert_eq!(dex_java_name("x"), "x");
        assert_eq!(
            dex_java_name("[[Ljava/lang/String;"),
            "java.lang.String[][]"
        );
    }

    #[test]
    fn real_formatting() {
        assert_eq!(real_format(1.0), "1.0");
        assert_eq!(real_format(1.10), "1.1");
        assert_eq!(real_format(2.5), "2.5");
        assert_eq!(real_format(-0.5), "-0.5");
    }
}
