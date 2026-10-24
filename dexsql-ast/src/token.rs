//! SQLite-flavored token scanner matching the reference `dexsql-ast/src/token.rs`.
//!
//! Diagnostics carry byte spans and reproduce the reference wording:
//!
//! ```text
//! unexpected byte 0x23 (at bytes 0..0)
//! unexpected '!' (only '!=' is valid) (at bytes 9..9)
//! unterminated string literal (at bytes 7..7)
//! unterminated quoted identifier (at bytes 7..7)
//! unterminated '[' identifier (at bytes 7..7)
//! unterminated blob literal (at bytes 7..7)
//! malformed blob literal (at bytes 9..9)
//! non-hex byte in blob literal (at bytes 9..9)
//! hex literal has no digits (at bytes 7..7)
//! prefixed string literals are outside the DexSQL read-only subset (at bytes 7..13)
//! ```
//!
//! Point error spans are `(pos, pos)` at the offending byte; the prefixed
//! string span covers the prefix through the closing quote.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    /// Bare identifier or keyword; `upper` is the ASCII-uppercased text.
    Ident {
        upper: String,
    },
    /// Numeric literal, kept as raw text.
    Number,
    /// `'...'` string literal.
    Str,
    /// `x'...'` blob literal (upper- or lower-case prefix).
    Blob,
    /// `"..."` or `[...]` quoted identifier.
    QuotedIdent,
    LParen,
    RParen,
    Semicolon,
    Comma,
    Dot,
    /// Operator or punctuation.
    Op(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub start: usize,
    pub end: usize,
}

impl Token {
    /// Raw source text of this token.
    pub fn text<'a>(&self, sql: &'a str) -> &'a str {
        &sql[self.start..self.end]
    }

    /// Keyword name if this is a bare identifier: ASCII-uppercased text.
    pub fn keyword(&self) -> Option<&str> {
        match &self.kind {
            TokenKind::Ident { upper } => Some(upper.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanError {
    pub message: String,
    pub span: (usize, usize),
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn scan_error(message: impl Into<String>, at: usize) -> ScanError {
    ScanError {
        message: message.into(),
        span: (at, at),
    }
}

/// Scan `sql` into tokens, or fail with the first reference-shaped error.
pub fn tokenize(sql: &str) -> Result<Vec<Token>, ScanError> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c => {
                i += 1;
            }
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                // An unterminated block comment consumes the rest of the
                // input, matching the reference tokenizer.
                i = (i + 2).min(bytes.len());
            }
            b'\'' => {
                let start = i;
                i += 1;
                loop {
                    match bytes.get(i) {
                        None => return Err(scan_error("unterminated string literal", start)),
                        Some(b'\'') => {
                            if bytes.get(i + 1) == Some(&b'\'') {
                                i += 2;
                            } else {
                                i += 1;
                                break;
                            }
                        }
                        Some(_) => i += 1,
                    }
                }
                tokens.push(Token {
                    kind: TokenKind::Str,
                    start,
                    end: i,
                });
            }
            b'"' => {
                let start = i;
                i += 1;
                loop {
                    match bytes.get(i) {
                        None => {
                            return Err(scan_error("unterminated quoted identifier", start));
                        }
                        Some(b'"') => {
                            if bytes.get(i + 1) == Some(&b'"') {
                                i += 2;
                            } else {
                                i += 1;
                                break;
                            }
                        }
                        Some(_) => i += 1,
                    }
                }
                tokens.push(Token {
                    kind: TokenKind::QuotedIdent,
                    start,
                    end: i,
                });
            }
            b'[' => {
                let start = i;
                i += 1;
                loop {
                    match bytes.get(i) {
                        None => return Err(scan_error("unterminated '[' identifier", start)),
                        Some(b']') => {
                            i += 1;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
                tokens.push(Token {
                    kind: TokenKind::QuotedIdent,
                    start,
                    end: i,
                });
            }
            b'(' => {
                tokens.push(Token {
                    kind: TokenKind::LParen,
                    start: i,
                    end: i + 1,
                });
                i += 1;
            }
            b')' => {
                tokens.push(Token {
                    kind: TokenKind::RParen,
                    start: i,
                    end: i + 1,
                });
                i += 1;
            }
            b';' => {
                tokens.push(Token {
                    kind: TokenKind::Semicolon,
                    start: i,
                    end: i + 1,
                });
                i += 1;
            }
            b',' => {
                tokens.push(Token {
                    kind: TokenKind::Comma,
                    start: i,
                    end: i + 1,
                });
                i += 1;
            }
            b'.' if !bytes.get(i + 1).is_some_and(|c| c.is_ascii_digit()) => {
                tokens.push(Token {
                    kind: TokenKind::Dot,
                    start: i,
                    end: i + 1,
                });
                i += 1;
            }
            b'0'..=b'9' | b'.' => {
                let start = i;
                if b == b'0'
                    && matches!(bytes.get(i + 1), Some(b'x') | Some(b'X'))
                    && bytes.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit())
                {
                    i += 2;
                    while bytes.get(i).is_some_and(|c| c.is_ascii_hexdigit()) {
                        i += 1;
                    }
                    tokens.push(Token {
                        kind: TokenKind::Number,
                        start,
                        end: i,
                    });
                    continue;
                }
                if b == b'0'
                    && matches!(bytes.get(i + 1), Some(b'x') | Some(b'X'))
                    && !bytes.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit())
                {
                    return Err(scan_error("hex literal has no digits", start));
                }
                while bytes.get(i).is_some_and(|c| c.is_ascii_digit()) {
                    i += 1;
                }
                if bytes.get(i) == Some(&b'.') {
                    i += 1;
                    while bytes.get(i).is_some_and(|c| c.is_ascii_digit()) {
                        i += 1;
                    }
                }
                if matches!(bytes.get(i), Some(b'e') | Some(b'E')) {
                    let mut j = i + 1;
                    if matches!(bytes.get(j), Some(b'+') | Some(b'-')) {
                        j += 1;
                    }
                    if bytes.get(j).is_some_and(|c| c.is_ascii_digit()) {
                        i = j;
                        while bytes.get(i).is_some_and(|c| c.is_ascii_digit()) {
                            i += 1;
                        }
                    }
                }
                tokens.push(Token {
                    kind: TokenKind::Number,
                    start,
                    end: i,
                });
            }
            _ if is_ident_start(b) => {
                let start = i;
                i += 1;
                while i < bytes.len() && is_ident_continue(bytes[i]) {
                    i += 1;
                }
                let text = &sql[start..i];
                // Blob and prefixed strings: an identifier glued to a string
                // literal forms one literal token (or a policy error).
                if matches!(bytes.get(i), Some(b'\'')) {
                    match text.to_ascii_uppercase().as_str() {
                        "X" => {
                            i += 1;
                            let digits_start = i;
                            loop {
                                match bytes.get(i) {
                                    None => {
                                        return Err(scan_error("unterminated blob literal", start));
                                    }
                                    Some(b'\'') => break,
                                    Some(c) if c.is_ascii_hexdigit() => i += 1,
                                    Some(_) => {
                                        return Err(scan_error("non-hex byte in blob literal", i));
                                    }
                                }
                            }
                            let digits_end = i;
                            i += 1;
                            if !(digits_end - digits_start).is_multiple_of(2) {
                                return Err(scan_error("malformed blob literal", digits_end));
                            }
                            tokens.push(Token {
                                kind: TokenKind::Blob,
                                start,
                                end: i,
                            });
                            continue;
                        }
                        "N" | "B" => {
                            let quote = i;
                            i += 1;
                            loop {
                                match bytes.get(i) {
                                    None => {
                                        return Err(scan_error(
                                            "unterminated string literal",
                                            quote,
                                        ));
                                    }
                                    Some(b'\'') => {
                                        if bytes.get(i + 1) == Some(&b'\'') {
                                            i += 2;
                                        } else {
                                            i += 1;
                                            break;
                                        }
                                    }
                                    Some(_) => i += 1,
                                }
                            }
                            return Err(ScanError {
                                message:
                                    "prefixed string literals are outside the DexSQL read-only subset"
                                        .to_owned(),
                                span: (start, i),
                            });
                        }
                        _ => {}
                    }
                }
                tokens.push(Token {
                    kind: TokenKind::Ident {
                        upper: text.to_ascii_uppercase(),
                    },
                    start,
                    end: i,
                });
            }
            b'!' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    tokens.push(Token {
                        kind: TokenKind::Op("!=".to_owned()),
                        start: i,
                        end: i + 2,
                    });
                    i += 2;
                } else {
                    return Err(scan_error("unexpected '!' (only '!=' is valid)", i));
                }
            }
            b'+' | b'-' | b'*' | b'/' | b'%' | b'=' | b'<' | b'>' | b'&' | b'|' | b'~' => {
                const TWO: &[&str] = &["<=", ">=", "==", "!=", "<>", "<<", ">>", "||", "->"];
                const THREE: &[&str] = &["->>"];
                let rest = &sql[i..];
                if let Some(op) = THREE.iter().find(|op| rest.starts_with(**op)) {
                    tokens.push(Token {
                        kind: TokenKind::Op((*op).to_owned()),
                        start: i,
                        end: i + op.len(),
                    });
                    i += op.len();
                } else if let Some(op) = TWO.iter().find(|op| rest.starts_with(**op)) {
                    tokens.push(Token {
                        kind: TokenKind::Op((*op).to_owned()),
                        start: i,
                        end: i + op.len(),
                    });
                    i += op.len();
                } else {
                    tokens.push(Token {
                        kind: TokenKind::Op((b as char).to_string()),
                        start: i,
                        end: i + 1,
                    });
                    i += 1;
                }
            }
            _ => {
                return Err(scan_error(format!("unexpected byte 0x{b:02x}"), i));
            }
        }
    }
    Ok(tokens)
}
