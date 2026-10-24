//! Placeholder for the reference `dexsql-ast/src/parser.rs` recursive-descent
//! expression grammar.
//!
//! The reference front-end owns the full SQLite expression grammar and emits
//! diagnostics such as `expected an expression`, `expected an identifier`,
//! `expected RParen`, and `expected keyword {KW}`, optionally followed by an
//! offending-token span (`(at bytes S..E)`, absent at end of input).  The
//! workspace currently parses expressions with `sqlparser` and maps its
//! failures onto the reference wording; this module will absorb the native
//! grammar as the dialect coverage grows.

/// Map a sqlparser failure onto the reference `validate_sql` wording for the
/// common statement shapes.  Returns the inner diagnostic message and, when
/// the reference reports one, the offending-token byte span relative to
/// `sql` (sqlparser reports 1-based line/column positions).
pub fn map_parser_error(sqlparser_message: &str, sql: &str) -> (String, Option<(usize, usize)>) {
    let message = sqlparser_message.trim();
    let found = found_token(message).map(|(text, line, column)| {
        let start = line_column_to_offset(sql, line, column);
        (text, start)
    });
    let span = found.map(|(text, start)| (start, start + text.chars().count()));
    if message.contains("Expected: identifier") {
        return ("expected an identifier".to_owned(), None);
    }
    if message.contains("Expected: an expression") || message.contains("Expected: expression") {
        return ("expected an expression".to_owned(), span);
    }
    if message.contains("Expected: ),") || message.contains("Expected: )") {
        return ("expected RParen".to_owned(), span);
    }
    if message.contains("Expected: [") {
        return ("expected LParen".to_owned(), span);
    }
    if message.contains("Expected: a data type name") {
        return ("expected a type name in CAST".to_owned(), span);
    }
    if message.contains("Expected: end of statement") {
        if let Some((text, _)) = found {
            if text.eq_ignore_ascii_case("GROUP") || text.eq_ignore_ascii_case("ORDER") {
                return ("expected keyword by".to_owned(), None);
            }
        }
    }
    if let Some(keyword) = message.strip_prefix("Expected: keyword ") {
        return (
            format!("expected keyword {}", keyword.trim().to_lowercase()),
            None,
        );
    }
    (message.to_owned(), None)
}

/// Extract `found: <token> at Line: L, Column: C` from a sqlparser message.
fn found_token(message: &str) -> Option<(&str, usize, usize)> {
    let found_at = message.find("found: ")?;
    let rest = &message[found_at + "found: ".len()..];
    let at = rest.find(" at Line: ")?;
    let text = &rest[..at];
    let position = &rest[at + " at Line: ".len()..];
    let mut parts = position.splitn(2, ", Column: ");
    let line = parts.next()?.trim().parse::<usize>().ok()?;
    let column = parts.next()?.trim().parse::<usize>().ok()?;
    Some((text, line, column))
}

/// 1-based (line, column) to a 0-based byte offset.  sqlparser columns count
/// characters from the line start.
fn line_column_to_offset(sql: &str, line: usize, column: usize) -> usize {
    let mut offset = 0usize;
    for (index, text_line) in sql.split('\n').enumerate() {
        if index + 1 == line {
            return offset + (column.saturating_sub(1)).min(text_line.chars().count());
        }
        offset += text_line.len() + 1;
    }
    offset
}
