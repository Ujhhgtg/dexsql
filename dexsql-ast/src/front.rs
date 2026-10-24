//! Statement classification for the read-only dialect, matching the
//! reference `dexsql-ast/src/front.rs` `validate_sql` stage.
//!
//! Reference-pinned behaviors (binary `dexsql-linux-amd64-0.1.1`):
//!
//! * Empty or comment-only input: `invalid_input: expected exactly one SQL
//!   statement` (no span).  Multiple statements: same message with
//!   `, found N` and a whole-input span.
//! * Rejected statement keywords (DROP, INSERT, REPLACE, ROLLBACK, END, ...)
//!   report `read_only_violation: {KW} statement is outside the read-only
//!   SQLite subset` with the first token's span; the keyword is uppercased.
//! * Unrecognized leading identifiers (TABLE, SELEC, TRANSACTION, FOOBAR)
//!   report the same message under `invalid_input`.
//! * Non-identifier leads (numbers, punctuation) report `UNKNOWN statement
//!   ...` with the first token's span.
//! * `CREATE VIEW`, `CREATE TEMP VIEW`, and `CREATE TEMP TABLE ... AS query`
//!   are the accepted definition forms; everything else about CREATE is
//!   `read_only_violation: only CREATE TEMP TABLE name AS query is inside
//!   the read-only subset` spanning the CREATE token.
//! * Non-whitelisted function calls report `read_only_violation: function
//!   call is outside the DexSQL read-only subset` spanning the trimmed
//!   statement.

use crate::token::{tokenize, ScanError, Token, TokenKind};
use crate::{FUNCTION_WHITELIST, REJECTED_STATEMENT_KEYWORDS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    InvalidInput,
    ReadOnlyViolation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontError {
    pub code: Code,
    pub message: String,
    pub span: Option<(usize, usize)>,
}

impl FrontError {
    fn invalid(message: impl Into<String>, span: Option<(usize, usize)>) -> Self {
        Self {
            code: Code::InvalidInput,
            message: message.into(),
            span,
        }
    }

    fn read_only(message: impl Into<String>, span: Option<(usize, usize)>) -> Self {
        Self {
            code: Code::ReadOnlyViolation,
            message: message.into(),
            span,
        }
    }

    /// Display form used as the inner `validate_sql` diagnostic message,
    /// including the reference `(at bytes S..E)` suffix.
    pub fn render(&self) -> String {
        match self.span {
            Some((start, end)) => format!("{} (at bytes {start}..{end})", self.message),
            None => self.message.clone(),
        }
    }
}

impl From<ScanError> for FrontError {
    fn from(error: ScanError) -> Self {
        FrontError::invalid(error.message, Some(error.span))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    /// SELECT/VALUES/WITH query (possibly parenthesized).  `query` is the
    /// trimmed statement text.
    Query { sql: String },
    /// `CREATE [TEMP] VIEW name [IF NOT EXISTS ignored] AS query` or
    /// `CREATE TEMP TABLE name AS query`.
    CreateDefinition {
        name: String,
        /// Definitions are lazy: this is the defining query text.
        query: String,
        /// A duplicate plain CREATE replaces the definition; `IF NOT EXISTS`
        /// keeps the existing one.
        replace: bool,
        table: bool,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct ValidateOptions {
    /// Enforce the function-name whitelist during statement validation.
    /// The reference front-end does this as part of `validate_sql`.
    pub check_functions: bool,
}

impl Default for ValidateOptions {
    fn default() -> Self {
        Self {
            check_functions: true,
        }
    }
}

/// Keywords that legitimately precede `(` and must not be classified as
/// function calls by the whitelist scan.  This mirrors the reference's
/// SQLite keyword table: an identifier followed by `(` is only a function
/// call when it is not a reserved word.
const KEYWORD_GUARD: &[&str] = &[
    "ABORT",
    "ACTION",
    "ADD",
    "AFTER",
    "ALL",
    "ALTER",
    "ALWAYS",
    "ANALYZE",
    "AND",
    "AS",
    "ASC",
    "ATTACH",
    "AUTOINCREMENT",
    "BEFORE",
    "BEGIN",
    "BETWEEN",
    "BY",
    "CASCADE",
    "CASE",
    "CAST",
    "CHECK",
    "COLLATE",
    "COLUMN",
    "COMMIT",
    "CONFLICT",
    "CONSTRAINT",
    "CREATE",
    "CROSS",
    "CURRENT",
    "CURRENT_DATE",
    "CURRENT_TIME",
    "CURRENT_TIMESTAMP",
    "DATABASE",
    "DEFERRABLE",
    "DEFERRED",
    "DELETE",
    "DESC",
    "DETACH",
    "DISTINCT",
    "DO",
    "DROP",
    "EACH",
    "ELSE",
    "END",
    "ESCAPE",
    "EXCEPT",
    "EXCLUDE",
    "EXCLUSIVE",
    "EXISTS",
    "EXPLAIN",
    "FAIL",
    "FILTER",
    "FIRST",
    "FOLLOWING",
    "FOR",
    "FOREIGN",
    "FROM",
    "FULL",
    "GENERATED",
    "GLOB",
    "GROUP",
    "GROUPS",
    "HAVING",
    "IF",
    "IGNORE",
    "IMMEDIATE",
    "IN",
    "INDEX",
    "INDEXED",
    "INITIALLY",
    "INNER",
    "INSERT",
    "INSTEAD",
    "INTERSECT",
    "INTO",
    "IS",
    "ISNULL",
    "JOIN",
    "KEY",
    "LAST",
    "LEFT",
    "LIKE",
    "LIMIT",
    "MATCH",
    "MATERIALIZED",
    "NATURAL",
    "NO",
    "NOT",
    "NOTHING",
    "NOTNULL",
    "NULL",
    "NULLS",
    "OF",
    "OFFSET",
    "ON",
    "OR",
    "ORDER",
    "OTHERS",
    "OUTER",
    "OVER",
    "PARTITION",
    "PLAN",
    "PRAGMA",
    "PRECEDING",
    "PRIMARY",
    "QUERY",
    "RAISE",
    "RANGE",
    "RECURSIVE",
    "REFERENCES",
    "REGEXP",
    "REINDEX",
    "RELEASE",
    "RENAME",
    "REPLACE",
    "RESTRICT",
    "RETURNING",
    "RIGHT",
    "ROLLBACK",
    "ROW",
    "ROWS",
    "SAVEPOINT",
    "SELECT",
    "SET",
    "TABLE",
    "TEMP",
    "TEMPORARY",
    "THEN",
    "TO",
    "TRANSACTION",
    "TRIGGER",
    "UNBOUNDED",
    "UNION",
    "UNIQUE",
    "UPDATE",
    "USING",
    "VACUUM",
    "VALUES",
    "VIEW",
    "VIRTUAL",
    "WHEN",
    "WHERE",
    "WINDOW",
    "WITH",
    "WITHOUT",
];

/// Validate one `--sql` value: tokenize, require exactly one statement, and
/// classify it under the read-only policy.
pub fn validate(sql: &str) -> Result<Statement, FrontError> {
    validate_with(sql, ValidateOptions::default())
}

pub fn validate_with(sql: &str, options: ValidateOptions) -> Result<Statement, FrontError> {
    let tokens = tokenize(sql)?;
    let groups = split_statements(&tokens);
    if groups.is_empty() {
        return Err(FrontError::invalid(
            "expected exactly one SQL statement",
            None,
        ));
    }
    if groups.len() > 1 {
        return Err(FrontError::invalid(
            format!("expected exactly one SQL statement, found {}", groups.len()),
            Some((0, sql.len())),
        ));
    }
    let group = &groups[0];
    let stmt_end = group.last().map(|token| token.end).unwrap_or(0);
    let stmt_start = group.first().map(|token| token.start).unwrap_or(0);
    let first = &group[0];
    match &first.kind {
        TokenKind::LParen => Ok(Statement::Query {
            sql: sql[stmt_start..stmt_end].to_owned(),
        }),
        TokenKind::Ident { upper } => match upper.as_str() {
            "SELECT" | "WITH" | "VALUES" => {
                if upper == "VALUES"
                    && !group
                        .get(1)
                        .is_some_and(|token| token.kind == TokenKind::LParen)
                {
                    let span = group.get(1).map(|token| (token.start, token.end));
                    return Err(FrontError::invalid("expected LParen", span));
                }
                check_query_group(group, sql, options)?;
                Ok(Statement::Query {
                    sql: sql[stmt_start..stmt_end].to_owned(),
                })
            }
            "CREATE" => classify_create(group, sql),
            keyword if REJECTED_STATEMENT_KEYWORDS.contains(&keyword) => {
                Err(FrontError::read_only(
                    format!("{keyword} statement is outside the read-only SQLite subset"),
                    Some((first.start, first.end)),
                ))
            }
            other => Err(FrontError::invalid(
                format!("{other} statement is outside the read-only SQLite subset"),
                Some((first.start, first.end)),
            )),
        },
        _ => Err(FrontError::invalid(
            "UNKNOWN statement is outside the read-only SQLite subset",
            Some((first.start, first.end)),
        )),
    }
}

/// Split a token stream into `;`-separated non-empty statement groups.
fn split_statements(tokens: &[Token]) -> Vec<&[Token]> {
    let mut groups = Vec::new();
    let mut start = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        if token.kind == TokenKind::Semicolon {
            if index > start {
                groups.push(&tokens[start..index]);
            }
            start = index + 1;
        }
    }
    if tokens.len() > start {
        groups.push(&tokens[start..]);
    }
    groups
}

/// Token-level checks applied to SELECT/VALUES/WITH statements.
fn check_query_group(
    group: &[Token],
    sql: &str,
    options: ValidateOptions,
) -> Result<(), FrontError> {
    // `SELECT DISTINCT ON (...)`: rejected with the ON token's span.
    for pair in group.windows(2) {
        if let (TokenKind::Ident { upper }, TokenKind::Ident { upper: next }) =
            (&pair[0].kind, &pair[1].kind)
        {
            if upper == "DISTINCT" && next == "ON" {
                return Err(FrontError::invalid(
                    "DISTINCT ON is not supported (outside the read-only SQLite subset)",
                    Some((pair[1].start, pair[1].end)),
                ));
            }
        }
    }
    if options.check_functions {
        check_function_calls(group, sql)?;
    }
    Ok(())
}

/// Index just past the token group starting at `open` (an LParen position).
fn skip_parenthesized(group: &[Token], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, token) in group.iter().enumerate().skip(open) {
        match token.kind {
            TokenKind::LParen => depth += 1,
            TokenKind::RParen => {
                depth -= 1;
                if depth == 0 {
                    return Some(offset + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn check_function_calls(group: &[Token], sql: &str) -> Result<(), FrontError> {
    let stmt_start = group.first().map(|token| token.start).unwrap_or(0);
    let stmt_end = group.last().map(|token| token.end).unwrap_or(0);
    for (index, pair) in group.windows(2).enumerate() {
        let TokenKind::Ident { upper } = &pair[0].kind else {
            continue;
        };
        if pair[1].kind != TokenKind::LParen {
            continue;
        };
        if KEYWORD_GUARD.contains(&upper.as_str()) {
            continue;
        }
        // `name ( columns ) AS` is a CTE header, not a function call.
        if let Some(after) = skip_parenthesized(group, index + 1) {
            if group
                .get(after)
                .is_some_and(|token| token.keyword() == Some("AS"))
            {
                continue;
            }
        }
        let name = sql[pair[0].start..pair[0].end].to_ascii_lowercase();
        if !FUNCTION_WHITELIST.contains(&name.as_str()) {
            return Err(FrontError::read_only(
                "function call is outside the DexSQL read-only subset",
                Some((stmt_start, stmt_end)),
            ));
        }
    }
    Ok(())
}

/// Parse `CREATE ...` forms after the CREATE keyword.
fn classify_create(group: &[Token], sql: &str) -> Result<Statement, FrontError> {
    let stmt_start = group.first().map(|token| token.start).unwrap_or(0);
    let stmt_end = group.last().map(|token| token.end).unwrap_or(0);
    let only_create = |message: &str| {
        Err(FrontError::read_only(
            message.to_owned(),
            Some((stmt_start, group[0].end)),
        ))
    };
    let mut index = 1usize;
    // CREATE [TEMP|TEMPORARY] (TABLE|VIEW)
    let mut temp = false;
    if let Some(token) = group.get(index) {
        if let Some(keyword) = token.keyword() {
            if keyword == "TEMP" || keyword == "TEMPORARY" {
                temp = true;
                index += 1;
            }
        }
    }
    let Some(object) = group.get(index) else {
        // `CREATE` alone: the reference parser expects the object keyword.
        return Err(FrontError::invalid("expected keyword table", None));
    };
    let object_kind = object.keyword().unwrap_or_default().to_owned();
    let table = match object_kind.as_str() {
        "TABLE" => true,
        "VIEW" => false,
        // Any other CREATE object (INDEX, TRIGGER, ...) is rejected like a
        // non-temp TABLE: only the temp forms are inside the subset.
        _ => {
            return only_create(
                "only CREATE TEMP TABLE name AS query is inside the read-only subset",
            );
        }
    };
    if table && !temp {
        return only_create("only CREATE TEMP TABLE name AS query is inside the read-only subset");
    }
    index += 1;

    // [IF NOT EXISTS] / optional OR REPLACE-style modifiers are not part of
    // the dialect; only IF NOT EXISTS is accepted.
    let mut replace = true;
    if let (Some(a), Some(b)) = (group.get(index), group.get(index + 1)) {
        if a.keyword() == Some("IF") && b.keyword() == Some("NOT") {
            if group
                .get(index + 2)
                .is_some_and(|token| token.keyword() == Some("EXISTS"))
            {
                replace = false;
                index += 3;
            }
        }
    }

    // Name: simple identifier, optionally qualified with `temp`.
    let Some(name_token) = group.get(index) else {
        return Err(FrontError::invalid("expected an identifier", None));
    };
    if matches!(name_token.kind, TokenKind::QuotedIdent) {
        // Quoted names parse as identifiers in SQLite but are rejected by
        // the read-only definition policy.
        return Err(FrontError::read_only(
            "CREATE TEMP TABLE names must be simple SQLite identifiers",
            Some((stmt_start, stmt_end)),
        ));
    }
    let name = match &name_token.kind {
        TokenKind::Ident { .. } => sql[name_token.start..name_token.end].to_owned(),
        // The reference parser consumes the offending token before failing,
        // so the reported span is the token *after* the bad name.
        _ => {
            let span = group
                .get(index + 1)
                .map(|next| (next.start, next.end))
                .or(None);
            return Err(FrontError::invalid("expected an identifier", span));
        }
    };
    index += 1;
    let mut name = name;
    if group
        .get(index)
        .is_some_and(|token| token.kind == TokenKind::Dot)
    {
        let qualifier_end = name_token.end;
        let Some(part) = group.get(index + 1) else {
            return Err(FrontError::invalid("expected an identifier", None));
        };
        match &part.kind {
            TokenKind::Ident { .. } => {
                name = sql[part.start..part.end].to_owned();
            }
            _ => {
                let span = group
                    .get(index + 2)
                    .map(|next| (next.start, next.end))
                    .or(None);
                return Err(FrontError::invalid("expected an identifier", span));
            }
        }
        let qualifier = sql[name_token.start..qualifier_end].to_ascii_uppercase();
        if qualifier != "TEMP" {
            return Err(FrontError::read_only(
                "CREATE TEMP TABLE names must be unqualified or use the temp schema",
                Some((stmt_start, stmt_end)),
            ));
        }
        index += 2;
    }

    // AS <query>
    let Some(as_token) = group.get(index) else {
        return Err(FrontError::invalid("expected keyword as", None));
    };
    if as_token.keyword() != Some("AS") {
        return Err(FrontError::invalid(
            "expected keyword as",
            Some((as_token.start, as_token.end)),
        ));
    }
    index += 1;
    let Some(query_first) = group.get(index) else {
        return Err(FrontError::invalid("expected keyword select", None));
    };
    let starts_query = matches!(query_first.kind, TokenKind::LParen)
        || query_first
            .keyword()
            .is_some_and(|keyword| matches!(keyword, "SELECT" | "VALUES" | "WITH"));
    if !starts_query {
        return Err(FrontError::invalid(
            "expected keyword select",
            Some((query_first.start, query_first.end)),
        ));
    }
    let query = sql[query_first.start..stmt_end].to_owned();
    check_query_group(&group[index..], sql, ValidateOptions::default())?;
    Ok(Statement::CreateDefinition {
        name: name.to_ascii_lowercase(),
        query,
        replace,
        table,
    })
}
