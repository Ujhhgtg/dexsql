//! SQL front-end recovered from the DexSQL 0.1.1 reference binary.
//!
//! The reference implements its own tokenizer and statement classifier in
//! `dexsql-ast/src/token.rs`, `parser.rs`, `front.rs`, and
//! `front/session.rs` (source paths retained in the release ELF).  This
//! module fills the same crate boundary: a SQLite-flavored scanner plus the
//! read-only statement classifier whose diagnostics, spans, and error codes
//! reproduce the reference `validate_sql` stage byte-for-byte.
//!
//! Error codes observed on the reference:
//!
//! * `invalid_input` — malformed SQL or unrecognized statements.
//! * `read_only_violation` — recognized statements outside the read-only
//!   subset (DROP, INSERT, ...), non-whitelisted function calls, and CREATE
//!   names that are not simple identifiers.

pub mod front;
pub mod parser;
#[path = "front/session.rs"]
pub mod session;
pub mod token;
pub mod walk;

pub use front::{validate, validate_with, Code, FrontError, Statement, ValidateOptions};
pub use token::{tokenize, ScanError, Token, TokenKind};

/// SQLite statement-introducing keywords that the read-only policy rejects.
/// Everything in this set reports `read_only_violation`; unrecognized
/// identifiers report `invalid_input` with the same message shape.
pub const REJECTED_STATEMENT_KEYWORDS: &[&str] = &[
    "ALTER",
    "ANALYZE",
    "ATTACH",
    "BEGIN",
    "COMMIT",
    "DELETE",
    "DETACH",
    "DROP",
    "END",
    "EXPLAIN",
    "INSERT",
    "REPLACE",
    "PRAGMA",
    "REINDEX",
    "RELEASE",
    "ROLLBACK",
    "SAVEPOINT",
    "UPDATE",
    "VACUUM",
];

/// Function names accepted by the read-only dialect (see the embedded
/// `dexsql://sql/functions.md` reference documentation).
pub const FUNCTION_WHITELIST: &[&str] = &[
    // text
    "length",
    "substr",
    "substring",
    "upper",
    "lower",
    "trim",
    "ltrim",
    "rtrim",
    "replace",
    "instr",
    "hex",
    "quote",
    "unicode",
    "char",
    // numeric
    "abs",
    "min",
    "max",
    // null / conditional
    "coalesce",
    "ifnull",
    "nullif",
    "iif",
    // introspection
    "typeof",
    // DEX-specific
    "dex_java_name",
    // aggregates
    "count",
    "sum",
    "avg",
    "total",
    "group_concat",
    "string_agg",
    // window
    "row_number",
    "rank",
    "dense_rank",
    "ntile",
    "lag",
    "lead",
    "first_value",
    "last_value",
    // keyword-shaped function handled by the expression grammar
    "cast",
];
