//! Multi-statement batch validation shared by the CLI `--sql` list and the
//! interactive session, mirroring `dexsql-ast/src/front/session.rs`.
//!
//! The reference validates every statement of a request up front: a
//! validation failure in statement *N* aborts the whole request with the
//! `SQL statement N failed` context before any statement executes.

use crate::front::{validate, Code, FrontError, Statement};

/// Validate a whole request batch, returning per-statement kinds or the
/// first validation failure paired with its 1-based statement index.
pub fn validate_batch(sqls: &[String]) -> Result<Vec<Statement>, (usize, FrontError)> {
    let mut statements = Vec::with_capacity(sqls.len());
    for (index, sql) in sqls.iter().enumerate() {
        match validate(sql) {
            Ok(statement) => statements.push(statement),
            Err(error) => return Err((index + 1, error)),
        }
    }
    Ok(statements)
}

/// Stable error-code spelling used by the library error envelope.
pub fn code_name(code: Code) -> &'static str {
    match code {
        Code::InvalidInput => "invalid_input",
        Code::ReadOnlyViolation => "read_only_violation",
    }
}
