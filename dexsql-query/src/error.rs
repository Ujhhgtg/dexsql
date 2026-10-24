//! Structured library errors matching the reference CLI/MCP envelope.
//!
//! The reference reports `{code} at {stage}: {message}` with an optional
//! single-level source, rendered through anyhow's `Debug` (one-shot mode:
//! numbered `Caused by` chain) or `{:#}` Display (interactive mode: a
//! `error: ...: ...: ...` flattened line).

use dexsql_ast::front::Code as FrontCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexSqlError {
    pub code: &'static str,
    pub stage: &'static str,
    pub message: String,
    pub source: Option<String>,
}

impl DexSqlError {
    pub fn new(code: &'static str, stage: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            stage,
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// `query_failed at execute_sql: ...` for executor limitations.
    pub fn query_failed(message: impl Into<String>) -> Self {
        Self::new("query_failed", "execute_sql", message)
    }

    /// `invalid_query at execute_sql: ...` for semantic query failures.
    pub fn invalid_query(message: impl Into<String>) -> Self {
        Self::new("invalid_query", "execute_sql", message)
    }

    pub fn from_front(code: FrontCode, rendered: String) -> Self {
        let code = match code {
            FrontCode::InvalidInput => "invalid_input",
            FrontCode::ReadOnlyViolation => "read_only_violation",
        };
        Self {
            code,
            stage: "validate_sql",
            // The reference repeats the span-bearing message as the source
            // of the coded context.
            source: Some(rendered.clone()),
            message: rendered,
        }
    }

    /// Map a legacy executor string onto the reference envelope.  The three
    /// high-traffic shapes keep their exact reference wording; anything else
    /// becomes a `query_failed at execute_sql` diagnostic.
    pub fn from_executor_string(message: String) -> Self {
        if let Some(table) = message
            .strip_prefix("unknown table '")
            .and_then(|rest| rest.strip_suffix('\''))
        {
            return Self::invalid_query(format!("unknown relation `{table}`"));
        }
        if let Some(table) = message
            .strip_prefix("unknown relation '")
            .and_then(|rest| rest.strip_suffix('\''))
        {
            return Self::invalid_query(format!("unknown relation `{table}`"));
        }
        if let Some(column) = message
            .strip_prefix("unknown column '")
            .and_then(|rest| rest.strip_suffix('\''))
        {
            return Self::invalid_query(format!("unknown column `{column}`"));
        }
        if message == "intermediate result exceeded the materialization memory budget" {
            return Self::query_failed("cache plan execution failed").with_source(message);
        }
        if message == "LIMIT cannot follow a bare VALUES clause" {
            return Self::invalid_query(message);
        }
        if message.starts_with("SELECTs to the left and right of the set operation") {
            return Self::invalid_query(message);
        }
        if message == "required execution data source is unavailable" {
            return Self::query_failed("relation-free execution failed").with_source(message);
        }
        Self::query_failed(message)
    }
}

impl std::fmt::Display for DexSqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}: {}", self.code, self.stage, self.message)
    }
}

/// Render the anyhow-style one-shot failure block printed after
/// `Error: {context}`: causes are numbered only when more than one exists.
pub fn render_caused_by(causes: &[String]) -> String {
    if causes.len() == 1 {
        format!("\n\nCaused by:\n    {}", causes[0])
    } else {
        let mut out = String::from("\n\nCaused by:");
        for (index, cause) in causes.iter().enumerate() {
            out.push_str(&format!("\n    {index}: {cause}"));
        }
        out
    }
}

/// Flattened `{:#}`-style chain used by the interactive session.
pub fn render_flat_chain(parts: &[String]) -> String {
    parts.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_cause_is_unnumbered() {
        let text = render_caused_by(&["inner".to_owned()]);
        assert_eq!(text, "\n\nCaused by:\n    inner");
    }

    #[test]
    fn multiple_causes_are_numbered() {
        let text = render_caused_by(&["outer".to_owned(), "inner".to_owned()]);
        assert_eq!(text, "\n\nCaused by:\n    0: outer\n    1: inner");
    }

    #[test]
    fn legacy_strings_map_to_reference_wording() {
        let error = DexSqlError::from_executor_string("unknown table 'nope'".to_owned());
        assert_eq!(
            error.to_string(),
            "invalid_query at execute_sql: unknown relation `nope`"
        );
        let error = DexSqlError::from_executor_string("unknown column 'a'".to_owned());
        assert_eq!(
            error.to_string(),
            "invalid_query at execute_sql: unknown column `a`"
        );
        let error = DexSqlError::from_executor_string(
            "required execution data source is unavailable".to_owned(),
        );
        assert_eq!(
            error.to_string(),
            "query_failed at execute_sql: relation-free execution failed"
        );
        assert_eq!(
            error.source.as_deref(),
            Some("required execution data source is unavailable")
        );
    }
}
