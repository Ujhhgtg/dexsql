//! Compatibility module exposing the shared SQL query engine to the MCP crate.
//!
//! The implementation is kept in `dexsql-query` so CLI and MCP cannot drift
//! in relation semantics, SQL evaluation, or result rendering.
pub use dexsql_query::*;
