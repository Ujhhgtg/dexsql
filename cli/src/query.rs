//! Shared SQL query engine facade for the command-line binary.
//!
//! The implementation lives in [`dexsql_query`] so the MCP server and CLI use
//! exactly the same parser, relation scanners, optimizer fast paths, and
//! renderer.  Keep this module as a narrow facade for the CLI's existing
//! module layout.
pub use dexsql_query::{run, run_cache, QueryRequest};
