//! Embedded documentation resources exposed through the MCP resource API.

use serde_json::{json, Value};

pub(crate) fn resource_specs() -> Vec<Value> {
    [
        "cli/cache.md",
        "cli/index.md",
        "cli/smali.md",
        "index.md",
        "license.md",
        "mcp/apk.md",
        "mcp/index.md",
        "mcp/lifecycle.md",
        "mcp/query.md",
        "mcp/smali.md",
        "sql/advanced.md",
        "sql/annotations.md",
        "sql/calls.md",
        "sql/data-model.md",
        "sql/examples.md",
        "sql/functions.md",
        "sql/index.md",
        "sql/schema.md",
    ]
    .iter()
    .map(|p| {
        let name = match *p {
            "cli/cache.md" => "Saved caches",
            "cli/index.md" => "Command-line usage",
            "cli/smali.md" => "Smali disassembly",
            "index.md" => "DexSQL documentation",
            "license.md" => "Documentation license",
            "mcp/apk.md" => "MCP APK tools",
            "mcp/index.md" => "MCP reference",
            "mcp/lifecycle.md" => "MCP lifecycle and limits",
            "mcp/query.md" => "MCP SQL requests and results",
            "mcp/smali.md" => "MCP smali decoding",
            "sql/advanced.md" => "DEX structure queries",
            "sql/annotations.md" => "Annotation queries",
            "sql/calls.md" => "Direct calls and override-related references",
            "sql/data-model.md" => "DEX keys and descriptors",
            "sql/examples.md" => "SQL examples",
            "sql/functions.md" => "SQL functions",
            "sql/index.md" => "SQL guide",
            "sql/schema.md" => "DexSQL schema reference",
            _ => p,
        };
        json!({"uri":format!("dexsql://{p}"),"name":name,"mimeType":"text/markdown"})
    })
    .collect()
}
pub(crate) fn resources_read(p: &Value) -> Result<Value, (i32, String)> {
    let uri = p
        .get("uri")
        .and_then(Value::as_str)
        .ok_or((-32602, "uri is required".into()))?;
    let path = uri
        .strip_prefix("dexsql://")
        .ok_or((-32602, "unknown resource URI".into()))?;
    let page = match path {
        "cli/cache.md" => include_str!("../docs/cli/cache.md"),
        "cli/index.md" => include_str!("../docs/cli/index.md"),
        "cli/smali.md" => include_str!("../docs/cli/smali.md"),
        "index.md" => include_str!("../docs/index.md"),
        "license.md" => include_str!("../docs/license.md"),
        "mcp/apk.md" => include_str!("../docs/mcp/apk.md"),
        "mcp/index.md" => include_str!("../docs/mcp/index.md"),
        "mcp/lifecycle.md" => include_str!("../docs/mcp/lifecycle.md"),
        "mcp/query.md" => include_str!("../docs/mcp/query.md"),
        "mcp/smali.md" => include_str!("../docs/mcp/smali.md"),
        "sql/advanced.md" => include_str!("../docs/sql/advanced.md"),
        "sql/annotations.md" => include_str!("../docs/sql/annotations.md"),
        "sql/calls.md" => include_str!("../docs/sql/calls.md"),
        "sql/data-model.md" => include_str!("../docs/sql/data-model.md"),
        "sql/examples.md" => include_str!("../docs/sql/examples.md"),
        "sql/functions.md" => include_str!("../docs/sql/functions.md"),
        "sql/index.md" => include_str!("../docs/sql/index.md"),
        "sql/schema.md" => include_str!("../docs/sql/schema.md"),
        _ => return Err((-32004, format!("resource not found: {uri}"))),
    };
    Ok(json!({"contents":[{"uri":uri,"mimeType":"text/markdown","text":page}]}))
}
