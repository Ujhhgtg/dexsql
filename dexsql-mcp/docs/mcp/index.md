# MCP reference

Use this reference when operating DexSQL through an MCP client. The `dexsql mcp`
command serves tools and English documentation over local stdio. User setup is
documented in the [CLI guide](dexsql://cli/index.md#connect-an-ai-client).

Server discovery identifies the build in `serverInfo.version`: the CLI crate
version followed by `+` and the full Git commit ID when available, for example
`0.1.0+1577eb3f7c5d150de836b24530ccc84cbc73ea37`. This appears in `initialize`
on the 2025-11-25 protocol and in the `io.modelcontextprotocol/serverInfo` metadata
on the 2026-07-28 protocol. Archive/CI builds can set `DEXSQL_BUILD_COMMIT` to a
full hexadecimal Git object ID at build time. Without Git or an explicit commit,
the server reports the crate version alone; it does not invent a revision.

## Start a task

1. Call `resources/list` to discover the available manuals. Use `list_tables`
   and `describe_table` with `{"name":"methods"}` to check tables and columns
   without opening an input.
2. Call `open_dataset` with local paths, for example
   `{"inputs":["/absolute/path/app.apk"]}`. Relative paths use the server's working
   directory. Several paths form one dataset. Inspect returned diagnostics,
   `has_dex` and `archive_inputs`; archives without DEX can still provide resources.
3. Use the returned `dataset_id` in later calls. Start with a selective SQL query,
   then inspect matched methods or resources. Do not invent dataset or file IDs.
4. Follow the continuation fields described by each tool. Query pagination
   re-executes SQL, so use a deterministic `ORDER BY` with a unique tie-breaker.
5. Reuse the dataset for related work. Call `close_dataset` when it is no longer
   needed. A server restart invalidates all dataset IDs.

Example `query` arguments (replace the ID with the one returned by `open_dataset`):

```json
{
  "dataset_id": "dataset-1",
  "sql": ["SELECT descriptor FROM classes ORDER BY file_id, class_idx LIMIT 20"]
}
```

## Tool reference

| Tools | Reference |
| --- | --- |
| `open_dataset`, `list_datasets`, `close_dataset` | [Lifecycle, cancellation and limits](dexsql://mcp/lifecycle.md) |
| `list_tables`, `describe_table` | [Table meanings](dexsql://sql/schema.md); tool output gives current names and types |
| `query` | [SQL requests, result encoding and pagination](dexsql://mcp/query.md) |
| `decode` | [Method summaries, smali and navigation context](dexsql://mcp/smali.md) |
| `get_manifest`, `get_manifest_components` | [APK tools](dexsql://mcp/apk.md) |
| `list_resource_files`, `read_resource`, `query_resources` | [APK tools](dexsql://mcp/apk.md) |

Use `tools/list` for exact argument schemas and defaults. [SQL examples](dexsql://sql/examples.md)
and [call references](dexsql://sql/calls.md) provide reusable query patterns.

## Documentation resources

`resources/list` returns the complete English document catalog, including pages
that have no links from other documents. Listing requires no prior resource reads
or open dataset. Use `resources/read` with a listed URI to retrieve one page.
All listed documents are included in the executable and match its
version; no separate document files or network connection are needed. Links in
resource responses use MCP URIs. A resource URI is `dexsql://` followed by the
Markdown file's path relative to the documentation root, including `.md`. Directory
index pages retain their filenames. There are no aliases or resources outside
this documentation tree.

## Session behavior

Opening an input prepares a dataset for successive queries. Reopening the same
path creates an independent dataset. If a source changes, close and reopen its
dataset before continuing. Closing rejects new work while already accepted work
may finish within its deadline.

Running timeout or cancellation closes the affected dataset; reopen it to
continue. Queued cancellation preserves existing datasets. Check `list_datasets`
after cancellation. See [lifecycle and limits](dexsql://mcp/lifecycle.md) for quotas and retry
rules.

stdout contains MCP messages only; diagnostics use stderr. Persistent disk caches
are managed by the [CLI cache commands](dexsql://cli/cache.md).

## Choosing the output representation

The seven data tools (`query`, `decode`, and the five APK tools) accept the optional
boolean `compact` on each call. Default/false retains the published text plus
structured representation. `true` keeps only `structuredContent` (`content: []`)
and uses [compact query cells](dexsql://mcp/query.md#opt-in-compact-output) for SQL. This requires
a client that reads structured content; there is no automatic client detection.
Lifecycle/schema tools and documentation `resources/read` are unchanged.

The structured representation preserves the tools' output-schema contract. MCP
[recommends a text duplicate for backward compatibility](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#structured-content);
compact deliberately opts out of that recommendation, not the schema requirement.
Use the default when client support is unknown.

Browser sessions already send one JSON value for decode/APK calls and accept
`compact` as a transport no-op. The browser SQL ABI (`dexsql_query_handle`) and the
WebMCP UI's rendered text tools have their own existing schemas, not the CLI query
DTO or dual MCP envelope; this option does not change those interfaces.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
