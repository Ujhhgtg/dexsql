# MCP lifecycle and limits

Heavy operations (open, query, decode, Manifest/resources) share one bounded queue.
Discovery and metadata stay responsive. Timeouts include queue time. Every heavy tool accepts `timeout_ms` in `1..=` the server timeout.
For progress notifications, set the MCP request's `_meta.progressToken`; progress
reports phase and elapsed seconds, not a completion percentage.

Running timeout/cancellation closes only the affected dataset.
Reopen it to continue. A timeout result includes `dataset_closed: true`; the SDK may
suppress the response to an explicit cancellation, so check `list_datasets` afterward.
Cancelling or timing out while queued preserves existing datasets. A cancelled open
never registers a dataset. Closing rejects new work; accepted work may finish within
its deadline and continues to count against quotas. EOF closes the session and its datasets.

Server defaults can be configured after `mcp` on the command line:

| Option | Default |
| --- | --- |
| `--timeout-ms` | 60000 |
| `--max-datasets` | 4 (open/opening/retained by accepted work) |
| `--max-pending` | 16 (running plus waiting heavy requests) |
| `--max-input-bytes` | 1073741824 source bytes per dataset |
| `--max-dex-bytes` | 1073741824 uncompressed DEX bytes per dataset |
| `--max-total-input-bytes` | 2147483648 source bytes across datasets |
| `--max-output-bytes` | 131072 serialized data-tool result bytes, including text and structured copies |
| `--max-resource-bytes` | 67108864 uncompressed bytes per resource entry |

`open_dataset.inputs` accepts 1–64 paths. Per-call `max_bytes` must be at least
4096 and at most the configured `--max-output-bytes`; it limits the whole
serialized tool result, including both JSON copies.

Open validates the archive directory and local entry headers and prepares DEX
before returning. Buffering archive reads does not postpone these checks to the
first query. Manifest and resource contents are decoded on demand by their tools.

Input requests are limited to 256 KiB per JSON-RPC frame; malformed/oversized frames
close the session. Query calls allow at most 16 statements, 16 temporary queries and
64 KiB of SQL. Archives allow at most 100000 entries. Resource limits apply before
decompression, and files are never extracted. Source/uncompressed byte quotas are
not an RSS limit: parsers and prepared data use additional memory, and the engine's
existing per-operator materialization limits still apply. `server_busy` and
`session_quota_exceeded` are recoverable; retry later or close unused datasets.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
