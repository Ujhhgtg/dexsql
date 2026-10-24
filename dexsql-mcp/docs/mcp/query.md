# MCP SQL requests and results

## Batches and temporary tables

sql is a non-empty array of SQL strings executed in order. SELECT/VALUES and
the engine's supported read-only statements are available. The existing engine
reports invalid or unsupported SQL; source inputs cannot be updated.
CREATE VIEW, CREATE TEMP VIEW and CREATE TEMP TABLE ... AS SELECT ... define
lazy relations in the dataset session. To name
intermediate results, supply:

```json
{
  "dataset_id": "dataset-1",
  "named_temp_queries": [
    {"name": "sizes", "sql": "select file_id, byte_len from dex_files"}
  ],
  "sql": ["select sum(byte_len) as bytes from sizes"]
}
```

Definitions survive later calls for the same dataset until DROP VIEW / DROP TABLE,
redefinition, or close_dataset. CREATE replaces the previous definition after
validation; IF NOT EXISTS keeps it. Named temporary queries have the same lifetime.
TEMP TABLE is lazy like TEMP VIEW: defining it does not execute or materialize its rows.
Definitions are isolated between datasets.
No tools create or open persistent disk caches; use the CLI for those operations.

## Results

query returns dataset_id, statements, and diagnostics. Every statement
contains its zero-based statement_index, sql, kind, columns, rows,
offset, next_offset, total_rows, and truncated. Rows are arrays aligned with the column order,
including duplicate column names. total_rows is the engine's result count
before applying the returned-row limit; an SQL LIMIT has already taken effect.

Each cell is { "type": "...", "value": ... }:

| type | value |
| --- | --- |
| null | JSON null |
| int64 / uint64 | Exact decimal string, including values beyond JavaScript's safe integer range |
| float64 | JSON number, or "NaN", "Infinity", "-Infinity" |
| utf8 | UTF-8 decoded text; see [text values](dexsql://sql/index.md#text-values) |
| binary | Lowercase hexadecimal bytes |

The default limit is 200 returned rows per statement (maximum 1000). `offset`
defaults to 0; `offset + limit` must not exceed 100000. Each statement has its own
`next_offset` because byte limits may shorten its page. Continue statements separately
if their offsets differ. Use a deterministic `ORDER BY` with a unique tie-breaker:
paging re-executes the SQL using the current session definitions. A changed SQL
request is a new result, not a continuation. Long request SQL metadata is abbreviated
with `sql_truncated: true`; cell values are never silently shortened.

`max_bytes` can lower the server result budget (minimum 4096 bytes). If one complete row cannot fit,
the tool returns `output_too_large`; select fewer columns or use `substr()` to read
large string values in pieces. These are response limits. Prefer selective WHERE
clauses and SQL LIMIT to reduce execution work; use keyset predicates for deep pages.
Set timing: true to include query timing and per-statement execute_ms,
all in milliseconds. Preparing a dataset reports prepare_ms separately.

Tool results contain both structured JSON and the same JSON as text for client
compatibility. Empty result sets are successful. Input, dataset and SQL failures
set isError: true and return an error object. Engine errors include kind,
stage, message, and a zero-based statement_index when known.

## Opt-in compact output

Add `"compact": true` to an individual query call. Omission or `false` preserves the
original response bytes; the setting does not persist on the dataset. Compact results
have `content: []` and one `structuredContent` object, including on tool errors. Use
this mode only with a client that consumes structured content. The output schema
accepts both query forms. Protocol-level JSON-RPC errors are unchanged.

Compact statements omit `sql` and `sql_truncated`. `columns` contains only names
(including duplicate names), and each row remains an array in column order. Column
inference and nullability metadata are omitted; runtime cell types remain lossless:

| JSON cell | Meaning |
| --- | --- |
| `null` | SQL NULL |
| `"text"` | UTF-8 text, even if it looks like a number, hex, or `NaN` |
| `1.25` | Finite float64 (including signed zero) |
| `["i", "-9223372036854775808"]` | int64, exact decimal string |
| `["u", "18446744073709551615"]` | uint64, exact decimal string |
| `["b", "00ff"]` | BLOB, lowercase hex; empty BLOB is `["b", ""]` |
| `["f", "NaN"]` | Non-finite float64; also `Infinity` and `-Infinity` |

Tags describe each value, so mixed-type columns require no inference. Diagnostics,
timing when requested, statement kind/index, `offset`, `next_offset`, `total_rows`,
`truncated`, and all error fields are retained. `max_bytes` counts the actual compact
MCP result (including its envelope); compact pages can therefore contain more rows.
Follow the returned offsets, and repeat `compact: true` on every continuation.

For example, `select 42 as n, NULL as absent, '42' as text` has compact
`columns: ["n", "absent", "text"]` and `rows: [[["i", "42"], null, "42"]]`
(the integer tag reflects the engine's actual signedness).

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
