# MCP smali decoding

Use the read-only `decode` tool.
After a query finds a method, pass its dataset ID and DEX-local coordinates:

```json
{"dataset_id":"dataset-1","file_id":0,"method_idx":123}
```

Supply exactly one of `method_idx`, `method`, or `class`. `method_idx` requires
`file_id`. `method` is a complete descriptor such as `LFoo;->bar(I)V`; `class`
is a complete class descriptor such as `LFoo;`. For descriptors found in several
DEX files, the error lists candidate file IDs; select one with `file_id`.

The result includes `mode`, `total_methods`, `method_offset`, `next_method_offset`,
and `methods`. Each method has `file_id`, `method_idx`, `descriptor`, access flags,
code-unit size, register count and try count where available. Class selection defaults
to `mode: "summary"`: up to 20 methods, ordered by method index, with no bodies.
Use `method_limit` (1–50) and follow `next_method_offset` to list more methods.
An empty class returns `[]`. Missing or merely referenced methods are errors.

Method selection defaults to `mode: "smali"`. Each method includes `declaration`,
`smali`, `offset`, `next_offset`, `total_bytes`, `total_lines`, zero-based line
coordinates and `starts_mid_line`/`ends_mid_line`. `offset` is a UTF-8 byte offset,
not an instruction offset or line number. Repeat the same method selector and mode
with the returned `next_offset` until it is null. Concatenate `smali` exactly to
recover the complete text. `max_lines` defaults to 200 (maximum 1000); `max_bytes`
can lower the server's byte budget. Very long lines are split at UTF-8 boundaries.
If selecting a class with `mode: "smali"`, continue each method's text using its
`file_id` and `method_idx`, then continue the class list with `next_method_offset`.

For branch/catch navigation, `mode: "context"` returns a separate paginated index
of the method declaration, registers, labels and catch directives with original
zero-based smali line numbers. Labels retain their original method-relative code-unit
offsets on every page. Context offsets refer to this index, not the full smali body.

Abstract/native methods have declarations and endings only. Smali output contains
method blocks with registers, instructions, stable code-unit labels, payloads and
catch directives; it omits class/field declarations, annotations, and debug directives.
Standard DEX 035 and 037–041 are supported; quickened/odex instructions are not.
This output is not a complete class intended for reassembly.

Decoding checks that the source still matches the opened dataset. Missing or changed sources require closing and reopening
the dataset. A decode failure sets `isError: true`, includes the dataset and available
file/method/code-unit coordinates, and returns no partial methods. Decode shares the
query worker queue and cancellation behavior.

See [lifecycle and limits](dexsql://mcp/lifecycle.md) for cancellation and timeouts.

## Compact transport

Add `compact: true` per `decode` call to receive only `structuredContent`, with an
empty `content` array. Default/false preserves the existing dual representation.
All method metadata, text, line/byte offsets, class continuations and error coordinates
are retained. The actual compact envelope is measured during both method and text
paging; pass the option again on each continuation. The browser's `dexsql_decode`
and threaded session already return one JSON value, so they accept this option
without changing their payload or budget measure.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
