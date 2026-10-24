# MCP APK tools

Inspect Manifest declarations, packaged files and resource values with the tools
below. Use SQL and smali to follow a component from its declaration to its code.

## Open an APK

Open the archive with `open_dataset` before calling these tools. Resource-only
archives are accepted; inspect `has_dex` before attempting SQL over code.
`input_index` is a zero-based index in `open_dataset.inputs`; it is required
when a dataset contains multiple archive inputs. Paths inside archives are exact
entry names, never filesystem extraction targets. Names come from raw ZIP header
bytes; Info-ZIP Unicode Path (0x7075) overrides are ignored, matching Android
libziparchive.

## Choose a tool

| Tool | Use |
| --- | --- |
| `get_manifest` | Default summary: package/version, application attributes, SDK, component counts, paginated permission declarations. `mode: "xml"` returns paginated decoded XML. |
| `get_manifest_components` | Page activities, aliases, services, receivers and providers; filter `kind` or `only_exported`. Includes qualified names/descriptors, alias targets, intent actions/categories/data, metadata and launcher intent filters. |
| `list_resource_files` | Page archive entries and sizes; optionally filter a case-sensitive `prefix`, e.g. `assets/` or `res/`. Obfuscated APKs may use other paths. |
| `read_resource` | Read an exact `name`: binary Android XML becomes XML, UTF-8 stays text, other bytes use lowercase hex. `format: "hex"` forces original bytes. |
| `query_resources` | Page `resources.arsc` entries by `resource_id` (JSON integer), exact `name` (`type/name` or `package:type/name`), `resource_type`, name substring `contains`, or exact `configuration`. |

## Follow a component into code

For example, call `get_manifest_components` with
`{"dataset_id":"dataset-1","kind":"activity","only_exported":true}`, then find
its class descriptor with SQL and inspect methods using `decode`.

## Continue a result

Row lists use `offset`, `limit` (1–200, default 100), `total_rows`, `next_offset`
and `truncated`. Text/XML results store continuation under `page`; append
`page.text` and pass `page.next_offset` back as `offset`. Hex results store
`content` and `next_offset` at the top level; offsets count original bytes.
Each byte budget includes both JSON result copies. An oversized individual row
returns `output_too_large`; read its XML/text resource in pages instead.

## Interpret values

Resource values preserve type, raw bits and configuration qualifiers. References
include their IDs and names where available; they are not recursively evaluated
and no device configuration is implicitly selected. Complex styles/arrays are
flattened into ordered map-item rows with parent ID and item index. XML retains
numeric resource IDs so it can be read independently of the resource table.

The first `query_resources` call parses and retains that archive's resource table
until the dataset closes. Later calls reuse it, with the same source-change check
before each request. A changed source returns `source_changed`; close and reopen
the dataset to read it. This trades resident memory for faster repeated queries
without parsing resources during `open_dataset`.

`exported` and `enabled` describe manifest configuration. Explicit `exported=true`
is included even without an intent filter. Missing values follow target-SDK defaults
assuming Android API 17+; unresolved/resource-valued or invalid configuration is
null. Runtime enablement, permissions and installation validity still affect access.
An activity alias names a manifest entry; use `target_activity` to locate its code.

## Compact transport

`get_manifest`, `get_manifest_components`, `list_resource_files`, `read_resource`, and
`query_resources` accept `compact: true` per call (default false). This sends the
original result object once in `structuredContent`, with `content: []`. Resource
rows retain their named fields and value-type/reference/configuration metadata;
text/hex encodings, NULLs, errors and all pagination coordinates are unchanged.
Byte budgets measure the actual selected transport, so compact pages may be larger.
Pass the option on each continuation. Clients that only read text must use the default.
The browser session already returns one JSON object and accepts the same option;
there is no duplicate MCP envelope to remove there.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
