# SQL guide

DexSQL accepts read-only SQL with joins, subqueries, CTEs, aggregates, windows and set operations. It follows SQLite semantics within its supported language, with the text rules below. Invalid or unsupported statements return structured errors.

Start with [DEX keys and descriptors](dexsql://sql/data-model.md), the [table reference](dexsql://sql/schema.md), or [query examples](dexsql://sql/examples.md). [Functions](dexsql://sql/functions.md), [callers and overrides](dexsql://sql/calls.md), [annotations](dexsql://sql/annotations.md), and [DEX structure queries](dexsql://sql/advanced.md) cover specific tasks.

## Statements and temporary results

`SELECT` and `VALUES` read data. `CREATE VIEW`, `CREATE TEMP VIEW` and
`CREATE TEMP TABLE ... AS SELECT ...` name intermediate relations. Source data
is read-only: `INSERT`, `UPDATE`, `DELETE`, `ALTER`, transactions and persistent
schema changes are not supported.

```sql
CREATE TEMP TABLE app_strings AS
SELECT string_pool_id, string_idx, value
FROM strings WHERE value LIKE '%example%';

SELECT DISTINCT method
FROM method_strings
WHERE value IN (SELECT value FROM app_strings);
```

In a one-shot CLI call, pass each statement as a separate `--sql`; definitions
last for that request. Interactive CLI and MCP datasets retain definitions across
submissions until `DROP VIEW` / `DROP TABLE`, redefinition or session close.
`CREATE` replaces an existing session definition after validation; `IF NOT EXISTS`
keeps it. All session definitions are lazy, including TEMP TABLE: their rows are
read when a query needs them. CLI `--cache NAME=SQL` follows the same scope rules.
These definitions do not create disk cache files.

## Text order

Text uses DEX's lexicographic UTF-16 code-unit order consistently in `ORDER BY`,
window ordering, `<`, `<=`, `>`, `>=`, `BETWEEN`, and `MIN`/`MAX`. This differs
from SQLite's UTF-8 `BINARY` order for some supplementary Unicode characters:
U+10000 sorts before U+FFFD. ASCII ordering is unchanged.

`BINARY` compares exact text; `NOCASE` first folds ASCII case; `RTRIM` first
removes trailing spaces (U+0020). Numeric conversion, NULL placement, and BLOB
byte ordering are unchanged. `LIKE` and `GLOB` keep their pattern-matching rules.

Local DEX IDs are not a global text-order key. For values spanning files, request
`ORDER BY` on the text itself; a complete method descriptor also does not
necessarily follow `method_idx` order.

## Text values

DEX text retains its original MUTF-8 bytes internally. Query output decodes to
UTF-8: `C0 80` becomes U+0000 and a valid surrogate pair becomes one Unicode
scalar. An isolated surrogate becomes one U+FFFD; other invalid bytes, including each
byte of a four-byte UTF-8 sequence, each produce U+FFFD. Distinct raw values can therefore
look identical in output; `hex(value)` exposes their stored bytes. CLI tables
escape control characters, and MCP strings use JSON escaping.

U+0000 is an ordinary character: text functions and patterns consume the complete
value, including embedded NULs. This differs from SQLite functions that stop at
NUL. `CAST(text AS BLOB)` exposes raw MUTF-8, and `CAST(blob AS TEXT)` keeps those
bytes. For valid DEX text, a surrogate pair counts as one character for `length`
and `substr`, even though sorting compares UTF-16 code units.

## Text matching

Without `ESCAPE`, `%` matches any sequence and `_` is a **literal underscore**. For example, `LIKE '%SEND_SMS%'` looks for that literal substring. An explicit `ESCAPE` clause enables SQLite-style patterns, including `_` as a single-character wildcard unless escaped.

`LIKE` folds ASCII case; `instr` and `=` preserve case. Choose the operation that matches your intent:

| Match | ASCII case-insensitive | Case-sensitive |
| --- | --- | --- |
| Contains | `value LIKE '%x%'` | `instr(value, 'x') > 0` |
| Prefix | `value LIKE 'x%'` | `instr(value, 'x') = 1` |
| Suffix | `value LIKE '%x'` | `substr(value, -length('x')) = 'x'` |
| Exact | `value LIKE 'x'` | `value = 'x'` |

```sql
SELECT 'SEND_SMS' LIKE '%SEND_SMS%';       -- 1
SELECT 'a' LIKE '_';                     -- 0
SELECT 'a' LIKE '_' ESCAPE '!';          -- 1
SELECT 'HTTPS://' LIKE 'https://%';       -- 1
```

## Practical query costs

Select the columns you need, filter before expanding large annotation or reference sets, and reuse a prepared dataset for repeated queries. Result limits in an API cap the response, not necessarily execution work. Some joins and `DISTINCT` queries can exceed intermediate-result budgets even with a small output limit. Measure the actual SQL with CLI `--timing`.

For a stable result order, use `ORDER BY` with a unique tie-breaker, such as
`file_id, method_idx`. A result page may run the query again; keep the SQL and
input unchanged when continuing it.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
