# SQL functions

DexSQL accepts a subset of SQLite's built-ins. Anything outside this list is rejected at parse time with `function call is outside the DexSQL read-only subset` rather than silently mis-evaluated.

**Scalar**

| | |
| --- | --- |
| text | `length` `substr`/`substring` `upper` `lower` `trim` `ltrim` `rtrim` `replace` `instr` `hex` `quote` `unicode` `char` |
| numeric | `abs` `min(a, b, …)` `max(a, b, …)` |
| null / conditional | `coalesce` `ifnull` `nullif` `iif` |
| introspection | `typeof` |
| DEX-specific | `dex_java_name` |

`dex_java_name` renders a DEX type descriptor as its Java-style name — `dex_java_name('Lcom/f/B;')` is `com.f.B`, `[I` is `int[]`, `V` is `void`. It is the function behind `types.java_name`, and writing the call inline gets the same treatment as reading the column.

`min`/`max` are scalar with two or more arguments and aggregate with one.

**Aggregate**

`count(*)` `count(x)` `count(DISTINCT x)` `sum` `avg` `total` `min` `max` `group_concat(x)` `group_concat(x, sep)` `string_agg(x, sep)`

`group_concat` accepts an ordering, which is what makes a concatenated list deterministic: `group_concat(value, ',' ORDER BY ordinal)`. The `protos` view's `param_descriptors` is built exactly that way.

`char(...)` builds text from code points; `char()` returns empty text. U+0000 is
preserved, and supplementary characters use MUTF-8 surrogate pairs internally.
See [text values](dexsql://sql/index.md#text-values) for output conversion and raw-byte casts.

**Window**

`row_number()` `rank()` `dense_rank()` `ntile(n)` `lag(x[, offset[, default]])`
`lead(x[, offset[, default]])` `first_value(x)` `last_value(x)`, plus `count`,
`sum`, `avg`, `min` and `max` with `OVER (...)`. DISTINCT window aggregates are
not supported. Unsupported names, arities or window shapes return an error.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
