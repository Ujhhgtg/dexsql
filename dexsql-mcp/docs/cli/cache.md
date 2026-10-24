# Saved caches

Use an in-memory prepared dataset when many queries run in the same process. CLI interactive mode keeps the input ready for successive queries. Use a disk cache when queries must reuse preparation across process launches.

```bash
dexsql prepare-cache \
  --input app.apk \
  --output app.dexsql-cache \
  --timing

dexsql query-cache \
  --cache-file app.dexsql-cache/cache.dxc2 \
  --sql "select count(*) from method_refs" \
  --timing
```

`prepare-cache` saves metadata, method references and instruction data for all
supported tables. It does not require separate decode flags. Later `query-cache`
calls can use any of these tables.

A one-shot `query` prepares only the data needed by its SQL. `query --full`
prepares the complete dataset; both modes return the same query results.

Keep cache files in a directory you control. When source inputs change, create a
new cache before querying again. Invalid or stale caches return errors. Caches
created before raw MUTF-8 storage are incompatible; rebuild them with the current
executable.

The MCP service keeps its own datasets in memory. Use these CLI commands when
you need a cache that survives process exits.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
