# Command-line usage

## Run the CLI

Place the supplied `dexsql` executable (`dexsql.exe` on Windows) in a directory
on your `PATH`, or invoke it by its full path. Examples use `dexsql`:

```bash
dexsql --version
dexsql --help
dexsql query --help
```

Each command's `--help` lists its options. Global options work before or after
the command name. Examples with `\` line continuations use a POSIX shell;
in PowerShell or Command Prompt, put the command on one line.

## Commands

- `tables --input app.apk`: print built-in table names, columns, and SQL types.
  The schema is fixed; the input flag is required for compatibility, but the
  file is not read.
- `query --input app.apk --sql "..."`: run one-shot SQL over the input. By
  default only the data needed by the supplied SQL is prepared; results are identical to
  `--full`.
- `query --input app.apk --interactive`: a persistent REPL session over one
  prepared in-memory dataset that supports successive queries.
- `prepare-cache --input app.apk --output app.dexsql-cache`: parse once
  and write `cache.dxc2` inside the output directory for repeated queries.
- `query-cache --cache-file app.dexsql-cache/cache.dxc2 --sql "..."`:
  query a prepared cache container file.
- `decode --input app.apk --method 'Lcom/example/Foo;->bar(I)V'`: disassemble
  a method; see [smali decoding](dexsql://cli/smali.md).
- `mcp`: serve MCP tools and documentation over stdio. The client opens
  datasets through `open_dataset`; see [MCP setup](dexsql://mcp/index.md).
- `extract licenses --output THIRD_PARTY_NOTICES`: export the third-party
  copyright and license notices embedded in this executable. Omit `--output`
  to print them to stdout. Existing files are not overwritten; no APK, network
  connection or source tree is needed. Notices cover program dependencies and
  runtimes, excluding build dependencies, procedural macros, compilers and linkers.

## Options

- `--threads N`: set worker thread count. `0` and the default use all
  available logical CPUs.
- `--full` (`query` only): prepare all metadata, method references, and opcode
  data instead of only the data needed by the supplied SQL. Results are the
  same. Interactive mode always prepares the full dataset, so `--full` has no
  effect there. Use `prepare-cache` to save a cache for later invocations.
- `--cache NAME=SQL`: name a `SELECT` body for later queries. It is request-scoped
  on `query --sql` and `query-cache`, and a lazy session definition on
  `query --interactive`.
- `--limit N`: cap returned rows per statement (unlimited by default), not
  the work done by the query.
- `--timing`: print load, parse, data preparation, cache, and SQL timing (a
  per-query line in interactive sessions) to stderr.
- `--trusted-input`: for environments where inputs and caches are controlled.
  Some validation is skipped, including strict source-input freshness checks
  for `query-cache`. This option is off by default.

Choose `--sql` or `--interactive` for `query`. Repeat `--input` for multiple
DEX/APK files; input is optional for SQL that does not read DEX/APK data, such
as `dexsql query --sql "SELECT 1"`. Pass one statement per `--sql`; multiple
`--sql` arguments run in order and share one loaded DEX session:

```bash
dexsql query \
  --input app.apk \
  --sql "select count(*) as class_count from classes" \
  --sql "select count(*) as method_count from class_methods"
```

Interactive mode requires at least one `--input` file and keeps the loaded
DEX/APK data in memory across queries. Submit a query with a trailing `;`
or by entering an empty line. Use `.help` for help, and exit with `.exit`,
`.quit`, or EOF. `--repl` is an alias for `--interactive`:

```bash
dexsql query --input app.apk --interactive
```

In interactive mode, `CREATE VIEW`, `CREATE TEMP VIEW`, `CREATE TEMP TABLE`,
and `--cache` definitions survive submissions. `CREATE` replaces an existing
session definition after validation; `IF NOT EXISTS` keeps it. `DROP VIEW` or
`DROP TABLE` removes it. All session definitions are lazy, including TEMP TABLE;
their rows are read only when a query needs them. Closing the session drops them.

Named relations are useful for repeated joins:

```bash
dexsql query \
  --input app.apk \
  --cache "refs_per_method=select file_id, method_idx, count(*) ref_count from method_refs group by file_id, method_idx" \
  --sql "select m.descriptor, r.ref_count from methods m join refs_per_method r using (file_id, method_idx) order by r.ref_count desc limit 20"
```

## Input files

DEX, APK, JAR and ZIP paths are supported. Repeat `--input` to combine inputs. Archives may contain non-contiguous `classes*.dex` names; a malformed DEX member is skipped while later readable members remain available. Archive corruption or decompression-budget failures still return errors, and SQL input loading requires at least one readable DEX.

For repeated sessions across process launches, use [prepared caches](dexsql://cli/cache.md). On-demand method disassembly is documented under [smali](dexsql://cli/smali.md).

## Connect an AI client

Configure a local stdio MCP connection with the absolute path to the executable:

```json
{
  "mcpServers": {
    "dexsql": {
      "command": "/absolute/path/to/dexsql",
      "args": ["mcp"]
    }
  }
}
```

On Windows, use a JSON-escaped path such as `"D:\\Tools\\dexsql.exe"`.
The client launches the process. Local input paths must be accessible to it.
The [MCP reference](dexsql://mcp/index.md) gives the connected agent its tool workflow.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
