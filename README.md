# DexSQL

DexSQL is an embedded SQL engine for inspecting Android DEX files and APK
archives. The `dexsql` crate is the supported library entry point; the CLI and
MCP server are separate applications built from the same parser and executor.

```toml
dexsql = { git = "https://github.com/Ujhhgtg/dexsql.git", rev = "<pinned-commit>" }
```

The library opens `.dex`, `.apk`, `.jar`, and `.zip` paths through
`dexsql::Engine`. A session keeps one immutable dataset so a resolver can run
many descriptor queries without reopening the APK:

```rust,no_run
use dexsql::Engine;

let engine = Engine::open(["classes.dex"])?;
let methods = engine.query(
    "SELECT descriptor FROM methods WHERE name = 'onCreate' ORDER BY descriptor",
)?;
for row in methods.rows {
    println!("{}", row[0]);
}
# Ok::<(), dexsql::Error>(())
```

The public API returns column names and all result rows as owned values. Empty
and multiple-row results are successful queries; callers decide how to select
rows and classify application-specific lookup states. Errors describe input
loading or SQL execution failures. Internal IR and MCP transport types are not
part of the library contract.
