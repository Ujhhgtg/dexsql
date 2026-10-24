# dexsql

a rust reimplementation of parts of [lsposed/dexsql-release](https://github.com/LSPosed/dexsql-release), because of course libraries have to at least provide an android lib for me to link to or else how the fuck can i use them (yes i know you released it to a few internal testers)

> [!warning]
> **please do not use this project in production. seriously.**
>
> this is an incomplete, reverse-engineered reimplementation, written primarily to replace dexkit in my own project.
>
> it is nowhere near a mature, general-purpose implementation. most of the functionality is either incomplete, poorly optimized, or optimized for my own specific workload. the implementation has serious memory and performance issues, and its behavior has not been validated across a sufficiently broad range of real-world inputs.
>
> **use [dexkit](https://github.com/LuckyPray/DexKit) for android, or the original [dexsql-release](https://github.com/LSPosed/dexsql-release) for desktop instead.** do not assume this project is a drop-in replacement for either of them.

## features

- some dexsql functionality
- sql-like queries over android dex and apk metadata
- supports opening `.dex`, `.apk`, `.jar`, and `.zip` files through the library api
- includes a command-line interface and an mcp server

## known issues

### performance

you should not assume this implementation is faster than the original dexsql. in fact, it even isn't on par with original, it is a lot worse than that.

also there is no proper benchmark suite, the only thing i can tell you is that, after replacing dexkit with this dexsql in wekit, total dex resolution time decreases from ~30s to ~11s. yes i know this sounds promising, but please. don't attempt to use this for serious work.

### memory usage

a significant amount of data is eagerly materialized instead of being processed lazily.

this means the engine may allocate and retain far more data than a query actually needs. on large apks, especially those containing many dex files, your computer/phone **will** oom.

### overfitted fast paths

some so-called 'fast paths' are essentially optimizations for query patterns observed in my own project.

they are not good general-purpose optimizations. *many* queries may perform much worse than expected.

### incomplete functionality

this is a partial reimplementation, not a complete reproduction of the original project.

functionality that happens to work for my own inputs may fail, behave differently, or perform poorly on other applications.

if your use case is not covered by mine, you are essentially on your own. if your use case *is* covered, you are still on your own. nobody (except your ai agent) would help you.

## usage

add the library to your `Cargo.toml`:

```toml
[dependencies]
dexsql = { git = "https://github.com/Ujhhgtg/dexsql.git", rev = "<commit>" }
```

pinning a commit is recommended, since the api and implementation may change without notice.

a minimal example:

```rust
use dexsql::Engine;

fn main() -> Result<(), dexsql::Error> {
    let engine = Engine::open(["classes.dex"])?;

    let methods = engine.query(
        "select descriptor from methods where name = 'onCreate' order by descriptor",
    )?;

    for row in methods.rows {
        println!("{}", row[0]);
    }

    Ok(())
}
```

## building

you need a working rust toolchain.

```bash
cargo build --workspace --release
```

to run the workspace tests:

```bash
cargo test --workspace
```

## related projects

- [LSPosed/dexsql-release](https://github.com/LSPosed/dexsql-release) — the original project this implementation attempts to reproduce
- [LuckyPray/DexKit](https://github.com/LuckyPray/DexKit) — an existing dex analysis library
- [Ujhhgtg/WeKit](https://github.com/Ujhhgtg/WeKit) — the project that motivated this implementation

## license

of course i have no permission to declare a license. the docs are fetched from original, which are MIT.
