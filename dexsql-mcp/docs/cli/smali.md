# Smali disassembly

## Read a method or class

Use `decode` to inspect a method by descriptor or by its DEX coordinates:

```bash
dexsql decode --input app.apk --method 'Lcom/example/Foo;->bar(I)V'
dexsql decode --input app.apk --file-id 0 --method-idx 123
dexsql decode --input app.apk --class 'Lcom/example/Foo;'
```

Repeat `--input` for several APK/DEX paths. Select exactly one of `--method`,
`--method-idx`, or `--class`; indices require `--file-id`. Duplicate descriptors
report candidate file IDs. Class selection outputs all defined methods in index
order, including abstract/native declarations; empty classes succeed without output.
All selected methods must decode successfully before stdout receives any text.

## Understand the output

Output uses `vN` registers, code-unit labels, exact constant bits and escaped UTF-16
strings. Standard DEX 035 and 037–041 instructions, payloads and catch directives
are supported. The output contains method blocks, omitting full class/field
declarations, annotations and debug directives; complete class reassembly is outside
its scope. NaN payload bits in call-site arguments and unreferenced switch tables
are preserved in comments where smali has no unambiguous literal/target spelling.
Quickened/odex instructions return errors with available method/offset
coordinates.

## Use an AI client

A connected AI client can find methods with SQL, then read their smali in pages.
The [MCP decoding reference](dexsql://mcp/smali.md) describes that tool workflow.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
