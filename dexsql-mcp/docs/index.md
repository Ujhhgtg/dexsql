# DexSQL documentation

Use SQL to explore the code inside Android DEX files and APKs. Begin with a
question about an app, find the relevant methods, and inspect their instructions
or the resources around them.

## Get started

The [command-line guide](dexsql://cli/index.md) walks through running the supplied executable
and opening an interactive session. The [SQL guide](dexsql://sql/index.md) explains the query
language; the same SQL concepts apply wherever a DexSQL query interface is provided.

## Find what you need

| Task | Guide |
| --- | --- |
| Find a string, method, field or bytecode pattern | [SQL examples](dexsql://sql/examples.md) |
| Understand names and join keys across multiple DEX files | [DEX data model](dexsql://sql/data-model.md) |
| Find callers or include selected overrides | [Call references](dexsql://sql/calls.md) |
| Search annotation owners and nested values | [Annotations](dexsql://sql/annotations.md) |
| Inspect raw indices, exceptions or debug information | [DEX structure queries](dexsql://sql/advanced.md) |
| Look up a table, column or function | [Table reference](dexsql://sql/schema.md) · [SQL functions](dexsql://sql/functions.md) |
| Read a method's instructions | [Smali disassembly](dexsql://cli/smali.md) |
| Understand Manifest entries and packaged resources | [APK Manifest and resources](dexsql://mcp/apk.md) |
| Avoid preparing the same input for each CLI session | [Saved caches](dexsql://cli/cache.md) |

## AI integration

To connect an AI client, see [CLI configuration](dexsql://cli/index.md#connect-an-ai-client).
The English [MCP reference](dexsql://mcp/index.md) documents tool calls, pagination and error
handling for the agent using that connection.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
