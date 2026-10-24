# DEX keys and descriptors

Three properties of DEX shape how you write queries here.

### An APK contains several dexes

An APK usually holds several `classes*.dex`. DexSQL puts them all in one set of SQL relations and distinguishes them by `file_id`. Three rules follow:

- **Every `*_idx` index is valid only within one dex.** `method_idx = 42` is a different method in a different dex. **Always include `file_id` in a join key**, or rows from different dexes will be crossed.
- **One entity appears once per dex that mentions it.** A method referenced by 5 dexes has 5 rows in `methods`. To count entities, use `DISTINCT descriptor`.
- **Strings are the exception: their scope is the pool, not the dex.** The key is `(string_pool_id, string_idx)`, reached from a `file_id` via `dex_files.string_pool_id`. In a DEX 041 container several logical dexes share one pool; before 041 each dex has one pool of its own.

### What a descriptor is

A descriptor is the string DEX uses to name an entity, and the most common lookup key in this schema:

| entity | form | example |
| --- | --- | --- |
| type | `L<package path>;` | `Ljava/lang/String;` |
| method | `<class><code>-></code><name>(<params…>)<return>` | `Lpkg/Cls;->name(I)V` |
| field | `<class><code>-></code><name>:<type>` | `Lpkg/Cls;->field:I` |

Primitives are single letters: `V` void, `Z` boolean, `B` byte, `S` short, `C` char, `I` int, `J` long, `F` float, `D` double. Arrays take a `[` prefix, e.g. `[Ljava/lang/String;`. Method parameters have no separator between them.

DEX itself stores only type descriptors; method and field descriptors are assembled by DexSQL from those parts.

### References vs. definitions

A DEX id section (`method_ids`, `field_ids`, `type_ids`) registers what the current dex **references**, wherever that entity is defined; the actual member definitions live in class-data, which is separate data. DexSQL preserves the distinction:

| relation | one row is |
| --- | --- |
| `methods`, `fields`, `types` | one **reference** |
| `class_methods`, `class_fields`, `classes` | one **definition** |

A method that is only referenced still appears in `methods`, with its definition-sourced columns `NULL`. See the [`methods`](dexsql://sql/schema.md#methods) entry for the exact behavior of these columns.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
