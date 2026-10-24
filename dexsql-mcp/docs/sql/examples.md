# SQL examples

Choose an example below and replace its class, method or value with the one you
want to investigate. See the [DEX data model](dexsql://sql/data-model.md) for descriptor syntax
and the difference between references and definitions.

## Find string references

```sql
-- Find methods that reference a given string (exact, then substring).
SELECT DISTINCT method FROM method_strings WHERE value = 'https://api.example.com';
SELECT DISTINCT method FROM method_strings WHERE value LIKE '%api.example.com%';
```

## Find callers and callees

```sql
-- Callees: the methods that com.example.Foo.bar() calls.
SELECT DISTINCT callee FROM method_calls
WHERE method = 'Lcom/example/Foo;->bar()V';

-- Callers: the methods that call com.example.Foo.bar().
SELECT DISTINCT method FROM method_calls
WHERE callee = 'Lcom/example/Foo;->bar()V';
```

## Find field accesses

```sql
-- Fields a method accesses.
SELECT DISTINCT field FROM method_field_accesses
WHERE method = 'Lcom/example/Foo;->bar()V';
```

## Find referenced types

```sql
-- Types a method uses (Java-style names).
SELECT DISTINCT type_name FROM method_used_types
WHERE method = 'Lcom/example/Foo;->bar()V';
```

## Find numeric constants

```sql
-- Methods that load a given immediate number.
SELECT DISTINCT method FROM method_using_numbers WHERE long_value = 114514;
```

## Inspect annotations

```sql
-- What carries an annotation type.
SELECT DISTINCT owner FROM annotation_elements_resolved
WHERE annotation = 'Landroidx/annotation/Keep;';

-- Annotation + element values, narrowed by annotation type.
SELECT owner, element_name, value_i64, value_index
FROM annotation_elements_resolved
WHERE annotation = 'Landroidx/annotation/Keep;';

-- Runtime-retained annotations on a specific owner.
SELECT annotation, element_name, value_i64, value_index
FROM annotation_elements_resolved
WHERE owner = 'Lcom/example/Foo;' AND retention_policy = 'runtime';
```

## List declared methods

```sql
-- List the methods a class declares.
SELECT method_descriptor FROM class_methods WHERE class_descriptor = 'Lcom/example/Foo;';

-- Contrast: this lists REFERENCED methods, including references from dexes that do not
-- define them, and the same method may appear more than once. See "References vs. definitions".
SELECT descriptor FROM methods WHERE class_descriptor = 'Lcom/example/Foo;';
```

## Match instruction sequences

```sql
-- Match methods by a contiguous opcode sequence. `opcode_hex` is the
-- space-separated two-hex-digit opcode stream; contains, starts-with '6e 0c%',
-- ends-with '%6e 0c', and exact matches are all supported.
SELECT DISTINCT descriptor FROM methods WHERE opcode_hex LIKE '%6e 0c 6e%';
```

For interface and override-related callers, see [call queries](dexsql://sql/calls.md). Filter annotation queries by annotation type or owner before expanding elements. For repeated queries, reuse a prepared dataset or [cache](dexsql://cli/cache.md).

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
