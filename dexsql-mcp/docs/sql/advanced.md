# DEX structure queries

These recipes use the existing read-only relations. Column meanings are in the [schema reference](dexsql://sql/schema.md). Start with selective predicates before using recursive or large joins.

## Read class descriptors and parents

For ordinary queries use `classes`. These joins show how to resolve the raw optional indices without treating a missing index as zero.

```sql
SELECT t.descriptor,
       st.descriptor AS superclass_descriptor,
       f.value AS source_file
FROM class_defs d
JOIN types t ON t.file_id = d.file_id AND t.type_idx = d.class_idx
LEFT JOIN types st ON st.file_id = d.file_id AND st.type_idx = d.superclass_idx
LEFT JOIN dex_files dd ON dd.file_id = d.file_id
LEFT JOIN strings f ON f.string_pool_id = dd.string_pool_id AND f.string_idx = d.source_file_idx;
```

## Resolve method handles

Handle kinds 0–3 reference fields; kinds 4–8 reference methods. Join the appropriate index domain.

```sql
SELECT h.method_handle_idx,
       CASE h.method_handle_type
         WHEN 0 THEN 'static_put' WHEN 1 THEN 'static_get'
         WHEN 2 THEN 'instance_put' WHEN 3 THEN 'instance_get'
         WHEN 4 THEN 'invoke_static' WHEN 5 THEN 'invoke_instance'
         WHEN 6 THEN 'invoke_constructor' WHEN 7 THEN 'invoke_direct'
         WHEN 8 THEN 'invoke_interface' ELSE 'unknown' END AS method_handle_kind,
       CASE WHEN h.method_handle_type <= 3 THEN 'field'
            WHEN h.method_handle_type <= 8 THEN 'method'
            ELSE 'unknown' END AS member_kind,
       coalesce(f.descriptor, m.descriptor) AS member_descriptor
FROM method_handles h
LEFT JOIN fields f ON h.method_handle_type <= 3
                  AND f.file_id = h.file_id AND f.field_idx = h.member_idx
LEFT JOIN methods m ON h.method_handle_type BETWEEN 4 AND 8
                   AND m.file_id = h.file_id AND m.method_idx = h.member_idx
```

## Read call-site bootstrap information

Names come from the shared string pool; prototypes come from `protos`. Nested argument values are available in `encoded_array_values`.

```sql
SELECT c.call_site_idx,
       s.value                                                  AS method_name,
       '(' || replace(p.param_descriptors, ',', '') || ')' || p.return_descriptor  AS proto_descriptor,
       max(c.value_count - 3, 0)                                 AS argument_count
FROM call_sites c
LEFT JOIN dex_files cd2 ON cd2.file_id = c.file_id
LEFT JOIN strings s ON s.string_pool_id = cd2.string_pool_id AND s.string_idx = c.method_name_idx
LEFT JOIN protos  p ON p.file_id = c.file_id AND p.proto_idx   = c.proto_idx;
```

## Walk encoded arrays

A direct child has depth one greater than its parent and a contained byte range. Limit the roots to the arrays you need when querying a large input.

```sql
WITH RECURSIVE tree(file_id, encoded_array_off, value_off, value_end_off, depth, path) AS (
  SELECT file_id, encoded_array_off, value_off, value_end_off, depth, CAST(ordinal AS TEXT)
  FROM encoded_array_values WHERE depth = 0
  UNION ALL
  SELECT c.file_id, c.encoded_array_off, c.value_off, c.value_end_off, c.depth,
         t.path || '.' || CAST(c.ordinal AS TEXT)
  FROM tree t
  JOIN encoded_array_values c
    ON c.file_id = t.file_id AND c.encoded_array_off = t.encoded_array_off
   AND c.depth = t.depth + 1
   AND c.value_off > t.value_off AND c.value_end_off <= t.value_end_off
)
SELECT * FROM tree;
```

## Summarize exception handlers

Join on file, method and handler offset. Addresses are 16-bit code units; the end of a protected range is `start_addr + insn_count`.

```sql
-- Resolve class_idx through the method key.
SELECT c.file_id, c.method_idx, m.class_idx
FROM code_items c
JOIN methods m ON m.file_id = c.file_id AND m.method_idx = c.method_idx;

-- Derive the end address and summarize each try range.
SELECT t.file_id, t.method_idx, t.try_idx,
       t.start_addr + t.insn_count AS end_addr,
       min(h.handler_idx) AS handler_idx,
       count(*) FILTER (WHERE NOT h.is_catch_all) AS catch_count,
       max(CASE WHEN h.is_catch_all THEN h.addr END) AS catch_all_addr
FROM try_items t
JOIN catch_handlers h ON h.file_id = t.file_id
                     AND h.method_idx = t.method_idx
                     AND h.handler_off = t.handler_off
GROUP BY t.file_id, t.method_idx, t.try_idx, t.start_addr, t.insn_count;

-- Resolve typed handlers; catch-all handlers have no type_idx.
SELECT ty.descriptor AS type_descriptor
FROM catch_handlers h
JOIN types ty ON ty.file_id = h.file_id AND ty.type_idx = h.type_idx;
```

## Resolve debug parameter names

Debug names are string indices. Resolve them through the DEX string pool; resolve type indices through `types`.

```sql
SELECT p.file_id, p.method_idx, s.value AS name
FROM debug_parameters p
JOIN dex_files pd ON pd.file_id = p.file_id
JOIN strings s ON s.string_pool_id = pd.string_pool_id AND p.name_idx = s.string_idx;
```

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
