# Annotation queries

These recipes use the existing read-only relations. Column meanings are in the [schema reference](dexsql://sql/schema.md). Start with selective predicates before using recursive or large joins.

## Find owners with nested annotation values

Filter by annotation type before expanding values. This example finds owners carrying a route table whose nested value is `/aio`.

```sql
WITH owners AS (
    SELECT DISTINCT file_id, annotation_off, owner
    FROM annotation_elements_resolved
    WHERE annotation = 'Lcom/example/RouteTable;'
)
SELECT DISTINCT a.file_id, a.owner
FROM owners a
JOIN annotation_elements e
  ON e.file_id = a.file_id AND e.annotation_off = a.annotation_off
JOIN dex_files d ON d.file_id = e.file_id
JOIN strings s
  ON s.string_pool_id = d.string_pool_id AND s.string_idx = e.value_index
WHERE e.depth > 0 AND e.value_kind = 'string' AND s.value = '/aio';
```

## Resolve an element value

`value_kind` selects the value domain. Read integers/booleans from `value_i64`, floating values from `value_f64`, and referenced strings/types/members through `value_index`. This example resolves the first nonempty annotation in file 0; change `selected`
to address your annotation. Keeping that selection inside the query bounds the joins.

```sql
WITH selected AS (
    SELECT file_id, annotation_off
    FROM annotations
    WHERE file_id = 0 AND element_count > 0
    ORDER BY annotation_off LIMIT 1
)
SELECT e.file_id, e.annotation_off, e.value_off,
       ns.value AS name, e.value_kind, e.value_i64, e.value_f64,
       vs.value AS string_value, vt.descriptor AS type_value,
       vf.descriptor AS field_value, vm.descriptor AS method_value
FROM annotation_elements e
JOIN selected a ON a.file_id = e.file_id AND a.annotation_off = e.annotation_off
JOIN dex_files d ON d.file_id = e.file_id
LEFT JOIN strings ns
  ON ns.string_pool_id = d.string_pool_id AND ns.string_idx = e.name_idx
LEFT JOIN strings vs
  ON e.value_kind = 'string'
 AND vs.string_pool_id = d.string_pool_id AND vs.string_idx = e.value_index
LEFT JOIN types vt
  ON e.value_kind IN ('type', 'annotation')
 AND vt.file_id = e.file_id AND vt.type_idx = e.value_index
LEFT JOIN fields vf
  ON e.value_kind IN ('field', 'enum')
 AND vf.file_id = e.file_id AND vf.field_idx = e.value_index
LEFT JOIN methods vm
  ON e.value_kind = 'method'
 AND vm.file_id = e.file_id AND vm.method_idx = e.value_index;
```

## Walk annotation nodes

Depth and byte-range containment identify direct children. The walk below derives a dotted path and enclosing annotation offset. The `selected` CTE picks the first nonempty annotation in file 0; both the seed
and recursive joins use only its nodes. Replace that selection with the
`(file_id, annotation_off)` values you need.

```sql
WITH RECURSIVE selected AS (
    SELECT file_id, annotation_off
    FROM annotations
    WHERE file_id = 0 AND element_count > 0
    ORDER BY annotation_off LIMIT 1
), elements AS (
    SELECT e.* FROM annotation_elements e
    JOIN selected a ON a.file_id = e.file_id AND a.annotation_off = e.annotation_off
), tree(file_id, annotation_off, value_off, value_end_off, depth, path, group_id) AS (
  SELECT file_id, annotation_off, value_off, value_end_off, depth,
         CAST(ordinal AS TEXT), annotation_off
  FROM elements WHERE depth = 0
  UNION ALL
  SELECT c.file_id, c.annotation_off, c.value_off, c.value_end_off, c.depth,
         t.path || '.' || CAST(c.ordinal AS TEXT),
         CASE p.value_kind WHEN 'annotation' THEN p.value_off ELSE t.group_id END
  FROM tree t
  JOIN elements p
    ON p.file_id = t.file_id AND p.annotation_off = t.annotation_off
   AND p.value_off = t.value_off
  JOIN elements c
    ON c.file_id = t.file_id AND c.annotation_off = t.annotation_off
   AND c.depth = t.depth + 1
   AND c.value_off > t.value_off AND c.value_end_off <= t.value_end_off
)
SELECT t.file_id, t.annotation_off, t.path, t.group_id, n.value_index AS nested_type_idx
FROM tree t
LEFT JOIN elements n
  ON n.file_id = t.file_id AND n.annotation_off = t.annotation_off
 AND n.value_off = t.group_id AND t.group_id <> t.annotation_off;
```

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
