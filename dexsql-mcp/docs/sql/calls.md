# Direct calls and override-related references

Use the full descriptor to select one method, including its parameter and return types. Filtering only by class/name includes all overloads. For callers of `Runnable.run()V`:

```sql
SELECT DISTINCT file_id, method_idx, method
FROM method_calls
WHERE callee = 'Ljava/lang/Runnable;->run()V';
```

This finds instructions that reference the interface method, even when the interface is defined outside the input APK. An instruction referencing `Lcom/example/Task;->run()V` is a different target. `method_calls` has one row per call instruction: `count(*)` counts calls, while the `DISTINCT` projection above returns caller methods identified by `(file_id, method_idx)`.

If you have already established that `Task.run()V` implements this interface method, query the selected targets together. Replace `Task` with the implementation you want to inspect:

```sql
SELECT DISTINCT file_id, method_idx, method
FROM method_calls
WHERE callee IN (
    'Ljava/lang/Runnable;->run()V',
    'Lcom/example/Task;->run()V'
);
```

To discover candidates, join the direct interface declarations to virtual method definitions. Keeping `file_id` in this join prevents mixing DEX-local class indices:

```sql
SELECT DISTINCT m.descriptor
FROM methods m
JOIN class_interfaces i
  ON m.file_id = i.file_id AND m.class_idx = i.class_idx
WHERE i.interface_descriptor = 'Ljava/lang/Runnable;'
  AND m.name = 'run'
  AND m.param_count = 0
  AND m.return_descriptor = 'V'
  AND m.method_kind = 'virtual';
```

The caller can select candidates from this result and reuse the resulting descriptor set for the same dataset. To count call instructions referencing any candidate or the interface method itself:

```sql
WITH targets AS (
    SELECT 'Ljava/lang/Runnable;->run()V' AS descriptor
    UNION
    SELECT m.descriptor
    FROM methods m
    JOIN class_interfaces i
      ON m.file_id = i.file_id AND m.class_idx = i.class_idx
    WHERE i.interface_descriptor = 'Ljava/lang/Runnable;'
      AND m.name = 'run'
      AND m.param_count = 0
      AND m.return_descriptor = 'V'
      AND m.method_kind = 'virtual'
)
SELECT count(*) AS call_count
FROM method_calls
WHERE callee IN (SELECT descriptor FROM targets);
```

Coverage and cost:

- The discovery query finds `run()V` methods declared by types that **directly** list `Runnable` in their interfaces. `method_kind = 'virtual'` excludes static/private methods and reference-only rows. It does not require a concrete method body; abstract declarations can also be call targets.
- Indirect interface implementations, subinterfaces, and methods inherited from a superclass require additional traversal through `classes.superclass_descriptor` and `class_interfaces`, followed by method resolution. A client can query these relations iteratively, deduplicate visited type descriptors, and apply signature/access rules before constructing the target set. For methods with parameters, match their types and order, not just `param_count`.
- The combined query counts references to the selected methods. It does not prove which implementation a particular interface call executes. In the selected-target caller query, also project `callee` when you need distinct caller/target pairs.
- Expand targets only when needed. Prefer the exact descriptor query for direct callers, or a selected `IN` list when the targets are already known. The all-candidate CTE can produce a large target set on a large APK and cost substantially more; it is not a persistent cache. Returning a full `DISTINCT` caller list instead of the count can also exceed the intermediate-result memory budget. For a large caller search, query selected targets in measured batches and merge/deduplicate `(file_id, method_idx)` in the client. Reuse discovered targets within the same dataset and measure the composed query before putting it on a frequent path.
- Keep cross-DEX target matching descriptor-based. A definition's `method_idx` belongs to its own DEX; references in other DEX files have their own indices. These recipes use the existing schema and perform expansion only when requested by the query.

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
