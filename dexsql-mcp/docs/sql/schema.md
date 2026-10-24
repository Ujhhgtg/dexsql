# DexSQL schema reference

This reference describes each built-in relation: what one row means, its keys, columns and nullability. Use resolved views for ordinary analysis and base tables for DEX structure.

`?` marks a nullable column. `Utf8`, `Utf8View` and string dictionaries are text in SQL; `Dynamic` can hold different SQL value types. Indices are scoped by `file_id`, except strings, whose key is `(string_pool_id, string_idx)`. Ordinals start at zero. Byte offsets end in `_off`; instruction addresses use 16-bit code units.

Text is stored as raw MUTF-8 and decoded at the output boundary; see
[text values](dexsql://sql/index.md#text-values). The catalog’s `Utf8` type names describe
SQL text, not its internal byte encoding.

For the schema in your executable, use `dexsql tables --input app.apk` or MCP `list_tables` / `describe_table`.

## Choose a relation

| To find | Use |
| --- | --- |
| A class by descriptor / name | `classes` |
| A method by descriptor / name / parameters | `methods` |
| A field by descriptor / name / type | `fields` |
| The methods a class **itself declares** | `class_methods` |
| The fields a class **itself declares** | `class_fields` |
| The string constants a method references | `method_strings` |
| Who calls whom | `method_calls` |
| The fields a method reads or writes | `method_field_accesses` |
| The types a method references | `method_used_types` |
| The immediate constants a method loads | `method_using_numbers` |
| Methods by bytecode shape | `methods` |
| Who carries a given annotation | `annotation_elements_resolved` |
| An annotation's nested value tree | `annotation_values` |
| The interfaces a class implements | `class_interfaces` |
| A prototype's parameter list | `proto_params` |
| The string pool itself | `strings` |

## Entity views

### `types`

One row per **type** the current dex references (one `type_ids` entry).

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `type_idx` | `UInt32` | Type id index. |
| `descriptor` | `Utf8` | Raw type descriptor, e.g. `Ljava/lang/String;`, `I`, `[B`. |
| `java_name` | `Utf8` | Type name closer to Java source style. |

### `protos`

One row per **method prototype** the current dex references (one `proto_ids` entry).

Parameters follow DEX order. No parameters means `param_count = 0` and `param_descriptors = ''`.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `proto_idx` | `UInt32` | Proto id index. |
| `shorty_idx` | `UInt32` | Shorty string index. |
| `shorty` | `Utf8` | Dex shorty descriptor. |
| `return_type_idx` | `UInt32` | `type_idx` of the return type. |
| `return_descriptor` | `Utf8` | Return type descriptor. |
| `parameters_off` | `UInt32` | Parameter `type_list` offset; 0 means no list. |
| `param_count` | `UInt32` | Parameter count. |
| `param_descriptors` | `Utf8` | Comma-joined parameter descriptors in ordinal order. |

### `fields`

One row per **field** the current dex references (one `field_ids` entry). This is a reference relation, not a definition relation — see [References and definitions](dexsql://sql/data-model.md#references-vs-definitions); for the fields a class itself declares, use `class_fields`.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `field_idx` | `UInt32` | Field id index. |
| `class_idx` | `UInt32` | `type_idx` of the class that owns the field. |
| `class_descriptor` | `Utf8` | Descriptor of the class that owns the field. |
| `type_idx` | `UInt32` | `type_idx` of the field's value type. |
| `type_descriptor` | `Utf8` | Descriptor of the field's value type. |
| `name` | `Utf8` | Field name. |
| `descriptor` | `Utf8` | Full field descriptor, e.g. `Lpkg/Cls;->field:I`. |

### `methods`

One row per method ID referenced by a DEX, whether or not that DEX defines the method. The key is `(file_id, method_idx)`. The same descriptor can occur in multiple DEX files.

`access_flags`, `method_kind`, `opcode_count` and `opcode_hex` are `NULL` on reference-only rows: the DEX does not declare the method, so its bytecode, if any, lives in another file. A declared method without a code item (abstract or native) has `opcode_count = 0` and `opcode_hex = ''`. Use `class_methods` for definitions.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `method_idx` | `UInt32` | Method id index. |
| `class_idx` | `UInt32` | `type_idx` of the class that owns the method. |
| `class_descriptor` | `Utf8View` | Descriptor of the class that owns the method. |
| `proto_idx` | `UInt32` | Method prototype index. |
| `name` | `Utf8View` | Method name. |
| `descriptor` | `Utf8View` | Full method descriptor, e.g. `Lpkg/Cls;->name(I)V`. |
| `return_descriptor` | `Utf8View` | Return type descriptor. |
| `param_count` | `UInt32` | Parameter count. |
| `param_descriptors` | `Utf8View` | Comma-joined parameter descriptors in parameter order (same form as `protos.param_descriptors`). |
| `access_flags` | `UInt32?` | Method access flags; `NULL` when this dex only references the method. |
| `opcode_count` | `UInt32?` | Decoded instruction count; `NULL` when this dex only references the method (its opcode data is unavailable here). |
| `opcode_hex` | `Utf8View?` | Space-separated two-digit opcode bytes; `NULL` when this dex only references the method. |
| `method_kind` | `Utf8?` | `direct` or `virtual` from class data; `NULL` when this dex only references the method. |

### `classes`

One row per class definition. A type that is only referenced appears in `types`, not here. `superclass_descriptor` and `source_file` are optional. `interface_count` counts directly declared interfaces; their names are in `class_interfaces`.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `class_def_idx` | `UInt32` | Sequential index within the class def section. |
| `class_idx` | `UInt32` | Type id index of the current class. |
| `descriptor` | `Utf8` | Descriptor of the current class. |
| `access_flags` | `UInt32` | Class access flags. |
| `superclass_descriptor` | `Utf8?` | Superclass descriptor; `NULL` when there is no superclass. |
| `interface_count` | `UInt32` | Number of implemented interfaces (`0`, never `NULL`, for a class implementing none). |
| `field_count` | `UInt32` | Number of declared fields (`0`, never `NULL`, for a class declaring none). |
| `method_count` | `UInt32` | Number of declared methods (`0`, never `NULL`, for a class declaring none). |
| `source_file` | `Utf8?` | Source file name; `NULL` when absent. |

## Reference and member views

### `method_strings`

One row per **string-referencing instruction**: one string constant used inside one method. A method that references the same string twice has two rows.

| Column | Type | Meaning |
| --- | --- | --- |
| `method` | `Utf8View` | Full descriptor of the method containing the instruction. |
| `method_class` | `Utf8View` | Descriptor of the instruction owner class. |
| `method_name` | `Utf8View` | Name of the instruction owner method. |
| `value` | `Utf8View` | String text; UTF-8 decoded on output. |
| `file_id` | `UInt32` | Owning logical DEX file ID. |
| `class_idx` | `UInt32` | Declaring class type index within the DEX. |
| `method_idx` | `UInt32` | Method index within the DEX. |
| `string_idx` | `UInt32` | String index in the DEX string pool. |

### `method_calls`

One row per call instruction. Unprefixed columns describe the caller; `callee*` columns describe the target referenced by the instruction. Repeated calls remain separate rows. Overrides and runtime dispatch are not expanded. See [call queries](dexsql://sql/calls.md).

| Column | Type | Meaning |
| --- | --- | --- |
| `method` | `Utf8View` | Full descriptor of the method containing the instruction. |
| `method_class` | `Utf8View` | Descriptor of the instruction owner class. |
| `method_name` | `Utf8View` | Name of the instruction owner method. |
| `callee` | `Utf8View` | Full descriptor of the referenced method. |
| `callee_class` | `Utf8View` | Class descriptor of the referenced method. |
| `callee_name` | `Utf8View` | Name of the referenced method. |
| `file_id` | `UInt32` | Owning logical DEX file ID. |
| `class_idx` | `UInt32` | Declaring class type index within the DEX. |
| `method_idx` | `UInt32` | Method index within the DEX. |
| `callee_method_idx` | `UInt32` | Referenced method index in the caller DEX. |

### `method_field_accesses`

One row per field-access instruction. `using_type` is lowercase `get` for reads or `put` for writes. The method columns identify the caller; the field columns identify the referenced field.

| Column | Type | Meaning |
| --- | --- | --- |
| `method` | `Utf8View` | Full descriptor of the method containing the instruction. |
| `method_class` | `Utf8View` | Descriptor of the instruction owner class. |
| `method_name` | `Utf8View` | Name of the instruction owner method. |
| `field` | `Utf8View` | Full descriptor of the referenced field. |
| `field_class` | `Utf8View` | Declaring class descriptor of the field. |
| `field_name` | `Utf8View` | Field name. |
| `field_type` | `Utf8View` | Field type descriptor. |
| `using_type` | `Utf8?` | `get` for a field read, `put` for a field write; otherwise `NULL`. |
| `file_id` | `UInt32` | Owning logical DEX file ID. |
| `class_idx` | `UInt32` | Declaring class type index within the DEX. |
| `method_idx` | `UInt32` | Method index within the DEX. |
| `field_idx` | `UInt32` | Field id index. |

### `method_used_types`

One row per **type-referencing instruction** (`check-cast`, `new-instance`, and so on).

| Column | Type | Meaning |
| --- | --- | --- |
| `method` | `Utf8View` | Full descriptor of the method containing the instruction. |
| `method_class` | `Utf8View` | Descriptor of the instruction owner class. |
| `method_name` | `Utf8View` | Name of the instruction owner method. |
| `type_descriptor` | `Utf8View` | Referenced type descriptor. |
| `type_name` | `Utf8View` | Java-style name of the referenced type. |
| `file_id` | `UInt32` | Owning logical DEX file ID. |
| `class_idx` | `UInt32` | Declaring class type index within the DEX. |
| `method_idx` | `UInt32` | Method index within the DEX. |
| `type_idx` | `UInt32` | Type index within the DEX. |

### `method_using_numbers`

One row per instruction that loads an immediate numeric constant. `long_value` contains a sign-extended integer or the raw floating-point bits; `double_value` contains the numeric floating value and is `NULL` for byte/short constants.

| Column | Type | Meaning |
| --- | --- | --- |
| `method` | `Utf8View` | Full descriptor of the method containing the instruction. |
| `method_class` | `Utf8View` | Descriptor of the instruction owner class. |
| `method_name` | `Utf8View` | Name of the instruction owner method. |
| `number_type` | `Dictionary(Int8, Utf8)` | Numeric kind, e.g. `byte`, `short`, `int`, `long`, `float`, `double`. |
| `long_value` | `Int64` | Integer value (sign-extended), or the raw bit pattern for `float`/`double`. |
| `double_value` | `Float64?` | Floating value; `NULL` for `byte`/`short`. |
| `opcode` | `UInt32` | Raw debug opcode value. |
| `file_id` | `UInt32` | Owning logical DEX file ID. |
| `class_idx` | `UInt32` | Declaring class type index within the DEX. |
| `method_idx` | `UInt32` | Method index within the DEX. |

### `proto_params`

One row per **parameter** of a prototype. Same data as `protos.param_descriptors` in a different shape: one row per parameter here, one joined string there.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning logical DEX file ID. |
| `proto_idx` | `UInt32` | Prototype index within the DEX. |
| `ordinal` | `UInt32` | Zero-based position within the parent. |
| `type_idx` | `UInt32` | Type index within the DEX. |
| `descriptor` | `Utf8` | Raw type descriptor, e.g. `Ljava/lang/String;`, `I`, `[B`. |

### `class_methods`

One row per method definition in class data, keyed by `(file_id, method_idx)`. Includes direct and virtual methods, including abstract/native declarations. Additional prototype and opcode columns are available in `methods` with the same key.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `class_idx` | `UInt32` | Owner class index. |
| `class_descriptor` | `Utf8` | Owner class descriptor. |
| `method_idx` | `UInt32` | Method id index. |
| `method_name` | `Utf8` | Method name. |
| `method_descriptor` | `Utf8` | Full method descriptor. |
| `kind` | `Utf8` | Method grouping, `direct` or `virtual`. |
| `access_flags` | `UInt32` | Method access flags. |

### `class_interfaces`

One row per interface directly declared by a class or interface. Inherited interfaces are not expanded. A type with no directly declared interfaces has no rows here.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning logical DEX file ID. |
| `class_idx` | `UInt32` | Declaring class type index within the DEX. |
| `ordinal` | `UInt32` | Zero-based position within the parent. |
| `interface_type_idx` | `UInt32` | Direct interface type index. |
| `interface_descriptor` | `Utf8` | Direct interface descriptor. |

### `annotation_elements_resolved`

One row per owner, annotation and top-level element. A marker annotation with no elements still produces a row with `NULL` element columns. An annotation shared by several owners produces rows for each owner.

`retention_policy` maps visibility 0/1/2 to `class`/`runtime`/`system`. `owner_kind` is `class`, `field`, `method` or `parameter`. Use `annotation_values` to inspect nested elements.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning logical DEX file ID. |
| `class_idx` | `UInt32` | Declaring class type index within the DEX. |
| `owner_kind` | `Dynamic` | `class`, `field`, `method` or `parameter`. |
| `owner_idx` | `UInt32` | Owner index, interpreted according to owner_kind. |
| `owner` | `Utf8?` | Descriptor of the annotated class, field, method or parameter owner. |
| `parameter_idx` | `Dynamic?` | Zero-based parameter position for parameter owners; otherwise `NULL`. |
| `annotation` | `Utf8` | Annotation type descriptor. |
| `visibility` | `UInt32` | Raw annotation visibility value (0 = build/class, 1 = runtime, 2 = system). |
| `element_count` | `UInt32` | Number of annotation elements. |
| `annotation_off` | `UInt32` | Annotation item offset (join key to `annotation_elements` and to the annotation sets that point at it). |
| `element_ordinal` | `UInt32?` | Top-level element position; `NULL` for a marker annotation. |
| `element_name` | `Utf8?` | Top-level element name; `NULL` for a marker annotation. |
| `value_kind` | `Utf8?` | Readable encoded value type. |
| `value_index` | `UInt32?` | The dex index an index-kinded value references — a `string_idx` for `string`, `type_idx` for `type` and for a nested `annotation`'s own type, `field_idx` for `field`/`enum`, `method_idx` for `method`, `proto_idx` for `method_type`, `method_handle_idx` for `method_handle`; `NULL` otherwise. |
| `value_i64` | `Int64?` | Scalar value representable as an integer. |
| `value_f64` | `Float64?` | Scalar value representable as a float. |
| `retention_policy` | `Dynamic?` | `class`, `runtime` or `system`, from visibility. |

### `annotation_values`

One row per owner and encoded-value node at any nesting depth. Marker annotations with no elements produce no rows. The owner-free value tree is in `annotation_elements`; use that table for byte ranges and raw `value_index` references. See [annotation queries](dexsql://sql/annotations.md).

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning logical DEX file ID. |
| `class_idx` | `UInt32` | Declaring class type index within the DEX. |
| `owner_kind` | `Dynamic` | `class` / `method` / `field` / `parameter`. |
| `owner_idx` | `UInt32` | Owner index, interpreted according to owner_kind. |
| `owner_descriptor` | `Utf8?` | Descriptor of the annotated class / method / field / parameter. |
| `parameter_idx` | `Dynamic?` | Zero-based parameter position for parameter owners; otherwise `NULL`. |
| `annotation_off` | `UInt32` | Annotation item offset (join key to `annotation_elements` and to the annotation sets that point at it). |
| `annotation_type_idx` | `UInt32` | Root annotation type index. |
| `annotation_descriptor` | `Utf8` | Descriptor of the root annotation type. |
| `depth` | `UInt32` | Nesting depth from the root annotation. |
| `ordinal` | `UInt32` | Order within the parent element/array. |
| `name_idx` | `UInt32?` | Element name string index; `NULL` for an `array` element, which has a position but no name. |
| `name` | `Utf8?` | Element name of this value. |
| `value_kind` | `Utf8` | Readable encoded value type. |
| `value_i64` | `Int64?` | Scalar value representable as an integer. |
| `value_f64` | `Float64?` | Scalar value representable as a float. |

## Strings and annotations

### `strings`

One row per **string-pool entry**, including constants, names and descriptors.
`value` retains raw MUTF-8 and is filterable directly with `WHERE value = '…'` or `WHERE value LIKE '%needle%'`.

| Column | Type | Meaning |
| --- | --- | --- |
| `string_pool_id` | `UInt32` | DexSQL-assigned string pool id; join `dex_files.string_pool_id` to reach it from a `file_id`. |
| `string_idx` | `UInt32` | String id index within that pool. |
| `value` | `Utf8View` | String text; UTF-8 decoded on output. |

### `class_fields`

One row per **field definition** (a class's class-data member). This is the definition-side counterpart to `fields`, the same relationship `class_methods` has to `methods` — see [References and definitions](dexsql://sql/data-model.md#references-vs-definitions). The columns carry a `field_` prefix: `field_name` / `field_descriptor` correspond to `fields`' `name` / `descriptor`.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `class_idx` | `UInt32` | Owner class index. |
| `class_descriptor` | `Utf8` | Owner class descriptor. |
| `field_idx` | `UInt32` | Field id index. |
| `field_name` | `Utf8` | Field name. |
| `field_descriptor` | `Utf8` | Full field descriptor. |
| `kind` | `Utf8` | Field grouping, usually `static` or `instance`. |
| `access_flags` | `UInt32` | Field access flags. |

### `annotations`

One row per DEX `annotation_item`, uniquely keyed by `(file_id, annotation_off)`. It has no owner columns: several owners can reference the same item through annotation sets. Use the resolved annotation views for ownership and `annotation_elements` for values.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `annotation_off` | `UInt32` | Annotation item offset (join key to `annotation_elements` and to the annotation sets that point at it). |
| `visibility` | `UInt32` | Raw annotation visibility value (0 = build/class, 1 = runtime, 2 = system). |
| `type_idx` | `UInt32` | Annotation type index (`types.type_idx`). |
| `element_count` | `UInt32` | Number of annotation elements. |

### `annotation_elements`

One row per encoded-value node, uniquely keyed by `(file_id, annotation_off, value_off)`. `depth = 0` identifies top-level elements. A direct child has depth one greater and lies inside the parent byte range `[value_off, value_end_off)`. Shared items are stored once here.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `annotation_off` | `UInt32` | Offset of the owning annotation item (join key to `annotations`). |
| `depth` | `UInt32` | Nesting depth; `0` is a declared element of the annotation item. |
| `ordinal` | `UInt32` | Position among the siblings at this depth. |
| `name_idx` | `UInt32?` | Element name string index; `NULL` for an `array` element, which has a position but no name. |
| `value_off` | `UInt32` | Start offset of this value's bytes. |
| `value_end_off` | `UInt32` | Offset one past this value's last byte. |
| `value_kind` | `Utf8` | Readable value type. |
| `value_index` | `UInt32?` | The dex index an index-kinded value references — a `string_idx` for `string`, `type_idx` for `type` and for a nested `annotation`'s own type, `field_idx` for `field`/`enum`, `method_idx` for `method`, `proto_idx` for `method_type`, `method_handle_idx` for `method_handle`; `NULL` otherwise. |
| `value_i64` | `Int64?` | Scalar value representable as an integer. |
| `value_f64` | `Float64?` | Scalar value representable as a float. |

## DEX layout

### `dex_files`

One row per LOGICAL dex; each `classes*.dex` in an APK/ZIP becomes a separate row, and so does each logical dex inside a DEX 041 container.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `string_pool_id` | `UInt32` | The string pool this dex resolves `string_idx` through. Below 041 it is this dex's own pool; inside a 041 container several logical dex files share one. |
| `source_path` | `Utf8` | Source name of the input: usually its original path, or a label for in-memory input. Not necessarily a filesystem path. |
| `entry_name` | `Utf8` | The dex entry name from the raw APK/ZIP header (Info-ZIP 0x7075 overrides are ignored); the matching input entry name when a dex is given directly. **041 containers are the exception**: the logical dex files of one physical entry are named `classes.dex`, `classes.dex#2`, … — those `#N` zip entries do not exist, they are synthesised. |
| `byte_len` | `UInt64` | Number of dex bytes actually loaded. |
| `dex_version` | `Utf8` | Version string from the dex header, e.g. `035`, `038`. |
| `checksum` | `UInt32` | Adler-32 checksum of the dex header. |
| `signature_hex` | `Utf8` | SHA-1 signature of the dex header, as hexadecimal text. |
| `file_size` | `UInt32` | Dex file size declared by the header. |
| `header_size` | `UInt32` | Header size. |
| `endian_tag` | `UInt32` | Dex endian tag. |
| `link_size` | `UInt32` | Link section size. |
| `link_off` | `UInt32` | Link section offset. |
| `map_off` | `UInt32` | `map_list` offset. |
| `string_count` | `UInt32` | Number of string ids. |
| `string_ids_off` | `UInt32` | String id section offset. |
| `type_count` | `UInt32` | Number of type ids. |
| `type_ids_off` | `UInt32` | Type id section offset. |
| `proto_count` | `UInt32` | Number of proto ids. |
| `proto_ids_off` | `UInt32` | Proto id section offset. |
| `field_count` | `UInt32` | Number of field ids. |
| `field_ids_off` | `UInt32` | Field id section offset. |
| `method_count` | `UInt32` | Number of method ids. |
| `method_ids_off` | `UInt32` | Method id section offset. |
| `class_count` | `UInt32` | Number of class defs. |
| `class_defs_off` | `UInt32` | Class def section offset. |
| `data_size` | `UInt32` | Data section size. |
| `data_off` | `UInt32` | Data section offset. |

### `map_items`

Exposes the dex `map_list`; it describes the type, size, and start offset of each section in the current dex.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `ordinal` | `UInt32` | Order of this map item within the `map_list`. |
| `type_code` | `UInt32` | Raw type code of the dex map item. |
| `size` | `UInt32` | Number of items in the section. |
| `offset` | `UInt32` | File offset of the section. |

### `id_items`

Uniformly exposes the raw item offsets of the various id sections; suited to low-level layout inspection.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `item_type_code` | `UInt32` | Dex type code of the section the id item belongs to. |
| `idx` | `UInt32` | Index within that section. |
| `item_off` | `UInt32` | Start offset of the id item itself. |
| `item_end_off` | `UInt32` | End offset of the id item itself. |
| `data_off` | `UInt32?` | Target offset when the id item points to a data-section structure; `NULL` when there is no target structure. |

## IDs and class data

### `type_ids`

The raw `type_ids` section: one row per type, holding only the string id of its descriptor. The readable `types` view is built over this.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `type_idx` | `UInt32` | Type id index. |
| `descriptor_idx` | `UInt32` | `string_idx` of the type's descriptor. |

### `type_lists`

Summary of raw `type_list` structures; both proto parameter lists and class interface lists reference them.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `type_list_off` | `UInt32` | `type_list` start offset. |
| `type_list_end_off` | `UInt32` | `type_list` end offset. |
| `size` | `UInt32` | Number of types in the list. |

### `type_list_entries`

Splits each `type_list` into per-entry rows.

Lists are shared by offset. Both prototype parameters and class interfaces can reference the same list.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `type_list_off` | `UInt32` | Start offset of the owning `type_list`. |
| `ordinal` | `UInt32` | Order of the type in the list. |
| `type_idx` | `UInt32` | Type index, pointing into `types.type_idx`. |

### `proto_ids`

Raw DEX `proto_id_item` rows. Readable text and parameter aggregation live in the `protos` view.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `proto_idx` | `UInt32` | Proto id index. |
| `shorty_idx` | `UInt32` | Shorty string index. |
| `return_type_idx` | `UInt32` | `type_idx` of the return type. |
| `parameters_off` | `UInt32` | Parameter `type_list` offset; 0 means no list. |

### `field_ids`

The raw `field_ids` section: one row per field id, holding only the three indices DEX stores. The readable `fields` view is built over this.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `field_idx` | `UInt32` | Field id index. |
| `class_idx` | `UInt32` | `type_idx` of the class that owns the field. |
| `type_idx` | `UInt32` | `type_idx` of the field's value type. |
| `name_idx` | `UInt32` | `string_idx` of the field name. |

### `method_ids`

The raw `method_ids` section: one row per method id, holding only the three indices DEX stores. The readable `methods` view is built over this.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `method_idx` | `UInt32` | Method id index (dense, in section order). |
| `class_idx` | `UInt32` | `type_idx` of the declaring class. |
| `proto_idx` | `UInt32` | Prototype index (`protos.proto_idx`). |
| `name_idx` | `UInt32` | String id of the method name. |

### `class_defs`

The raw `class_def_item` records — DEX INDICES only, one row per declared class, in class-def
record order. Every readable spelling of these indices lives in the `classes` view;
this is where the offsets that address the class's other structures live.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `class_def_idx` | `UInt32` | Sequential index within the class def section. |
| `class_idx` | `UInt32` | Type id index of the current class. |
| `access_flags` | `UInt32` | Class access flags. |
| `superclass_idx` | `UInt32?` | Type id index of the superclass; `NULL` for `NO_INDEX`. |
| `interfaces_off` | `UInt32` | Offset of the interface `type_list`; `0` when the class implements none. |
| `source_file_idx` | `UInt32?` | String id index of the source file name; `NULL` for `NO_INDEX`. |
| `annotations_off` | `UInt32` | Offset of the `annotations_directory_item`; `0` when absent. |
| `class_data_off` | `UInt32` | Offset of the `class_data_item`; `0` when the class declares no members. |
| `static_values_off` | `UInt32` | Offset of the static-field initializer `encoded_array_item`; `0` when absent. |

### `class_data_items`

Summary of a class `class_data_item`, recording field/method group counts and byte range.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `class_idx` | `UInt32` | Owner class index. |
| `class_data_off` | `UInt32` | Class data start offset. |
| `class_data_end_off` | `UInt32` | Class data end offset. |
| `static_fields_size` | `UInt32` | Number of static fields. |
| `instance_fields_size` | `UInt32` | Number of instance fields. |
| `direct_methods_size` | `UInt32` | Number of direct methods. |
| `virtual_methods_size` | `UInt32` | Number of virtual methods. |

### `class_data_methods`

One row per **method definition** in class-data, carrying its access flags and which encoded list held it (`direct` / `virtual`). A `method_id` this dex only references has no row here — that is the source of the `NULL`s in `methods.access_flags` and `methods.method_kind`; see [References and definitions](dexsql://sql/data-model.md#references-vs-definitions). For a readable form with class and method names, use the `class_methods` view.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `class_idx` | `UInt32` | `type_idx` of the declaring class. |
| `method_idx` | `UInt32` | Method id index (`method_ids.method_idx`). |
| `access_flags` | `UInt32?` | Method access flags. |
| `kind` | `Utf8?` | Which encoded list held the record — `direct` or `virtual`. |

### `class_static_values`

Initial values of class static fields; maps the `static_values_off` encoded array back onto static fields in order.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `class_idx` | `UInt32` | Owner class index. |
| `static_values_off` | `UInt32` | Static values encoded array offset. |
| `ordinal` | `UInt32` | Order of the static initial value. |
| `field_idx` | `UInt32?` | Field id index of the matching static field; `NULL` when it cannot be mapped. |
| `value_kind` | `Utf8` | Readable value type. |
| `value_index` | `UInt32?` | The dex index an index-kinded value references, per `value_kind` — exactly as `encoded_array_values.value_index`; `NULL` otherwise. |
| `value_i64` | `Int64?` | Scalar value representable as an integer. |
| `value_f64` | `Float64?` | Scalar value representable as a float. |

## Method handles and call sites

### `method_handles`

The DEX 038+ `method_handle_item` table: the handle type and the member index it addresses.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `method_handle_idx` | `UInt32` | Method handle index. |
| `method_handle_type` | `UInt32` | Raw method handle type value. |
| `member_idx` | `UInt32` | Target field id or method id index, per `method_handle_type`. |

### `call_sites`

Summary of DEX 038+ `call_site_id_item`; resolves bootstrap info for invoke-custom.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `call_site_idx` | `UInt32` | Call site index. |
| `call_site_off` | `UInt32` | Call site encoded array offset. |
| `value_count` | `UInt32` | Total number of encoded values in the call site encoded array. |
| `method_handle_idx` | `UInt32?` | Bootstrap method handle index; `NULL` when absent or when the format does not match. |
| `method_name_idx` | `UInt32?` | Call site method name string index. |
| `proto_idx` | `UInt32?` | Call site method prototype index. |

### `call_site_args`

Splits each encoded value of a call site encoded array into per-entry rows.

Only top-level values are listed. The nested tree is in `encoded_array_values` at `encoded_array_off = call_site_off`.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `call_site_idx` | `UInt32` | Owning call site index. |
| `call_site_off` | `UInt32` | Owning call site encoded array offset. |
| `ordinal` | `UInt32` | Order of the argument in the encoded array. |
| `value_kind` | `Utf8` | Readable value type, e.g. `string`, `method_type`, `int`. |
| `value_index` | `UInt32?` | Index the value references, per `value_kind`: `string`→`strings.string_idx`, `type`/`annotation`→`type_ids.type_idx`, `field`/`enum`→`field_idx`, `method`→`method_idx`, `method_type`→`proto_idx`, `method_handle`→`method_handle_idx`. |
| `value_i64` | `Int64?` | Scalar value representable as an integer. |
| `value_f64` | `Float64?` | Scalar value representable as a float. |

## Encoded values

### `encoded_arrays`

Summary of all discovered `encoded_array_item`s.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `encoded_array_idx` | `UInt32` | Sequential number DexSQL assigns to the encoded array. |
| `encoded_array_off` | `UInt32` | Encoded array start offset. |
| `encoded_array_end_off` | `UInt32` | Encoded array end offset. |
| `value_count` | `UInt32` | Number of top-level encoded values. |

### `encoded_array_values`

One row per encoded-value node within an encoded array. `depth = 0` identifies top-level entries; depth and byte-range containment describe nested arrays and annotations. Decode referenced names using the domain indicated by `value_kind`.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `encoded_array_off` | `UInt32` | Start offset of the top-level encoded array. |
| `depth` | `UInt32` | Nesting depth; 0 at the top level. |
| `ordinal` | `UInt32` | Order of the value within the current level. |
| `name_idx` | `UInt32?` | Annotation element name string index; `NULL` for non-annotation-element values. |
| `value_off` | `UInt32` | Encoded value start offset. |
| `value_end_off` | `UInt32` | Encoded value end offset. |
| `value_kind` | `Utf8` | Readable value type. |
| `value_index` | `UInt32?` | Index the value references, per `value_kind` (same mapping as `call_site_args.value_index`). |
| `value_i64` | `Int64?` | Scalar value representable as an integer. |
| `value_f64` | `Float64?` | Scalar value representable as a float. |

### `encoded_array_owners`

Links encoded array offsets back to known owners, e.g. class static values or a call site.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `encoded_array_off` | `UInt32` | Encoded array start offset. |
| `owner_kind` | `Utf8` | Owner kind, e.g. `class_static_values` or `call_site`. |
| `owner_idx` | `UInt32` | Owner index, e.g. class idx or call site idx. |

### `hiddenapi_flags`

Android hidden API metadata; only has rows when the dex carries the matching hiddenapi data.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `class_idx` | `UInt32` | Owner class index. |
| `ordinal` | `UInt32` | Number of the hiddenapi flag in the class member expansion order. |
| `member_kind` | `Utf8` | Member category, usually `field` or `method`. |
| `member_idx` | `UInt32` | Field id or method id index. |
| `flag` | `UInt32` | Raw hiddenapi flag value. |

## Code and exceptions

### `code_items`

`code_item` header and layout info for method implementations.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `method_idx` | `UInt32` | Method index. |
| `code_off` | `UInt32` | `code_item` start offset. |
| `registers_size` | `UInt32` | Total number of registers used by the method. |
| `ins_size` | `UInt32` | Registers (in words) used by incoming arguments. |
| `outs_size` | `UInt32` | Out registers in words. |
| `tries_size` | `UInt32` | Number of try items. |
| `debug_info_off` | `UInt32` | `debug_info_item` offset; 0 in the dex when there is none. |
| `insns_size` | `UInt32` | Instruction-area size in 16-bit code units. |
| `insns_off` | `UInt32` | Start byte offset of the instruction array. |
| `tries_off` | `UInt32?` | Start offset of the try item array; `NULL` when there is no try. |
| `handlers_off` | `UInt32?` | Start offset of the encoded catch handler list; `NULL` when there is no try. |

### `try_items`

Protected instruction ranges inside a method `code_item`.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `method_idx` | `UInt32` | Method index. |
| `try_idx` | `UInt32` | Try item order. |
| `start_addr` | `UInt32` | Start instruction address of the try range, in code units. |
| `insn_count` | `UInt32` | Length of the try range, in code units. |
| `handler_off` | `UInt32` | Relative offset of the catch handler within the handler list. |

### `catch_handlers`

Expands the typed catch and catch-all entries in an `encoded_catch_handler_list`.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `method_idx` | `UInt32` | Method index. |
| `handler_idx` | `UInt32` | DexSQL-assigned handler sequence number. |
| `handler_off` | `UInt32` | Relative offset of the handler within the handler list. |
| `ordinal` | `UInt32` | Order of the catch entry within the current handler. |
| `type_idx` | `UInt32?` | Caught exception type index; `NULL` for catch-all. |
| `addr` | `UInt32` | Handler start instruction address, in code units. |
| `is_catch_all` | `Boolean` | Whether this is a catch-all entry. |

## Debug information

### `debug_info`

Method-level `debug_info_item` summary.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `method_idx` | `UInt32` | Method index. |
| `debug_info_off` | `UInt32` | `debug_info_item` start offset. |
| `line_start` | `UInt32` | Initial source line number of the debug state machine. |
| `parameters_size` | `UInt32` | Number of parameters declared in the debug header. |

### `debug_parameters`

Method parameter names from the debug header.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `method_idx` | `UInt32` | Method index. |
| `debug_info_off` | `UInt32` | Owning `debug_info_item` offset. |
| `ordinal` | `UInt32` | Parameter order. |
| `name_idx` | `UInt32?` | Parameter name string index; `NULL` for anonymous parameters. |

### `debug_positions`

Source position mappings produced by the debug state machine.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `method_idx` | `UInt32` | Method index. |
| `debug_info_off` | `UInt32` | Owning `debug_info_item` offset. |
| `ordinal` | `UInt32` | Position record order. |
| `address` | `UInt32` | Instruction address, in code units. |
| `line` | `Int32` | Source line number. |
| `source_file_idx` | `UInt32?` | Current source file string index. |
| `prologue_end` | `Boolean` | Whether this position carries the prologue end state. |
| `epilogue_begin` | `Boolean` | Whether this position carries the epilogue begin state. |

### `debug_locals`

Local variable events from the debug state machine.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `method_idx` | `UInt32` | Method index. |
| `debug_info_off` | `UInt32` | Owning `debug_info_item` offset. |
| `ordinal` | `UInt32` | Local event order. |
| `address` | `UInt32` | Instruction address where the event occurs, in code units. |
| `event` | `Utf8` | Local event type, e.g. start, end, restart. |
| `register_num` | `UInt32` | Register number holding the local variable. |
| `name_idx` | `UInt32?` | Local name string index. |
| `type_idx` | `UInt32?` | Local type index. |
| `signature_idx` | `UInt32?` | Local generic signature string index. |

### `debug_opcodes`

Exposes the debug state machine bytecode one opcode at a time, along with the state after executing each opcode.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `method_idx` | `UInt32` | Method index. |
| `debug_info_off` | `UInt32` | Owning `debug_info_item` offset. |
| `ordinal` | `UInt32` | Debug opcode order. |
| `opcode_off` | `UInt32` | Debug opcode start offset. |
| `opcode_end_off` | `UInt32` | Debug opcode end offset. |
| `opcode` | `UInt32` | Raw debug opcode value. |
| `address` | `UInt32` | Instruction address in the state machine after execution. |
| `line` | `Int32` | Source line number in the state machine after execution. |
| `address_diff` | `UInt32?` | Address increment introduced by this opcode. |
| `line_diff` | `Int32?` | Line increment introduced by this opcode. |
| `register_num` | `UInt32?` | Register number involved in this opcode. |
| `name_idx` | `UInt32?` | Name string index involved in this opcode. |
| `type_idx` | `UInt32?` | Type index involved in this opcode. |
| `signature_idx` | `UInt32?` | Signature string index involved in this opcode. |
| `source_file_idx` | `UInt32?` | Source file string index set by this opcode. |
| `emits_position` | `Boolean` | Whether this opcode emits a source position record. |
| `emits_local` | `Boolean` | Whether this opcode emits a local variable event. |

## Annotation structure

### `annotation_directories`

Summary of a class annotation directory.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `class_idx` | `UInt32` | Declaring class type index. |
| `annotations_off` | `UInt32` | Annotation directory start offset. |
| `class_annotations_off` | `UInt32?` | Offset of the class's own annotation set. |
| `fields_size` | `UInt32` | Number of field annotation entries. |
| `methods_size` | `UInt32` | Number of method annotation entries. |
| `parameters_size` | `UInt32` | Number of parameter annotation entries. |

### `annotation_directory_entries`

Unified expansion of the field, method, and parameter entries in an annotation directory.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `class_idx` | `UInt32` | Declaring class type index. |
| `annotations_off` | `UInt32` | Annotation directory start offset. |
| `entry_kind` | `Utf8` | Entry type, usually `field`, `method`, or `parameter`. |
| `entry_idx` | `UInt32` | Matching field id or method id index. |
| `annotation_set_off` | `UInt32?` | Field/method annotation set offset. |
| `annotation_set_ref_list_off` | `UInt32?` | Parameter annotation set ref list offset. |

### `annotation_sets`

Summary of a raw `annotation_set_item`.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `annotation_set_off` | `UInt32` | Annotation set start offset. |
| `size` | `UInt32` | Number of annotations in the annotation set. |

### `annotation_set_entries`

Splits an annotation set into per-annotation-reference rows.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `annotation_set_off` | `UInt32` | Owning annotation set offset. |
| `ordinal` | `UInt32` | Order of the annotation in the set. |
| `annotation_off` | `UInt32` | Annotation item offset. |

### `annotation_set_ref_lists`

Summary of the `annotation_set_ref_list` used by parameter annotations.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `annotation_set_ref_list_off` | `UInt32` | Annotation set ref list start offset. |
| `size` | `UInt32` | Number of parameter positions in the ref list. |

### `annotation_set_refs`

Splits a parameter annotation ref list into per-parameter-position rows.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `annotation_set_ref_list_off` | `UInt32` | Owning annotation set ref list offset. |
| `ordinal` | `UInt32` | Parameter position order. |
| `annotation_set_off` | `UInt32?` | Annotation set offset for this parameter position; `NULL` when there is no annotation. |

## Bytecode references and summaries

### `method_refs`

A low-level sparse reference table over method bytecode. Each row is one instruction in some method that carries a dex-index reference. It keeps the reference kind and the raw index, and does not resolve the target into a string, field, or method descriptor. For ordinary feature queries prefer the higher-level semantic views (`method_strings` for string kind, `method_calls` for method kind, `method_field_accesses` for field kind, `method_used_types` for type kind).

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `class_idx` | `UInt32` | Declaring class type index within the DEX. |
| `method_idx` | `UInt32` | Index of the calling method. |
| `index_kind` | `Dictionary(Int8, Utf8)` | Reference index type, e.g. `string`, `type`, `field`, `method`, `proto`. |
| `index` | `UInt32` | Raw dex index referenced by the instruction. |
| `using_type` | `Utf8?` | `get` for a field read, `put` for a field write; otherwise `NULL`. |

### `method_numbers`

A low-level per-instruction table of the immediate numeric constants loaded in method bytecode — the raw backing for the `method_using_numbers` view. Each row is one const-loading instruction; unlike `method_refs` the value is intrinsic, not a dex-index reference. For feature queries prefer the `method_using_numbers` view, which resolves the using method's descriptor.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | Owning dex file id. |
| `class_idx` | `UInt32` | Declaring class type index within the DEX. |
| `method_idx` | `UInt32` | Index of the using method. |
| `opcode` | `UInt32` | Opcode value of the const instruction. |
| `number_type` | `Dictionary(Int8, Utf8)` | Numeric kind, e.g. `byte`, `short`, `int`, `long`, `float`, `double`. |
| `long_value` | `Int64` | Integer value (sign-extended), or the raw bit pattern for `float`/`double`. |
| `double_value` | `Float64?` | Floating value; `NULL` for `byte`/`short`. |

### `method_opcodes`

Per-method opcode summaries, one row per `method_ids` row, keyed by `(file_id, method_idx)`, backing the opcode columns of `methods`. Rows require opcode data to have been prepared. Both opcode columns are `NULL` for a method this dex only references, and `0` / `''` for a declared method without a code item.

| Column | Type | Meaning |
| --- | --- | --- |
| `file_id` | `UInt32` | DexSQL-assigned dex file id. |
| `method_idx` | `UInt32` | Method id index (`method_ids.method_idx`). |
| `opcode_count` | `UInt32?` | Number of decoded Dalvik instructions; `NULL` for a reference-only method. |
| `opcode_hex` | `Utf8View?` | Compact hexadecimal string of the opcode sequence; `NULL` for a reference-only method. |

---

Copyright (c) 2026 LSPosed. Documentation licensed under [MIT](dexsql://license.md).
