//! Stable JSON view of the dataset metadata that WeKit reads through DexKit's
//! `*Data` API.
//!
//! [`Engine::metadata`](crate::Engine::metadata) resolves one class, method, or
//! field descriptor through the indexed lookups in `dexsql_cache::metadata` and
//! renders the JSON document documented below. The format mirrors DexKit's
//! Kotlin `*Data` model so the WeKit JNI bridge and the Kotlin replacement layer
//! can be validated against the Phase 0 DexKit snapshot without further
//! interpretation.
//!
//! # Document shapes
//!
//! Every successful document starts with a `kind` discriminator.
//!
//! ## `kind = "class"`
//!
//! | key | type | meaning |
//! | --- | --- | --- |
//! | `descriptor` | string | `Lpkg/Class;` |
//! | `name` | string | dotted Java name |
//! | `simple_name` | string | DexKit `simpleName` (after the last `.`) |
//! | `source_file` | string | raw DEX source file string, `""` when absent |
//! | `access_flags` | number | raw DEX class-def access flags |
//! | `modifiers` | number | Java modifier view (`access_flags & 0xffff`) |
//! | `is_array` | bool | always false (the API accepts class descriptors) |
//! | `super_class` | object or null | `{"descriptor", "name"}` of the superclass |
//! | `super_class_name` | string or null | extra convenience copy of the dotted name |
//! | `interfaces` | [object] | `{"descriptor", "name"}` in DEX declaration order |
//! | `methods` | [method ref] | declared methods, ordered by method id |
//! | `annotations` | [annotation] | class-level annotations in DEX order |
//! | `fields` | [field ref] | declared fields, ordered by field id |
//!
//! ## method refs (nested in classes and returned for `kind = "method"`)
//!
//! `descriptor`, `name`, `declared_class_name` (dotted), `access_flags`,
//! `modifiers`, `defined`, `method_sign`, `return_type_name`,
//! `param_type_names`, `param_count`, `is_constructor`,
//! `is_static_initializer`, `is_method`.
//!
//! Extra convenience keys: `declared_class` (descriptor), `return_type`
//! (descriptor) and `param_types` (descriptors).
//!
//! `method_sign` is DexKit's `MethodData.methodSign`: the proto sign
//! `(<param descriptors>)<return descriptor>` without the method name, e.g.
//! `()V` or `(Ljava/lang/String;)Ldo0/q;`.
//!
//! ## field refs
//!
//! `descriptor`, `name`, `declared_class_name` (dotted), `access_flags`,
//! `modifiers`, `defined`, `type_name`. Extra convenience keys: `declared_class`
//! and `type` (descriptors).
//!
//! ## Resolving the `defined` flag and access flags
//!
//! A top-level query locates the defining file across the whole dataset
//! (delegate descriptors name classes/members defined by the host APK).
//!
//! Nested references (`invokes`, `using_fields` and the cross-DEX part of
//! `callers`) reproduce DexKit's per-file cross-DEX identity binding
//! (DexItem::PutCrossRef): a reference that the referencing DEX defines uses
//! its class-data flags; otherwise local method/field ids are matched against
//! the defining DEX's sorted member ids with DexKit's greedy two-pointer walk.
//! References the walk binds render the defining DEX's flags; unbound
//! references render `access_flags = 0`, `modifiers = 0` and
//! `defined = false`. The walk is reproduced exactly (including its skipping
//! behaviour) because that is what the validated Phase 0 DexKit snapshot
//! records.
//!
//! ## Relation fields on a top-level method
//!
//! | key | type |
//! | --- | --- |
//! | `invokes` | [method ref], instruction order, duplicates preserved |
//! | `using_strings` | [string], instruction order, duplicates preserved |
//! | `using_numbers` | [{`kind`: "long" or "double", `value`: string}] |
//! | `using_fields` | [{`field`: field ref, `using_type`: "read" or "write"}] |
//!
//! ## Opcode fields on a top-level method
//!
//! | key | type | meaning |
//! | --- | --- | --- |
//! | `opcode_count` | number or null | instruction count when the method has a code item |
//! | `opcodes` | [string] | Dalvik mnemonics in code order (payload pseudo-instructions skipped) |
//!
//! Opcode data is additive and mirrors the SQL `method_opcodes` relation
//! (`opcode_count` / `opcode_hex`). It needs a load with
//! `EngineOptions::full_code_items = true`; loads that keep only parsed
//! metadata render `opcode_count = null` and `opcodes = []` instead of
//! erroring. Class member refs stay shallow and do not carry opcode data.
//!
//! ## Annotation fields
//!
//! Class and top-level method documents gain an `annotations` array in DEX
//! annotation-set order:
//!
//! ```text
//! [{"type": "Ldalvik/annotation/Signature;",
//!   "type_name": "dalvik.annotation.Signature",
//!   "visibility": "system",
//!   "elements": [{"name": "value", "value": ["..."]}]}]
//! ```
//!
//! `visibility` is DexKit's `AnnotationVisibilityType` name: `build`,
//! `runtime`, or `system` (unknown visibility bytes render `unknown`).
//! Element values mirror the DEX encoded-value encoding: string arrays become
//! JSON string arrays (e.g. `@dalvik/annotation/Signature`), integers /
//! booleans / floats are JSON scalars, type/field/method/enum values are
//! descriptor strings, and nested annotations are objects. Parameter
//! annotations are not exposed yet.
//!
//! Annotation bytes and opcode data both need a load with
//! `EngineOptions::full_code_items = true`; metadata-only loads render
//! `annotations = []` instead of erroring.
//!
//! Caller lists are not part of the default document because some host methods
//! have tens of thousands of callers; use
//! [`Engine::metadata_callers`](crate::Engine::metadata_callers) when a
//! consumer needs them (Phase 4).
//!
//! `using_numbers` collapses DexSQL's six SQL literal labels into the two
//! DexKit literal families: `float`/`double` literals use `kind = "double"`
//! (the string is the floating value), and `byte`/`short`/`int`/`long`
//! literals use `kind = "long"` (the string is the signed integer value).
//!
//! # Errors and missing data
//!
//! * A well-formed descriptor that no input DEX matches yields JSON `null`.
//! * A malformed descriptor yields `Err(String)`.
//! * When the dataset was loaded without relation indexes
//!   (`IndexNeeds::method_calls = false` and the other needs), `invokes`,
//!   `callers`, `using_strings`, `using_numbers`, and `using_fields` are empty
//!   arrays rather than errors.

use dexsql_cache::metadata::{
    class_descriptor_to_name, class_modifiers, descriptor_to_type_name, field_access_is_read,
    field_modifiers, method_modifiers, simple_type_name, ClassLocation, CrossRefCache,
    FieldLocation, MetaQuery, MethodDescriptorParts, MethodLocation,
};
use dexsql_cache::{Dataset, DexFile, MethodNumberRef};

use crate::annotations;
use crate::opcodes;
use serde_json::{Map, Value};

/// Render the metadata document for one query.
pub(crate) fn metadata_json(
    dataset: &Dataset,
    cross: &CrossRefCache,
    query: &MetaQuery,
) -> Result<Value, String> {
    match query {
        MetaQuery::Class { descriptor } => match dataset.locate_class(descriptor)? {
            None => Ok(Value::Null),
            Some(location) => class_json(dataset, cross, &location),
        },
        MetaQuery::Method { descriptor } => match dataset.locate_method(descriptor)? {
            None => Ok(Value::Null),
            Some(location) => method_json(dataset, cross, &location),
        },
        MetaQuery::Field { descriptor } => match dataset.locate_field(descriptor)? {
            None => Ok(Value::Null),
            Some(location) => field_json(dataset, cross, &location),
        },
    }
}

fn class_json(
    dataset: &Dataset,
    cross: &CrossRefCache,
    location: &ClassLocation<'_>,
) -> Result<Value, String> {
    let file = location.file;
    let class = location.class;
    let descriptor = file.type_descriptor(class.class_idx).to_owned();
    let name = class_descriptor_to_name(&descriptor)?;
    let simple_name = simple_type_name(&name).to_owned();
    let source_file = class
        .source_file_idx
        .map(|index| file.string(index))
        .unwrap_or("")
        .to_owned();
    let super_class = class
        .superclass_idx
        .map(|index| file.type_descriptor(index).to_owned());
    let super_class_name = super_class
        .as_deref()
        .map(class_descriptor_to_name)
        .transpose()?;
    let super_class_object = match (&super_class, &super_class_name) {
        (Some(descriptor), Some(name)) => Value::Object(Map::from_iter([
            ("descriptor".to_owned(), Value::from(descriptor.clone())),
            ("name".to_owned(), Value::from(name.clone())),
        ])),
        _ => Value::Null,
    };
    let interfaces = class
        .interfaces
        .iter()
        .map(|&index| {
            let descriptor = file.type_descriptor(index as u32).to_owned();
            let name = class_descriptor_to_name(&descriptor)?;
            Ok(Value::Object(Map::from_iter([
                ("descriptor".to_owned(), Value::from(descriptor)),
                ("name".to_owned(), Value::from(name)),
            ])))
        })
        .collect::<Result<Vec<_>, String>>()?;
    // DexKit exposes declared members in DEX id order (class_method_ids range
    // and field-id range), not class_data order.
    let mut method_indices = class
        .methods
        .iter()
        .map(|method| method.method_idx)
        .collect::<Vec<_>>();
    method_indices.sort_unstable();
    let mut field_indices = class
        .fields
        .iter()
        .map(|field| field.field_idx)
        .collect::<Vec<_>>();
    field_indices.sort_unstable();
    let methods = method_indices
        .into_iter()
        .map(|method_idx| method_ref_json(dataset, cross, file, method_idx))
        .collect::<Result<Vec<_>, _>>()?;
    let fields = field_indices
        .into_iter()
        .map(|field_idx| field_ref_json(dataset, cross, file, field_idx))
        .collect::<Result<Vec<_>, _>>()?;

    let mut document = Map::new();
    document.insert("kind".into(), Value::from("class"));
    document.insert("descriptor".into(), Value::from(descriptor));
    document.insert("name".into(), Value::from(name));
    document.insert("simple_name".into(), Value::from(simple_name));
    document.insert("source_file".into(), Value::from(source_file));
    document.insert(
        "access_flags".into(),
        Value::from(class.access_flags as u64),
    );
    document.insert(
        "modifiers".into(),
        Value::from(class_modifiers(class.access_flags)),
    );
    document.insert("is_array".into(), Value::Bool(false));
    document.insert("super_class".into(), super_class_object);
    document.insert(
        "super_class_name".into(),
        super_class_name.map(Value::from).unwrap_or(Value::Null),
    );
    document.insert("interfaces".into(), Value::Array(interfaces));
    document.insert("methods".into(), Value::Array(methods));
    document.insert("fields".into(), Value::Array(fields));
    document.insert(
        "annotations".into(),
        annotations::class_annotations(file, class)?,
    );
    Ok(Value::Object(document))
}

fn method_json(
    dataset: &Dataset,
    cross: &CrossRefCache,
    location: &MethodLocation<'_>,
) -> Result<Value, String> {
    let file = location.file;
    let method_idx = location.method_idx;
    let mut document = method_ref_object(dataset, cross, file, method_idx)?;
    document.insert("kind".into(), Value::from("method"));

    let invokes = file
        .invokes_for_method(method_idx)
        .iter()
        .map(|row| method_ref_json(dataset, cross, file, row.callee_method_idx))
        .collect::<Result<Vec<_>, _>>()?;
    let using_strings = file
        .using_string_refs(method_idx)
        .iter()
        .map(|row| Value::from(file.string(row.string_idx)))
        .collect::<Vec<_>>();
    let using_numbers = file
        .using_number_refs(method_idx)
        .iter()
        .map(number_json)
        .collect::<Vec<_>>();
    let using_fields = file
        .using_field_refs(method_idx)
        .iter()
        .map(|row| {
            Ok(Value::Object(Map::from_iter([
                (
                    "field".to_owned(),
                    field_ref_json(dataset, cross, file, row.field_idx)?,
                ),
                (
                    "using_type".to_owned(),
                    Value::from(if field_access_is_read(row.opcode) {
                        "read"
                    } else {
                        "write"
                    }),
                ),
            ])))
        })
        .collect::<Result<Vec<_>, String>>()?;

    document.insert("invokes".into(), Value::Array(invokes));
    document.insert("using_strings".into(), Value::Array(using_strings));
    document.insert("using_numbers".into(), Value::Array(using_numbers));
    document.insert("using_fields".into(), Value::Array(using_fields));
    let (opcode_count, opcodes) = match opcodes::method_opcode_names(file, method_idx) {
        Some((count, names)) => (
            Value::from(count as u64),
            Value::Array(names.into_iter().map(Value::from).collect()),
        ),
        None => (Value::Null, Value::Array(Vec::new())),
    };
    document.insert("opcode_count".into(), opcode_count);
    document.insert("opcodes".into(), opcodes);
    document.insert(
        "annotations".into(),
        annotations::method_annotations(file, method_idx)?,
    );
    Ok(Value::Object(document))
}

fn field_json(
    dataset: &Dataset,
    cross: &CrossRefCache,
    location: &FieldLocation<'_>,
) -> Result<Value, String> {
    let mut document = field_ref_json(dataset, cross, location.file, location.field_idx)?;
    if let Value::Object(object) = &mut document {
        object.insert("kind".into(), Value::from("field"));
    }
    Ok(document)
}

fn callers_json(
    dataset: &Dataset,
    cross: &CrossRefCache,
    target_file: &DexFile,
    target_method_idx: u32,
    target_defined: bool,
) -> Result<Vec<Value>, String> {
    let parts = target_file
        .method_parts(target_method_idx)
        .ok_or_else(|| format!("method id {target_method_idx} is out of range"))?;
    let descriptor_parts = MethodDescriptorParts {
        class_descriptor: parts.class_descriptor,
        name: parts.name,
        param_descriptors: parts.param_descriptors.clone(),
        return_descriptor: parts.return_descriptor,
    };
    let target_file_index = dataset.file_index(target_file);
    // DexKit caller-list order: the defining DEX's own callers first, then
    // cross-DEX imports in the bridge's numeric multidex order. Inside one DEX,
    // edges follow class_def order, method id order, and instruction order.
    let mut file_order = dataset.dexkit_file_order();
    if let Some(index) = target_file_index {
        if let Some(position) = file_order.iter().position(|&file| file == index) {
            let local = file_order.remove(position);
            file_order.insert(0, local);
        }
    }
    let mut callers = Vec::new();
    for file_index in file_order {
        let file = &dataset.files[file_index];
        let Some(type_idx) = file.type_idx_for_descriptor(parts.class_descriptor) else {
            continue;
        };
        let Some(method_idx) = file.method_reference_for_type(type_idx, &descriptor_parts) else {
            continue;
        };
        // DexKit imports a caller edge into the defining method's caller list
        // only when the reference is bound by its cross-DEX identity walk
        // (same rule as nested invoke flags). Callers that reference an
        // undefined method stay local to their DEX.
        let include = if Some(file_index) == target_file_index {
            true
        } else if target_defined {
            cross
                .method_binding(dataset, file_index, method_idx)
                .and_then(|binding| {
                    binding
                        .origin_method(method_idx)
                        .map(|origin_idx| (binding.origin_file_index, origin_idx))
                })
                .is_some_and(|(origin_file, origin_idx)| {
                    Some(origin_file as usize) == target_file_index
                        && origin_idx == target_method_idx
                })
        } else {
            false
        };
        if !include {
            continue;
        }
        let mut caller_ids = file.callers_for_method(method_idx).collect::<Vec<_>>();
        caller_ids.sort_by_key(|&caller_idx| {
            let class_def = file
                .methods
                .get(caller_idx as usize)
                .and_then(|caller| file.class_for_type_idx(caller.class_idx as u32))
                .map(|class| class.class_def_idx)
                .unwrap_or(u32::MAX);
            (class_def, caller_idx)
        });
        for caller_idx in caller_ids {
            callers.push(method_ref_json(dataset, cross, file, caller_idx)?);
        }
    }
    Ok(callers)
}

/// Render the caller list for one method descriptor.
///
/// Callers are intentionally not part of the default metadata document: some
/// host methods have tens of thousands of callers, which makes the document
/// disproportionately large and slow, and WeKit resolution does not read it.
/// Phase 4 consumers (for example Monet evidence collection) can request the
/// list explicitly. The result is a JSON array of method refs in DexKit order
/// (defining DEX callers first, then cross-DEX imports in the bridge's numeric
/// multidex order); a missing method descriptor yields JSON null.
pub(crate) fn callers_json_for_descriptor(
    dataset: &Dataset,
    cross: &CrossRefCache,
    descriptor: &str,
) -> Result<Value, String> {
    dexsql_cache::metadata::parse_method_descriptor(descriptor)?;
    match dataset.locate_method(descriptor)? {
        None => Ok(Value::Null),
        Some(location) => {
            let callers = callers_json(
                dataset,
                cross,
                location.file,
                location.method_idx,
                location.defined,
            )?;
            Ok(Value::Array(callers))
        }
    }
}

/// Dotted Java name of a referenced declaring class.
///
/// Method ids may target an array type (for example the fixture method
/// `[I->clone()Ljava/lang/Object;` emitted for `array.clone()`). DexKit renders
/// such references instead of failing the document, using the array's Java
/// type name as the declared class name.
fn declared_class_type_name(descriptor: &str) -> Result<String, String> {
    if descriptor.starts_with('[') {
        descriptor_to_type_name(descriptor)
    } else {
        class_descriptor_to_name(descriptor)
    }
}

fn method_ref_json(
    dataset: &Dataset,
    cross: &CrossRefCache,
    file: &DexFile,
    method_idx: u32,
) -> Result<Value, String> {
    method_ref_object(dataset, cross, file, method_idx).map(Value::Object)
}

fn method_ref_object(
    dataset: &Dataset,
    cross: &CrossRefCache,
    file: &DexFile,
    method_idx: u32,
) -> Result<Map<String, Value>, String> {
    let parts = file
        .method_parts(method_idx)
        .ok_or_else(|| format!("method id {method_idx} is out of range"))?;
    let declared_class_name = declared_class_type_name(parts.class_descriptor)?;
    let return_type_name = descriptor_to_type_name(parts.return_descriptor)?;
    let param_type_names = parts
        .param_descriptors
        .iter()
        .map(|descriptor| descriptor_to_type_name(descriptor))
        .collect::<Result<Vec<_>, _>>()?;
    let (access_flags, defined) = method_ref_flags(dataset, cross, file, method_idx);
    let name = parts.name;
    let mut document = Map::new();
    document.insert("descriptor".into(), Value::from(parts.descriptor()));
    document.insert("name".into(), Value::from(name));
    document.insert("declared_class".into(), Value::from(parts.class_descriptor));
    document.insert(
        "declared_class_name".into(),
        Value::from(declared_class_name),
    );
    document.insert("access_flags".into(), Value::from(access_flags as u64));
    document.insert(
        "modifiers".into(),
        Value::from(method_modifiers(access_flags)),
    );
    document.insert("defined".into(), Value::Bool(defined));
    document.insert("return_type".into(), Value::from(parts.return_descriptor));
    document.insert("return_type_name".into(), Value::from(return_type_name));
    document.insert(
        "param_types".into(),
        Value::from(parts.param_descriptors.clone()),
    );
    document.insert("param_type_names".into(), Value::from(param_type_names));
    document.insert(
        "param_count".into(),
        Value::from(parts.param_descriptors.len() as u64),
    );
    document.insert("is_constructor".into(), Value::Bool(name == "<init>"));
    document.insert(
        "is_static_initializer".into(),
        Value::Bool(name == "<clinit>"),
    );
    document.insert(
        "is_method".into(),
        Value::Bool(!matches!(name, "<init>" | "<clinit>")),
    );
    document.insert("method_sign".into(), Value::from(parts.method_sign()));
    Ok(document)
}

fn field_ref_json(
    dataset: &Dataset,
    cross: &CrossRefCache,
    file: &DexFile,
    field_idx: u32,
) -> Result<Value, String> {
    let parts = file
        .field_parts(field_idx)
        .ok_or_else(|| format!("field id {field_idx} is out of range"))?;
    let declared_class_name = declared_class_type_name(parts.class_descriptor)?;
    let type_name = descriptor_to_type_name(parts.type_descriptor)?;
    let (access_flags, defined) = field_ref_flags(dataset, cross, file, field_idx);
    let mut document = Map::new();
    document.insert("descriptor".into(), Value::from(parts.descriptor()));
    document.insert("name".into(), Value::from(parts.name));
    document.insert("declared_class".into(), Value::from(parts.class_descriptor));
    document.insert(
        "declared_class_name".into(),
        Value::from(declared_class_name),
    );
    document.insert("access_flags".into(), Value::from(access_flags as u64));
    document.insert(
        "modifiers".into(),
        Value::from(field_modifiers(access_flags)),
    );
    document.insert("defined".into(), Value::Bool(defined));
    document.insert("type".into(), Value::from(parts.type_descriptor));
    document.insert("type_name".into(), Value::from(type_name));
    Ok(Value::Object(document))
}

/// DexKit-visible flags for a nested method reference.
///
/// The referencing file's own definition wins. Otherwise the cross-DEX
/// identity binding decides whether DexKit resolves the reference to its
/// defining DEX; unbound references render as external refs with zero flags.
fn method_ref_flags(
    dataset: &Dataset,
    cross: &CrossRefCache,
    file: &DexFile,
    method_idx: u32,
) -> (u32, bool) {
    if let Some(access_flags) = file.method_access_flags(method_idx) {
        return (access_flags, true);
    }
    let Some(file_index) = dataset.file_index(file) else {
        return (0, false);
    };
    let Some(binding) = cross.method_binding(dataset, file_index, method_idx) else {
        return (0, false);
    };
    let Some(origin_idx) = binding.origin_method(method_idx) else {
        return (0, false);
    };
    let origin_file = &dataset.files[binding.origin_file_index as usize];
    (
        origin_file.method_access_flags(origin_idx).unwrap_or(0),
        true,
    )
}

fn field_ref_flags(
    dataset: &Dataset,
    cross: &CrossRefCache,
    file: &DexFile,
    field_idx: u32,
) -> (u32, bool) {
    if let Some(access_flags) = file.defined_field_flags(field_idx) {
        return (access_flags, true);
    }
    let Some(file_index) = dataset.file_index(file) else {
        return (0, false);
    };
    let Some(binding) = cross.field_binding(dataset, file_index, field_idx) else {
        return (0, false);
    };
    let Some(origin_idx) = binding.origin_field(field_idx) else {
        return (0, false);
    };
    let origin_file = &dataset.files[binding.origin_file_index as usize];
    (
        origin_file.defined_field_flags(origin_idx).unwrap_or(0),
        true,
    )
}

fn number_json(reference: &MethodNumberRef) -> Value {
    let (kind, value) = match (reference.double_value, reference.opcode) {
        // DexSQL's SQL label calls const/high16 + const (0x14/0x15) float and
        // const-wide/high16 (0x19) double; every other literal is an integer.
        (Some(double), 0x14 | 0x15 | 0x19) => ("double", format_double(double)),
        _ => ("long", reference.long_value.to_string()),
    };
    Value::Object(Map::from_iter([
        ("kind".to_owned(), Value::from(kind)),
        ("value".to_owned(), Value::from(value)),
    ]))
}

fn format_double(value: f64) -> String {
    if value.is_finite() {
        let mut text = value.to_string();
        if !text.contains(['.', 'e', 'E']) {
            text.push_str(".0");
        }
        text
    } else {
        value.to_string()
    }
}
