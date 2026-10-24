//! Canonical table metadata shared by the CLI, SQL engine, and MCP server.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnMeta {
    pub name: &'static str,
    pub sql_type: &'static str,
    pub nullable: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableMeta {
    pub name: &'static str,
    pub columns: &'static [ColumnMeta],
}

const TABLE_DEX_FILES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "string_pool_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "source_path",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "entry_name",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "byte_len",
        sql_type: "UInt64",
        nullable: false,
    },
    ColumnMeta {
        name: "dex_version",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "checksum",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "signature_hex",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "file_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "header_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "endian_tag",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "link_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "link_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "map_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "string_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "string_ids_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_ids_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "proto_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "proto_ids_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "field_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "field_ids_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_ids_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_defs_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "data_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "data_off",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_MAP_ITEMS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_code",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "offset",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_ID_ITEMS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "item_type_code",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "item_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "item_end_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "data_off",
        sql_type: "UInt32",
        nullable: true,
    },
];
const TABLE_STRINGS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "string_pool_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "string_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "value",
        sql_type: "Utf8View",
        nullable: false,
    },
];
const TABLE_TYPE_IDS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "descriptor_idx",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_TYPES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "java_name",
        sql_type: "Utf8",
        nullable: false,
    },
];
const TABLE_TYPE_LISTS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_list_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_list_end_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "size",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_TYPE_LIST_ENTRIES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_list_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_PROTO_IDS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "proto_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "shorty_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "return_type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "parameters_off",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_PROTOS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "proto_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "shorty_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "shorty",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "return_type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "return_descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "parameters_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "param_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "param_descriptors",
        sql_type: "Utf8",
        nullable: false,
    },
];
const TABLE_PROTO_PARAMS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "proto_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
];
const TABLE_FIELD_IDS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "field_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "name_idx",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_FIELDS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "field_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "name",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
];
const TABLE_METHOD_IDS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "proto_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "name_idx",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_METHOD_OPCODES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "opcode_count",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "opcode_hex",
        sql_type: "Utf8View",
        nullable: true,
    },
];
const TABLE_CLASS_DATA_METHODS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "access_flags",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "kind",
        sql_type: "Utf8",
        nullable: true,
    },
];
const TABLE_METHODS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_descriptor",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "proto_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "name",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "descriptor",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "return_descriptor",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "param_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "param_descriptors",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "access_flags",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "opcode_count",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "opcode_hex",
        sql_type: "Utf8View",
        nullable: true,
    },
    ColumnMeta {
        name: "method_kind",
        sql_type: "Utf8",
        nullable: true,
    },
];
const TABLE_METHOD_HANDLES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_handle_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_handle_type",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "member_idx",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_CALL_SITES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "call_site_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "call_site_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "value_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_handle_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "method_name_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "proto_idx",
        sql_type: "UInt32",
        nullable: true,
    },
];
const TABLE_CALL_SITE_ARGS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "call_site_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "call_site_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "value_kind",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "value_index",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "value_i64",
        sql_type: "Int64",
        nullable: true,
    },
    ColumnMeta {
        name: "value_f64",
        sql_type: "Float64",
        nullable: true,
    },
];
const TABLE_ENCODED_ARRAYS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "encoded_array_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "encoded_array_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "encoded_array_end_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "value_count",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_ENCODED_ARRAY_VALUES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "encoded_array_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "depth",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "name_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "value_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "value_end_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "value_kind",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "value_index",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "value_i64",
        sql_type: "Int64",
        nullable: true,
    },
    ColumnMeta {
        name: "value_f64",
        sql_type: "Float64",
        nullable: true,
    },
];
const TABLE_ENCODED_ARRAY_OWNERS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "encoded_array_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "owner_kind",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "owner_idx",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_CLASS_DEFS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_def_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "access_flags",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "superclass_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "interfaces_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "source_file_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "annotations_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_data_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "static_values_off",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_CLASSES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_def_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "access_flags",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "superclass_descriptor",
        sql_type: "Utf8",
        nullable: true,
    },
    ColumnMeta {
        name: "interface_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "field_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "source_file",
        sql_type: "Utf8",
        nullable: true,
    },
];
const TABLE_CLASS_INTERFACES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "interface_type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "interface_descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
];
const TABLE_CLASS_DATA_ITEMS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_data_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_data_end_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "static_fields_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "instance_fields_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "direct_methods_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "virtual_methods_size",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_CLASS_FIELDS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "field_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "field_name",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "field_descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "kind",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "access_flags",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_CLASS_STATIC_VALUES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "static_values_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "field_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "value_kind",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "value_index",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "value_i64",
        sql_type: "Int64",
        nullable: true,
    },
    ColumnMeta {
        name: "value_f64",
        sql_type: "Float64",
        nullable: true,
    },
];
const TABLE_CLASS_METHODS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_name",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "method_descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "kind",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "access_flags",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_HIDDENAPI_FLAGS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "member_kind",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "member_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "flag",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_CODE_ITEMS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "code_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "registers_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ins_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "outs_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "tries_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "debug_info_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "insns_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "insns_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "tries_off",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "handlers_off",
        sql_type: "UInt32",
        nullable: true,
    },
];
const TABLE_TRY_ITEMS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "try_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "start_addr",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "insn_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "handler_off",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_CATCH_HANDLERS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "handler_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "handler_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "addr",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "is_catch_all",
        sql_type: "Boolean",
        nullable: false,
    },
];
const TABLE_DEBUG_INFO: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "debug_info_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "line_start",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "parameters_size",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_DEBUG_PARAMETERS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "debug_info_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "name_idx",
        sql_type: "UInt32",
        nullable: true,
    },
];
const TABLE_DEBUG_POSITIONS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "debug_info_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "address",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "line",
        sql_type: "Int32",
        nullable: false,
    },
    ColumnMeta {
        name: "source_file_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "prologue_end",
        sql_type: "Boolean",
        nullable: false,
    },
    ColumnMeta {
        name: "epilogue_begin",
        sql_type: "Boolean",
        nullable: false,
    },
];
const TABLE_DEBUG_LOCALS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "debug_info_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "address",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "event",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "register_num",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "name_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "type_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "signature_idx",
        sql_type: "UInt32",
        nullable: true,
    },
];
const TABLE_DEBUG_OPCODES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "debug_info_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "opcode_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "opcode_end_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "opcode",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "address",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "line",
        sql_type: "Int32",
        nullable: false,
    },
    ColumnMeta {
        name: "address_diff",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "line_diff",
        sql_type: "Int32",
        nullable: true,
    },
    ColumnMeta {
        name: "register_num",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "name_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "type_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "signature_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "source_file_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "emits_position",
        sql_type: "Boolean",
        nullable: false,
    },
    ColumnMeta {
        name: "emits_local",
        sql_type: "Boolean",
        nullable: false,
    },
];
const TABLE_ANNOTATION_DIRECTORIES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotations_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_annotations_off",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "fields_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "methods_size",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "parameters_size",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_ANNOTATION_DIRECTORY_ENTRIES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotations_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "entry_kind",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "entry_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_set_off",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "annotation_set_ref_list_off",
        sql_type: "UInt32",
        nullable: true,
    },
];
const TABLE_ANNOTATION_SETS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_set_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "size",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_ANNOTATION_SET_ENTRIES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_set_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_off",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_ANNOTATION_SET_REF_LISTS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_set_ref_list_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "size",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_ANNOTATION_SET_REFS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_set_ref_list_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_set_off",
        sql_type: "UInt32",
        nullable: true,
    },
];
const TABLE_ANNOTATIONS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "visibility",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "element_count",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_ANNOTATION_ELEMENTS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "depth",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "name_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "value_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "value_end_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "value_kind",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "value_index",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "value_i64",
        sql_type: "Int64",
        nullable: true,
    },
    ColumnMeta {
        name: "value_f64",
        sql_type: "Float64",
        nullable: true,
    },
];
const TABLE_METHOD_REFS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "index_kind",
        sql_type: "Dictionary(Int8, Utf8)",
        nullable: false,
    },
    ColumnMeta {
        name: "index",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "using_type",
        sql_type: "Utf8",
        nullable: true,
    },
];
const TABLE_METHOD_NUMBERS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "opcode",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "number_type",
        sql_type: "Dictionary(Int8, Utf8)",
        nullable: false,
    },
    ColumnMeta {
        name: "long_value",
        sql_type: "Int64",
        nullable: false,
    },
    ColumnMeta {
        name: "double_value",
        sql_type: "Float64",
        nullable: true,
    },
];
const TABLE_METHOD_USING_NUMBERS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "method",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "method_class",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "method_name",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "number_type",
        sql_type: "Dictionary(Int8, Utf8)",
        nullable: false,
    },
    ColumnMeta {
        name: "long_value",
        sql_type: "Int64",
        nullable: false,
    },
    ColumnMeta {
        name: "double_value",
        sql_type: "Float64",
        nullable: true,
    },
    ColumnMeta {
        name: "opcode",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_METHOD_STRINGS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "method",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "method_class",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "method_name",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "value",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "string_idx",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_METHOD_CALLS: &[ColumnMeta] = &[
    ColumnMeta {
        name: "method",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "method_class",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "method_name",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "callee",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "callee_class",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "callee_name",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "callee_method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_METHOD_FIELD_ACCESSES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "method",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "method_class",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "method_name",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "field",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "field_class",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "field_name",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "field_type",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "using_type",
        sql_type: "Utf8",
        nullable: true,
    },
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "field_idx",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_METHOD_USED_TYPES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "method",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "method_class",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "method_name",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "type_descriptor",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "type_name",
        sql_type: "Utf8View",
        nullable: false,
    },
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "method_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
];
const TABLE_ANNOTATION_VALUES: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "owner_kind",
        sql_type: "Dynamic",
        nullable: false,
    },
    ColumnMeta {
        name: "owner_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "owner_descriptor",
        sql_type: "Utf8",
        nullable: true,
    },
    ColumnMeta {
        name: "parameter_idx",
        sql_type: "Dynamic",
        nullable: true,
    },
    ColumnMeta {
        name: "annotation_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_type_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_descriptor",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "depth",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "ordinal",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "name_idx",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "name",
        sql_type: "Utf8",
        nullable: true,
    },
    ColumnMeta {
        name: "value_kind",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "value_i64",
        sql_type: "Int64",
        nullable: true,
    },
    ColumnMeta {
        name: "value_f64",
        sql_type: "Float64",
        nullable: true,
    },
];
const TABLE_ANNOTATION_ELEMENTS_RESOLVED: &[ColumnMeta] = &[
    ColumnMeta {
        name: "file_id",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "class_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "owner_kind",
        sql_type: "Dynamic",
        nullable: false,
    },
    ColumnMeta {
        name: "owner_idx",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "owner",
        sql_type: "Utf8",
        nullable: true,
    },
    ColumnMeta {
        name: "parameter_idx",
        sql_type: "Dynamic",
        nullable: true,
    },
    ColumnMeta {
        name: "annotation",
        sql_type: "Utf8",
        nullable: false,
    },
    ColumnMeta {
        name: "visibility",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "element_count",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "annotation_off",
        sql_type: "UInt32",
        nullable: false,
    },
    ColumnMeta {
        name: "element_ordinal",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "element_name",
        sql_type: "Utf8",
        nullable: true,
    },
    ColumnMeta {
        name: "value_kind",
        sql_type: "Utf8",
        nullable: true,
    },
    ColumnMeta {
        name: "value_index",
        sql_type: "UInt32",
        nullable: true,
    },
    ColumnMeta {
        name: "value_i64",
        sql_type: "Int64",
        nullable: true,
    },
    ColumnMeta {
        name: "value_f64",
        sql_type: "Float64",
        nullable: true,
    },
    ColumnMeta {
        name: "retention_policy",
        sql_type: "Dynamic",
        nullable: true,
    },
];

pub static TABLES: &[TableMeta] = &[
    TableMeta {
        name: "dex_files",
        columns: TABLE_DEX_FILES,
    },
    TableMeta {
        name: "map_items",
        columns: TABLE_MAP_ITEMS,
    },
    TableMeta {
        name: "id_items",
        columns: TABLE_ID_ITEMS,
    },
    TableMeta {
        name: "strings",
        columns: TABLE_STRINGS,
    },
    TableMeta {
        name: "type_ids",
        columns: TABLE_TYPE_IDS,
    },
    TableMeta {
        name: "types",
        columns: TABLE_TYPES,
    },
    TableMeta {
        name: "type_lists",
        columns: TABLE_TYPE_LISTS,
    },
    TableMeta {
        name: "type_list_entries",
        columns: TABLE_TYPE_LIST_ENTRIES,
    },
    TableMeta {
        name: "proto_ids",
        columns: TABLE_PROTO_IDS,
    },
    TableMeta {
        name: "protos",
        columns: TABLE_PROTOS,
    },
    TableMeta {
        name: "proto_params",
        columns: TABLE_PROTO_PARAMS,
    },
    TableMeta {
        name: "field_ids",
        columns: TABLE_FIELD_IDS,
    },
    TableMeta {
        name: "fields",
        columns: TABLE_FIELDS,
    },
    TableMeta {
        name: "method_ids",
        columns: TABLE_METHOD_IDS,
    },
    TableMeta {
        name: "method_opcodes",
        columns: TABLE_METHOD_OPCODES,
    },
    TableMeta {
        name: "class_data_methods",
        columns: TABLE_CLASS_DATA_METHODS,
    },
    TableMeta {
        name: "methods",
        columns: TABLE_METHODS,
    },
    TableMeta {
        name: "method_handles",
        columns: TABLE_METHOD_HANDLES,
    },
    TableMeta {
        name: "call_sites",
        columns: TABLE_CALL_SITES,
    },
    TableMeta {
        name: "call_site_args",
        columns: TABLE_CALL_SITE_ARGS,
    },
    TableMeta {
        name: "encoded_arrays",
        columns: TABLE_ENCODED_ARRAYS,
    },
    TableMeta {
        name: "encoded_array_values",
        columns: TABLE_ENCODED_ARRAY_VALUES,
    },
    TableMeta {
        name: "encoded_array_owners",
        columns: TABLE_ENCODED_ARRAY_OWNERS,
    },
    TableMeta {
        name: "class_defs",
        columns: TABLE_CLASS_DEFS,
    },
    TableMeta {
        name: "classes",
        columns: TABLE_CLASSES,
    },
    TableMeta {
        name: "class_interfaces",
        columns: TABLE_CLASS_INTERFACES,
    },
    TableMeta {
        name: "class_data_items",
        columns: TABLE_CLASS_DATA_ITEMS,
    },
    TableMeta {
        name: "class_fields",
        columns: TABLE_CLASS_FIELDS,
    },
    TableMeta {
        name: "class_static_values",
        columns: TABLE_CLASS_STATIC_VALUES,
    },
    TableMeta {
        name: "class_methods",
        columns: TABLE_CLASS_METHODS,
    },
    TableMeta {
        name: "hiddenapi_flags",
        columns: TABLE_HIDDENAPI_FLAGS,
    },
    TableMeta {
        name: "code_items",
        columns: TABLE_CODE_ITEMS,
    },
    TableMeta {
        name: "try_items",
        columns: TABLE_TRY_ITEMS,
    },
    TableMeta {
        name: "catch_handlers",
        columns: TABLE_CATCH_HANDLERS,
    },
    TableMeta {
        name: "debug_info",
        columns: TABLE_DEBUG_INFO,
    },
    TableMeta {
        name: "debug_parameters",
        columns: TABLE_DEBUG_PARAMETERS,
    },
    TableMeta {
        name: "debug_positions",
        columns: TABLE_DEBUG_POSITIONS,
    },
    TableMeta {
        name: "debug_locals",
        columns: TABLE_DEBUG_LOCALS,
    },
    TableMeta {
        name: "debug_opcodes",
        columns: TABLE_DEBUG_OPCODES,
    },
    TableMeta {
        name: "annotation_directories",
        columns: TABLE_ANNOTATION_DIRECTORIES,
    },
    TableMeta {
        name: "annotation_directory_entries",
        columns: TABLE_ANNOTATION_DIRECTORY_ENTRIES,
    },
    TableMeta {
        name: "annotation_sets",
        columns: TABLE_ANNOTATION_SETS,
    },
    TableMeta {
        name: "annotation_set_entries",
        columns: TABLE_ANNOTATION_SET_ENTRIES,
    },
    TableMeta {
        name: "annotation_set_ref_lists",
        columns: TABLE_ANNOTATION_SET_REF_LISTS,
    },
    TableMeta {
        name: "annotation_set_refs",
        columns: TABLE_ANNOTATION_SET_REFS,
    },
    TableMeta {
        name: "annotations",
        columns: TABLE_ANNOTATIONS,
    },
    TableMeta {
        name: "annotation_elements",
        columns: TABLE_ANNOTATION_ELEMENTS,
    },
    TableMeta {
        name: "method_refs",
        columns: TABLE_METHOD_REFS,
    },
    TableMeta {
        name: "method_numbers",
        columns: TABLE_METHOD_NUMBERS,
    },
    TableMeta {
        name: "method_using_numbers",
        columns: TABLE_METHOD_USING_NUMBERS,
    },
    TableMeta {
        name: "method_strings",
        columns: TABLE_METHOD_STRINGS,
    },
    TableMeta {
        name: "method_calls",
        columns: TABLE_METHOD_CALLS,
    },
    TableMeta {
        name: "method_field_accesses",
        columns: TABLE_METHOD_FIELD_ACCESSES,
    },
    TableMeta {
        name: "method_used_types",
        columns: TABLE_METHOD_USED_TYPES,
    },
    TableMeta {
        name: "annotation_values",
        columns: TABLE_ANNOTATION_VALUES,
    },
    TableMeta {
        name: "annotation_elements_resolved",
        columns: TABLE_ANNOTATION_ELEMENTS_RESOLVED,
    },
];

/// Render the fixed schema in the CLI's stable human-readable format.
pub fn render_tables() -> String {
    let mut output = String::new();
    for table in TABLES {
        output.push_str(table.name);
        output.push('\n');
        for column in table.columns {
            // Keep the type column at byte 27 for normal names, while long
            // names naturally expand beyond the padding width.
            output.push_str("  ");
            output.push_str(&format!("{:<24} ", column.name));
            output.push_str(column.sql_type);
            if column.nullable {
                output.push('?');
            }
            output.push('\n');
        }
    }
    output
}
