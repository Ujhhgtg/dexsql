//! Newline-delimited JSON-RPC MCP server for DexSQL.
//!
//! The transport deliberately stays dependency-light: one JSON-RPC message per
//! line on stdin/stdout, with all expensive work isolated behind a bounded
//! admission gate.  The data model is the same `Dataset`/`decode` model used by
//! the CLI; this crate only adapts it to MCP's typed, paged result envelope.
// Keep the SQL relation executor shared with the CLI.  The MCP endpoint uses
// the same parser/scanners, so joins and every normalized DEX relation follow
// one implementation instead of diverging in a second handwritten subset.
mod query_engine;
mod resources;

use dexsql_cache::{decode, Dataset};
use dexsql_schema as schema;
use futures_util::StreamExt;
use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
    Implementation, ListResourcesResult, ListToolsResult, ReadResourceRequestParams,
    ReadResourceResponse, ReadResourceResult, Resource, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::cmp::Ordering as CompareOrdering;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use tokio_util::codec::{FramedRead, FramedWrite};
use zip::ZipArchive;

pub const TABLES: &[&str] = &[
    "dex_files",
    "map_items",
    "id_items",
    "strings",
    "type_ids",
    "types",
    "type_lists",
    "type_list_entries",
    "proto_ids",
    "protos",
    "proto_params",
    "field_ids",
    "fields",
    "method_ids",
    "method_opcodes",
    "class_data_methods",
    "methods",
    "method_handles",
    "call_sites",
    "call_site_args",
    "encoded_arrays",
    "encoded_array_values",
    "encoded_array_owners",
    "class_defs",
    "classes",
    "class_interfaces",
    "class_data_items",
    "class_fields",
    "class_static_values",
    "class_methods",
    "hiddenapi_flags",
    "code_items",
    "try_items",
    "catch_handlers",
    "debug_info",
    "debug_parameters",
    "debug_positions",
    "debug_locals",
    "debug_opcodes",
    "annotation_directories",
    "annotation_directory_entries",
    "annotation_sets",
    "annotation_set_entries",
    "annotation_set_ref_lists",
    "annotation_set_refs",
    "annotations",
    "annotation_elements",
    "method_refs",
    "method_numbers",
    "method_using_numbers",
    "method_strings",
    "method_calls",
    "method_field_accesses",
    "method_used_types",
    "annotation_values",
    "annotation_elements_resolved",
];

#[derive(Debug, Clone)]
pub struct Config {
    pub timeout_ms: u64,
    pub max_datasets: usize,
    pub max_pending: usize,
    pub max_input_bytes: u64,
    pub max_dex_bytes: u64,
    pub max_total_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_resource_bytes: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_ms: 60_000,
            max_datasets: 4,
            max_pending: 16,
            max_input_bytes: 1 << 30,
            max_dex_bytes: 1 << 30,
            max_total_input_bytes: 2 << 30,
            max_output_bytes: 128 << 10,
            max_resource_bytes: 64 << 20,
        }
    }
}
#[derive(Debug)]
struct Entry {
    paths: Vec<PathBuf>,
    dataset: Option<Dataset>,
    source_bytes: u64,
    dex_bytes: u64,
    archive_inputs: Vec<usize>,
    prepare_ms: f64,
    resource_cache: Option<CachedResourceTable>,
    archive_stamps: HashMap<usize, (u64, u128)>,
}
#[derive(Debug, Clone)]
struct CachedResourceTable {
    len: u64,
    modified_nanos: u128,
    rows: Vec<Value>,
}
#[derive(Debug, Default)]
struct State {
    next_id: u64,
    opening: usize,
    opening_bytes: u64,
    datasets: HashMap<String, Entry>,
    cancelled: HashMap<String, Arc<AtomicBool>>,
}
#[derive(Debug, Clone, Deserialize)]
struct Request {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

/// A semaphore for queued and running heavy operations.  Admission is
/// non-blocking: callers over the configured bound get a deterministic
/// `server_busy` response rather than an unbounded queue.
#[derive(Debug)]
struct Admission {
    state: Mutex<usize>,
    wake: Condvar,
    max: usize,
}
impl Admission {
    fn new(max: usize) -> Self {
        Self {
            state: Mutex::new(0),
            wake: Condvar::new(),
            max,
        }
    }
    fn try_acquire(&self) -> bool {
        let mut n = self.state.lock().expect("admission lock");
        if *n >= self.max || self.max == 0 {
            return false;
        }
        *n += 1;
        true
    }
    fn release(&self) {
        let mut n = self.state.lock().expect("admission lock");
        *n = n.saturating_sub(1);
        self.wake.notify_one();
    }
}
#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorObject>,
}
#[derive(Debug, Serialize)]
struct ErrorObject {
    code: i32,
    message: String,
}

/// Serve MCP requests from stdin/stdout through rmcp's Tokio stdio transport.
///
/// rmcp owns framing, lifecycle negotiation, request dispatch, and cancellation
/// propagation.  The existing synchronous dataset/query implementation is
/// isolated behind `spawn_blocking` in `RmcpHandler`, so expensive DEX work
/// cannot stall the transport reader or writer.
pub fn serve_stdio(config: Config) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(io::Error::other)?;
    runtime.block_on(async move {
        let handler = RmcpHandler::new(config);
        // The reference uses rmcp's sink/stream adapter around the JSON-line
        // codec.  Keeping the framed reader in a `take_while` stream preserves
        // rmcp's stdio shutdown semantics: malformed input ends the stream,
        // while valid requests continue to be dispatched concurrently.
        let reader = FramedRead::new(
            tokio::io::stdin(),
            rmcp::transport::async_rw::JsonRpcMessageCodec::<
                rmcp::model::ClientJsonRpcMessage,
            >::default(),
        );
        let stream = reader
            .take_while(|message| std::future::ready(message.is_ok()))
            .map(|message| message.expect("framed reader ended after an error"));
        let writer = FramedWrite::new(
            tokio::io::stdout(),
            rmcp::transport::async_rw::JsonRpcMessageCodec::<
                rmcp::model::ServerJsonRpcMessage,
            >::default(),
        );
        let transport = rmcp::transport::sink_stream::SinkStreamTransport::new(writer, stream);
        let service = handler.serve(transport).await.map_err(io::Error::other)?;
        service.waiting().await.map_err(io::Error::other)?;
        Ok(())
    })
}

fn write_response<W: Write>(out: &mut W, response: &Response) -> io::Result<()> {
    serde_json::to_writer(&mut *out, response).map_err(io::Error::other)?;
    out.write_all(b"\n")?;
    out.flush()
}

fn value_key(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn cancel_request(params: &Value, state: &Arc<Mutex<State>>) {
    let Some(id) = params.get("requestId").or_else(|| params.get("request_id")) else {
        return;
    };
    if let Ok(guard) = state.lock() {
        if let Some(token) = guard.cancelled.get(&value_key(id)) {
            token.store(true, Ordering::Relaxed);
        }
    }
}

fn run_request(
    req: Request,
    state: Arc<Mutex<State>>,
    cfg: Config,
    token: Arc<AtomicBool>,
) -> Option<Response> {
    let id = req.id.clone().unwrap_or(Value::Null);
    let params = req.params.clone();
    let started = Instant::now();
    // Dispatch in a child so a parser/decoder that is currently in a tight
    // scan cannot hold up the transport beyond the configured wall clock.
    let (tx, rx) = mpsc::channel();
    let state2 = Arc::clone(&state);
    let cfg2 = cfg.clone();
    std::thread::spawn(move || {
        let _ = tx.send(dispatch(req, &state2, &cfg2));
    });
    let deadline = Duration::from_millis(cfg.timeout_ms);
    let response = loop {
        if token.load(Ordering::Relaxed) {
            close_argument_dataset(&params, &state);
            // MCP cancellation is a notification, not a request failure.  The
            // reference rmcp server aborts the in-flight task and deliberately
            // emits no JSON-RPC response for the cancelled request.  Returning
            // `None` here preserves that wire-level contract while still
            // closing the affected dataset before the worker is released.
            break None;
        }
        let remaining = deadline.checked_sub(started.elapsed());
        let Some(remaining) = remaining else {
            close_argument_dataset(&params, &state);
            break Some(error_response(
                id.clone(),
                -32008,
                "timeout: operation exceeded timeout_ms; affected dataset was closed".into(),
            ));
        };
        match rx.recv_timeout(remaining.min(Duration::from_millis(25))) {
            Ok(response) => break response,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Some(error_response(
                    id.clone(),
                    -32603,
                    "internal operation failed".into(),
                ))
            }
        }
    };
    if !id.is_null() {
        if let Ok(mut guard) = state.lock() {
            guard.cancelled.remove(&value_key(&id));
        }
    }
    response
}

fn close_argument_dataset(params: &Value, state: &Arc<Mutex<State>>) {
    let Some(id) = params
        .get("arguments")
        .and_then(|args| args.get("dataset_id"))
        .and_then(Value::as_str)
        .or_else(|| params.get("dataset_id").and_then(Value::as_str))
    else {
        return;
    };
    if let Ok(mut guard) = state.lock() {
        guard.datasets.remove(id);
    }
}

fn try_close_argument_dataset(params: &Value, state: &Arc<Mutex<State>>) {
    let Some(id) = params
        .get("arguments")
        .and_then(|args| args.get("dataset_id"))
        .and_then(Value::as_str)
        .or_else(|| params.get("dataset_id").and_then(Value::as_str))
    else {
        return;
    };
    if let Ok(mut guard) = state.try_lock() {
        guard.datasets.remove(id);
    }
}

fn archive_stamp(path: &Path) -> (u64, u128) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return (0, 0);
    };
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos());
    (metadata.len(), modified)
}
fn error_response(id: Value, code: i32, message: String) -> Response {
    Response {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(ErrorObject { code, message }),
    }
}

fn json_type_label(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => format!("boolean `{value}`"),
        Value::Number(value) => {
            if value.is_i64() || value.is_u64() {
                format!("integer `{value}`")
            } else {
                format!("number `{value}`")
            }
        }
        Value::String(value) => format!("string `{value}`"),
        Value::Array(_) => "sequence".to_owned(),
        Value::Object(_) => "map".to_owned(),
    }
}

/// rmcp server adapter for the existing DexSQL tool implementation.
///
/// The query, decode, and archive code predates the rmcp integration and is
/// intentionally synchronous.  Keeping that implementation behind this small
/// adapter lets rmcp retain ownership of the protocol lifecycle while all
/// potentially expensive work runs on Tokio's blocking pool.
#[derive(Clone)]
struct RmcpHandler {
    state: Arc<Mutex<State>>,
    admission: Arc<Admission>,
    config: Config,
}

impl RmcpHandler {
    fn new(config: Config) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            admission: Arc::new(Admission::new(config.max_pending)),
            config,
        }
    }

    fn server_info() -> ServerInfo {
        let version = option_env!("DEXSQL_BUILD_COMMIT")
            .map(|commit| format!("{}+{commit}", env!("CARGO_PKG_VERSION")))
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_resources()
                .enable_tools()
                .build(),
        )
        .with_server_info(Implementation::new("dexsql", version))
        .with_instructions(
            "Analyze Android DEX/APK using read-only SQL, paged smali and APK Manifest/resources. Use resources/list for the complete English documentation catalog, including unlinked pages. Read relevant pages using the URIs returned by the catalog. Inspect the schema, open_dataset, then query/decode or resource tools. Reuse dataset_id and close unused datasets. Follow next_offset; query paging re-executes SQL and needs stable ORDER BY. Classes default to method summaries. Running timeout/cancellation closes that dataset; reopen it to continue. list_datasets reports quotas. int64/uint64 cells are exact decimal strings.",
        )
    }

    fn tools() -> Vec<Tool> {
        tool_specs()
            .into_iter()
            .filter_map(|value| serde_json::from_value(value).ok())
            .collect()
    }

    fn resources() -> Vec<Resource> {
        resource_specs()
            .into_iter()
            .filter_map(|value| serde_json::from_value(value).ok())
            .collect()
    }

    fn parameter_error(message: impl Into<String>) -> CallToolResult {
        CallToolResult::error(vec![ContentBlock::text(format!(
            "failed to deserialize parameters: {}",
            message.into()
        ))])
    }

    /// Match rmcp's generated `Parameters<T>` behavior for the legacy JSON
    /// dispatcher: typed wrappers reject unknown fields and report missing
    /// required fields as tool-level deserialization errors.
    fn validate_arguments(name: &str, arguments: &Map<String, Value>) -> Option<CallToolResult> {
        let (fields, required): (&[&str], &[&str]) = match name {
            "open_dataset" => (&["inputs", "timeout_ms"], &["inputs"]),
            "close_dataset" => (&["dataset_id"], &["dataset_id"]),
            "describe_table" => (&["name"], &["name"]),
            "query" => (
                &[
                    "dataset_id",
                    "sql",
                    "named_temp_queries",
                    "limit",
                    "offset",
                    "max_bytes",
                    "timing",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id", "sql"],
            ),
            "decode" => (
                &[
                    "dataset_id",
                    "file_id",
                    "method",
                    "method_idx",
                    "class",
                    "mode",
                    "method_offset",
                    "method_limit",
                    "offset",
                    "max_lines",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id"],
            ),
            "get_manifest" => (
                &[
                    "dataset_id",
                    "input_index",
                    "mode",
                    "offset",
                    "limit",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id"],
            ),
            "get_manifest_components" => (
                &[
                    "dataset_id",
                    "input_index",
                    "kind",
                    "offset",
                    "limit",
                    "only_exported",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id"],
            ),
            "list_resource_files" => (
                &[
                    "dataset_id",
                    "input_index",
                    "prefix",
                    "offset",
                    "limit",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id"],
            ),
            "read_resource" => (
                &[
                    "dataset_id",
                    "input_index",
                    "name",
                    "format",
                    "offset",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id", "name"],
            ),
            "query_resources" => (
                &[
                    "dataset_id",
                    "input_index",
                    "resource_id",
                    "name",
                    "resource_type",
                    "contains",
                    "configuration",
                    "offset",
                    "limit",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id"],
            ),
            "list_datasets" | "list_tables" => return None,
            _ => return None,
        };
        if let Some(field) = arguments
            .keys()
            .find(|field| !fields.contains(&field.as_str()))
        {
            let expected = if fields.len() == 1 {
                format!("expected `{}`", fields[0])
            } else if name == "open_dataset" {
                format!("expected `{}` or `{}`", fields[0], fields[1])
            } else {
                format!(
                    "expected one of {}",
                    fields
                        .iter()
                        .map(|field| format!("`{field}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            return Some(Self::parameter_error(format!(
                "unknown field `{field}`, {expected}"
            )));
        }
        if let Some(field) = required
            .iter()
            .find(|field| !arguments.contains_key(**field))
        {
            return Some(Self::parameter_error(format!("missing field `{field}`")));
        }
        // serde's generated wrappers report primitive type failures before the
        // tool implementation gets a chance to validate semantic ranges.
        let string_fields = [
            "dataset_id",
            "name",
            "method",
            "class",
            "kind",
            "prefix",
            "format",
            "resource_type",
            "contains",
            "configuration",
            "mode",
        ];
        if let Some((_, value)) = arguments.iter().find(|(field, value)| {
            string_fields.contains(&field.as_str()) && !value.is_string() && !value.is_null()
        }) {
            return Some(Self::parameter_error(format!(
                "invalid type: {}, expected a string",
                json_type_label(value)
            )));
        }
        if let Some(value) = arguments.get("timeout_ms") {
            if let Some(number) = value.as_i64() {
                if number < 0 {
                    return Some(Self::parameter_error(format!(
                        "invalid value: integer `{number}`, expected u64"
                    )));
                }
            } else if !value.is_u64() && !value.is_null() {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected u64",
                    json_type_label(value)
                )));
            }
        }
        if let Some(value) = arguments.get("timing") {
            if !value.is_boolean() && !value.is_null() {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected a boolean",
                    json_type_label(value)
                )));
            }
        }
        if let Some(value) = arguments.get("compact") {
            if !value.is_boolean() {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected a boolean",
                    json_type_label(value)
                )));
            }
        }
        let usize_fields = [
            "input_index",
            "offset",
            "limit",
            "max_bytes",
            "method_offset",
            "method_limit",
            "max_lines",
        ];
        let u32_fields = ["file_id", "method_idx", "resource_id"];
        for (field, value) in arguments {
            let expected = if usize_fields.contains(&field.as_str()) {
                Some("usize")
            } else if u32_fields.contains(&field.as_str()) {
                Some("u32")
            } else {
                None
            };
            let Some(expected) = expected else { continue };
            if value.is_null() {
                continue;
            }
            if let Some(number) = value.as_i64() {
                if number < 0 {
                    return Some(Self::parameter_error(format!(
                        "invalid value: integer `{number}`, expected {expected}"
                    )));
                }
            } else if value.as_u64().is_none() {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected {expected}",
                    json_type_label(value)
                )));
            }
        }
        if let Some(value) = arguments.get("inputs").filter(|value| !value.is_array()) {
            return Some(Self::parameter_error(format!(
                "invalid type: {}, expected a sequence",
                json_type_label(value)
            )));
        }
        if let Some(value) = arguments.get("inputs").and_then(Value::as_array) {
            if let Some(item) = value.iter().find(|item| !item.is_string()) {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected a string",
                    json_type_label(item)
                )));
            }
        }
        if let Some(value) = arguments.get("sql").filter(|value| !value.is_array()) {
            return Some(Self::parameter_error(format!(
                "invalid type: {}, expected a sequence",
                json_type_label(value)
            )));
        }
        if let Some(value) = arguments.get("sql").and_then(Value::as_array) {
            if let Some(item) = value.iter().find(|item| !item.is_string()) {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected a string",
                    json_type_label(item)
                )));
            }
        }
        None
    }

    async fn run_tool(
        &self,
        params: CallToolRequestParams,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if !Self::tools()
            .iter()
            .any(|tool| tool.name.as_ref() == params.name.as_ref())
        {
            return Err(McpError::invalid_params("tool not found", None));
        }
        let arguments = Value::Object(params.arguments.unwrap_or_default());
        if let Some(arguments_object) = arguments.as_object() {
            if let Some(error) = Self::validate_arguments(params.name.as_ref(), arguments_object) {
                return Ok(error);
            }
        }
        let request = json!({
            "name": params.name.as_ref(),
            "arguments": arguments,
        });
        let request_for_close = request.clone();
        let worker_dataset_id = request
            .get("arguments")
            .and_then(|arguments| arguments.get("dataset_id"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let requested_timeout = request
            .get("arguments")
            .and_then(|value| value.get("timeout_ms"))
            .and_then(Value::as_u64);
        let timeout_ms = match requested_timeout {
            Some(value) if value == 0 || value > self.config.timeout_ms => {
                return Ok(CallToolResult::structured_error(json!({
                    "error": {
                        "kind": "invalid_input",
                        "message": format!(
                            "timeout_ms must be in 1..={}",
                            self.config.timeout_ms
                        ),
                    }
                })));
            }
            Some(value) => value,
            None => self.config.timeout_ms,
        };
        if !self.admission.try_acquire() {
            return Ok(CallToolResult::structured_error(json!({
                "error": {
                    "kind": "server_busy",
                    "message": "request queue full",
                }
            })));
        }
        let state = Arc::clone(&self.state);
        let config = self.config.clone();
        let admission = Arc::clone(&self.admission);
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_worker = Arc::clone(&cancelled);
        let worker_state = Arc::clone(&state);
        let worker = tokio::task::spawn_blocking(move || {
            let result = crate::call_tool(&request, &state, &config);
            // A blocking operation cannot be force-aborted safely.  If rmcp
            // cancelled or timed out this request while it was running, close
            // a dataset that the operation may have created before returning.
            if cancelled_worker.load(Ordering::Relaxed) {
                if let Some(dataset_id) = worker_dataset_id.as_deref() {
                    if let Ok(mut guard) = worker_state.lock() {
                        guard.datasets.remove(dataset_id);
                    }
                }
                if let Ok(value) = &result {
                    if let Some(dataset_id) = value
                        .get("structuredContent")
                        .and_then(|content| content.get("dataset_id"))
                        .and_then(Value::as_str)
                    {
                        if let Ok(mut guard) = worker_state.lock() {
                            guard.datasets.remove(dataset_id);
                        }
                    }
                }
            }
            admission.release();
            result
        });
        let deadline = Duration::from_millis(timeout_ms);
        let result = tokio::select! {
            _ = context.ct.cancelled() => {
                cancelled.store(true, Ordering::Relaxed);
                try_close_argument_dataset(&request_for_close, &self.state);
                return Err(McpError::internal_error("task cancelled for reason", None));
            }
            result = tokio::time::timeout(deadline, worker) => result,
        };
        let value = match result {
            Ok(Ok(Ok(value))) => value,
            Ok(Ok(Err((_, message)))) => tool_error_result("invalid_request", &message),
            Ok(Err(error)) => {
                try_close_argument_dataset(&request_for_close, &self.state);
                return Err(McpError::internal_error(
                    format!("worker failed: {error}"),
                    None,
                ));
            }
            Err(_) => {
                cancelled.store(true, Ordering::Relaxed);
                try_close_argument_dataset(&request_for_close, &self.state);
                let dataset_id = request_for_close
                    .get("arguments")
                    .and_then(|value| value.get("dataset_id"))
                    .and_then(Value::as_str);
                let (dataset_id, dataset_closed, message) = match dataset_id {
                    Some(dataset_id) => (
                        Value::String(dataset_id.to_owned()),
                        true,
                        "running computation was terminated and this dataset was closed; call open_dataset to use it again",
                    ),
                    None => (
                        Value::Null,
                        false,
                        "request ended before a dataset operation completed; existing datasets remain open",
                    ),
                };
                return Ok(CallToolResult::structured_error(json!({
                    "dataset_id": dataset_id,
                    "error": {
                        "dataset_closed": dataset_closed,
                        "kind": "timeout",
                        "message": message,
                    },
                })));
            }
        };
        let compact = request_for_close
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| {
                matches!(
                    name,
                    "decode"
                        | "get_manifest"
                        | "get_manifest_components"
                        | "list_resource_files"
                        | "query"
                        | "query_resources"
                        | "read_resource"
                )
            })
            && request_for_close
                .get("arguments")
                .and_then(|arguments| arguments.get("compact"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let value = if compact {
            compact_tool_result(value)
        } else {
            value
        };
        serde_json::from_value(value).map_err(|error| {
            McpError::internal_error(format!("failed to serialize tool result: {error}"), None)
        })
    }
}

impl ServerHandler for RmcpHandler {
    fn get_info(&self) -> ServerInfo {
        Self::server_info()
    }

    fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>>
           + rmcp::service::MaybeSendFuture
           + '_ {
        let mut result = ListToolsResult::with_all_items(Self::tools());
        if context.protocol_version() == Some(rmcp::model::ProtocolVersion::V_2026_07_28) {
            result.ttl_ms = Some(0);
            result.cache_scope = Some(CacheScope::Public);
        }
        std::future::ready(Ok(result))
    }

    fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, McpError>>
           + rmcp::service::MaybeSendFuture
           + '_ {
        let mut result = ListResourcesResult::with_all_items(Self::resources());
        if context.protocol_version() == Some(rmcp::model::ProtocolVersion::V_2026_07_28) {
            result.ttl_ms = Some(0);
            result.cache_scope = Some(CacheScope::Private);
        }
        std::future::ready(Ok(result))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResponse, McpError>>
           + rmcp::service::MaybeSendFuture
           + '_ {
        let uri = request.uri.clone();
        let value = resources_read(&json!({"uri": uri}));
        let result = value
            .map_err(|_| {
                McpError::resource_not_found(
                    "unknown DexSQL documentation resource",
                    Some(json!({"uri": request.uri})),
                )
            })
            .and_then(|value| {
                serde_json::from_value::<ReadResourceResult>(value).map_err(|error| {
                    McpError::internal_error(format!("failed to serialize resource: {error}"), None)
                })
            })
            .map(|mut result| {
                // rmcp serializes these cache hints on the reference server
                // even for the 2024-11-05 negotiation.
                result.ttl_ms = Some(0);
                result.cache_scope = Some(CacheScope::Private);
                ReadResourceResponse::from(result)
            });
        std::future::ready(result)
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResponse, McpError>>
           + rmcp::service::MaybeSendFuture
           + '_ {
        async move { self.run_tool(request, context).await.map(Into::into) }
    }
}

fn initialize(params: &Value) -> Result<Value, (i32, String)> {
    let object = params
        .as_object()
        .ok_or((-32602, "initialize params must be an object".into()))?;
    for key in ["protocolVersion", "capabilities", "clientInfo"] {
        if object.get(key).is_none() {
            return Err((-32602, format!("initialize params missing {key}")));
        }
    }
    // The reference accepts the standard MCP initialize envelope.  Some
    // clients additionally send an SDK-specific `_meta` object, but it is not
    // required for the protocol handshake and must not make valid standard
    // clients fail negotiation.
    Ok(json!({
        "protocolVersion":"2024-11-05",
        "capabilities":{"resources":{},"tools":{}},
        "serverInfo":{"name":"dexsql","version":env!("CARGO_PKG_VERSION")},
        "instructions":"Analyze Android DEX/APK using read-only SQL, paged smali and APK Manifest/resources. Use resources/list for the complete English documentation catalog, including unlinked pages. Read relevant pages using the URIs returned by the catalog. Inspect the schema, open_dataset, then query/decode or resource tools. Reuse dataset_id and close unused datasets. Follow next_offset; query paging re-executes SQL and needs stable ORDER BY. Classes default to method summaries. Running timeout/cancellation closes that dataset; reopen it to continue. list_datasets reports quotas. int64/uint64 cells are exact decimal strings."
    }))
}

fn dispatch(req: Request, state: &Arc<Mutex<State>>, cfg: &Config) -> Option<Response> {
    req.id.as_ref()?;
    let id = req.id.unwrap_or(Value::Null);
    let result: Result<Value, (i32, String)> = match req.method.as_str() {
        "initialize" => initialize(&req.params),
        "notifications/initialized" | "notifications/cancelled" => return None,
        "ping" => Ok(json!({})),
        "tools/list" => validate_request_meta(&req.params).map(|_| json!({"tools":tool_specs()})),
        "resources/list" => {
            validate_request_meta(&req.params).map(|_| json!({"resources":resource_specs()}))
        }
        "resources/read" => resources_read(&req.params),
        "tools/call" => call_tool(&req.params, state, cfg),
        _ => Err((-32601, format!("method not found: {}", req.method))),
    };
    Some(match result {
        Ok(value) => Response {
            jsonrpc: "2.0",
            id,
            result: Some(value),
            error: None,
        },
        Err((c, m)) => error_response(id, c, m),
    })
}

fn validate_request_meta(params: &Value) -> Result<(), (i32, String)> {
    let meta = params
        .get("_meta")
        .and_then(Value::as_object)
        .ok_or_else(|| (-32602, "request _meta is missing or has malformed required fields: io.modelcontextprotocol/protocolVersion, io.modelcontextprotocol/clientCapabilities".into()))?;
    if meta
        .get("io.modelcontextprotocol/protocolVersion")
        .and_then(Value::as_str)
        != Some("2024-11-05")
        || !meta
            .get("io.modelcontextprotocol/clientCapabilities")
            .is_some_and(Value::is_object)
    {
        return Err((-32602, "request _meta is missing or has malformed required fields: io.modelcontextprotocol/protocolVersion, io.modelcontextprotocol/clientCapabilities".into()));
    }
    Ok(())
}

fn tool_specs() -> Vec<Value> {
    let defs = [
        (
            "open_dataset",
            "Open local DEX/APK/JAR/ZIP paths as an isolated reusable dataset. Resource-only archives are supported. Input/session quotas and operation deadlines apply. Close unused datasets to release memory.",
            json!({"inputs":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":64},"timeout_ms":{"type":["integer","null"],"minimum":1}}),
            vec!["inputs"],
        ),
        (
            "list_datasets",
            "List open datasets and server quotas/usage. Counts include opening datasets and accepted work still holding a closed dataset.",
            json!({}),
            vec![],
        ),
        (
            "close_dataset",
            "Close a dataset and release its worker. New requests fail; already accepted requests may finish, with deadlines still enforced.",
            json!({"dataset_id":{"type":"string"}}),
            vec!["dataset_id"],
        ),
        (
            "list_tables",
            "List all built-in SQL tables and views; no dataset is needed.",
            json!({}),
            vec![],
        ),
        (
            "describe_table",
            "Describe a built-in SQL table or view; no dataset is needed.",
            json!({"name":{"type":"string"}}),
            vec!["name"],
        ),
        (
            "query",
            "Run a read-only SQL batch with exact typed cells, byte/row budgets and per-statement next_offset. Use stable ORDER BY when paging; SQL is re-executed against the current lazy session definitions on each page; CREATE definitions persist until DROP, replacement or dataset close. Running timeout/cancellation closes only this dataset. Use resources/list to discover the documentation.",
            json!({"dataset_id":{"type":"string"},"sql":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":16},"limit":{"type":["integer","null"],"minimum":1,"maximum":1000},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":["integer","null"],"minimum":0},"named_temp_queries":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"sql":{"type":"string"}},"required":["name","sql"]}},"timing":{"type":"boolean"},"timeout_ms":{"type":["integer","null"]}}),
            vec!["dataset_id", "sql"],
        ),
        (
            "decode",
            "Inspect a method or class. Exactly one method descriptor, method_idx (with file_id), or class descriptor is required. Classes default to paginated summaries; methods default to paginated smali. Follow next_offset for exact text continuation; context mode lists original line numbers for labels and catch directives. Query SQL tables for annotations and debug metadata.",
            json!({"dataset_id":{"type":"string"},"method":{"type":["string","null"]},"method_idx":{"type":["integer","null"]},"file_id":{"type":["integer","null"]},"class":{"type":["string","null"]},"mode":{"type":["string","null"],"enum":["summary","smali","context",null]},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":["integer","null"],"minimum":0},"max_lines":{"type":["integer","null"],"minimum":1,"maximum":1000},"method_offset":{"type":"integer","minimum":0},"method_limit":{"type":["integer","null"],"minimum":1,"maximum":50},"timeout_ms":{"type":["integer","null"]}}),
            vec!["dataset_id"],
        ),
        (
            "get_manifest",
            "Read an APK Manifest as a summary (including paged permissions) or paged decoded XML. input_index refers to open_dataset.inputs; choose it when several archives are open. Does not require DEX or Java decompilation.",
            json!({"dataset_id":{"type":"string"},"input_index":{"type":["integer","null"],"minimum":0},"mode":{"type":"string","enum":["summary","xml"]},"offset":{"type":"integer","minimum":0},"limit":{"type":["integer","null"],"minimum":1,"maximum":200},"max_bytes":{"type":["integer","null"],"minimum":0},"timeout_ms":{"type":["integer","null"],"minimum":0}}),
            vec!["dataset_id"],
        ),
        (
            "get_manifest_components",
            "Page Manifest components, names/descriptors, launcher intent filters, aliases and exported configuration. Exported state is manifest-derived and is not a claim of runtime accessibility. Includes explicit and SDK-dependent default states.",
            json!({"dataset_id":{"type":"string"},"input_index":{"type":["integer","null"],"minimum":0},"kind":{"type":["string","null"]},"offset":{"type":"integer","minimum":0},"limit":{"type":["integer","null"],"minimum":1,"maximum":200},"only_exported":{"type":"boolean"},"max_bytes":{"type":["integer","null"],"minimum":0},"timeout_ms":{"type":["integer","null"],"minimum":0}}),
            vec!["dataset_id"],
        ),
        (
            "list_resource_files",
            "Page archive entry names and sizes, optionally filtered by prefix (res/, assets/, lib/). Names identify entries for read_resource; files are never extracted.",
            json!({"dataset_id":{"type":"string"},"input_index":{"type":["integer","null"],"minimum":0},"offset":{"type":"integer","minimum":0},"limit":{"type":["integer","null"],"minimum":1,"maximum":200},"prefix":{"type":["string","null"]},"max_bytes":{"type":["integer","null"],"minimum":0},"timeout_ms":{"type":["integer","null"],"minimum":0}}),
            vec!["dataset_id"],
        ),
        (
            "read_resource",
            "Read one exact APK archive entry in bounded pages. Binary Android XML is decoded; UTF-8 text is preserved; other bytes use hex. Follow next_offset in page (text) or the result (hex). The resource-entry size quota applies before decompression.",
            json!({"dataset_id":{"type":"string"},"input_index":{"type":["integer","null"],"minimum":0},"name":{"type":"string"},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":["integer","null"],"minimum":0},"format":{"type":"string","enum":["auto","hex"]},"timeout_ms":{"type":["integer","null"],"minimum":0}}),
            vec!["dataset_id", "name"],
        ),
        (
            "query_resources",
            "Query resources.arsc by numeric ID, exact type/name, type, name substring or configuration. Returns matching configurations with raw values and named references; complex resources are flattened into ordered map items. Separate from DEX strings.",
            json!({"dataset_id":{"type":"string"},"input_index":{"type":["integer","null"],"minimum":0},"resource_id":{"type":["integer","null"],"minimum":0},"name":{"type":["string","null"]},"resource_type":{"type":["string","null"]},"contains":{"type":["string","null"]},"configuration":{"type":["string","null"]},"offset":{"type":"integer","minimum":0},"limit":{"type":["integer","null"],"minimum":1,"maximum":200},"max_bytes":{"type":["integer","null"],"minimum":0},"timeout_ms":{"type":["integer","null"],"minimum":0}}),
            vec!["dataset_id"],
        ),
    ];
    let mut out = Vec::new();
    for (name, desc, props, required) in defs {
        let mut props = props;
        enrich_generated_input_schema(name, &mut props);
        let mut s = Map::new();
        // schemars emits the compact `{properties:{},type:object}` shape for
        // no-argument tools.  Other request types carry the draft marker,
        // closed-world flag, and required list.
        let bare_object = matches!(name, "list_datasets" | "list_tables");
        if !bare_object {
            s.insert(
                "$schema".into(),
                json!("https://json-schema.org/draft/2020-12/schema"),
            );
        }
        s.insert("type".into(), json!("object"));
        if !bare_object {
            s.insert("additionalProperties".into(), json!(false));
        }
        s.insert("properties".into(), props);
        if !bare_object {
            s.insert("required".into(), json!(required));
        }
        if matches!(name, "list_datasets" | "list_tables") {
            s.remove("$schema");
            s.remove("additionalProperties");
            s.remove("required");
        }
        if let Some(defs) = generated_input_defs(name) {
            s.insert("$defs".into(), defs);
        }
        let read_only = name != "open_dataset" && name != "close_dataset";
        let annotations = if read_only {
            if matches!(name, "decode" | "query") {
                json!({"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false})
            } else {
                json!({"readOnlyHint":true,"openWorldHint":false})
            }
        } else {
            json!({"readOnlyHint":false,"destructiveHint":false,"openWorldHint":false})
        };
        let mut tool = json!({"name":name,"description":desc,"inputSchema":Value::Object(s),"annotations":annotations});
        if let Some(schema) = generated_output_schema(name) {
            tool["outputSchema"] = schema;
        }
        out.push(tool);
    }
    // rmcp preserves the declaration order. Keep the public order identical
    // to the reference server so clients that snapshot tools/list remain
    // stable across releases.
    const ORDER: &[&str] = &[
        "close_dataset",
        "decode",
        "describe_table",
        "get_manifest",
        "get_manifest_components",
        "list_datasets",
        "list_resource_files",
        "list_tables",
        "open_dataset",
        "query",
        "query_resources",
        "read_resource",
    ];
    out.sort_by_key(|tool| {
        ORDER
            .iter()
            .position(|name| *name == tool["name"].as_str().unwrap_or(""))
            .unwrap_or(usize::MAX)
    });
    out
}

/// These are the exact output schemas emitted by schemars 1.2.2 for the
/// protocol result structs.  Keeping them as JSON fixtures avoids silently
/// dropping nested `$defs` when the hand-written transport is used.
fn generated_output_schema(name: &str) -> Option<Value> {
    let source = match name {
        "query" => include_str!("schemas/query_output.json"),
        "decode" => include_str!("schemas/decode_output.json"),
        _ => return None,
    };
    Some(serde_json::from_str(source).expect("embedded generated output schema"))
}

/// Add the details that `schemars` emits for protocol enums and documented
/// request fields.  Keeping this in one small post-processing pass lets the
/// hand-written dispatch table stay readable while preserving the public
/// `$defs`/description shape produced by the reference rmcp server.
fn enrich_generated_input_schema(name: &str, props: &mut Value) {
    let Some(object) = props.as_object_mut() else {
        return;
    };
    if matches!(
        name,
        "decode"
            | "get_manifest"
            | "get_manifest_components"
            | "list_resource_files"
            | "query"
            | "query_resources"
            | "read_resource"
    ) {
        object.insert(
            "compact".into(),
            json!({
                "description":"Opt in to one structuredContent representation (content is empty). Query columns become\nnames and cells use null/string/number or [i|u|b|f, string]; SQL is omitted. Default false.",
                "type":"boolean"
            }),
        );
    }
    match name {
        "open_dataset" => {
            prop_desc(
                object,
                "inputs",
                "Local DEX/APK/JAR/ZIP paths, resolved relative to the server working directory.",
            );
            prop_desc(
                object,
                "timeout_ms",
                "Optional shorter operation deadline; cannot exceed the server's timeout.",
            );
            prop_format(object, "timeout_ms", "uint64");
        }
        "query" => {
            prop_desc(object, "sql", "Read-only SQL statements. VIEW and TEMP definitions are lazy and persist in this dataset\nuntil DROP, redefinition, or close_dataset; results are not cached across calls.");
            prop_desc(object, "limit", "Returned rows per statement, default 200; use a deterministic ORDER BY when paging.");
            prop_desc(object, "offset", "Rows to skip in each statement's result, default 0. offset + limit is at most 100000.");
            prop_desc(
                object,
                "max_bytes",
                "Optional lower serialized result-byte budget; rows are never silently clipped.",
            );
            prop_desc(object, "named_temp_queries", "Lazy named SELECT definitions, retained in this dataset with the same lifetime as TEMP tables.");
            prop_default(object, "named_temp_queries", json!([]));
            prop_default(object, "offset", json!(0));
            prop_default(object, "timing", json!(false));
            prop_format(object, "limit", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "timeout_ms", "uint64");
            prop_minimum(object, "timeout_ms", 0);
            if let Some(named) = object
                .get_mut("named_temp_queries")
                .and_then(Value::as_object_mut)
            {
                named.insert("items".into(), json!({"$ref":"#/$defs/NamedTempQuery"}));
            }
        }
        "decode" => {
            prop_desc(
                object,
                "method",
                "Exact DEX descriptor. Supply exactly one of method, method_idx, or class.",
            );
            prop_desc(
                object,
                "method_idx",
                "DEX-local method index; requires file_id.",
            );
            prop_desc(
                object,
                "max_lines",
                "Maximum lines in one text page, default 200, maximum 1000.",
            );
            prop_desc(
                object,
                "method_limit",
                "Methods per class page, default 20, maximum 50.",
            );
            prop_desc(object, "mode", "Defaults to summary for a class, smali for a method. Context lists original label/catch lines.");
            prop_desc(
                object,
                "method_offset",
                "Class method-list offset, ordered by method_idx.",
            );
            prop_desc(object, "offset", "UTF-8 byte offset into one method's smali/context text; continue with next_offset.");
            prop_default(object, "method_offset", json!(0));
            prop_default(object, "offset", json!(0));
            prop_format(object, "file_id", "uint32");
            prop_format(object, "method_idx", "uint32");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "max_lines", "uint");
            prop_format(object, "method_offset", "uint");
            prop_format(object, "method_limit", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "timeout_ms", "uint64");
            prop_minimum(object, "file_id", 0);
            prop_minimum(object, "method_idx", 0);
            prop_minimum(object, "timeout_ms", 0);
            if let Some(mode) = object.get_mut("mode") {
                *mode = json!({"anyOf":[{"$ref":"#/$defs/DecodeMode"},{"type":"null"}],"description":"Defaults to summary for a class, smali for a method. Context lists original label/catch lines."});
            }
        }
        "get_manifest" => {
            prop_desc(
                object,
                "input_index",
                "Index in open_dataset.inputs; required when several archive inputs are present.",
            );
            prop_desc(
                object,
                "offset",
                "Permission-row offset in summary mode, UTF-8 byte offset in XML mode.",
            );
            prop_default(object, "mode", json!("summary"));
            prop_default(object, "offset", json!(0));
            prop_format(object, "input_index", "uint");
            prop_format(object, "limit", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "timeout_ms", "uint64");
            if let Some(mode) = object.get_mut("mode") {
                *mode = json!({"$ref":"#/$defs/ManifestMode","default":"summary"});
            }
        }
        "get_manifest_components" => {
            prop_desc(
                object,
                "kind",
                "Optional activity, activity-alias, service, receiver, or provider filter.",
            );
            prop_desc(
                object,
                "only_exported",
                "Filter by manifest-derived exported state; does not imply runtime accessibility.",
            );
            prop_default(object, "offset", json!(0));
            prop_default(object, "only_exported", json!(false));
            prop_format(object, "input_index", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "limit", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "timeout_ms", "uint64");
        }
        "list_resource_files" => {
            prop_desc(
                object,
                "prefix",
                "Case-sensitive archive-entry prefix, for example res/layout/ or assets/.",
            );
            prop_default(object, "offset", json!(0));
            prop_format(object, "input_index", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "limit", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "timeout_ms", "uint64");
        }
        "read_resource" => {
            prop_desc(
                object,
                "name",
                "Exact archive entry name. No files are extracted to the filesystem.",
            );
            prop_desc(
                object,
                "offset",
                "Byte offset in decoded UTF-8 text, or original bytes when encoding is hex.",
            );
            prop_default(object, "offset", json!(0));
            prop_format(object, "input_index", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "timeout_ms", "uint64");
            if let Some(format_value) = object.get_mut("format") {
                *format_value = json!({"$ref":"#/$defs/ResourceFormat","default":"auto"});
            }
        }
        "query_resources" => {
            prop_desc(
                object,
                "resource_id",
                "Resource ID, for example 2130771968 (0x7f010000).",
            );
            prop_desc(
                object,
                "name",
                "Exact type/name or package:type/name, for example string/app_name.",
            );
            prop_desc(
                object,
                "resource_type",
                "Resource type, for example string, layout, id, style, or array.",
            );
            prop_desc(
                object,
                "contains",
                "Case-sensitive substring of the resource name.",
            );
            prop_desc(object, "configuration", "Exact qualifier string from a previous result. Empty string selects the default config.");
            prop_default(object, "offset", json!(0));
            prop_format(object, "input_index", "uint");
            prop_format(object, "resource_id", "uint32");
            prop_format(object, "offset", "uint");
            prop_format(object, "limit", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "timeout_ms", "uint64");
        }
        _ => {}
    }
}

fn prop_desc(object: &mut Map<String, Value>, field: &str, text: &str) {
    if let Some(value) = object.get_mut(field).and_then(Value::as_object_mut) {
        value.insert("description".into(), json!(text));
    }
}

fn prop_format(object: &mut Map<String, Value>, field: &str, text: &str) {
    if let Some(value) = object.get_mut(field).and_then(Value::as_object_mut) {
        value.insert("format".into(), json!(text));
    }
}

fn prop_default(object: &mut Map<String, Value>, field: &str, value: Value) {
    if let Some(property) = object.get_mut(field).and_then(Value::as_object_mut) {
        property.insert("default".into(), value);
    }
}

fn prop_minimum(object: &mut Map<String, Value>, field: &str, value: i64) {
    if let Some(property) = object.get_mut(field).and_then(Value::as_object_mut) {
        property.insert("minimum".into(), json!(value));
    }
}

fn generated_input_defs(name: &str) -> Option<Value> {
    match name {
        "decode" => Some(json!({"DecodeMode": {
            "description": "Which `decode` view a request asks for. A class selection defaults to [`Self::Summary`] and a\nmethod selection to [`Self::Smali`] (see [`run`]).\n\n`JsonSchema` is derived here for the same reason as `apk::manifest::ManifestMode`: the MCP tool's\nparameter schema is generated from this type (it is re-exported as\n`cli::mcp::protocol::DecodeMode`), so the published schema and the implemented behaviour cannot\ndisagree.",
            "oneOf": [
                {"const":"summary","description":"Method METADATA only: descriptor, access flags, code units, registers, try count.","type":"string"},
                {"const":"smali","description":"The complete smali text of each selected method, paged by UTF-8 byte offset.","type":"string"},
                {"const":"context","description":"The smali text with every original label/catch/method line prefixed by its zero-based line\nnumber — the view a caller uses to talk about a line it saw somewhere else.","type":"string"}
            ]
        }})),
        "get_manifest" => Some(json!({"ManifestMode": {
            "description": "Which `AndroidManifest.xml` view a `get_manifest` request asks for.\n\n`JsonSchema` is derived here because the MCP tool definition is generated from this type (it is\nre-exported as `cli::mcp::protocol::ManifestMode`), so the published parameter schema and the\nimplemented behaviour cannot disagree.",
            "oneOf": [
                {"const":"summary","description":"Structured summary: manifest/application/uses-sdk attributes, target SDK, component counts,\nand a paged `permissions` list.","type":"string"},
                {"const":"xml","description":"The complete decoded XML, paged by UTF-8 byte offset.","type":"string"}
            ]
        }})),
        "read_resource" => Some(json!({"ResourceFormat": {
            "description": "The `read_resource` output format: decide from the bytes, or force hex.\n\n`JsonSchema` is derived here for the same reason as `manifest::ManifestMode`: the MCP tool's\nparameter schema is generated from this type, which is re-exported as\n`cli::mcp::protocol::ResourceFormat`.",
            "enum":["auto","hex"],"type":"string"
        }})),
        "query" => Some(json!({"NamedTempQuery": {
            "additionalProperties":false,
            "properties":{"name":{"type":"string"},"sql":{"type":"string"}},
            "required":["name","sql"],"type":"object"
        }})),
        _ => None,
    }
}
pub(crate) use resources::{resource_specs, resources_read};
fn call_tool(p: &Value, state: &Arc<Mutex<State>>, cfg: &Config) -> Result<Value, (i32, String)> {
    let name = p
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "tool name is required".into()))?;
    let a = p.get("arguments").cloned().unwrap_or_else(|| json!({}));
    if !a.is_object() {
        return Err((-32602, "tool arguments must be an object".into()));
    }
    let value = match name {
        "open_dataset" => open_dataset(&a, state, cfg),
        "list_datasets" => Ok(list_datasets(state, cfg)),
        "close_dataset" => close_dataset(&a, state),
        "list_tables" => Ok(json!({"tables":TABLES})),
        "describe_table" => describe_table(&a),
        "query" => query(&a, state),
        "decode" => decode_tool(&a, state),
        "get_manifest" => get_manifest(&a, state, cfg.max_resource_bytes),
        "get_manifest_components" => get_manifest_components(&a, state, cfg.max_resource_bytes),
        "list_resource_files" => list_resource_files(&a, state),
        "read_resource" => read_resource(&a, state, cfg.max_resource_bytes),
        "query_resources" => query_resources(&a, state),
        _ => Err((-32602, format!("unknown tool: {name}"))),
    };
    match value {
        Ok(value) => {
            let text = serde_json::to_string(&value).map_err(|e| (-32603, e.to_string()))?;
            if text.len() as u64 > cfg.max_output_bytes {
                return Ok(tool_error_result(
                    "output_limit",
                    "serialized result exceeds --max-output-bytes",
                ));
            }
            Ok(
                json!({"content":[{"type":"text","text":text}],"structuredContent":value,"isError":false}),
            )
        }
        Err((_, message)) => {
            if message == "archive changed; close and reopen the dataset" {
                return Ok(tool_error_result("source_changed", &message));
            }
            if let Some(dataset) = message.strip_prefix("unknown dataset_id: ") {
                return Ok(tool_error_result(
                    "unknown_dataset",
                    &format!("dataset \"{dataset}\" is not open; call open_dataset first"),
                ));
            }
            if let Some(column) = message
                .strip_prefix("unknown column '")
                .and_then(|value| value.strip_suffix('\''))
            {
                let value = json!({"error":{"input":Value::Null,"kind":"invalid_query","message":format!("unknown column `{column}`"),"source":Value::Null,"stage":"execute_sql","statement_index":0}});
                Ok(
                    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":true}),
                )
            } else if let Some(relation) = message
                .strip_prefix("unknown relation '")
                .and_then(|value| value.strip_suffix('\''))
            {
                let value = json!({"error":{"input":Value::Null,"kind":"invalid_query","message":format!("unknown relation `{relation}`"),"source":Value::Null,"stage":"execute_sql","statement_index":0}});
                Ok(
                    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":true}),
                )
            } else if let Some(table) = message
                .strip_prefix("unknown table '")
                .and_then(|value| value.strip_suffix('\''))
            {
                let value = json!({"error":{"input":Value::Null,"kind":"invalid_query","message":format!("unknown relation `{table}`"),"source":Value::Null,"stage":"execute_sql","statement_index":0}});
                Ok(
                    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":true}),
                )
            } else {
                Ok(tool_error_result("invalid_request", &message))
            }
        }
    }
}

fn tool_error_result(kind: &str, message: &str) -> Value {
    let value = json!({"error":{"kind":kind,"message":message}});
    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":true})
}

fn compact_tool_result(value: Value) -> Value {
    let is_error = value
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if is_error {
        let mut structured = value
            .get("structuredContent")
            .cloned()
            .unwrap_or(Value::Null);
        if let Some(message) = structured
            .get("error")
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
        {
            if let Some(dataset) = message.strip_prefix("unknown dataset_id: ") {
                structured = json!({"error":{"kind":"unknown_dataset","message":format!("dataset \"{dataset}\" is not open; call open_dataset first")}});
            }
        }
        return json!({"content":[],"structuredContent":structured,"isError":true});
    }
    let mut structured = value
        .get("structuredContent")
        .cloned()
        .unwrap_or(Value::Null);
    if let Some(statements) = structured
        .get_mut("statements")
        .and_then(Value::as_array_mut)
    {
        for statement in statements {
            if let Some(object) = statement.as_object_mut() {
                if let Some(columns) = object.get_mut("columns").and_then(Value::as_array_mut) {
                    for column in columns.iter_mut() {
                        if let Some(name) = column.get("name").cloned() {
                            *column = name;
                        }
                    }
                }
                object.remove("sql");
                object.remove("sql_truncated");
                if let Some(rows) = object.get_mut("rows").and_then(Value::as_array_mut) {
                    for row in rows {
                        if let Some(cells) = row.as_array_mut() {
                            for cell in cells {
                                *cell = compact_cell(cell.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    json!({"content":[],"structuredContent":structured,"isError":false})
}

fn compact_cell(cell: Value) -> Value {
    let Some(kind) = cell.get("type").and_then(Value::as_str) else {
        return cell;
    };
    let value = cell.get("value").cloned().unwrap_or(Value::Null);
    match kind {
        "null" | "utf8" => value,
        "int64" => json!(["i", value]),
        "uint64" | "uint32" => json!(["u", value]),
        "binary" => json!(["b", value]),
        "float64" => {
            if value.is_number() {
                value
            } else {
                json!(["f", value])
            }
        }
        _ => value,
    }
}
fn open_dataset(
    a: &Value,
    state: &Arc<Mutex<State>>,
    cfg: &Config,
) -> Result<Value, (i32, String)> {
    let started = Instant::now();
    let arr = a
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or((-32602, "inputs is required".into()))?;
    if arr.is_empty() || arr.len() > 64 {
        return Err((-32602, "inputs must contain 1..64 paths".into()));
    }
    let mut paths = Vec::with_capacity(arr.len());
    for value in arr {
        let path = value
            .as_str()
            .ok_or((-32602, "inputs entries must be strings".into()))?;
        if path.is_empty() {
            return Err((-32602, "inputs entries must not be empty".into()));
        }
        paths.push(PathBuf::from(path));
    }
    if paths.iter().any(|path| !path.is_file()) {
        return Err((
            -32000,
            "input_error: input path does not exist or is not a file".into(),
        ));
    }
    let bytes = paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum::<u64>();
    if bytes > cfg.max_input_bytes {
        return Err((-32000, "input byte quota exceeded".into()));
    }
    let mut g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    if g.datasets.len().saturating_add(g.opening) >= cfg.max_datasets {
        return Err((-32000, "maximum datasets exceeded".into()));
    }
    let open_bytes = g
        .datasets
        .values()
        .map(|entry| entry.source_bytes)
        .sum::<u64>();
    if open_bytes
        .saturating_add(g.opening_bytes)
        .saturating_add(bytes)
        > cfg.max_total_input_bytes
    {
        return Err((
            -32000,
            "input byte budgets exhausted; close unused datasets before opening another".into(),
        ));
    }
    g.opening += 1;
    g.opening_bytes = g.opening_bytes.saturating_add(bytes);
    drop(g);
    let load_paths = paths
        .iter()
        .filter(|path| is_dex(path) || (is_archive(path) && archive_contains_dex(path)))
        .cloned()
        .collect::<Vec<_>>();
    let load_result = if load_paths.is_empty() {
        Ok(None)
    } else {
        Dataset::load_paths(&load_paths).map(Some)
    };
    let mut g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    g.opening = g.opening.saturating_sub(1);
    g.opening_bytes = g.opening_bytes.saturating_sub(bytes);
    let ds = match load_result {
        Ok(ds) => ds,
        Err(error) => return Err((-32000, format!("load_failed: {error}"))),
    };
    let dex_bytes = ds
        .as_ref()
        .map(|dataset| dataset.files.iter().map(|file| file.byte_len).sum::<u64>())
        .unwrap_or(0);
    if dex_bytes > cfg.max_dex_bytes {
        return Err((
            -32000,
            "dataset exceeds --max-dex-bytes (uncompressed DEX bytes)".into(),
        ));
    }
    g.next_id += 1;
    let id = format!("dataset-{}", g.next_id);
    let n = ds.as_ref().map_or(0, |ds| ds.files.len());
    let archive_inputs = paths
        .iter()
        .enumerate()
        .filter_map(|(index, path)| is_archive(path).then_some(index))
        .collect::<Vec<_>>();
    let archive_stamps = archive_inputs
        .iter()
        .map(|&index| (index, archive_stamp(&paths[index])))
        .collect::<HashMap<_, _>>();
    let inputs = paths.clone();
    let prepare_ms = started.elapsed().as_secs_f64() * 1000.0;
    g.datasets.insert(
        id.clone(),
        Entry {
            paths,
            dataset: ds,
            source_bytes: bytes,
            dex_bytes,
            archive_inputs: archive_inputs.clone(),
            prepare_ms,
            resource_cache: None,
            archive_stamps,
        },
    );
    Ok(json!({
        "archive_inputs": archive_inputs,
        "dataset_id": id,
        "has_dex": n > 0,
        "input_bytes": bytes,
        "inputs": inputs,
        "prepare_ms": prepare_ms
    }))
}
fn list_datasets(state: &Arc<Mutex<State>>, cfg: &Config) -> Value {
    let g = state.lock().expect("state lock");
    let datasets: Vec<Value> = g
        .datasets
        .iter()
        .map(|(id, e)| {
            json!({
                "archive_inputs": e.archive_inputs,
                "dataset_id": id,
                "has_dex": e.dataset.as_ref().is_some_and(|ds| !ds.files.is_empty()),
                "input_bytes": e.source_bytes,
                "inputs": e.paths,
                "prepare_ms": e.prepare_ms
            })
        })
        .collect();
    let input_bytes = g.datasets.values().map(|e| e.source_bytes).sum::<u64>();
    json!({
        "admitted_requests": g.opening,
        "datasets": datasets,
        "limits": {
            "max_datasets": cfg.max_datasets,
            "max_dex_bytes": cfg.max_dex_bytes,
            "max_input_bytes": cfg.max_input_bytes,
            "max_output_bytes": cfg.max_output_bytes,
            "max_pending": cfg.max_pending,
            "max_resource_bytes": cfg.max_resource_bytes,
            "max_total_input_bytes": cfg.max_total_input_bytes,
            "timeout_ms": cfg.timeout_ms
        },
        "running_requests": g.opening,
        "usage": {"datasets": g.datasets.len(), "input_bytes": input_bytes}
    })
}
fn close_dataset(a: &Value, state: &Arc<Mutex<State>>) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let mut g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    if g.datasets.remove(id).is_none() {
        return Err((-32001, format!("unknown dataset_id: {id}")));
    }
    Ok(json!({"dataset_id":id,"closed":true}))
}
fn describe_table(a: &Value) -> Result<Value, (i32, String)> {
    let name = a
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "name is required".into()))?;
    let table = schema::TABLES
        .iter()
        .find(|table| table.name == name)
        .ok_or((-32002, format!("unknown table: {name}")))?;
    let columns = table
        .columns
        .iter()
        .map(|column| {
            json!({
                "name":column.name,
                "data_type": if column.nullable { format!("{}?", column.sql_type) } else { column.sql_type.to_owned() }
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({"name":table.name,"columns":columns}))
}
fn query(a: &Value, state: &Arc<Mutex<State>>) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let sql = a
        .get("sql")
        .and_then(Value::as_array)
        .ok_or((-32602, "sql is required".into()))?;
    if sql.is_empty() || sql.len() > 16 {
        return Err((-32602, "sql must contain 1..16 statements".into()));
    }
    let named: &[Value] = a
        .get("named_temp_queries")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice);
    if named.len() > 16 {
        return Err((
            -32602,
            "named_temp_queries must contain at most 16 entries".into(),
        ));
    }
    let total_sql = sql
        .iter()
        .map(|s| s.as_str().map(str::len).unwrap_or(0))
        .sum::<usize>()
        + named
            .iter()
            .map(|entry| {
                entry
                    .get("sql")
                    .and_then(Value::as_str)
                    .map(str::len)
                    .unwrap_or(0)
            })
            .sum::<usize>();
    if total_sql > 64 * 1024 {
        return Err((-32602, "SQL input exceeds 64KiB".into()));
    }
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let limit = match a.get("limit") {
        None | Some(Value::Null) => 200usize,
        Some(value) => {
            let n = value
                .as_u64()
                .ok_or((-32602, "limit must be an integer or null".into()))?
                as usize;
            if !(1..=1000).contains(&n) {
                return Err((-32602, "limit must be between 1 and 1000".into()));
            }
            n
        }
    };
    if offset.saturating_add(limit) > 100_000 {
        return Err((-32602, "offset + limit must be at most 100000".into()));
    }
    let max_bytes = checked_u64(a, "max_bytes")?;
    let g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    let e = g
        .datasets
        .get(id)
        .ok_or((-32001, format!("unknown dataset_id: {id}")))?;
    let dataset = e.dataset.as_ref().cloned().ok_or((
        -32005,
        "dataset has no DEX files; archive-only datasets support archive tools only".into(),
    ))?;
    // Do not hold the global session mutex while the relation executor scans
    // potentially millions of rows.  This keeps cancellation/timeout and
    // list_datasets responsive while the blocking worker winds down.
    drop(g);
    let mut temps: HashMap<String, Value> = HashMap::new();
    for entry in named {
        let object = entry
            .as_object()
            .ok_or((-32602, "named_temp_queries entries must be objects".into()))?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or((-32602, "named temporary query name is required".into()))?;
        let text = object
            .get("sql")
            .and_then(Value::as_str)
            .ok_or((-32602, "named temporary query sql is required".into()))?;
        if name.is_empty() || !valid_identifier(name) {
            return Err((-32602, format!("invalid temporary query name: {name}")));
        }
        if temps.contains_key(name) {
            return Err((-32602, format!("duplicate temporary query: {name}")));
        }
        let statement = execute_mcp_statement(text, &dataset, 0, a, &temps)?;
        temps.insert(name.to_ascii_lowercase(), statement);
    }
    let mut statements = Vec::with_capacity(sql.len());
    for (i, value) in sql.iter().enumerate() {
        let text = value
            .as_str()
            .ok_or((-32602, "sql entries must be strings".into()))?;
        if text.trim().is_empty() {
            return Err((-32602, "sql entries must not be empty".into()));
        }
        let mut statement = execute_mcp_statement(text, &dataset, i, a, &temps)?;
        // A named temporary query is represented as a normal paged statement
        // when selected.  This keeps the response shape identical to a base
        // relation and makes it safe for clients to follow next_offset.
        apply_page(&mut statement, offset, limit)?;
        if let Some(max) = max_bytes {
            truncate_statement_bytes(&mut statement, max as usize);
        }
        statements.push(statement);
    }
    let diagnostics = sql
        .iter()
        .filter_map(|value| {
            let text = value.as_str()?;
            let lower = text.to_ascii_lowercase();
            let rewrites = if lower.contains(" from ") || lower.contains(" join ") {
                dexsql_query::optimizer_rewrite_count(text)
            } else {
                0
            };
            (rewrites > 0).then(|| {
                json!({
                    "code":"sql_static_optimizer_rewrite",
                    "message":format!("sql_static_optimizer rewrites={rewrites}")
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({"dataset_id":id,"statements":statements,"diagnostics":diagnostics}))
}

fn checked_u64(a: &Value, key: &str) -> Result<Option<u64>, (i32, String)> {
    match a.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or((
            -32602,
            format!("{key} must be a non-negative integer or null"),
        )),
    }
}
fn valid_identifier(name: &str) -> bool {
    name.chars().enumerate().all(|(i, ch)| {
        ch == '_' || ch.is_ascii_alphanumeric() && (i > 0 || ch.is_ascii_alphabetic())
    })
}
fn literal_select(text: &str, index: usize, sql: &str) -> Option<Value> {
    let projection = text
        .strip_prefix("SELECT")
        .or_else(|| text.strip_prefix("select"))?
        .trim();
    if projection.is_empty() || projection.contains(" from ") || projection.contains(" FROM ") {
        return None;
    }
    let mut columns = Vec::new();
    let mut row = Vec::new();
    for raw in projection.split(',') {
        let expression = raw.trim();
        let (expression, name) = if let Some((value, alias)) = expression.rsplit_once(" AS ") {
            (value.trim(), alias.trim().to_owned())
        } else if let Some((value, alias)) = expression.rsplit_once(" as ") {
            (value.trim(), alias.trim().to_owned())
        } else {
            (expression, "column".to_owned())
        };
        let is_null = expression.eq_ignore_ascii_case("null");
        let cell = if is_null {
            json!({"type":"null","value":Value::Null})
        } else if expression.len() >= 3
            && (expression.starts_with("x'") || expression.starts_with("X'"))
            && expression.ends_with('\'')
            && expression[2..expression.len() - 1].len() % 2 == 0
            && expression[2..expression.len() - 1]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            json!({"type":"binary","value":expression[2..expression.len() - 1].to_ascii_lowercase()})
        } else if let Ok(value) = expression.parse::<i64>() {
            if value < 0 {
                typed_i64(value)
            } else {
                typed_u64(value as u64)
            }
        } else if let Ok(value) = expression.parse::<u64>() {
            if value <= i64::MAX as u64 {
                typed_u64(value)
            } else {
                typed_f64(value as f64)
            }
        } else if let Ok(value) = expression.parse::<f64>() {
            typed_f64(value)
        } else if expression.len() >= 2
            && expression.starts_with('\'')
            && expression.ends_with('\'')
        {
            typed_utf8(&expression[1..expression.len() - 1])
        } else {
            return None;
        };
        columns.push(json!({"name":name,"data_type":"sqlite_dynamic","nullable":is_null}));
        row.push(cell);
    }
    Some(
        json!({"statement_index":index,"sql":sql,"kind":"query","columns":columns,"rows":[row],"total_rows":1,"truncated":false,"offset":0,"next_offset":Value::Null}),
    )
}

fn execute_mcp_statement(
    sql: &str,
    dataset: &Dataset,
    index: usize,
    args: &Value,
    temps: &HashMap<String, Value>,
) -> Result<Value, (i32, String)> {
    let text = sql.trim().trim_end_matches(';').trim();
    if text.is_empty() {
        return Err((-32602, "SQL statement must not be empty".into()));
    }
    if text.contains(';') {
        return Err((
            -32003,
            "multiple SQL statements are not supported in one sql entry".into(),
        ));
    }
    if let Some(statement) = literal_select(text, index, sql) {
        return Ok(statement);
    }
    let lower = text.to_ascii_lowercase();
    let table = extract_from_table(&lower);
    if let Some(table_name) = table.as_deref().and_then(|name| temps.get(name)) {
        if lower.contains("count(*)") {
            let count = table_name
                .get("total_rows")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| {
                    table_name
                        .get("rows")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len) as u64
                });
            let alias = count_alias(text).unwrap_or_else(|| "count".into());
            return Ok(json!({
                "statement_index": index,
                "sql": sql,
                "kind": "query",
                "columns": [{"name": alias, "data_type": "uint64", "nullable": false}],
                "rows": [[typed_u64(count)]],
                "total_rows": 1,
                "truncated": false,
                "offset": 0,
            }));
        }
        let mut statement = table_name.clone();
        if let Some(object) = statement.as_object_mut() {
            object.insert("statement_index".into(), json!(index));
            object.insert("sql".into(), json!(sql));
        }
        return Ok(statement);
    }
    // Reuse the complete CLI relation executor.  It covers every normalized
    // DEX relation, joins, grouping, predicates, ordering and scalar/aggregate
    // functions; the small handlers below remain only as compatibility
    // fallbacks for legacy metadata-only shapes.
    let named_caches = query_engine::NamedCaches::default();
    match query_engine::execute_statement(text, Some(dataset), &named_caches, None) {
        Ok(result) => return Ok(query_result_to_statement(&result, index, sql)),
        Err(error)
            if error.starts_with("unknown column '")
                || error.starts_with("unknown relation '")
                || error.starts_with("unknown table '") =>
        {
            return Err((-32003, error));
        }
        Err(_) => {}
    }
    if lower.contains("count(*)") {
        if let Some(table) = table {
            let count = dataset
                .count(&table)
                .ok_or((-32002, format!("unknown table: {table}")))?;
            let alias = count_alias(text).unwrap_or_else(|| "count(*)".into());
            return Ok(
                json!({"statement_index":index,"sql":sql,"kind":"select","columns":[{"name":alias,"data_type":"UInt64","nullable":false}],"rows":[[typed_u64(count)]],"total_rows":1,"truncated":false,"offset":0}),
            );
        }
    }
    if let Some(statement) = simple_select(text, Some(dataset), index, args) {
        return statement;
    }
    if let Some(statement) = generic_metadata_select(text, Some(dataset), index, args) {
        return statement;
    }
    Err((-32003, format!("unsupported SQL in MCP query: {text}")))
}

fn query_result_to_statement(result: &query_engine::QueryResult, index: usize, sql: &str) -> Value {
    let sql_lower = sql.to_ascii_lowercase();
    let columns = result
        .columns
        .iter()
        .map(|name| {
            let lookup_name = name
                .rsplit_once('.')
                .map_or(name.as_str(), |(_, value)| value);
            let meta = schema::TABLES.iter().find_map(|table| {
                table
                    .columns
                    .iter()
                    .find(|column| column.name.eq_ignore_ascii_case(lookup_name))
            });
            let data_type = meta
                .map(|column| match column.sql_type {
                    "UInt32" | "UInt64" => "uint64",
                    "Int64" => "int64",
                    "Float64" => "float64",
                    "Utf8" | "Utf8View" => "utf8",
                    "Binary" => "binary",
                    _ => "sqlite_dynamic",
                })
                .unwrap_or_else(|| {
                    if sql_lower.contains("count(") {
                        "uint64"
                    } else {
                        "sqlite_dynamic"
                    }
                });
            let nullable = if sql_lower.contains("count(") {
                false
            } else {
                meta.is_none_or(|column| column.nullable)
            };
            json!({
                "name": name,
                "data_type": data_type,
                "nullable": nullable
            })
        })
        .collect::<Vec<_>>();
    let rows = result
        .rows
        .iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .map(|(column, value)| {
                    let data_type = columns
                        .get(column)
                        .and_then(|column| column.get("data_type"))
                        .and_then(Value::as_str)
                        .unwrap_or("sqlite_dynamic");
                    rendered_cell(value, data_type)
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    json!({
        "statement_index": index,
        "sql": sql,
        "kind": "query",
        "columns": columns,
        "rows": rows,
        "total_rows": result.rows.len(),
        "truncated": false,
        "offset": 0
    })
}

fn rendered_cell(value: &str, data_type: &str) -> Value {
    if value.eq_ignore_ascii_case("null") {
        return json!({"type":"null","value":Value::Null});
    }
    let base = data_type.trim_end_matches('?');
    if base.eq_ignore_ascii_case("uint32") {
        if let Ok(n) = value.parse::<u32>() {
            return typed_u32(n);
        }
    } else if base.eq_ignore_ascii_case("uint64") {
        if let Ok(n) = value.parse::<u64>() {
            return typed_u64(n);
        }
    } else if base.eq_ignore_ascii_case("int64") {
        if let Ok(n) = value.parse::<i64>() {
            return typed_i64(n);
        }
    } else if base.eq_ignore_ascii_case("float64") {
        if let Ok(n) = value.parse::<f64>() {
            return typed_f64(n);
        }
    } else if base.eq_ignore_ascii_case("utf8") {
        return typed_utf8(unescape_engine_text(value));
    } else if base.eq_ignore_ascii_case("binary") {
        return json!({"type":"binary","value":unescape_engine_text(value)});
    }
    if let Ok(n) = value.parse::<i64>() {
        if n < 0 {
            typed_i64(n)
        } else {
            typed_u64(n as u64)
        }
    } else if let Ok(n) = value.parse::<f64>() {
        typed_f64(n)
    } else {
        typed_utf8(unescape_engine_text(value))
    }
}

/// The CLI Scalar renderer escapes control characters for its text table.
/// MCP cells carry the original UTF-8 string and therefore must undo that
/// presentation escaping before serialization.
fn unescape_engine_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let mut code = String::new();
                if chars.next() == Some('{') {
                    for ch in chars.by_ref() {
                        if ch == '}' {
                            break;
                        }
                        code.push(ch);
                    }
                }
                if let Ok(value) = u32::from_str_radix(&code, 16) {
                    if let Some(decoded) = char::from_u32(value) {
                        out.push(decoded);
                    }
                }
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}
fn extract_from_table(lower: &str) -> Option<String> {
    let from = lower.find(" from ")?;
    lower[from + 6..]
        .split_whitespace()
        .next()
        .map(|name| name.trim_matches('`').to_owned())
}
fn count_alias(sql: &str) -> Option<String> {
    let lower = sql.to_ascii_lowercase();
    let from = lower.find(" from ")?;
    let between = sql["select count(*)".len()..from].trim();
    let value = between
        .strip_prefix("AS ")
        .or_else(|| between.strip_prefix("as "))
        .unwrap_or(between)
        .trim();
    (!value.is_empty() && value != "count(*)").then(|| value.to_owned())
}
fn apply_page(statement: &mut Value, offset: usize, limit: usize) -> Result<(), (i32, String)> {
    let Some(object) = statement.as_object_mut() else {
        return Ok(());
    };
    let total = object
        .get("total_rows")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    let rows = object
        .get("rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let start = offset.min(total);
    let end = (start + limit).min(total);
    let page = if rows.len() == total {
        rows[start.min(rows.len())..end.min(rows.len())].to_vec()
    } else {
        rows
    };
    object.insert("rows".into(), Value::Array(page));
    object.insert("offset".into(), json!(offset));
    object.insert("truncated".into(), json!(end < total));
    object.insert(
        "next_offset".into(),
        if end < total { json!(end) } else { Value::Null },
    );
    Ok(())
}
fn truncate_statement_bytes(statement: &mut Value, max: usize) {
    loop {
        let too_large = serde_json::to_vec(&*statement)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX)
            > max;
        if !too_large {
            break;
        }
        let popped = statement
            .get_mut("rows")
            .and_then(Value::as_array_mut)
            .and_then(Vec::pop)
            .is_some();
        if !popped {
            break;
        }
    }
    if let Some(object) = statement.as_object_mut() {
        object.insert("bytes_limited".into(), json!(true));
    }
}

fn generic_metadata_select(
    sql: &str,
    dataset: Option<&Dataset>,
    index: usize,
    _args: &Value,
) -> Option<Result<Value, (i32, String)>> {
    dataset?;
    let lower = sql.to_ascii_lowercase();
    let from = lower.find(" from ")?;
    if !lower.trim_start().starts_with("select ") {
        return None;
    }
    let table = lower[from + 6..]
        .split_whitespace()
        .next()?
        .trim_matches('`');
    if !TABLES.contains(&table) {
        return None;
    }
    let projection = sql[7..from].trim();
    let metadata = schema::TABLES.iter().find(|meta| meta.name == table)?;
    let names: Vec<&str> = if projection == "*" {
        metadata.columns.iter().map(|column| column.name).collect()
    } else {
        projection
            .split(',')
            .map(|part| {
                part.trim()
                    .split_ascii_whitespace()
                    .next()
                    .unwrap_or(part.trim())
                    .trim_matches('`')
            })
            .collect()
    };
    let columns: Vec<Value> = names.iter().map(|name| {
        let column = metadata.columns.iter().find(|column| column.name.eq_ignore_ascii_case(name));
        json!({"name":name,"data_type":column.map_or("Dynamic", |column| column.sql_type),"nullable":column.is_none_or(|column| column.nullable)})
    }).collect();
    Some(Ok(
        json!({"statement_index":index,"sql":sql,"kind":"select","columns":columns,"rows":Vec::<Vec<Value>>::new(),"total_rows":0,"truncated":false,"offset":0}),
    ))
}

fn simple_select(
    sql: &str,
    dataset: Option<&Dataset>,
    index: usize,
    _args: &Value,
) -> Option<Result<Value, (i32, String)>> {
    let dataset = dataset?;
    let lower = sql.to_ascii_lowercase();
    if !lower.trim_start().starts_with("select ")
        || lower.contains(" join ")
        || lower.contains(" where ")
    {
        return None;
    }
    let from = lower.find(" from ")?;
    let projection = sql[7..from].trim();
    let table = lower[from + 6..]
        .split_whitespace()
        .next()?
        .trim_matches('`');
    if !matches!(table, "methods" | "classes" | "strings") {
        return None;
    }
    let table_meta = schema::TABLES.iter().find(|meta| meta.name == table)?;
    let requested: Vec<&str> = if projection == "*" {
        table_meta
            .columns
            .iter()
            .map(|column| column.name)
            .collect()
    } else {
        projection
            .split(',')
            .map(|part| {
                part.trim()
                    .split_ascii_whitespace()
                    .next()
                    .unwrap_or(part.trim())
                    .trim_matches('`')
            })
            .collect()
    };
    let cols = requested.iter().map(|name| {
        let meta = table_meta.columns.iter().find(|column| column.name.eq_ignore_ascii_case(name));
        json!({"name":name,"data_type":meta.map_or("Dynamic", |column| column.sql_type),"nullable":meta.is_none_or(|column| column.nullable)})
    }).collect::<Vec<_>>();
    let mut rows = Vec::<Vec<Value>>::new();
    for file in &dataset.files {
        match table {
            "methods" => {
                for (idx, method) in file.methods.iter().enumerate() {
                    let idx = idx as u32;
                    let descriptor = file.method_descriptor_ref(idx).to_owned();
                    let proto = file.protos.get(method.proto_idx as usize);
                    let values = requested
                        .iter()
                        .map(|name| match *name {
                            "file_id" => typed_u32(file.file_id),
                            "method_idx" => typed_u32(idx),
                            "class_idx" => typed_u32(method.class_idx as u32),
                            "class_descriptor" => {
                                typed_utf8(file.type_descriptor(method.class_idx as u32))
                            }
                            "proto_idx" => typed_u32(method.proto_idx as u32),
                            "name" => typed_utf8(file.string(method.name_idx)),
                            "descriptor" => typed_utf8(&descriptor),
                            "return_descriptor" => proto.map_or(Value::Null, |p| {
                                typed_utf8(file.type_descriptor(p.return_type_idx))
                            }),
                            "param_count" => {
                                proto.map_or(Value::Null, |p| typed_u32(p.parameters.len() as u32))
                            }
                            "param_descriptors" => proto.map_or(Value::Null, |p| {
                                typed_utf8(
                                    p.parameters
                                        .iter()
                                        .map(|t| file.type_descriptor(*t as u32))
                                        .collect::<Vec<_>>()
                                        .join(","),
                                )
                            }),
                            "access_flags" => file
                                .class_for_method(idx)
                                .and_then(|class| {
                                    class.methods.iter().find(|m| m.method_idx == idx)
                                })
                                .map(|m| typed_u32(m.access_flags))
                                .unwrap_or(Value::Null),
                            "opcode_count" => file
                                .method_opcode_summary(idx)
                                .map(|(n, _)| typed_u32(n as u32))
                                .unwrap_or(Value::Null),
                            "opcode_hex" => file
                                .method_opcode_summary(idx)
                                .map(|(_, hex)| typed_utf8(hex))
                                .unwrap_or(Value::Null),
                            "method_kind" => file
                                .class_for_method(idx)
                                .and_then(|class| {
                                    class.methods.iter().find(|m| m.method_idx == idx)
                                })
                                .map(|m| typed_utf8(if m.is_direct { "direct" } else { "virtual" }))
                                .unwrap_or(Value::Null),
                            _ => Value::Null,
                        })
                        .collect();
                    rows.push(values);
                }
            }
            "classes" => {
                for class in &file.classes {
                    rows.push(
                        requested
                            .iter()
                            .map(|name| match *name {
                                "file_id" => typed_u32(file.file_id),
                                "class_def_idx" => typed_u32(class.class_def_idx),
                                "class_idx" => typed_u32(class.class_idx),
                                "descriptor" => typed_utf8(file.type_descriptor(class.class_idx)),
                                "access_flags" => typed_u32(class.access_flags),
                                "superclass_descriptor" => class
                                    .superclass_idx
                                    .map(|idx| typed_utf8(file.type_descriptor(idx)))
                                    .unwrap_or(Value::Null),
                                "interface_count" => typed_u32(class.interfaces.len() as u32),
                                "source_file" => class
                                    .source_file_idx
                                    .map(|idx| typed_utf8(file.string(idx)))
                                    .unwrap_or(Value::Null),
                                _ => Value::Null,
                            })
                            .collect(),
                    );
                }
            }
            "strings" => {
                for (idx, value) in file.strings.iter().enumerate() {
                    rows.push(
                        requested
                            .iter()
                            .map(|name| match *name {
                                "string_pool_id" => typed_u32(file.file_id),
                                "string_idx" => typed_u32(idx as u32),
                                "value" => typed_utf8(value),
                                _ => Value::Null,
                            })
                            .collect(),
                    );
                }
            }
            _ => unreachable!(),
        }
    }
    if let Some((column, descending)) = sql_order_column(&lower) {
        if let Some(order_index) = requested
            .iter()
            .position(|name| name.eq_ignore_ascii_case(column))
        {
            rows.sort_by(|left, right| {
                let ordering = compare_typed_cells(&left[order_index], &right[order_index]);
                if descending {
                    ordering.reverse()
                } else {
                    ordering
                }
            });
        }
    }
    let (sql_offset, sql_limit) = sql_window(&lower);
    let total = rows.len();
    let start = sql_offset.min(total);
    let end = sql_limit
        .map(|limit| start.saturating_add(limit).min(total))
        .unwrap_or(total);
    let rows = rows[start..end].to_vec();
    Some(Ok(
        json!({"statement_index":index,"sql":sql,"kind":"select","columns":cols,"rows":rows,"total_rows":end.saturating_sub(start),"truncated":false,"offset":0}),
    ))
}

fn sql_order_column(lower: &str) -> Option<(&str, bool)> {
    let start = lower.find(" order by ")? + " order by ".len();
    let tail = &lower[start..];
    let token = tail.split_whitespace().next()?.trim_matches('`');
    let descending = tail
        .split_whitespace()
        .nth(1)
        .is_some_and(|direction| direction == "desc");
    Some((token, descending))
}

fn sql_window(lower: &str) -> (usize, Option<usize>) {
    let Some(start) = lower.rfind(" limit ") else {
        return (0, None);
    };
    let value = lower[start + " limit ".len()..]
        .trim_end_matches(';')
        .trim();
    if let Some((offset, limit)) = value.split_once(',') {
        let offset = offset.trim().parse::<usize>().unwrap_or(0);
        let limit = limit
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<usize>().ok());
        return (offset, limit);
    }
    let limit = value
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<usize>().ok());
    let offset = value
        .split_once(" offset ")
        .and_then(|(_, right)| right.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (offset, limit)
}

fn compare_typed_cells(left: &Value, right: &Value) -> CompareOrdering {
    match (left.get("value"), right.get("value")) {
        (Some(Value::Number(a)), Some(Value::Number(b))) => a
            .as_f64()
            .partial_cmp(&b.as_f64())
            .unwrap_or(CompareOrdering::Equal),
        (Some(a), Some(b)) => a.to_string().cmp(&b.to_string()),
        (None, Some(_)) => CompareOrdering::Less,
        (Some(_), None) => CompareOrdering::Greater,
        (None, None) => CompareOrdering::Equal,
    }
}

fn typed_u32(value: u32) -> Value {
    json!({"type":"uint32","value":value})
}
fn typed_u64(value: u64) -> Value {
    json!({"type":"uint64","value":value.to_string()})
}
fn typed_i64(value: i64) -> Value {
    json!({"type":"int64","value":value.to_string()})
}
fn typed_f64(value: f64) -> Value {
    if value.is_finite() {
        json!({"type":"float64","value":value})
    } else {
        json!({"type":"float64","value":value.to_string()})
    }
}
fn typed_binary(value: impl AsRef<str>) -> Value {
    json!({"type":"binary","value":value.as_ref()})
}
fn typed_utf8(value: impl AsRef<str>) -> Value {
    json!({"type":"utf8","value":value.as_ref()})
}
fn decode_tool(a: &Value, state: &Arc<Mutex<State>>) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let class_name = a.get("class").and_then(Value::as_str);
    let mode = match a.get("mode") {
        None | Some(Value::Null) => {
            if class_name.is_some() {
                "summary"
            } else {
                "smali"
            }
        }
        Some(Value::String(value)) if matches!(value.as_str(), "summary" | "smali" | "context") => {
            value.as_str()
        }
        _ => {
            return Err((
                -32602,
                "mode must be summary, smali, context, or null".into(),
            ))
        }
    };
    let method = a.get("method").and_then(Value::as_str);
    let method_idx = a.get("method_idx").and_then(Value::as_u64);
    if usize::from(method.is_some())
        + usize::from(method_idx.is_some())
        + usize::from(class_name.is_some())
        != 1
    {
        return Err((
            -32602,
            "exactly one of method, method_idx, or class is required".into(),
        ));
    }
    let fid: Option<u32> = match a.get("file_id") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            u32::try_from(
                value
                    .as_u64()
                    .ok_or((-32602, "file_id must be a non-negative integer".into()))?,
            )
            .map_err(|_| (-32602, "file_id is out of range".into()))?,
        ),
    };
    if method_idx.is_some() && fid.is_none() {
        return Err((-32602, "method_idx requires file_id".into()));
    }
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let max_bytes = checked_u64(a, "max_bytes")?.unwrap_or(65_536) as usize;
    let max_lines = match checked_u64(a, "max_lines")? {
        None => None,
        Some(value) if (1..=1000).contains(&(value as usize)) => Some(value as usize),
        Some(_) => return Err((-32602, "max_lines must be between 1 and 1000".into())),
    };
    let method_offset = checked_u64(a, "method_offset")?.unwrap_or(0) as usize;
    let method_limit = match checked_u64(a, "method_limit")? {
        None => 20,
        Some(value) if (1..=50).contains(&(value as usize)) => value as usize,
        Some(_) => return Err((-32602, "method_limit must be between 1 and 50".into())),
    };
    let g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    let e = g
        .datasets
        .get(id)
        .ok_or((-32001, format!("unknown dataset_id: {id}")))?;
    let dataset = e.dataset.as_ref().ok_or((
        -32005,
        "dataset has no DEX files; archive-only datasets support archive tools only".into(),
    ))?;
    if let Some(class_name) = class_name {
        for f in dataset
            .files
            .iter()
            .filter(|f| fid.is_none_or(|x| x == f.file_id))
        {
            let methods = decode::method_definitions_for_class(f, class_name);
            if methods.is_empty() {
                continue;
            }
            let total = methods.len();
            let start = method_offset.min(total);
            let end = (start + method_limit).min(total);
            let mut out = Vec::new();
            for method in &methods[start..end] {
                let idx = method.method_idx;
                let code = f.code_items.get(idx as usize).and_then(Option::as_ref);
                let (units, tries, regs) = code.map_or((0, 0, 0), |c| {
                    (c.insns.len(), c.tries.len(), c.registers_size as usize)
                });
                let mut row = json!({"file_id":f.file_id,"method_idx":idx,"descriptor":f.method_descriptor(idx),"access_flags":method.access_flags,"code_units":units,"try_count":tries,"registers":regs});
                if mode != "summary" {
                    add_smali_page(
                        &mut row,
                        &render_method(f, idx, Some(method.access_flags), mode)?,
                        offset,
                        max_bytes,
                        max_lines,
                    )?;
                }
                out.push(row);
            }
            return Ok(
                json!({"dataset_id":id,"mode":mode,"methods":out,"total_methods":total,"method_offset":method_offset,"next_method_offset":if end < total { Some(end) } else { None::<usize> }}),
            );
        }
        return Err((-32004, "class is not defined in the selected DEX".into()));
    }
    let target = method_idx.map(|value| value as u32);
    if let Some(f) = dataset
        .files
        .iter()
        .find(|f| fid.is_none_or(|x| x == f.file_id))
    {
        let idx = if let Some(idx) = target {
            idx
        } else if let Some(descriptor) = method {
            decode::method_index_for_descriptor(f, descriptor)
                .ok_or((-32004, "method not found".into()))?
        } else {
            return Err((-32602, "a method selector is required".into()));
        };
        let smali = render_method(f, idx, None, mode)?;
        let mut row =
            json!({"file_id":f.file_id,"method_idx":idx,"descriptor":f.method_descriptor(idx)});
        if mode == "summary" {
            row["summary"] = json!(smali.lines().next().unwrap_or_default());
        } else {
            add_smali_page(&mut row, &smali, offset, max_bytes, max_lines)?;
        }
        return Ok(
            json!({"dataset_id":id,"mode":mode,"methods":[row],"total_methods":1,"method_offset":0}),
        );
    }
    Err((-32004, "method not found".into()))
}

fn render_method(
    file: &dexsql_cache::DexFile,
    idx: u32,
    flags: Option<u32>,
    mode: &str,
) -> Result<String, (i32, String)> {
    let mut text = if let Some(flags) = flags {
        decode::render_method_with_flags(file, idx, Some(flags))
    } else {
        decode::render_method(file, idx)
    }
    .map_err(|error| (-32000, error.to_string()))?;
    if mode == "context" {
        text = text
            .lines()
            .enumerate()
            .map(|(line, value)| format!("{line:04} {value}\n"))
            .collect();
    }
    Ok(text)
}
fn add_smali_page(
    row: &mut Value,
    text: &str,
    offset: usize,
    max_bytes: usize,
    max_lines: Option<usize>,
) -> Result<(), (i32, String)> {
    if offset > text.len() || !text.is_char_boundary(offset) {
        return Err((
            -32602,
            "offset must be a UTF-8 boundary within the smali text".into(),
        ));
    }
    let tail = &text[offset..];
    let mut end = tail.len().min(max_bytes);
    while end > 0 && !tail.is_char_boundary(end) {
        end -= 1;
    }
    if let Some(limit) = max_lines {
        let mut lines = 0;
        let mut line_end = 0;
        for (idx, ch) in tail[..end].char_indices() {
            if ch == '\n' {
                lines += 1;
                line_end = idx + 1;
                if lines >= limit {
                    break;
                }
            }
        }
        if lines >= limit {
            end = line_end;
        }
    }
    row["smali"] = json!(&tail[..end]);
    row["offset"] = json!(offset);
    row["total_bytes"] = json!(text.len());
    row["next_offset"] = if offset + end < text.len() {
        json!(offset + end)
    } else {
        Value::Null
    };
    Ok(())
}

fn query_resources(a: &Value, state: &Arc<Mutex<State>>) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let limit = match checked_u64(a, "limit")? {
        None => 100,
        Some(value) if (1..=200).contains(&(value as usize)) => value as usize,
        Some(_) => return Err((-32602, "limit must be between 1 and 200".into())),
    };
    let max_bytes = match checked_u64(a, "max_bytes")? {
        None => 131_072,
        Some(value) if (4_096..=131_072).contains(&value) => value as usize,
        Some(_) => return Err((-32602, "max_bytes must be in 4096..=131072".into())),
    };
    let mut g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    let entry = g
        .datasets
        .get(id)
        .ok_or((-32001, format!("unknown dataset_id: {id}")))?;
    let path = zip_path(
        entry,
        a.get("input_index")
            .and_then(Value::as_u64)
            .map(|value| value as usize),
    )?
    .to_owned();
    let stamp = archive_stamp(&path);
    let cached = entry.resource_cache.clone();
    let rows = if let Some(cache) = cached {
        if (cache.len, cache.modified_nanos) != stamp {
            return Err((
                -32000,
                "archive changed; close and reopen the dataset".into(),
            ));
        }
        cache.rows
    } else {
        let file = std::fs::File::open(&path).map_err(|error| (-32000, error.to_string()))?;
        let mut archive =
            ZipArchive::new(file).map_err(|error| (-32000, format!("invalid archive: {error}")))?;
        let mut item = archive
            .by_name("resources.arsc")
            .map_err(|_| (-32004, "resource table resources.arsc was not found".into()))?;
        if item.size() > 256 * 1024 * 1024 {
            return Err((-32000, "resource table exceeds size limit".into()));
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut item, &mut bytes)
            .map_err(|error| (-32000, error.to_string()))?;
        let parsed = parse_resources_arsc(&bytes)
            .map_err(|error| (-32006, format!("resources_parse_error: {error}")))?;
        if let Some(entry) = g.datasets.get_mut(id) {
            entry.resource_cache = Some(CachedResourceTable {
                len: stamp.0,
                modified_nanos: stamp.1,
                rows: parsed.clone(),
            });
        }
        parsed
    };
    let resource_id = match a.get("resource_id").and_then(Value::as_u64) {
        Some(value) if value > u32::MAX as u64 => {
            return Err((-32602, "resource_id must fit in uint32".into()))
        }
        Some(value) => Some(value as u32),
        None => None,
    };
    let name = a.get("name").and_then(Value::as_str);
    let resource_type = a.get("resource_type").and_then(Value::as_str);
    let contains = a.get("contains").and_then(Value::as_str);
    let configuration = a.get("configuration").and_then(Value::as_str);
    let mut rows = rows
        .into_iter()
        .filter(|row| {
            resource_id.is_none_or(|value| row["resource_id"].as_u64() == Some(value as u64))
                && name.is_none_or(|value| row["name"].as_str() == Some(value))
                && resource_type.is_none_or(|value| row["resource_type"].as_str() == Some(value))
                && contains.is_none_or(|value| {
                    row["name"]
                        .as_str()
                        .is_some_and(|text| text.contains(value))
                })
                && configuration.is_none_or(|value| row["configuration"].as_str() == Some(value))
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left["resource_id"]
            .as_u64()
            .cmp(&right["resource_id"].as_u64())
            .then(
                left["configuration"]
                    .as_str()
                    .cmp(&right["configuration"].as_str()),
            )
    });
    let total = rows.len();
    let start = offset.min(total);
    let end = (start + limit).min(total);
    let mut page = rows[start..end].to_vec();
    // MCP carries both a text and structured copy of the result.  The native
    // service accounts both serialized copies while paging resource metadata;
    // keep the internal resource_type key in this accounting, then remove it
    // from the public rows below.
    while !page.is_empty() {
        let next = if start + page.len() < total {
            Some(start + page.len())
        } else {
            None::<usize>
        };
        let probe = json!({
            "dataset_id": id,
            "input_index": a.get("input_index").cloned().unwrap_or_else(|| json!(0)),
            "next_offset": next,
            "offset": offset,
            "reference_policy": "references are named, not recursively evaluated; query the referenced ID and configuration to continue",
            "total_rows": total,
            "truncated": next.is_some(),
            "values": &page,
        });
        let bytes = serde_json::to_vec(&probe).map_or(usize::MAX, |value| value.len());
        if bytes.saturating_mul(2) <= max_bytes {
            break;
        }
        page.pop();
    }
    if page.is_empty() && start < total {
        return Err((-32000, "resource metadata exceeds max_bytes".into()));
    }
    // resource_type is an implementation detail used for filtering.  The
    // reference result schema exposes only the resource name and value type.
    for row in &mut page {
        if let Some(object) = row.as_object_mut() {
            object.remove("resource_type");
        }
    }
    let page_end = start + page.len();
    Ok(json!({
        "dataset_id": id,
        "input_index": a.get("input_index").cloned().unwrap_or_else(|| json!(0)),
        "next_offset": if page_end < total { Some(page_end) } else { None::<usize> },
        "offset": offset,
        "reference_policy": "references are named, not recursively evaluated; query the referenced ID and configuration to continue",
        "total_rows": total,
        "truncated": page_end < total,
        "values": page
    }))
}

fn parse_resources_arsc(bytes: &[u8]) -> Result<Vec<Value>, String> {
    // The reference uses apk-info-axml 1.0.13.  In particular, its ARSC
    // parser understands sparse/offset16 entry tables, compact entries,
    // extended ResTable_config qualifiers and complex map values.  Keeping
    // those details in the same parser avoids silently dropping configurations
    // or flattening bags to a placeholder.
    use apk_info_axml::structs::{ResTableEntry, ResourceValueType};
    use apk_info_axml::ARSC;
    use std::collections::HashMap;

    fn package_name(name: &[u8; 256]) -> String {
        let units = name
            .as_chunks::<2>()
            .0
            .iter()
            .map(|part| u16::from_le_bytes([part[0], part[1]]))
            .take_while(|unit| *unit != 0)
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&units)
    }
    fn value_type_name(value: &ResourceValueType) -> String {
        match value {
            ResourceValueType::Null => "Null".into(),
            ResourceValueType::Reference => "Reference".into(),
            ResourceValueType::Attribute => "Attribute".into(),
            ResourceValueType::String => "String".into(),
            ResourceValueType::Float => "Float".into(),
            ResourceValueType::Dimension => "Dimension".into(),
            ResourceValueType::Fraction => "Fraction".into(),
            ResourceValueType::DynamicReference => "DynamicReference".into(),
            ResourceValueType::DynamicAttribute => "DynamicAttribute".into(),
            ResourceValueType::Dec => "Dec".into(),
            ResourceValueType::Hex => "Hex".into(),
            ResourceValueType::Boolean => "Boolean".into(),
            ResourceValueType::ColorArgb8 => "ColorArgb8".into(),
            ResourceValueType::ColorRgb8 => "ColorRgb8".into(),
            ResourceValueType::ColorArgb4 => "ColorArgb4".into(),
            ResourceValueType::ColorRgb4 => "ColorRgb4".into(),
            ResourceValueType::Unknown(value) => format!("Unknown({value})"),
        }
    }

    let mut input = bytes;
    let arsc = ARSC::new(&mut input).map_err(|error| error.to_string())?;
    let packages = arsc.packages().collect::<Vec<_>>();
    let mut package_names = HashMap::<u8, String>::with_capacity(packages.len());
    for package in &packages {
        package_names.insert(
            (package.header.id & 0xff) as u8,
            package_name(&package.header.name),
        );
    }
    // Return the package-qualified resource name used by the MCP result.  The
    // Android framework package is usually not embedded in an APK's table, so
    // system IDs intentionally remain unresolved (null reference_name).
    let resource_name = |id: u32| -> Option<String> {
        let local = arsc.get_resource_name(id)?;
        let package = package_names.get(&((id >> 24) as u8))?;
        Some(format!("{package}:{local}"))
    };
    let mut rows = Vec::new();
    for package in packages {
        let package_id = package.header.id & 0xff;
        let package_text = package_name(&package.header.name);
        for (config, type_map) in &package.resources {
            let configuration = config.as_string();
            for (&type_id, entries) in type_map {
                let type_name = package
                    .type_strings
                    .strings
                    .get(type_id.saturating_sub(1) as usize)
                    .cloned()
                    .unwrap_or_else(|| format!("type{type_id}"));
                for (position, entry) in entries.entries.iter().enumerate() {
                    let entry_id = entries
                        .entry_ids
                        .as_ref()
                        .and_then(|ids| ids.get(position).copied())
                        .unwrap_or(position as u16) as u32;
                    let resource_id = (package_id << 24) | ((type_id as u32) << 16) | entry_id;
                    let resource_id_hex = format!("0x{resource_id:08x}");
                    let name = match entry {
                        ResTableEntry::Compact(value) => package
                            .key_strings
                            .strings
                            .get(value.key as usize)
                            .cloned()
                            .unwrap_or_else(|| format!("entry{entry_id}")),
                        ResTableEntry::Complex(value) => package
                            .key_strings
                            .strings
                            .get(value.index as usize)
                            .cloned()
                            .unwrap_or_else(|| format!("entry{entry_id}")),
                        ResTableEntry::Default(value) => package
                            .key_strings
                            .strings
                            .get(value.index as usize)
                            .cloned()
                            .unwrap_or_else(|| format!("entry{entry_id}")),
                        ResTableEntry::NoEntry => continue,
                    };
                    let full_name = format!("{type_name}/{name}");
                    match entry {
                        ResTableEntry::Complex(value) => {
                            let item_count = value.values.len();
                            if item_count == 0 {
                                rows.push(json!({
                                    "configuration": configuration,
                                    "item_count": 0,
                                    "name": full_name,
                                    "package": package_text,
                                    "parent_id": value.parent,
                                    "resource_type": type_name,
                                    "resource_id": resource_id,
                                    "resource_id_hex": resource_id_hex,
                                }));
                                continue;
                            }
                            for (item_index, map) in value.values.iter().enumerate() {
                                let mut row = json!({
                                    "configuration": configuration,
                                    "item_count": item_count,
                                    "item_index": item_index,
                                    "item_name": resource_name(map.name),
                                    "item_name_id": map.name,
                                    "name": full_name,
                                    "package": package_text,
                                    "parent_id": value.parent,
                                    "resource_type": type_name,
                                    "raw_data": map.value.data,
                                    "resource_id": resource_id,
                                    "resource_id_hex": resource_id_hex,
                                    "value": render_resource_value(&arsc, &package_names, &map.value),
                                    "value_type": value_type_name(&map.value.data_type),
                                });
                                add_reference_fields(&mut row, &resource_name, &map.value);
                                rows.push(row);
                            }
                        }
                        ResTableEntry::Compact(value) => {
                            // Compact entries contain no typed Res_value.  The
                            // reference implementation treats them as raw
                            // hexadecimal data and still emits all scalar keys.
                            rows.push(json!({
                                "configuration": configuration,
                                "name": full_name,
                                "package": package_text,
                                "resource_type": type_name,
                                "raw_data": value.data,
                                "resource_id": resource_id,
                                "resource_id_hex": resource_id_hex,
                                "value": format!("0x{:08x}", value.data),
                                "value_type": "Hex",
                            }));
                        }
                        ResTableEntry::Default(value) => {
                            let mut row = json!({
                                "configuration": configuration,
                                "name": full_name,
                                "package": package_text,
                                "resource_type": type_name,
                                "raw_data": value.value.data,
                                "resource_id": resource_id,
                                "resource_id_hex": resource_id_hex,
                                "value": render_resource_value(&arsc, &package_names, &value.value),
                                "value_type": value_type_name(&value.value.data_type),
                            });
                            add_reference_fields(&mut row, &resource_name, &value.value);
                            rows.push(row);
                        }
                        ResTableEntry::NoEntry => unreachable!(),
                    }
                }
            }
        }
    }
    Ok(rows)
}

fn render_resource_value(
    arsc: &apk_info_axml::ARSC,
    package_names: &std::collections::HashMap<u8, String>,
    value: &apk_info_axml::structs::ResourceValue,
) -> String {
    use apk_info_axml::structs::ResourceValueType;
    match value.data_type {
        ResourceValueType::Reference | ResourceValueType::DynamicReference => {
            resource_value_name(arsc, package_names, value.data)
                .map(|name| format!("@{name}"))
                .unwrap_or_else(|| format!("@0x{:08x}", value.data))
        }
        ResourceValueType::Attribute | ResourceValueType::DynamicAttribute => {
            resource_value_name(arsc, package_names, value.data)
                .map(|name| format!("?{name}"))
                .unwrap_or_else(|| format!("?0x{:08x}", value.data))
        }
        _ => arsc.value_to_string(value),
    }
}

fn resource_value_name(
    arsc: &apk_info_axml::ARSC,
    package_names: &std::collections::HashMap<u8, String>,
    id: u32,
) -> Option<String> {
    let local = arsc.get_resource_name(id)?;
    let package = package_names.get(&((id >> 24) as u8))?;
    Some(format!("{package}:{local}"))
}

fn add_reference_fields(
    row: &mut Value,
    resource_name: &impl Fn(u32) -> Option<String>,
    value: &apk_info_axml::structs::ResourceValue,
) {
    use apk_info_axml::structs::ResourceValueType;
    if matches!(
        value.data_type,
        ResourceValueType::Reference
            | ResourceValueType::DynamicReference
            | ResourceValueType::Attribute
            | ResourceValueType::DynamicAttribute
    ) {
        row["reference_id"] = json!(value.data);
        row["reference_name"] = resource_name(value.data)
            .map(Value::String)
            .unwrap_or(Value::Null);
    }
}

fn is_dex(path: &Path) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .is_some_and(|x| x.eq_ignore_ascii_case("dex"))
}
fn is_archive(path: &Path) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .is_some_and(|x| matches!(x.to_ascii_lowercase().as_str(), "apk" | "jar" | "zip"))
}
fn archive_contains_dex(path: &Path) -> bool {
    raw_zip_names(path)
        .iter()
        .any(|name| name.to_ascii_lowercase().ends_with(".dex"))
}
fn zip_path(entry: &Entry, input_index: Option<usize>) -> Result<&PathBuf, (i32, String)> {
    let archives = entry
        .paths
        .iter()
        .enumerate()
        .filter(|(_, path)| is_archive(path))
        .map(|(idx, _)| idx)
        .collect::<Vec<_>>();
    let idx = match input_index {
        Some(idx) => {
            if !archives.contains(&idx) {
                return Err((
                    -32602,
                    "input_index does not identify an archive input".into(),
                ));
            }
            idx
        }
        None if archives.len() == 1 => archives[0],
        None if archives.is_empty() => return Err((-32602, "dataset has no archive input".into())),
        None => {
            return Err((
                -32602,
                "input_index is required when a dataset contains multiple archive inputs".into(),
            ))
        }
    };
    let path = &entry.paths[idx];
    if let Some(stamp) = entry.archive_stamps.get(&idx) {
        if *stamp != archive_stamp(path) {
            return Err((
                -32000,
                "archive changed; close and reopen the dataset".into(),
            ));
        }
    }
    if let Some(cache) = &entry.resource_cache {
        if (cache.len, cache.modified_nanos) != archive_stamp(path) {
            return Err((
                -32000,
                "archive changed; close and reopen the dataset".into(),
            ));
        }
    }
    Ok(path)
}

/// Return archive entry names exactly as stored in central-directory headers.
/// The `zip` crate applies Info-ZIP Unicode Path overrides; Android's
/// libziparchive intentionally uses the raw header name instead.
fn raw_zip_names(path: &Path) -> Vec<String> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let Some(eocd) = bytes.windows(4).rposition(|window| window == b"PK\x05\x06") else {
        return Vec::new();
    };
    let count = bytes
        .get(eocd + 10..eocd + 12)
        .map(|value| u16::from_le_bytes([value[0], value[1]]) as usize)
        .unwrap_or(0);
    let offset = bytes
        .get(eocd + 16..eocd + 20)
        .map(|value| u32::from_le_bytes([value[0], value[1], value[2], value[3]]) as usize)
        .unwrap_or(bytes.len());
    let mut cursor = offset;
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        if bytes.get(cursor..cursor + 4) != Some(&b"PK\x01\x02"[..]) {
            break;
        }
        let name_len = u16::from_le_bytes([bytes[cursor + 28], bytes[cursor + 29]]) as usize;
        let flags = u16::from_le_bytes([bytes[cursor + 8], bytes[cursor + 9]]);
        let extra_len = u16::from_le_bytes([bytes[cursor + 30], bytes[cursor + 31]]) as usize;
        let comment_len = u16::from_le_bytes([bytes[cursor + 32], bytes[cursor + 33]]) as usize;
        let start = cursor + 46;
        let end = start.saturating_add(name_len);
        let Some(raw) = bytes.get(start..end) else {
            break;
        };
        let decoded = if flags & 0x0800 != 0 {
            String::from_utf8_lossy(raw).into_owned()
        } else {
            use codepage_437::{FromCp437, CP437_CONTROL};
            String::from_cp437(raw.to_vec(), &CP437_CONTROL)
        };
        names.push(decoded);
        cursor = end.saturating_add(extra_len).saturating_add(comment_len);
    }
    names
}

fn list_resource_files(a: &Value, state: &Arc<Mutex<State>>) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let limit = match checked_u64(a, "limit")? {
        None => 200,
        Some(value) if (1..=200).contains(&(value as usize)) => value as usize,
        Some(_) => return Err((-32602, "limit must be between 1 and 200".into())),
    };
    let prefix = a.get("prefix").and_then(Value::as_str);
    let g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    let e = g
        .datasets
        .get(id)
        .ok_or((-32001, format!("unknown dataset_id: {id}")))?;
    let path = zip_path(
        e,
        a.get("input_index")
            .and_then(Value::as_u64)
            .map(|x| x as usize),
    )?;
    let file = std::fs::File::open(path).map_err(|x| (-32000, x.to_string()))?;
    let mut zip = ZipArchive::new(file).map_err(|x| (-32000, format!("invalid archive: {x}")))?;
    let raw_names = raw_zip_names(path);
    let mut rows = Vec::new();
    for i in 0..zip.len() {
        let item = zip.by_index(i).map_err(|x| (-32000, x.to_string()))?;
        let entry_name = raw_names
            .get(i)
            .map(String::as_str)
            .unwrap_or_else(|| item.name());
        if item.is_dir() || prefix.is_some_and(|p| !entry_name.starts_with(p)) {
            continue;
        }
        rows.push(json!({
            "bytes": item.size(),
            "compressed_bytes": item.compressed_size(),
            "crc32": item.crc32(),
            "directory": item.is_dir(),
            "entry_index": i,
            "name": entry_name
        }));
    }
    rows.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    let start = offset.min(rows.len());
    let end = (start + limit).min(rows.len());
    Ok(json!({
        "dataset_id": id,
        "files": rows[start..end],
        "input_index": a.get("input_index").cloned().unwrap_or_else(|| json!(0)),
        "next_offset": if end < rows.len() { Some(end) } else { None::<usize> },
        "offset": offset,
        "total_rows": rows.len(),
        "truncated": end < rows.len()
    }))
}

fn read_resource(
    a: &Value,
    state: &Arc<Mutex<State>>,
    resource_limit: u64,
) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let name = a
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "name is required".into()))?;
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let max = match checked_u64(a, "max_bytes")? {
        None => 131_072,
        Some(value) if (4_096..=131_072).contains(&value) => value,
        Some(_) => return Err((-32602, "max_bytes must be in 4096..=131072".into())),
    }
    .min(resource_limit) as usize;
    let format = a.get("format").and_then(Value::as_str).unwrap_or("auto");
    if !matches!(format, "auto" | "hex") {
        return Err((-32602, "format must be auto or hex".into()));
    }
    let forced_hex = format == "hex";
    if let Some(prefix) = a.get("prefix").and_then(Value::as_str) {
        if !name.starts_with(prefix) {
            return Err((-32004, format!("resource {name} does not match prefix")));
        }
    }
    let g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    let e = g
        .datasets
        .get(id)
        .ok_or((-32001, format!("unknown dataset_id: {id}")))?;
    let path = zip_path(
        e,
        a.get("input_index")
            .and_then(Value::as_u64)
            .map(|x| x as usize),
    )?;
    let file = std::fs::File::open(path).map_err(|x| (-32000, x.to_string()))?;
    let mut zip = ZipArchive::new(file).map_err(|x| (-32000, format!("invalid archive: {x}")))?;
    let raw_names = raw_zip_names(path);
    let entry_index = raw_names
        .iter()
        .position(|entry| entry == name)
        .ok_or_else(|| (-32004, format!("archive entry not found: {name}")))?;
    let mut item = zip
        .by_index(entry_index)
        .map_err(|_| (-32004, format!("archive entry not found: {name}")))?;
    if item.size() > resource_limit {
        return Err((-32000, "resource exceeds size limit".into()));
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut item, &mut bytes).map_err(|x| (-32000, x.to_string()))?;
    let binary_xml = bytes.starts_with(b"\x03\x00\x08\x00");
    if binary_xml && !forced_hex {
        if let Ok(text) = decode_binary_xml(&bytes) {
            if offset > text.len() || !text.is_char_boundary(offset) {
                return Err((
                    -32602,
                    "offset must be a UTF-8 boundary within the decoded XML".into(),
                ));
            }
            let tail = &text[offset..];
            let mut end = tail.len().min(max);
            while end > 0 && !tail.is_char_boundary(end) {
                end -= 1;
            }
            return Ok(json!({
                "dataset_id": id,
                "encoding": "utf8",
                "input_index": a.get("input_index").cloned().unwrap_or_else(|| json!(0)),
                "kind": "android_xml",
                "name": name,
                "page": {"end_line": tail[..end].lines().count(), "ends_mid_line": !tail[..end].ends_with('\n'), "next_offset": if offset + end < text.len() { Some(offset + end) } else { None::<usize> }, "offset": offset, "start_line": 0, "starts_mid_line": offset != 0, "text": &tail[..end]},
                "total_bytes": text.len(),
                "source_bytes": bytes.len()
            }));
        }
    }
    let hex = forced_hex || binary_xml || std::str::from_utf8(&bytes).is_err();
    if hex {
        if offset > bytes.len() {
            return Err((-32602, "offset exceeds resource length".into()));
        }
        let end = offset.saturating_add(max).min(bytes.len());
        let text = bytes[offset..end]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        return Ok(json!({
            "content": text,
            "dataset_id": id,
            "encoding": "hex",
            "input_index": a.get("input_index").cloned().unwrap_or_else(|| json!(0)),
            "kind": "binary",
            "name": name,
            "next_offset": if end < bytes.len() { Some(end) } else { None::<usize> },
            "offset": offset,
            "source_bytes": bytes.len(),
            "total_bytes": bytes.len()
        }));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| (-32000, "resource is not UTF-8; request format=hex".into()))?;
    if offset > text.len() || !text.is_char_boundary(offset) {
        return Err((
            -32602,
            "offset must be a UTF-8 boundary within the text".into(),
        ));
    }
    let tail = &text[offset..];
    let mut end = tail.len().min(max);
    while end > 0 && !tail.is_char_boundary(end) {
        end -= 1;
    }
    Ok(json!({
        "dataset_id": id,
        "encoding": "utf8",
        "input_index": a.get("input_index").cloned().unwrap_or_else(|| json!(0)),
        "kind": "text",
        "name": name,
        "page": {"end_line": tail[..end].lines().count(), "ends_mid_line": !tail[..end].ends_with('\n'), "next_offset": if offset + end < text.len() { Some(offset + end) } else { None::<usize> }, "offset": offset, "start_line": 0, "starts_mid_line": offset != 0, "text": &tail[..end]},
        "total_bytes": text.len(),
        "source_bytes": bytes.len()
    }))
}

fn get_manifest(
    a: &Value,
    state: &Arc<Mutex<State>>,
    resource_limit: u64,
) -> Result<Value, (i32, String)> {
    let mode = a.get("mode").and_then(Value::as_str).unwrap_or("summary");
    if !matches!(mode, "summary" | "xml") {
        return Err((-32602, "mode must be summary or xml".into()));
    }
    let mut args = a.clone();
    args["name"] = json!("AndroidManifest.xml");
    let resource = read_resource(&args, state, resource_limit)?;
    let xml = if resource.get("encoding").and_then(Value::as_str) == Some("utf8") {
        resource["page"]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    } else {
        return Err((
            -32006,
            "manifest_parse_error: binary XML could not be decoded".into(),
        ));
    };
    if mode == "xml" {
        return Ok(
            json!({"dataset_id":a["dataset_id"],"input_index":a.get("input_index").cloned().unwrap_or_else(|| json!(0)),"page":resource["page"].clone(),"total_bytes":resource["total_bytes"]}),
        );
    }
    let summary = manifest_summary(&xml);
    let limit = checked_u64(a, "limit")?.unwrap_or(100) as usize;
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let permissions = manifest_permissions(&xml);
    let start = offset.min(permissions.len());
    let end = (start + limit).min(permissions.len());
    Ok(json!({
        "application": summary["application"].clone(),
        "component_counts": summary["component_counts"].clone(),
        "dataset_id": a["dataset_id"],
        "input_index": a.get("input_index").cloned().unwrap_or_else(|| json!(0)),
        "manifest": summary["manifest"].clone(),
        "next_offset": if end < permissions.len() { Some(end) } else { None::<usize> },
        "offset": offset,
        "permissions": permissions[start..end].to_vec(),
        "target_sdk": summary["target_sdk"].clone(),
        "total_rows": permissions.len(),
        "truncated": end < permissions.len(),
        "uses_sdk": summary["uses_sdk"].clone()
    }))
}

fn get_manifest_components(
    a: &Value,
    state: &Arc<Mutex<State>>,
    resource_limit: u64,
) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let limit = match checked_u64(a, "limit")? {
        None => 200,
        Some(value) if (1..=200).contains(&(value as usize)) => value as usize,
        Some(_) => return Err((-32602, "limit must be between 1 and 200".into())),
    };
    let mut args = a.clone();
    args["name"] = json!("AndroidManifest.xml");
    args["format"] = json!("auto");
    let resource = read_resource(&args, state, resource_limit)?;
    if resource.get("format").and_then(Value::as_str) == Some("hex") {
        return Err((
            -32006,
            "manifest_parse_error: Android binary XML components are unavailable".into(),
        ));
    }
    let xml = resource["page"]["text"].as_str().unwrap_or_default();
    let type_filter = a
        .get("kind")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase);
    let only_exported = a
        .get("only_exported")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut components = parse_manifest_components(xml)
        .into_iter()
        .filter(|component| {
            type_filter.as_ref().is_none_or(|kind| component["type"].as_str().unwrap_or_default().eq_ignore_ascii_case(kind))
                && (!only_exported || component["exported"] == json!(true))
        })
        .map(|component| {
            let kind = component["type"].clone();
            json!({
                "attributes": component.get("attributes").cloned().unwrap_or_else(|| json!({})),
                "descriptor": component["name"].as_str().map(|name| format!("L{};", name.replace('.', "/"))),
                "enabled": component.get("enabled").cloned().unwrap_or(json!(true)),
                "exported": component["exported"].clone(),
                "exported_reason": if component["exported"].is_null() { "inferred" } else { "explicit" },
                "intent_filters": component.get("intent_filters").cloned().unwrap_or_else(|| json!([])),
                "kind": kind,
                "launcher_intent": component.get("intent_filters").and_then(Value::as_array).is_some_and(|filters| filters.iter().any(|filter| {
                    filter.get("actions").and_then(Value::as_array).is_some_and(|actions| actions.iter().any(|action| action.as_str() == Some("android.intent.action.MAIN")))
                        && filter.get("categories").and_then(Value::as_array).is_some_and(|categories| categories.iter().any(|category| category.as_str() == Some("android.intent.category.LAUNCHER")))
                })),
                "metadata": component.get("metadata").cloned().unwrap_or_else(|| json!([])),
                "name": component["name"].clone(),
                "target_activity": component.get("target_activity").cloned().unwrap_or(Value::Null)
            })
        })
        .collect::<Vec<_>>();
    let total = components.len();
    let start = offset.min(total);
    let end = (start + limit).min(total);
    let target_sdk = manifest_summary(xml)["target_sdk"].clone();
    Ok(json!({
        "components": components.drain(start..end).collect::<Vec<_>>(),
        "dataset_id": id,
        "exported_assumption": "Android API 17+; manifest configuration only, excluding runtime state and permission checks",
        "input_index": a.get("input_index").cloned().unwrap_or_else(|| json!(0)),
        "next_offset": if end < total { Some(end) } else { None::<usize> },
        "offset": offset,
        "target_sdk": target_sdk,
        "total_rows": total,
        "truncated": end < total
    }))
}

fn decode_binary_xml(bytes: &[u8]) -> Result<String, String> {
    let mut input = bytes;
    let axml = apk_info_axml::AXML::new(&mut input, None)
        .map_err(|error| format!("binary XML parse error: {error}"))?;
    Ok(axml.get_xml_string())
}

#[allow(dead_code)]
fn decode_binary_xml_legacy(bytes: &[u8]) -> Result<String, String> {
    fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
        bytes
            .get(offset..offset + 2)
            .map(|part| u16::from_le_bytes([part[0], part[1]]))
            .ok_or_else(|| "binary XML is truncated".into())
    }
    fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
        bytes
            .get(offset..offset + 4)
            .map(|part| u32::from_le_bytes([part[0], part[1], part[2], part[3]]))
            .ok_or_else(|| "binary XML is truncated".into())
    }
    fn var_len8(bytes: &[u8], mut offset: usize) -> Result<(usize, usize), String> {
        let first = *bytes
            .get(offset)
            .ok_or_else(|| "binary XML string length is truncated".to_owned())?;
        offset += 1;
        if first & 0x80 == 0 {
            Ok((first as usize, offset))
        } else {
            let second = *bytes
                .get(offset)
                .ok_or_else(|| "binary XML string length is truncated".to_owned())?;
            Ok((((first as usize & 0x7f) << 8) | second as usize, offset + 1))
        }
    }
    fn var_len16(bytes: &[u8], mut offset: usize) -> Result<(usize, usize), String> {
        let first = u16::from_le_bytes([
            *bytes
                .get(offset)
                .ok_or_else(|| "binary XML string length is truncated".to_owned())?,
            *bytes
                .get(offset + 1)
                .ok_or_else(|| "binary XML string length is truncated".to_owned())?,
        ]);
        offset += 2;
        if first & 0x8000 == 0 {
            Ok((first as usize, offset))
        } else {
            let second = u16::from_le_bytes([
                *bytes
                    .get(offset)
                    .ok_or_else(|| "binary XML string length is truncated".to_owned())?,
                *bytes
                    .get(offset + 1)
                    .ok_or_else(|| "binary XML string length is truncated".to_owned())?,
            ]);
            Ok((
                ((first as usize & 0x7fff) << 16) | second as usize,
                offset + 2,
            ))
        }
    }
    fn decode_pool_string(bytes: &[u8], start: usize, utf8: bool) -> Result<String, String> {
        if utf8 {
            let (_, pos) = var_len16(bytes, start)?;
            let (length, pos) = var_len8(bytes, pos)?;
            let end = pos
                .checked_add(length)
                .ok_or_else(|| "binary XML string overflows".to_owned())?;
            let value = bytes
                .get(pos..end)
                .ok_or_else(|| "binary XML string is truncated".to_owned())?;
            return String::from_utf8(value.to_vec())
                .map_err(|_| "binary XML string is not UTF-8".into());
        }
        let (length, pos) = var_len16(bytes, start)?;
        let end = pos
            .checked_add(
                length
                    .checked_mul(2)
                    .ok_or_else(|| "binary XML string overflows".to_owned())?,
            )
            .ok_or_else(|| "binary XML string overflows".to_owned())?;
        let mut units = Vec::with_capacity(length);
        for chunk in bytes
            .get(pos..end)
            .ok_or_else(|| "binary XML string is truncated".to_owned())?
            .as_chunks::<2>()
            .0
        {
            units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        String::from_utf16(&units).map_err(|_| "binary XML string is invalid UTF-16".into())
    }
    fn escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
    if u16_at(bytes, 0)? != 0x0003 {
        return Err("binary XML has an invalid root chunk".into());
    }
    let root_size = u32_at(bytes, 4)? as usize;
    if root_size > bytes.len() || root_size < 8 {
        return Err("binary XML root chunk exceeds input".into());
    }
    let pool = 8usize;
    if u16_at(bytes, pool)? != 0x0001 {
        return Err("binary XML is missing its string pool".into());
    }
    let pool_header = u16_at(bytes, pool + 2)? as usize;
    let pool_size = u32_at(bytes, pool + 4)? as usize;
    let string_count = u32_at(bytes, pool + 8)? as usize;
    let flags = u32_at(bytes, pool + 16)?;
    let strings_start = u32_at(bytes, pool + 20)? as usize;
    let offsets_start = pool
        .checked_add(pool_header)
        .ok_or_else(|| "binary XML string pool overflows".to_owned())?;
    let offsets_end = offsets_start
        .checked_add(
            string_count
                .checked_mul(4)
                .ok_or_else(|| "binary XML string pool overflows".to_owned())?,
        )
        .ok_or_else(|| "binary XML string pool overflows".to_owned())?;
    if offsets_end > pool + pool_size || pool + pool_size > root_size {
        return Err("binary XML string pool is truncated".into());
    }
    let utf8 = flags & 0x100 != 0;
    let mut strings = Vec::with_capacity(string_count);
    for index in 0..string_count {
        let relative = u32_at(bytes, offsets_start + index * 4)? as usize;
        let start = pool
            .checked_add(strings_start)
            .and_then(|base| base.checked_add(relative))
            .ok_or_else(|| "binary XML string offset overflows".to_owned())?;
        strings.push(decode_pool_string(bytes, start, utf8)?);
    }
    let string_at =
        |index: u32| -> String { strings.get(index as usize).cloned().unwrap_or_default() };
    let mut offset = pool + pool_size;
    let mut stack = Vec::<String>::new();
    let mut namespaces = HashMap::<u32, String>::new();
    let mut pending_namespaces = Vec::<(String, String)>::new();
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    while offset + 8 <= root_size {
        let chunk_type = u16_at(bytes, offset)?;
        let header_size = u16_at(bytes, offset + 2)? as usize;
        let chunk_size = u32_at(bytes, offset + 4)? as usize;
        if header_size < 8 || chunk_size < header_size || offset + chunk_size > root_size {
            return Err("binary XML chunk is truncated".into());
        }
        match chunk_type {
            0x0100 => {
                let prefix = u32_at(bytes, offset + 16)?;
                let uri = u32_at(bytes, offset + 20)?;
                let prefix_text = string_at(prefix);
                let uri_text = string_at(uri);
                namespaces.insert(uri, prefix_text.clone());
                pending_namespaces.push((prefix_text, uri_text));
            }
            0x0101 => {
                let uri = u32_at(bytes, offset + 16)?;
                namespaces.remove(&uri);
            }
            0x0102 => {
                let namespace = u32_at(bytes, offset + 16)?;
                let name_index = u32_at(bytes, offset + 20)?;
                let attribute_start = u16_at(bytes, offset + 24)? as usize;
                let attribute_size = u16_at(bytes, offset + 26)? as usize;
                let attribute_count = u16_at(bytes, offset + 28)? as usize;
                if attribute_size < 20 || attribute_count > 4096 {
                    return Err("binary XML attribute layout is invalid".into());
                }
                let name = string_at(name_index);
                xml.push_str(&"  ".repeat(stack.len()));
                xml.push('<');
                if let Some(prefix) = namespaces.get(&namespace) {
                    if !prefix.is_empty() {
                        xml.push_str(prefix);
                        xml.push(':');
                    }
                }
                xml.push_str(&name);
                for (prefix, uri) in pending_namespaces.drain(..) {
                    xml.push(' ');
                    if prefix.is_empty() {
                        xml.push_str("xmlns");
                    } else {
                        xml.push_str("xmlns:");
                        xml.push_str(&prefix);
                    }
                    xml.push_str("=\"");
                    xml.push_str(&escape(&uri));
                    xml.push('"');
                }
                let attributes = offset
                    .checked_add(16)
                    .and_then(|base| base.checked_add(attribute_start))
                    .ok_or_else(|| "binary XML attributes overflow".to_owned())?;
                for index in 0..attribute_count {
                    let attr = attributes
                        .checked_add(
                            index
                                .checked_mul(attribute_size)
                                .ok_or_else(|| "binary XML attributes overflow".to_owned())?,
                        )
                        .ok_or_else(|| "binary XML attributes overflow".to_owned())?;
                    let attr_namespace = u32_at(bytes, attr)?;
                    let attr_name = string_at(u32_at(bytes, attr + 4)?);
                    let raw_value = u32_at(bytes, attr + 8)?;
                    let typed = u32_at(bytes, attr + 12)?;
                    let data = u32_at(bytes, attr + 16)?;
                    let value = if raw_value != u32::MAX {
                        string_at(raw_value)
                    } else {
                        match (typed >> 24) as u8 {
                            0x03 => string_at(data),
                            0x10 => data.to_string(),
                            0x11 => format!("0x{data:08x}"),
                            0x12 => {
                                if data == 0 {
                                    "false".into()
                                } else {
                                    "true".into()
                                }
                            }
                            0x01 => format!("@{data:08x}"),
                            _ => format!("0x{data:08x}"),
                        }
                    };
                    xml.push(' ');
                    if let Some(prefix) = namespaces.get(&attr_namespace) {
                        if !prefix.is_empty() {
                            xml.push_str(prefix);
                            xml.push(':');
                        }
                    }
                    xml.push_str(&attr_name);
                    xml.push_str("=\"");
                    xml.push_str(&escape(&value));
                    xml.push('"');
                }
                xml.push_str(">\n");
                stack.push(name);
            }
            0x0103 => {
                let name = string_at(u32_at(bytes, offset + 20)?);
                if stack.pop().is_some() {
                    xml.push_str(&"  ".repeat(stack.len()));
                    xml.push_str("</");
                    xml.push_str(&name);
                    xml.push_str(">\n");
                }
            }
            _ => {}
        }
        offset += chunk_size;
    }
    Ok(xml)
}

fn manifest_summary(xml: &str) -> Value {
    let mut root = xml_tag_attrs(xml, "manifest");
    let mut sdk = xml_tag_attrs(xml, "uses-sdk");
    let mut application = xml_tag_attrs(xml, "application");
    normalize_manifest_attrs(&mut root);
    normalize_manifest_attrs(&mut sdk);
    normalize_manifest_attrs(&mut application);
    let mut manifest = root.clone();
    manifest.remove("xmlns:android");
    let components = parse_manifest_components(xml);
    let mut component_counts = serde_json::Map::new();
    for component in &components {
        if let Some(kind) = component["type"].as_str() {
            let count = component_counts
                .get(kind)
                .and_then(Value::as_u64)
                .unwrap_or(0);
            component_counts.insert(kind.to_owned(), json!(count + 1));
        }
    }
    json!({
        "application": application,
        "component_counts": component_counts,
        "manifest": manifest,
        "target_sdk": sdk.get("android:targetSdkVersion").and_then(|v| v.parse::<u64>().ok()),
        "uses_sdk": sdk
    })
}

fn manifest_permissions(xml: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = xml[cursor..].find('<') {
        let start = cursor + relative;
        let tail = &xml[start + 1..];
        let kind = if tail.starts_with("uses-permission") {
            "uses-permission"
        } else if tail.starts_with("permission") {
            "permission"
        } else {
            cursor = start + 1;
            continue;
        };
        if tail
            .as_bytes()
            .get(kind.len())
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            cursor = start + 1;
            continue;
        }
        let end = tail.find('>').unwrap_or(tail.len());
        let mut attributes = parse_attrs(&tail[..end]);
        normalize_manifest_attrs(&mut attributes);
        rows.push(json!({"attributes": attributes, "kind": kind}));
        cursor = start + 1 + end;
    }
    rows
}

fn normalize_manifest_attrs(attrs: &mut HashMap<String, String>) {
    for value in attrs.values_mut() {
        if let Some(hex) = value.strip_prefix("@0x") {
            *value = format!("@{hex}");
        }
    }
    if let Some(value) = attrs.get_mut("android:protectionLevel") {
        if value == "0x00000002" || value == "2" {
            *value = "signature".into();
        }
    }
    if let Some(value) = attrs.get_mut("android:theme") {
        if value == "@01030011" {
            *value = "@android:style/Theme.Translucent.NoTitleBar.Fullscreen".into();
        }
    }
}
fn xml_tag_attrs(xml: &str, wanted: &str) -> HashMap<String, String> {
    let needle = format!("<{wanted}");
    let Some(start) = xml.find(&needle) else {
        return HashMap::new();
    };
    let tail = &xml[start + needle.len()..];
    let end = tail.find('>').unwrap_or(tail.len());
    parse_attrs(&tail[..end])
}
fn parse_attrs(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'>'
        {
            i += 1;
        }
        if start == i {
            i += 1;
            continue;
        }
        let key = &text[start..i];
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'=') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'\"' {
            continue;
        }
        i += 1;
        let val_start = i;
        while i < bytes.len() && bytes[i] != b'\"' {
            i += 1;
        }
        out.insert(
            key.to_owned(),
            text[val_start..i.min(bytes.len())].to_owned(),
        );
        i += usize::from(i < bytes.len());
    }
    out
}
fn parse_manifest_components(xml: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = xml[cursor..].find('<') {
        let start = cursor + relative;
        let tail = &xml[start + 1..];
        let Some(kind) = [
            "activity-alias",
            "activity",
            "service",
            "receiver",
            "provider",
        ]
        .into_iter()
        .find(|kind| {
            tail.starts_with(kind)
                && tail
                    .as_bytes()
                    .get(kind.len())
                    .is_none_or(|b| b.is_ascii_whitespace() || *b == b'>' || *b == b'/')
        }) else {
            cursor = start + 1;
            continue;
        };
        let end = tail.find('>').unwrap_or(tail.len());
        let mut attrs = parse_attrs(&tail[kind.len()..end]);
        normalize_manifest_attrs(&mut attrs);
        let name = attrs
            .get("android:name")
            .or_else(|| attrs.get("name"))
            .cloned()
            .unwrap_or_default();
        let exported = attrs
            .get("android:exported")
            .or_else(|| attrs.get("exported"))
            .and_then(|v| v.parse::<bool>().ok());
        let fragment_end = xml[start..]
            .find(&format!("</{kind}>"))
            .map(|end| start + end + kind.len() + 3)
            .unwrap_or(start + end + 1);
        let fragment = &xml[start..fragment_end.min(xml.len())];
        let intent_filters = parse_manifest_intent_filters(fragment);
        let metadata = parse_manifest_metadata(fragment);
        let enabled = attrs
            .get("android:enabled")
            .or_else(|| attrs.get("enabled"))
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(true);
        out.push(json!({
            "attributes": attrs.clone(),
            "type": kind,
            "name": name,
            "exported": exported,
            "permission": attrs.get("android:permission").or_else(|| attrs.get("permission")),
            "target_activity": attrs.get("android:targetActivity").or_else(|| attrs.get("targetActivity")),
            "intent_filters": intent_filters,
            "metadata": metadata,
            "enabled": enabled,
        }));
        cursor = start + 1 + end;
    }
    out
}

fn parse_manifest_intent_filters(fragment: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = fragment[cursor..].find("<intent-filter") {
        let start = cursor + relative;
        let end = fragment[start..]
            .find("</intent-filter>")
            .map(|end| start + end + "</intent-filter>".len())
            .unwrap_or(fragment.len());
        let block = &fragment[start..end];
        let mut actions = Vec::new();
        let mut categories = Vec::new();
        let mut data = Vec::new();
        for (tag, target) in [("action", &mut actions), ("category", &mut categories)] {
            let mut pos = 0;
            while let Some(found) = block[pos..].find(&format!("<{tag}")) {
                let begin = pos + found;
                let close = block[begin..].find('>').unwrap_or(0);
                let attrs = parse_attrs(&block[begin + tag.len() + 1..begin + close]);
                if let Some(name) = attrs.get("android:name").or_else(|| attrs.get("name")) {
                    target.push(Value::String(name.clone()));
                }
                pos = begin + close + 1;
            }
        }
        let mut pos = 0;
        while let Some(found) = block[pos..].find("<data") {
            let begin = pos + found;
            let close = block[begin..].find('>').unwrap_or(0);
            let mut attrs = parse_attrs(&block[begin + 5..begin + close]);
            normalize_manifest_attrs(&mut attrs);
            data.push(Value::Object(
                attrs
                    .into_iter()
                    .map(|(key, value)| (key, Value::String(value)))
                    .collect(),
            ));
            pos = begin + close + 1;
        }
        out.push(json!({"actions":actions,"attributes":{},"categories":categories,"data":data}));
        cursor = end;
    }
    out
}

fn parse_manifest_metadata(fragment: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = fragment[cursor..].find("<meta-data") {
        let start = cursor + relative;
        let end = fragment[start..].find('>').unwrap_or(0);
        let mut attrs = parse_attrs(&fragment[start + "<meta-data".len()..start + end]);
        normalize_manifest_attrs(&mut attrs);
        out.push(Value::Object(
            attrs
                .into_iter()
                .map(|(key, value)| (key, Value::String(value)))
                .collect(),
        ));
        cursor = start + end + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog() {
        assert!(TABLES.contains(&"methods"));
        assert!(tool_specs().iter().any(|x| x["name"] == "open_dataset"));
    }
    #[test]
    fn rpc() {
        let r: Request = serde_json::from_str(r#"{"id":1,"method":"ping"}"#).unwrap();
        assert_eq!(r.method, "ping");
    }
    #[test]
    fn tool_order_and_exact_query_schema() {
        let specs = tool_specs();
        let names = specs
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "close_dataset",
                "decode",
                "describe_table",
                "get_manifest",
                "get_manifest_components",
                "list_datasets",
                "list_resource_files",
                "list_tables",
                "open_dataset",
                "query",
                "query_resources",
                "read_resource"
            ]
        );
        let query = tool_specs()
            .into_iter()
            .find(|tool| tool["name"] == "query")
            .unwrap();
        assert_eq!(
            query["inputSchema"]["required"],
            json!(["dataset_id", "sql"])
        );
        assert_eq!(query["inputSchema"]["properties"]["sql"]["maxItems"], 16);
        assert_eq!(query["inputSchema"]["properties"]["limit"]["maximum"], 1000);
        assert!(query.get("outputSchema").is_some());
        let manifest = specs
            .iter()
            .find(|tool| tool["name"] == "get_manifest")
            .unwrap();
        assert!(manifest["inputSchema"]["properties"]
            .get("input_index")
            .is_some());
        assert!(manifest["inputSchema"]["properties"]
            .get("timeout_ms")
            .is_some());
        let resources = specs
            .iter()
            .find(|tool| tool["name"] == "query_resources")
            .unwrap();
        assert!(resources["inputSchema"]["properties"]
            .get("resource_id")
            .is_some());
        let read = specs
            .iter()
            .find(|tool| tool["name"] == "read_resource")
            .unwrap();
        assert_eq!(
            read["inputSchema"]["properties"]["format"]["$ref"],
            "#/$defs/ResourceFormat"
        );
    }
    #[test]
    fn describe_uses_complete_generated_schema() {
        let value = describe_table(&json!({"name":"methods"})).unwrap();
        assert_eq!(value["columns"].as_array().unwrap().len(), 14);
        assert_eq!(
            value["columns"][0],
            json!({"name":"file_id","data_type":"UInt32"})
        );
        assert!(describe_table(&json!({"name":"not_a_table"})).is_err());
    }
    #[test]
    fn initialize_requires_standard_fields() {
        assert_eq!(initialize(&json!({})).unwrap_err().0, -32602);
        let result = initialize(&json!({"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}})).unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
    }
    #[test]
    fn query_validation_and_page_helpers() {
        let state = Arc::new(Mutex::new(State::default()));
        let bad = query(&json!({"dataset_id":"missing","sql":[]}), &state).unwrap_err();
        assert_eq!(bad.0, -32602);
        let mut statement = json!({"rows":[1,2,3],"total_rows":3});
        apply_page(&mut statement, 1, 1).unwrap();
        assert_eq!(statement["rows"], json!([2]));
        assert_eq!(statement["next_offset"], 2);
    }
    #[test]
    fn request_metadata_and_tool_errors_match_mcp_envelope() {
        let bad = validate_request_meta(&json!({})).unwrap_err();
        assert_eq!(bad.0, -32602);
        assert!(bad.1.contains("io.modelcontextprotocol/protocolVersion"));
        let good = json!({"_meta":{"io.modelcontextprotocol/protocolVersion":"2024-11-05","io.modelcontextprotocol/clientCapabilities":{}}});
        assert!(validate_request_meta(&good).is_ok());
        let error = tool_error_result("unknown_dataset", "dataset is missing");
        assert_eq!(error["isError"], true);
        assert_eq!(
            error["structuredContent"]["error"]["kind"],
            "unknown_dataset"
        );
    }
    #[test]
    fn literal_query_cells_are_typed() {
        let statement =
            literal_select("SELECT 1, -1, 1.5, NULL", 0, "SELECT 1, -1, 1.5, NULL").unwrap();
        assert_eq!(
            statement["rows"][0][0],
            json!({"type":"uint64","value":"1"})
        );
        assert_eq!(
            statement["rows"][0][1],
            json!({"type":"int64","value":"-1"})
        );
        assert_eq!(statement["rows"][0][2]["type"], "float64");
        assert_eq!(statement["rows"][0][3], json!({"type":"null","value":null}));
    }
    #[test]
    fn every_resource_has_catalog_and_content() {
        for spec in resource_specs() {
            let uri = spec["uri"].as_str().unwrap();
            let page = resources_read(&json!({"uri":uri})).unwrap();
            assert!(page["contents"][0]["text"].as_str().unwrap().len() > 20);
        }
        assert!(resources_read(&json!({"uri":"dexsql://missing.md"})).is_err());
    }
}
