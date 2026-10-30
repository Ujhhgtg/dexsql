//! JNI bridge for `dev.ujhhgtg.dexsql.DexSqlNative`.
//!
//! Sessions are IDs in a process-wide registry rather than raw pointers: an
//! in-flight query keeps its `Arc<Engine>` alive when another thread closes the
//! handle, and a stale handle is reported as a structured error instead of
//! becoming a use-after-free.
//!
//! Every operation that can fail returns a small JSON envelope,
//! `{"ok":true,...}` or `{"ok":false,"error":{"kind":...,"message":...}}`, so
//! no Java exception is ever raised from native code. Strings cross the
//! boundary as UTF-16 (`GetStringChars`/`NewString`) because query results and
//! metadata carry arbitrary host strings that modified UTF-8 would mangle.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use dexsql::{Engine, EngineOptions, Error as DexSqlError, IndexNeeds, MetaQuery};
use jni_sys::{JNIEnv, jlong, jobject, jobjectArray, jsize, jstring};
use serde_json::{Value, json};

type Session = Arc<Engine>;

static SESSIONS: OnceLock<Mutex<HashMap<jlong, Session>>> = OnceLock::new();
static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);

fn sessions() -> &'static Mutex<HashMap<jlong, Session>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn registry() -> std::sync::MutexGuard<'static, HashMap<jlong, Session>> {
    // A panic while holding the lock cannot leave the map half-updated
    // (insert/remove are atomic), so a poisoned registry is still usable.
    sessions()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ─── JSON envelopes ──────────────────────────────────────────────────────────

fn json_string(value: Value) -> String {
    serde_json::to_string(&value)
        .unwrap_or_else(|error| failure("serialization", error.to_string()))
}

fn success(value: Value) -> String {
    let mut object = match value {
        Value::Object(object) => object,
        other => {
            let mut object = serde_json::Map::new();
            object.insert("value".to_owned(), other);
            object
        }
    };
    object.insert("ok".to_owned(), Value::Bool(true));
    json_string(Value::Object(object))
}

fn failure(kind: &str, message: impl Into<String>) -> String {
    // Built by hand so this path cannot recurse into json_string's fallback.
    let error = json!({ "kind": kind, "message": message.into() });
    format!("{{\"ok\":false,\"error\":{error}}}")
}

fn engine_error(error: DexSqlError) -> String {
    match error {
        DexSqlError::Load(message) => failure("load", message),
        DexSqlError::Query(message) => failure("query", message),
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "native panic".to_owned()
    }
}

/// Runs `body`, converting a Rust panic into a `panic` envelope so it never
/// unwinds into the JVM.
fn guarded(body: impl FnOnce() -> String) -> String {
    catch_unwind(AssertUnwindSafe(body))
        .unwrap_or_else(|payload| failure("panic", panic_message(payload)))
}

// ─── JNI string helpers ──────────────────────────────────────────────────────

/// Copies a Java string into an owned Rust `String`; `None` for null or
/// unreadable strings (any pending Java exception is cleared).
fn read_string(env: *mut JNIEnv, value: jstring) -> Option<String> {
    if env.is_null() || value.is_null() {
        return None;
    }
    unsafe {
        let fns = &**env;
        let len = (fns.v1_1.GetStringLength)(env, value);
        let chars = (fns.v1_1.GetStringChars)(env, value, std::ptr::null_mut());
        if chars.is_null() {
            if (fns.v1_2.ExceptionCheck)(env) {
                (fns.v1_1.ExceptionClear)(env);
            }
            return None;
        }
        let units = std::slice::from_raw_parts(chars, len.max(0) as usize);
        let decoded = String::from_utf16(units).ok();
        (fns.v1_1.ReleaseStringChars)(env, value, chars);
        decoded
    }
}

fn read_string_array(env: *mut JNIEnv, array: jobjectArray) -> Result<Vec<String>, String> {
    if env.is_null() || array.is_null() {
        return Err("path array is null".to_owned());
    }
    unsafe {
        let fns = &**env;
        let len = (fns.v1_1.GetArrayLength)(env, array);
        let mut result = Vec::with_capacity(len.max(0) as usize);
        for index in 0..len {
            let item = (fns.v1_1.GetObjectArrayElement)(env, array, index as jsize) as jstring;
            let value = read_string(env, item);
            if !item.is_null() {
                (fns.v1_1.DeleteLocalRef)(env, item as jobject);
            }
            result.push(value.ok_or_else(|| format!("path #{index} is null or unreadable"))?);
        }
        Ok(result)
    }
}

fn new_string(env: *mut JNIEnv, value: &str) -> jstring {
    if env.is_null() {
        return std::ptr::null_mut();
    }
    let utf16: Vec<u16> = value.encode_utf16().collect();
    unsafe {
        let fns = &**env;
        (fns.v1_1.NewString)(
            env,
            utf16.as_ptr(),
            jsize::try_from(utf16.len()).unwrap_or(jsize::MAX),
        )
    }
}

// ─── Sessions ────────────────────────────────────────────────────────────────

fn session_for(handle: jlong) -> Result<Session, String> {
    if handle <= 0 {
        return Err(failure("invalid_handle", "session handle must be positive"));
    }
    registry().get(&handle).cloned().ok_or_else(|| {
        failure(
            "invalid_handle",
            format!("unknown DexSQL session handle {handle}"),
        )
    })
}

fn insert_session(engine: Engine) -> jlong {
    let mut registry = registry();
    loop {
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        if handle > 0 && !registry.contains_key(&handle) {
            registry.insert(handle, Arc::new(engine));
            return handle;
        }
    }
}

/// Index set used by every session: the SQL DSL and query matcher read method
/// strings, numbers, calls and field accesses, and opcode/annotation
/// constraints need full code items.
fn engine_options() -> EngineOptions {
    EngineOptions {
        index_needs: IndexNeeds {
            method_lookup: true,
            method_strings: true,
            method_numbers: true,
            method_calls: true,
            method_field_accesses: true,
            method_used_types: false,
            ..IndexNeeds::default()
        },
        eager_code_items: true,
        full_code_items: true,
        retain_classes: true,
        threads: None,
    }
}

// ─── JNI exports ─────────────────────────────────────────────────────────────

/// `open([Ljava/lang/String;)Ljava/lang/String;`
///
/// Envelope: `{ok:true, handle:<long>}` or `{ok:false,error}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_ujhhgtg_dexsql_DexSqlNative_open(
    env: *mut JNIEnv,
    _this: jobject,
    paths: jobjectArray,
) -> jstring {
    let response = guarded(|| {
        let paths = match read_string_array(env, paths) {
            Ok(paths) if !paths.is_empty() => paths,
            Ok(_) => return failure("invalid_input", "at least one input path is required"),
            Err(error) => return failure("invalid_input", error),
        };
        match Engine::open_with_options(paths, engine_options()) {
            Ok(engine) => success(json!({ "handle": insert_session(engine) })),
            Err(error) => engine_error(error),
        }
    });
    new_string(env, &response)
}

/// `query(JLjava/lang/String;)Ljava/lang/String;`
///
/// Envelope: `{ok:true, columns:[...], rows:[[...]]}` or `{ok:false,error}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_ujhhgtg_dexsql_DexSqlNative_query(
    env: *mut JNIEnv,
    _this: jobject,
    handle: jlong,
    sql: jstring,
) -> jstring {
    let response = guarded(|| {
        let session = match session_for(handle) {
            Ok(session) => session,
            Err(error) => return error,
        };
        let Some(sql) = read_string(env, sql) else {
            return failure("invalid_input", "SQL string is null or unreadable");
        };
        match session.query(&sql) {
            Ok(result) => success(json!({ "columns": result.columns, "rows": result.rows })),
            Err(error) => engine_error(error),
        }
    });
    new_string(env, &response)
}

/// `metadata(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;`
///
/// `kind` is `class`, `method` or `field`; `descriptor` is a DEX descriptor.
/// Envelope: `{ok:true, metadata:<object|null>}` or `{ok:false,error}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_ujhhgtg_dexsql_DexSqlNative_metadata(
    env: *mut JNIEnv,
    _this: jobject,
    handle: jlong,
    kind: jstring,
    descriptor: jstring,
) -> jstring {
    let response = guarded(|| {
        let session = match session_for(handle) {
            Ok(session) => session,
            Err(error) => return error,
        };
        let (Some(kind), Some(descriptor)) = (read_string(env, kind), read_string(env, descriptor))
        else {
            return failure(
                "invalid_input",
                "metadata kind or descriptor is null or unreadable",
            );
        };
        let query = match kind.to_ascii_lowercase().as_str() {
            "class" => MetaQuery::class(descriptor),
            "method" => MetaQuery::method(descriptor),
            "field" => MetaQuery::field(descriptor),
            other => return failure("invalid_kind", format!("unknown metadata kind {other}")),
        };
        match session.metadata(&query) {
            Ok(value) => success(json!({ "metadata": value })),
            Err(error) => failure("metadata", error),
        }
    });
    new_string(env, &response)
}

/// `metadataCallers(JLjava/lang/String;)Ljava/lang/String;`
///
/// Envelope: `{ok:true, callers:<array|null>}` or `{ok:false,error}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_ujhhgtg_dexsql_DexSqlNative_metadataCallers(
    env: *mut JNIEnv,
    _this: jobject,
    handle: jlong,
    descriptor: jstring,
) -> jstring {
    let response = guarded(|| {
        let session = match session_for(handle) {
            Ok(session) => session,
            Err(error) => return error,
        };
        let Some(descriptor) = read_string(env, descriptor) else {
            return failure("invalid_input", "caller descriptor is null or unreadable");
        };
        match session.metadata_callers(&descriptor) {
            Ok(value) => success(json!({ "callers": value })),
            Err(error) => failure("metadata", error),
        }
    });
    new_string(env, &response)
}

/// `close(J)Ljava/lang/String;`
///
/// Envelope: `{ok:true, closed:true}` or `{ok:false,error}` for an unknown
/// handle. In-flight queries keep their engine alive until they return.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_ujhhgtg_dexsql_DexSqlNative_close(
    env: *mut JNIEnv,
    _this: jobject,
    handle: jlong,
) -> jstring {
    let response = guarded(|| {
        if handle <= 0 {
            return failure("invalid_handle", "session handle must be positive");
        }
        match registry().remove(&handle) {
            Some(_) => success(json!({ "closed": true })),
            None => failure(
                "invalid_handle",
                format!("unknown DexSQL session handle {handle}"),
            ),
        }
    });
    new_string(env, &response)
}
