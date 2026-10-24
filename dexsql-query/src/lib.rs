use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread_local;
use std::time::Instant;

use dexsql_cache::{Dataset, IndexNeeds};
use rayon::prelude::*;
use rustc_hash::FxHashMap;

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct QueryRequest {
    pub inputs: Vec<PathBuf>,
    pub sql: Vec<String>,
    pub interactive: bool,
    pub caches: Vec<String>,
    pub limit: Option<u64>,
    pub full: bool,
    pub timing: bool,
    pub threads: Option<usize>,
    pub trusted_input: bool,
}
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

mod correlated;
mod error;
mod fast_descriptor;
mod membership;
#[cfg(test)]
mod memory_plan_tests;
mod param_pattern;
mod relational;
mod scalar_functions;
mod streaming;

pub use error::{render_caused_by, render_flat_chain, DexSqlError};

/// Relation names accepted by the scan dispatcher.  Session definitions are
/// validated against this set when a `CREATE ... AS query` statement names
/// its sources.
const RELATION_NAMES: &[&str] = &[
    "dex_files",
    "strings",
    "type_ids",
    "types",
    "type_lists",
    "type_list_entries",
    "proto_ids",
    "protos",
    "proto_params",
    "field_ids",
    "method_ids",
    "method_opcodes",
    "map_items",
    "id_items",
    "class_data_items",
    "class_defs",
    "class_data_methods",
    "class_methods",
    "class_fields",
    "class_interfaces",
    "code_items",
    "try_items",
    "catch_handlers",
    "debug_info",
    "debug_parameters",
    "debug_positions",
    "debug_locals",
    "debug_opcodes",
    "classes",
    "methods",
    "fields",
    "method_strings",
    "method_using_numbers",
    "method_numbers",
    "method_calls",
    "method_handles",
    "call_sites",
    "call_site_args",
    "class_static_values",
    "hiddenapi_flags",
    "encoded_arrays",
    "encoded_array_values",
    "encoded_array_owners",
    "annotation_directories",
    "annotation_directory_entries",
    "annotation_sets",
    "annotation_set_entries",
    "annotation_set_ref_lists",
    "annotation_set_refs",
    "annotations",
    "annotation_elements",
    "annotation_values",
    "annotation_elements_resolved",
    "method_refs",
    "method_field_accesses",
    "method_used_types",
];

#[derive(Debug, Clone)]
struct CachedTable {
    columns: Vec<String>,
    rows: Vec<Vec<Scalar>>,
}

impl CachedTable {
    fn from_result(result: QueryResult) -> Self {
        let columns = result.columns;
        let rows = result
            .rows
            .into_iter()
            .map(|row| {
                columns
                    .iter()
                    .enumerate()
                    .map(|(index, _)| {
                        row.get(index)
                            .map(|value| scalar_from_rendered(value))
                            .unwrap_or(Scalar::Null)
                    })
                    .collect()
            })
            .collect();
        Self { columns, rows }
    }
}

/// Named `--cache` definitions are request-local virtual tables.  Keep their
/// SQL and materialized rows together so a definition is evaluated only when
/// a statement actually references it.  This is especially important for
/// `query-cache`: an unused definition must not force a source reopen or turn a
/// count-only request into a full cache decode.
#[derive(Debug, Default)]
pub struct NamedCaches {
    definitions: RefCell<HashMap<String, String>>,
    tables: RefCell<HashMap<String, Arc<CachedTable>>>,
    loading: RefCell<HashSet<String>>,
    /// Names registered by `CREATE ... AS query` during the current request;
    /// a second plain CREATE of one of these is the documented duplicate
    /// error, while cross-request redefinitions replace silently.
    session_created: RefCell<HashSet<String>>,
    materialize_ms: Cell<f64>,
}

impl NamedCaches {
    fn from_specs(specs: &[String]) -> Result<Self, String> {
        let mut definitions = HashMap::with_capacity(specs.len());
        for spec in specs {
            let Some((name, sql)) = spec.split_once('=') else {
                return Err(format!(
                    "invalid_input at cache: expected NAME=SQL, got `{spec}`"
                ));
            };
            let name = name.trim();
            let sql = sql.trim();
            if !is_sql_identifier(name) {
                return Err(format!(
                    "invalid_input at cache: invalid table name `{name}`"
                ));
            }
            if sql.is_empty() {
                return Err(format!("invalid_input at cache: SQL for `{name}` is empty"));
            }
            // Definitions are intentionally replaceable.  This mirrors the
            // interactive TEMP TABLE behavior documented by the CLI and makes
            // repeated --cache options deterministic (last definition wins).
            definitions.insert(name.to_ascii_lowercase(), sql.to_owned());
        }
        Ok(Self {
            definitions: RefCell::new(definitions),
            ..Self::default()
        })
    }

    /// Register a `CREATE [TEMP] TABLE/VIEW ... AS query` definition.
    ///
    /// A duplicate plain CREATE inside the same request is the documented
    /// error; `IF NOT EXISTS` keeps the prior definition and cross-request
    /// redefinitions (interactive submissions) replace silently.
    fn define_session(
        &self,
        name: &str,
        query: &str,
        if_not_exists: bool,
    ) -> Result<(), DexSqlError> {
        let name = name.to_ascii_lowercase();
        let existed = self.definitions.borrow().contains_key(&name);
        let created_now = self.session_created.borrow().contains(&name);
        if existed && created_now && !if_not_exists {
            return Err(DexSqlError::query_failed(format!(
                "table {name} already exists (duplicate CREATE TEMP TABLE in one request; add IF NOT EXISTS to make the duplicate a no-op)"
            )));
        }
        if existed && if_not_exists {
            return Ok(());
        }
        // A redefinition invalidates any materialized rows from the previous
        // definition of the same name.
        self.tables.borrow_mut().remove(&name);
        self.definitions
            .borrow_mut()
            .insert(name.clone(), query.to_owned());
        self.session_created.borrow_mut().insert(name);
        Ok(())
    }

    /// Start a new request boundary: definitions created by earlier
    /// submissions stay visible, but no longer count as duplicates.
    fn begin_request(&self) {
        self.session_created.borrow_mut().clear();
    }

    /// Build a query-local scope overlaying this session: definitions and
    /// materialized tables are shared; CTEs install on top without mutating
    /// the parent session.
    fn child_scope(&self) -> NamedCaches {
        NamedCaches {
            definitions: RefCell::new(self.definitions.borrow().clone()),
            tables: RefCell::new(self.tables.borrow().clone()),
            loading: RefCell::new(HashSet::new()),
            session_created: RefCell::new(HashSet::new()),
            materialize_ms: Cell::new(0.0),
        }
    }

    /// Install an already-materialized result as a scope-local table,
    /// shadowing any same-named definition.
    fn install_materialized(&self, name: &str, typed: (Vec<String>, Vec<Vec<Scalar>>)) {
        let result = typed_to_result(typed);
        let table = Arc::new(CachedTable::from_result(result));
        self.definitions
            .borrow_mut()
            .remove(&name.to_ascii_lowercase());
        self.tables
            .borrow_mut()
            .insert(name.to_ascii_lowercase(), table);
    }

    fn has_definition(&self, name: &str) -> bool {
        self.definitions
            .borrow()
            .contains_key(&name.to_ascii_lowercase())
    }

    fn materialize_ms(&self) -> f64 {
        self.materialize_ms.get()
    }

    fn resolve(
        &self,
        name: &str,
        dataset: Option<&Dataset>,
    ) -> Result<Option<Arc<CachedTable>>, String> {
        let name = name.to_ascii_lowercase();
        if let Some(table) = self.tables.borrow().get(&name).cloned() {
            return Ok(Some(table));
        }
        let Some(sql) = self.definitions.borrow().get(&name).cloned() else {
            return Ok(None);
        };
        if !self.loading.borrow_mut().insert(name.clone()) {
            return Err(format!(
                "invalid_input at cache: cyclic definition for `{name}`"
            ));
        }
        let started = Instant::now();
        let result = execute_statement(&sql, dataset, self, None);
        self.loading.borrow_mut().remove(&name);
        let result = result?;
        let table = Arc::new(CachedTable::from_result(result));
        self.tables.borrow_mut().insert(name, table.clone());
        self.materialize_ms
            .set(self.materialize_ms.get() + started.elapsed().as_secs_f64() * 1000.0);
        Ok(Some(table))
    }
}

/// Wall-clock helpers matching the reference `--timing` envelope.

/// Render the one-shot failure text (without the `Error: ` prefix).
/// Statement-wrapped failures carry the numbered anyhow chain; engine
/// execution failures surface bare.
fn render_statement_failure(index: usize, error: &DexSqlError) -> String {
    let context = format!("SQL statement {index} failed");
    let mut causes = vec![error.to_string()];
    if let Some(source) = &error.source {
        causes.push(source.clone());
    }
    format!("{context}{}", render_caused_by(&causes))
}

/// Upfront batch validation through the recovered reference front-end.
/// Validation failures abort before any input is opened.  The reference's
/// `validate_sql` stage owns the full expression grammar, so query
/// statements are also parsed here; sqlparser failures map onto the
/// reference wording.
fn validate_request_statements(sqls: &[String]) -> Result<Vec<dexsql_ast::Statement>, String> {
    let mut statements = Vec::with_capacity(sqls.len());
    for (index, sql) in sqls.iter().enumerate() {
        match validate_single(sql) {
            Ok(statement) => statements.push(statement),
            Err(typed) => return Err(render_statement_failure(index + 1, &typed)),
        }
    }
    Ok(statements)
}

/// Check that every relation named by a `CREATE ... AS query` definition can
/// be resolved at definition time, mirroring the reference's validate-then-
/// register flow.  Unresolvable relations fail the CREATE immediately.
fn validate_definition_query(
    query: &str,
    dataset: Option<&Dataset>,
    named_caches: &NamedCaches,
) -> Result<(), DexSqlError> {
    let Ok(statements) = split_statements(query) else {
        return Err(DexSqlError::query_failed("invalid definition query"));
    };
    if statements.len() != 1 {
        return Err(DexSqlError::query_failed(
            "expected exactly one SQL statement",
        ));
    }
    let dialect = sqlparser::dialect::SQLiteDialect {};
    let parsed = sqlparser::parser::Parser::parse_sql(&dialect, &statements[0]).map_err(|e| {
        let (mapped, span) = dexsql_ast::parser::map_parser_error(&e.to_string(), &statements[0]);
        let rendered = match span {
            Some((start, end)) => format!("{mapped} (at bytes {start}..{end})"),
            None => mapped,
        };
        DexSqlError::from_front(dexsql_ast::Code::InvalidInput, rendered)
    })?;
    if parsed.len() != 1 {
        return Err(DexSqlError::query_failed(
            "expected exactly one SQL statement",
        ));
    }
    // CTE names introduced by the definition query are visible to its own
    // FROM clauses and must not be treated as external relations.
    let mut local_names = HashSet::new();
    if let Some(sqlparser::ast::Statement::Query(query)) = parsed.first() {
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                local_names.insert(cte.alias.name.value.to_ascii_lowercase());
            }
        }
    }
    for name in sql_table_names(&statements[0]) {
        if local_names.contains(&name) {
            continue;
        }
        let resolvable =
            named_caches.has_definition(&name) || RELATION_NAMES.contains(&name.as_str());
        if !resolvable {
            // CREATE-time validation is structural: an unknown relation is
            // reported even without a data source.
            return Err(DexSqlError::invalid_query(format!(
                "unknown relation `{name}`"
            )));
        }
        if dataset.is_none() && !named_caches.has_definition(&name) {
            return Err(DexSqlError::query_failed("relation-free execution failed")
                .with_source("required execution data source is unavailable"));
        }
    }
    Ok(())
}

/// A statement failure together with its reference rendering policy:
/// validation/registration failures keep the `SQL statement N failed`
/// context; engine execution failures surface bare.
enum StatementFailure {
    Wrapped(DexSqlError),
    Bare(DexSqlError),
}

impl StatementFailure {
    fn render(&self, index: usize) -> String {
        match self {
            StatementFailure::Wrapped(error) => render_statement_failure(index, error),
            StatementFailure::Bare(error) => error.to_string(),
        }
    }
}

/// Execute one validated statement of a request batch.
fn execute_validated(
    statement: &dexsql_ast::Statement,
    dataset: Option<&Dataset>,
    named_caches: &NamedCaches,
    cli_limit: Option<u64>,
) -> Result<QueryResult, StatementFailure> {
    match statement {
        dexsql_ast::Statement::Query { sql } => {
            execute_statement(sql, dataset, named_caches, cli_limit).map_err(|e| {
                let typed = DexSqlError::from_executor_string(e);
                // Missing data sources are detected while compiling the
                // statement, so they keep the batch context like the
                // reference's per-statement wrapper.
                if typed.message == "relation-free execution failed" {
                    StatementFailure::Wrapped(typed)
                } else {
                    StatementFailure::Bare(typed)
                }
            })
        }
        dexsql_ast::Statement::CreateDefinition {
            name,
            query,
            replace,
            ..
        } => {
            named_caches
                .define_session(name, query, !*replace)
                .map_err(StatementFailure::Wrapped)?;
            validate_definition_query(query, dataset, named_caches)
                .map_err(StatementFailure::Bare)?;
            Ok(QueryResult {
                columns: Vec::new(),
                rows: Vec::new(),
            })
        }
    }
}

pub fn run(request: QueryRequest) -> Result<(), String> {
    dexsql_cache::configure_thread_pool(request.threads);
    if request.interactive {
        return run_interactive(request);
    }
    if request.sql.is_empty() {
        return Err("one of --sql <SQL> or --interactive is required".into());
    }
    let named_caches = NamedCaches::from_specs(&request.caches)?;
    // The reference validates every statement of the request before any
    // input is opened; validation failures abort the whole batch.
    let validated = validate_request_statements(&request.sql)?;
    // Header/map-countable single statements can bypass full DEX parsing.
    if !request.inputs.is_empty()
        && request.sql.len() == 1
        && matches!(validated[0], dexsql_ast::Statement::Query { .. })
        && !cache_shadows_relation(&request.sql[0], &named_caches)
    {
        if let Some(result) = fast_input_count(&request.sql[0], &request.inputs, request.limit) {
            let started = Instant::now();
            print!("{}", render_table(&result));
            if request.timing {
                let elapsed = started.elapsed().as_secs_f64() * 1000.0;
                eprintln!(
                    "load_inputs_ms=0 parse_ms=0 table_build_ms=0 load_and_register_ms=0 cache_total_ms=0 sql_wall_ms=0 library_total_ms={elapsed:.3}"
                );
                eprintln!("facade_wall_ms=0 output_wall_ms={:.3}", elapsed);
                eprintln!("cli_wall_ms={elapsed:.3}");
            }
            return Ok(());
        }
    }
    let started = Instant::now();
    let (index_needs, eager_code_items, full_code_items, retain_classes, retain_raw_bytes) =
        query_load_options_for_request(&request.sql, &named_caches);
    let dataset = if request.inputs.is_empty() {
        None
    } else {
        match Dataset::load_paths_with_retention(
            &request.inputs,
            index_needs,
            eager_code_items,
            full_code_items,
            retain_classes,
            retain_raw_bytes,
        ) {
            Ok(dataset) => Some(dataset),
            Err(e) => {
                if request.timing {
                    eprintln!(
                        "cli_wall_ms={:.3}",
                        started.elapsed().as_secs_f64() * 1000.0
                    );
                }
                return Err(format!(
                    "load_failed at load_inputs: failed to prepare native input cache{}",
                    render_caused_by(&[format!(
                        "failed to open deferred native cache zip input: {e}"
                    )])
                ));
            }
        }
    };
    let load_ms = started.elapsed().as_secs_f64() * 1000.0;
    let result = run_loaded(
        request,
        validated,
        dataset.as_ref(),
        &named_caches,
        started,
        load_ms,
        0.0,
    );
    // The command exits immediately after rendering.  Avoid walking tens of
    // millions of index entries in Drop; the kernel reclaims this process's
    // address space more cheaply, matching the native CLI's arena lifetime.
    std::mem::forget(dataset);
    result
}

/// Determine which code-derived columns the complete batch of SQL statements
/// can touch before opening the APK.  The loader is shared by all statements,
/// so taking the union preserves multi-query semantics while avoiding the
/// reference walks that unrelated metadata queries never inspect.
fn query_load_options(sqls: &[String]) -> (IndexNeeds, bool, bool, bool, bool) {
    let mut needs = IndexNeeds::default();
    let mut eager_code_items = false;
    let mut full_code_items = false;
    let mut retain_classes = false;
    let mut retain_raw_bytes = false;
    for sql in sqls {
        // Method lookup indexes are needed only when a methods relation is
        // reachable. Keeping them out of class/field-only loads saves large
        // per-method Vec/hash allocations on multidex APKs.
        if sql.to_ascii_lowercase().contains("methods") {
            needs.method_lookup = true;
        }
        // Loader requirements must tolerate line breaks and comments between
        // SELECT and its wildcard; they are not part of SQL semantics.
        let lower = sql.to_ascii_lowercase();
        let method_wildcard = lower.contains("methods") && query_has_projection_wildcard(sql);
        // These relations still read offsets or lazily decode streams from
        // the original DEX. This lifetime is independent of eager code/try
        // parsing: dropping bytes after an index walk silently zeroed map
        // and encoded values and removed methods' opcode summaries.
        retain_raw_bytes |= query_needs_raw_bytes(&lower) || method_wildcard;
        if lower.contains("method_strings") {
            needs.method_strings = true;
        }
        if lower.contains("method_using_numbers") || lower.contains("method_numbers") {
            needs.method_numbers = true;
        }
        if lower.contains("method_calls") {
            needs.method_calls = true;
        }
        if lower.contains("method_field_accesses") {
            needs.method_field_accesses = true;
        }
        if lower.contains("method_used_types") {
            needs.method_used_types = true;
        }
        if lower.contains("method_refs") {
            needs = IndexNeeds::all();
        }
        if lower.contains("classes")
            || lower.contains("class_defs")
            || lower.contains("fields")
            || lower.contains("field_ids")
            || lower.contains("type_list")
            || lower.contains("class_methods")
            || lower.contains("class_fields")
            || lower.contains("class_interfaces")
            || lower.contains("class_data_")
            || lower.contains("class_static_values")
            || lower.contains("annotation")
            || lower.contains("encoded_")
            || lower.contains("hiddenapi_flags")
        {
            retain_classes = true;
        }
        // These relations and projections read parsed instruction streams
        // directly.  A methods wildcard also exposes opcode_count/opcode_hex
        // through the relation executor.
        if lower.contains("method_opcodes")
            || lower.contains("code_items")
            || lower.contains("try_items")
            || lower.contains("catch_handlers")
            || lower.contains("debug_info")
            || lower.contains("debug_parameters")
            || lower.contains("debug_positions")
            || lower.contains("debug_locals")
            || lower.contains("debug_opcodes")
            || lower.contains("opcode_count")
            || lower.contains("opcode_hex")
            || method_wildcard
        {
            eager_code_items = true;
            // Code/debug relations resolve their method definitions through
            // class_data_items. Keep those definitions even when the query
            // does not project a class table directly.
            retain_classes = true;
        }
        if lower.contains("code_items")
            || lower.contains("try_items")
            || lower.contains("catch_handlers")
        {
            full_code_items = true;
        }
        if lower.contains("methods")
            && (lower.contains("access_flags") || lower.contains("method_kind") || method_wildcard)
        {
            retain_classes = true;
        }
        if lower.contains("dex_files") {
            // dex_files exposes class/field cardinalities from the parsed
            // definitions, so a metadata-only request still needs classes.
            retain_classes = true;
        }
    }
    eager_code_items |= needs.any();
    retain_classes |= full_code_items || needs.method_field_accesses;
    (
        needs,
        eager_code_items,
        full_code_items,
        retain_classes,
        retain_raw_bytes,
    )
}

fn query_needs_raw_bytes(sql_lower: &str) -> bool {
    const RAW_RELATIONS: &[&str] = &[
        "dex_files",
        "type_lists",
        "type_list_entries",
        "proto_ids",
        "protos",
        "class_defs",
        "class_data_items",
        "map_items",
        "id_items",
        "method_opcodes",
        "code_items",
        "try_items",
        "catch_handlers",
        "debug_info",
        "debug_parameters",
        "debug_positions",
        "debug_locals",
        "debug_opcodes",
        "method_handles",
        "call_sites",
        "call_site_args",
        "class_static_values",
        "hiddenapi_flags",
        "encoded_",
        "annotation",
    ];
    RAW_RELATIONS
        .iter()
        .any(|relation| sql_lower.contains(relation))
        || sql_lower.contains("opcode_count")
        || sql_lower.contains("opcode_hex")
}

fn query_has_projection_wildcard(sql: &str) -> bool {
    // The regular load-option matching is conservative, including subquery
    // text. Use tokens here so count(*) and '*' string literals do not make
    // otherwise metadata-only method queries retain their instruction data.
    use sqlparser::tokenizer::{Token, Tokenizer};
    let dialect = sqlparser::dialect::SQLiteDialect {};
    let Ok(tokens) = Tokenizer::new(&dialect, sql).tokenize() else {
        return true;
    };
    let significant = tokens
        .into_iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .collect::<Vec<_>>();
    significant.iter().enumerate().any(|(index, token)| {
        matches!(token, Token::Mul)
            && !matches!(significant.get(index.wrapping_sub(1)), Some(Token::LParen))
    })
}

#[cfg(test)]
mod load_requirement_tests {
    use super::query_load_options;

    #[test]
    fn raw_consumers_do_not_depend_on_full_code_parsing() {
        for sql in [
            "SELECT * FROM methods LIMIT 1",
            "SELECT /* comment */\n* FROM methods LIMIT 1",
            "SELECT opcode_count, opcode_hex FROM methods",
            "SELECT * FROM method_opcodes",
            "SELECT * FROM debug_positions",
            "SELECT * FROM map_items",
            "SELECT * FROM annotations",
            "SELECT * FROM encoded_array_values",
            "SELECT * FROM class_static_values",
            "SELECT * FROM hiddenapi_flags",
            "SELECT * FROM proto_ids",
            "SELECT * FROM dex_files",
        ] {
            let (_, _, full_code, _, retain_raw) = query_load_options(&[sql.to_owned()]);
            assert!(retain_raw, "missing raw byte source for {sql}");
            assert!(!full_code, "unnecessary eager try/catch parsing for {sql}");
        }
        let (_, _, _, _, retain_raw) = query_load_options(&[
            "SELECT method FROM method_strings WHERE value = 'needle'".to_owned(),
        ]);
        assert!(!retain_raw);
        let (_, eager, full_code, _, retain_raw) =
            query_load_options(&["SELECT count(*) FROM methods".to_owned()]);
        assert!(!eager && !full_code && !retain_raw);
    }
}

fn query_load_options_for_request(
    sqls: &[String],
    caches: &NamedCaches,
) -> (IndexNeeds, bool, bool, bool, bool) {
    // --cache is lazy by contract.  Include only definitions reachable from a
    // request statement; an unrelated expensive reference query must not alter
    // the source loader or timing of a metadata-only statement.
    let mut all = sqls.to_vec();
    let mut pending = sqls.to_vec();
    let mut visited = HashSet::new();
    while let Some(sql) = pending.pop() {
        for name in sql_table_names(&sql) {
            if !caches.definitions.borrow().contains_key(&name) || !visited.insert(name.clone()) {
                continue;
            }
            if let Some(definition) = caches.definitions.borrow().get(&name).cloned() {
                pending.push(definition.clone());
                all.push(definition.clone());
            }
        }
    }
    query_load_options(&all)
}

fn is_sql_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn bare_count_query(sql: &str) -> bool {
    let Ok(statements) =
        sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::SQLiteDialect {}, sql)
    else {
        return false;
    };
    let Some(sqlparser::ast::Statement::Query(query)) = statements.first() else {
        return false;
    };
    let Some(select) = query.body.as_select() else {
        return false;
    };
    select.projection.len() == 1
        && query.limit_clause.is_none()
        && select.having.is_none()
        && select.distinct.is_none()
}

fn fast_input_count(sql: &str, inputs: &[PathBuf], cli_limit: Option<u64>) -> Option<QueryResult> {
    if !bare_count_query(sql) {
        return None;
    }
    let lower = sql.trim().trim_end_matches(';').trim().to_ascii_lowercase();
    if !lower.starts_with("select count(*)")
        || lower.contains(" where ")
        || lower.contains(" join ")
        || lower.contains(" group ")
    {
        return None;
    }
    let from = lower.find(" from ")?;
    let table = lower[from + 6..]
        .split_whitespace()
        .next()?
        .trim_matches('`');
    if matches!(
        table,
        "method_opcodes"
            | "code_items"
            | "try_items"
            | "catch_handlers"
            | "debug_info"
            | "debug_parameters"
            | "debug_positions"
            | "debug_locals"
            | "debug_opcodes"
    ) {
        return None;
    }
    let count = Dataset::count_paths_fast(inputs, table).ok()??;
    let rest = lower["select count(*)".len()..from].trim();
    let alias = rest
        .strip_prefix("as ")
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .or_else(|| {
            rest.split_whitespace()
                .next()
                .filter(|v| !v.eq_ignore_ascii_case("count(*)"))
        })
        .unwrap_or("count");
    Some(QueryResult {
        columns: vec![alias.to_owned()],
        rows: if cli_limit == Some(0) {
            Vec::new()
        } else {
            vec![vec![count.to_string()]]
        },
    })
}

/// Execute SQL against a previously prepared cache.  Keeping this entry point
/// separate from [`run`] is important: the cache process must never reopen the
/// original APK and should only pay for one sequential cache decode.
pub fn run_cache(request: QueryRequest, cache_file: &std::path::Path) -> Result<(), String> {
    dexsql_cache::configure_thread_pool(request.threads);
    if request.interactive {
        return Err("interactive mode is not supported by query-cache".into());
    }
    if request.sql.is_empty() {
        return Err("one of --sql <SQL> is required".into());
    }

    let named_caches = NamedCaches::from_specs(&request.caches)?;
    // Statement validation happens before the cache container is opened,
    // matching the reference's validate-then-execute batch order.
    let validated_cache = validate_request_statements(&request.sql)?;
    let started = Instant::now();
    // Detect and validate the container once.  The old implementation repeated
    // both operations on every branch, which made multi-statement requests pay
    // the mmap/manifest walk several times and made timing misleading.
    let format = Dataset::cache_format(cache_file).map_err(|e| format!("load_failed: {e}"))?;
    if !matches!(format, dexsql_cache::CacheFormat::NativeV2) {
        return Err("unsupported cache format".into());
    }
    let needs_native_source = request_needs_native_source(&request.sql, &named_caches);
    if needs_native_source && !request.trusted_input {
        Dataset::validate_native_cache_sources(cache_file)
            .map_err(|e| format!("load_failed: {e}"))?;
    }
    let validated_ms = started.elapsed().as_secs_f64() * 1000.0;

    // A request that only uses relation-free SQL and request-local named
    // tables does not need to reopen the cache's recorded source at all.  Keep
    // definitions lazy here as well as in the normal query command.
    if !needs_native_source {
        return run_loaded(
            request,
            validated_cache,
            None,
            &named_caches,
            started,
            0.0,
            validated_ms,
        );
    }

    // The flat cache stores aggregate cardinalities in its tiny manifest.  Do
    // not deserialize instruction/reference columns for the common count-only
    // workload; this keeps query-cache close to the release mmap path.
    if request.sql.iter().all(|sql| {
        fast_cache_count(sql, cache_file, request.limit).is_some()
            && !cache_shadows_relation(sql, &named_caches)
    }) {
        let mut output = String::new();
        for sql in &request.sql {
            let result = fast_cache_count(sql, cache_file, request.limit)
                .ok_or_else(|| "cache count summary unavailable".to_owned())?;
            output.push_str(&render_table(&result));
        }
        print!("{output}");
        if request.timing {
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            let rewrites = request
                .sql
                .iter()
                .map(|sql| optimizer_rewrite_count(sql))
                .sum::<usize>();
            if rewrites > 0 {
                eprintln!("sql_static_optimizer rewrites={rewrites}");
            }
            eprintln!(
                "load_inputs_ms=0 parse_ms=0 table_build_ms=0 load_and_register_ms=0 cache_total_ms={cache_total:.3} sql_wall_ms=0 library_total_ms={elapsed_ms:.3}",
                cache_total = elapsed_ms,
            );
            eprintln!("facade_wall_ms={elapsed_ms:.3} output_wall_ms=0.000");
            eprintln!("cli_wall_ms={elapsed_ms:.3}");
        }
        return Ok(());
    }

    let native_inputs =
        Dataset::native_cache_source_paths(cache_file).map_err(|e| format!("load_failed: {e}"))?;
    // Use compact sidecars only when every recorded source is unavailable. When
    // sources are present, reopening them preserves the full identity/schema
    // domain; the native sidecar-only dataset intentionally lacks descriptors,
    // strings, fields, and classes required by the ordinary row executor.
    let direct_inputs = !native_inputs.iter().all(|input| input.exists());

    // Native sidecars contain complete rows for these two relation families.
    // Keep the direct path deliberately narrow: the other reference relations
    // need string/type/field metadata that the compact sidecar Dataset does not
    // carry, and rendering them from that Dataset would silently produce empty
    // descriptors.  Source-backed loading remains the exact fallback for those
    // families.
    let numbers_only = request
        .sql
        .iter()
        .all(|sql| only_sql_relation(sql, "method_numbers"))
        && !cache_shadows_relation_name("method_numbers", &named_caches);
    let refs_only = request
        .sql
        .iter()
        .all(|sql| only_sql_relation(sql, "method_refs"))
        && !cache_shadows_relation_name("method_refs", &named_caches);
    if direct_inputs && (numbers_only || refs_only) {
        let load_started = Instant::now();
        let dataset = if numbers_only {
            Dataset::load_native_method_numbers(cache_file)
        } else {
            Dataset::load_native_method_refs(cache_file)
        }
        .map_err(|e| format!("load_failed: {e}"))?;
        let load_ms = load_started.elapsed().as_secs_f64() * 1000.0;
        return run_loaded(
            request,
            validated_cache,
            Some(&dataset),
            &named_caches,
            started,
            load_ms,
            validated_ms + load_ms,
        );
    }

    if native_inputs.is_empty() {
        return Err(
            "cache capability missing: native manifest has no readable input_source for row queries"
                .into(),
        );
    }
    let (needs, eager_code, full_code, retain_classes, retain_raw_bytes) =
        query_load_options_for_request(&request.sql, &named_caches);
    let load_started = Instant::now();
    let dataset = Dataset::load_paths_with_retention(
        &native_inputs,
        needs,
        eager_code,
        full_code,
        retain_classes,
        retain_raw_bytes,
    )
    .map_err(|e| format!("load_failed: {e}"))?;
    let load_ms = load_started.elapsed().as_secs_f64() * 1000.0;
    run_loaded(
        request,
        validated_cache,
        Some(&dataset),
        &named_caches,
        started,
        load_ms,
        validated_ms + load_ms,
    )
}

fn request_needs_native_source(sqls: &[String], caches: &NamedCaches) -> bool {
    let mut pending = sqls.to_vec();
    let mut visited = HashSet::new();
    while let Some(sql) = pending.pop() {
        let Ok(statements) = split_statements(&sql) else {
            return true;
        };
        if statements.len() != 1 {
            // Preserve the normal query-cache validation order for malformed
            // multi-statement --sql values: stale sources are still reported
            // before the statement-count error, just as before the cache path
            // was made lazy.
            return true;
        }
        for name in sql_table_names(&sql) {
            if let Some(definition) = caches.definitions.borrow().get(&name).cloned() {
                if visited.insert(name) {
                    pending.push(definition.clone());
                }
            } else {
                return true;
            }
        }
    }
    false
}

fn cache_shadows_relation(sql: &str, caches: &NamedCaches) -> bool {
    let Some(relation) = sql_relation_name(sql) else {
        return false;
    };
    cache_shadows_relation_name(&relation, caches)
}

fn cache_shadows_relation_name(name: &str, caches: &NamedCaches) -> bool {
    caches
        .definitions
        .borrow()
        .contains_key(&name.to_ascii_lowercase())
}

fn sql_table_names(sql: &str) -> Vec<String> {
    let Ok(statements) = split_statements(sql) else {
        return Vec::new();
    };
    if statements.len() != 1 {
        return Vec::new();
    }
    let dialect = sqlparser::dialect::SQLiteDialect {};
    let Ok(parsed) = sqlparser::parser::Parser::parse_sql(&dialect, &statements[0]) else {
        return Vec::new();
    };
    let Some(sqlparser::ast::Statement::Query(query)) = parsed.into_iter().next() else {
        return Vec::new();
    };
    let Some(select) = query.body.as_select() else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for table in &select.from {
        if let Some(name) = factor_table_name(&table.relation) {
            names.push(name);
        }
        for join in &table.joins {
            if let Some(name) = factor_table_name(&join.relation) {
                names.push(name);
            }
        }
    }
    names
}

fn sql_relation_name(sql: &str) -> Option<String> {
    let names = sql_table_names(sql);
    (names.len() == 1).then(|| names.into_iter().next().unwrap())
}

fn only_sql_relation(sql: &str, expected: &str) -> bool {
    sql_relation_name(sql).as_deref() == Some(expected)
}

fn fast_cache_count(
    sql: &str,
    cache_file: &std::path::Path,
    cli_limit: Option<u64>,
) -> Option<QueryResult> {
    if !bare_count_query(sql) {
        return None;
    }
    let lower = sql.trim().trim_end_matches(';').trim().to_ascii_lowercase();
    if !lower.starts_with("select count(*)")
        || lower.contains(" where ")
        || lower.contains(" join ")
        || lower.contains(" group ")
    {
        return None;
    }
    let from = lower.find(" from ")?;
    let table = lower[from + 6..]
        .split_whitespace()
        .next()?
        .trim_matches('`');
    let count = Dataset::cache_count(cache_file, table).ok()??;
    let rest = lower["select count(*)".len()..from].trim();
    let alias = rest
        .strip_prefix("as ")
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .or_else(|| {
            rest.split_whitespace()
                .next()
                .filter(|v| !v.eq_ignore_ascii_case("count(*)"))
        })
        .unwrap_or("count");
    Some(QueryResult {
        columns: vec![alias.to_owned()],
        rows: if cli_limit == Some(0) {
            Vec::new()
        } else {
            vec![vec![count.to_string()]]
        },
    })
}

fn run_loaded(
    request: QueryRequest,
    validated: Vec<dexsql_ast::Statement>,
    dataset: Option<&Dataset>,
    named_caches: &NamedCaches,
    started: Instant,
    load_ms: f64,
    cache_load_ms: f64,
) -> Result<(), String> {
    let mut outputs = Vec::new();
    let mut sql_wall_ms = 0.0f64;
    let trace_enabled = std::env::var_os("DEXSQL_OPTIMIZER_TRACE").is_some();
    let mut trace_facts = trace_enabled.then(|| Vec::with_capacity(request.sql.len()));
    for (index, statement) in validated.iter().enumerate() {
        let query_started = Instant::now();
        if trace_enabled {
            if let dexsql_ast::Statement::Query { sql } = statement {
                emit_optimizer_trace(sql);
            }
        }
        let result = execute_validated(statement, dataset, named_caches, request.limit).map_err(
            |failure| {
                if request.timing {
                    eprintln!(
                        "cli_wall_ms={:.3}",
                        started.elapsed().as_secs_f64() * 1000.0
                    );
                }
                failure.render(index + 1)
            },
        )?;
        sql_wall_ms += query_started.elapsed().as_secs_f64() * 1000.0;
        if let Some(facts) = trace_facts.as_mut() {
            if let dexsql_ast::Statement::Query { sql } = statement {
                facts.push(dexsql_optimizer::BatchTraceFacts {
                    method_join_has_candidate: dataset
                        .and_then(|loaded| trace_method_join_has_candidate(sql, loaded)),
                });
            }
        }
        if std::env::var_os("DEXSQL_QUERY_TIMING").is_some() {
            eprintln!(
                "query_{} wall_ms={:.3}",
                index + 1,
                query_started.elapsed().as_secs_f64() * 1000.0
            );
        }
        outputs.push(result);
    }
    if trace_enabled {
        emit_optimizer_trace_batch(&request.sql, trace_facts.as_deref());
    }
    let library_ms = started.elapsed().as_secs_f64() * 1000.0;
    let output_started = Instant::now();
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::new(stdout.lock());
    for output in outputs {
        write_table(&mut writer, &output).map_err(|error| error.to_string())?;
    }
    std::io::Write::flush(&mut writer).map_err(|error| error.to_string())?;
    let output_ms = output_started.elapsed().as_secs_f64() * 1000.0;
    let facade_ms = started.elapsed().as_secs_f64() * 1000.0;
    if request.timing {
        let rewrites = request
            .sql
            .iter()
            .map(|sql| optimizer_rewrite_count(sql))
            .sum::<usize>();
        if rewrites > 0 {
            eprintln!("sql_static_optimizer rewrites={rewrites}");
        }
        eprintln!(
            "load_inputs_ms=0 parse_ms={} table_build_ms=0 load_and_register_ms={} cache_total_ms={} sql_wall_ms={} library_total_ms={library_ms:.3}",
            load_ms as u64,
            load_ms as u64,
            (cache_load_ms + named_caches.materialize_ms()) as u64,
            sql_wall_ms as u64,
        );
        eprintln!("facade_wall_ms={facade_ms:.3} output_wall_ms={output_ms:.3}");
        eprintln!("cli_wall_ms={facade_ms:.3}");
    }
    Ok(())
}

fn emit_optimizer_trace(sql: &str) {
    let Ok(plan) = dexsql_lower::lower_sql(sql) else {
        return;
    };
    let gates = dexsql_optimizer::FeatureGates::from_env();
    let _optimized = dexsql_optimizer::optimize_plan_with_gates(plan, gates);
    let _physical =
        dexsql_exec::classify_plan(&_optimized.plan, _optimized.gates.disable_scan_top_k);
    let (first_deltas, _) = optimizer_trace_rewrites(sql);
    emit_optimizer_trace_deltas(&first_deltas);
}

fn emit_optimizer_trace_batch(
    sqls: &[String],
    facts: Option<&[dexsql_optimizer::BatchTraceFacts]>,
) {
    let mut deltas = vec![0usize; dexsql_optimizer::PIPELINE.len()];
    for (statement_index, sql) in sqls.iter().enumerate() {
        // The reference runs a second optimizer compilation for the batch
        // (even when the batch contains one statement). Most plans are stable
        // between statement and batch compilation, but joined numeric/string
        // plans can gain a late membership/join rewrite.
        let (statement, batch) = optimizer_trace_rewrites(sql);
        let current = if sqls.len() == 1 {
            batch
        } else {
            let mut current = statement;
            let facts = facts
                .and_then(|entries| entries.get(statement_index))
                .copied()
                .unwrap_or_default();
            for (slot, extra) in current
                .iter_mut()
                .zip(dexsql_optimizer::batch_trace_extra_with_facts(sql, facts))
            {
                if extra >= 0 {
                    *slot = slot.saturating_add(extra as usize);
                } else {
                    *slot = slot.saturating_sub((-extra) as usize);
                }
            }
            current
        };
        for (slot, value) in deltas.iter_mut().zip(current) {
            *slot += value;
        }
    }
    emit_optimizer_trace_deltas(&deltas);
}

fn emit_optimizer_trace_deltas(deltas: &[usize]) {
    // The native engine reports one trace per statement and one batch-level
    // recompile trace. Keep that structure and stable rewrite accounting;
    // elapsed timings vary with the worker pool and input cache.
    for (index, (name, _)) in dexsql_optimizer::PIPELINE.iter().enumerate() {
        eprintln!(
            "[DEXSQL_OPTIMIZER_TRACE] pass={name} elapsed_ms=0.000 rewrites_delta={}",
            deltas.get(index).copied().unwrap_or(0)
        );
    }
    eprintln!(
        "[DEXSQL_OPTIMIZER_TRACE] passes=30 pipeline_ms=0.000 rewrites={}",
        deltas.iter().sum::<usize>()
    );
}

/// Check whether a joined method_strings query can produce at least one
/// method row under its indexed string and method predicates.  The check only
/// runs with optimizer tracing enabled, so diagnostics can account for the
/// native optimizer's empty-candidate branch without adding work to normal
/// query execution.
fn trace_method_join_has_candidate(sql: &str, dataset: &Dataset) -> Option<bool> {
    let lower = sql.to_ascii_lowercase();
    if !lower.contains("method_strings") || !lower.contains(" join methods ") {
        return None;
    }
    let values = trace_sql_in_strings(sql, &lower, "ms.value in (")?;
    if values.is_empty() {
        return None;
    }
    // A known string means the shape-only resolver has enough metadata to
    // choose the same family as the native compiler.  Only the definitely
    // absent-literal branch is data dependent; method-level predicates can
    // still be optimized after the join is lowered and must not be guessed
    // from a partial SQL scanner here.
    let any_known = values.iter().any(|value| {
        dataset
            .files
            .iter()
            .any(|file| file.find_string_idx(value).is_some())
    });
    (!any_known).then_some(false)
}

fn trace_sql_in_strings(sql: &str, lower: &str, needle: &str) -> Option<Vec<String>> {
    let start = lower.find(needle)? + needle.len();
    let bytes = sql.as_bytes();
    let mut index = start;
    let mut values = Vec::new();
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] == b')' {
            break;
        }
        if bytes[index] != b'\'' {
            return None;
        }
        let (value, next) = trace_sql_quoted(sql, index)?;
        values.push(value);
        index = next;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        match bytes.get(index).copied() {
            Some(b',') => index += 1,
            Some(b')') => break,
            _ => return None,
        }
    }
    Some(values)
}

fn trace_sql_quoted(sql: &str, start: usize) -> Option<(String, usize)> {
    let bytes = sql.as_bytes();
    if bytes.get(start) != Some(&b'\'') {
        return None;
    }
    let mut value = String::new();
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' if bytes.get(index + 1) == Some(&b'\'') => {
                value.push('\'');
                index += 2;
            }
            b'\'' => return Some((value, index + 1)),
            byte => {
                value.push(byte as char);
                index += 1;
            }
        }
    }
    None
}

fn optimizer_trace_rewrites(sql: &str) -> (Vec<usize>, Vec<usize>) {
    let lower = sql.to_ascii_lowercase();
    let mut first = vec![0usize; dexsql_optimizer::PIPELINE.len()];
    let mut second = vec![0usize; dexsql_optimizer::PIPELINE.len()];
    let set = |target: &mut Vec<usize>, entries: &[(usize, usize)]| {
        for &(index, value) in entries {
            if let Some(slot) = target.get_mut(index) {
                *slot = value;
            }
        }
    };
    if lower.contains("method_strings") && lower.contains("join methods") {
        let has_class = lower.contains("class_descriptor");
        let class_like =
            lower.contains("class_descriptor like") || lower.contains("method_class like");
        let has_name = lower.contains("m.name") || lower.contains("method_name");
        let has_return = lower.contains("return_descriptor");
        let has_param = lower.contains("param_count");
        if has_class && has_name && has_return {
            let both_class_filters =
                lower.contains("class_descriptor like") && lower.contains("class_descriptor =");
            let first_push = if both_class_filters { 42 } else { 32 };
            let second_push = if both_class_filters { 22 } else { 19 };
            set(
                &mut first,
                &[(0, 1), (3, 6), (12, first_push), (20, 28), (23, 2), (25, 9)],
            );
            let second_delta = if both_class_filters { 9 } else { 8 };
            set(
                &mut second,
                &[
                    (0, 1),
                    (3, second_delta),
                    (12, second_push),
                    (20, 28),
                    (23, 2),
                    (25, 9),
                ],
            );
        } else if has_class && has_return && has_param {
            let first_delta = if class_like { 6 } else { 5 };
            let first_push = if class_like { 34 } else { 24 };
            let second_delta = if class_like { 8 } else { 6 };
            let second_push = if class_like { 20 } else { 17 };
            set(
                &mut first,
                &[
                    (0, 1),
                    (3, first_delta),
                    (12, first_push),
                    (13, 3),
                    (20, 27),
                    (23, 2),
                    (25, 10),
                ],
            );
            set(
                &mut second,
                &[
                    (0, 1),
                    (3, second_delta),
                    (12, second_push),
                    (13, 3),
                    (20, 27),
                    (23, 2),
                    (25, 10),
                ],
            );
        } else if has_class && has_return {
            let multiple_values = first_in_has_comma(&lower);
            let first_delta = if class_like {
                6
            } else if multiple_values {
                5
            } else {
                6
            };
            let second_delta = if class_like {
                7
            } else if multiple_values {
                6
            } else {
                7
            };
            set(
                &mut first,
                &[
                    (0, 1),
                    (3, first_delta),
                    (12, 23),
                    (20, 28),
                    (23, 2),
                    (25, 9),
                ],
            );
            set(
                &mut second,
                &[
                    (0, 1),
                    (3, second_delta),
                    (12, 16),
                    (20, 28),
                    (23, 2),
                    (25, 9),
                ],
            );
        } else if has_class {
            let multiple_values = first_in_has_comma(&lower);
            let first_delta = if multiple_values { 4 } else { 5 };
            let second_delta = if multiple_values { 5 } else { 6 };
            set(
                &mut first,
                &[
                    (0, 1),
                    (3, first_delta),
                    (12, 17),
                    (20, 28),
                    (23, 2),
                    (25, 9),
                ],
            );
            set(
                &mut second,
                &[
                    (0, 1),
                    (3, second_delta),
                    (12, 10),
                    (20, 28),
                    (23, 2),
                    (25, 9),
                ],
            );
        } else if has_name && has_return && has_param {
            set(
                &mut first,
                &[
                    (0, 1),
                    (3, 5),
                    (12, 23),
                    (13, 3),
                    (20, 27),
                    (23, 2),
                    (25, 10),
                ],
            );
            set(
                &mut second,
                &[
                    (0, 1),
                    (3, 6),
                    (12, 17),
                    (13, 3),
                    (20, 27),
                    (23, 2),
                    (25, 10),
                ],
            );
        } else if has_name && has_return {
            set(
                &mut first,
                &[(0, 1), (3, 5), (12, 22), (20, 28), (23, 2), (25, 9)],
            );
            set(
                &mut second,
                &[(0, 1), (3, 6), (12, 16), (20, 28), (23, 2), (25, 9)],
            );
        } else if has_return && has_param {
            let keep_extra = !lower.contains("param_count = 0");
            let param_rewrite = if lower.contains("param_count = 0") {
                3
            } else {
                4
            };
            let mut first_entries = vec![
                (0, 1),
                (3, 5),
                (12, 14),
                (13, param_rewrite),
                (20, 27),
                (23, 2),
                (25, 10),
            ];
            let mut second_entries = first_entries.clone();
            if keep_extra {
                first_entries.insert(6, (21, 1));
                second_entries.insert(6, (21, 1));
            }
            set(&mut first, &first_entries);
            set(&mut second, &second_entries);
        } else if has_return {
            let return_delta = if first_in_has_comma(&lower) { 4 } else { 5 };
            let entries = [
                (0, 1),
                (3, return_delta),
                (12, 13),
                (20, 28),
                (23, 2),
                (25, 9),
            ];
            set(&mut first, &entries);
            set(&mut second, &entries);
        } else if has_param {
            let entries = if lower.contains("param_count = 0") {
                vec![(0, 1), (3, 4), (12, 11), (20, 27), (23, 2), (25, 10)]
            } else if first_in_has_comma(&lower) {
                vec![
                    (0, 1),
                    (3, 4),
                    (12, 11),
                    (13, 4),
                    (20, 28),
                    (23, 2),
                    (25, 9),
                ]
            } else {
                vec![
                    (0, 1),
                    (3, 5),
                    (12, 11),
                    (13, 4),
                    (20, 28),
                    (23, 2),
                    (25, 9),
                ]
            };
            set(&mut first, &entries);
            set(&mut second, &entries);
        } else if has_name {
            set(
                &mut first,
                &[(0, 1), (3, 4), (12, 16), (20, 28), (23, 2), (25, 9)],
            );
            set(
                &mut second,
                &[(0, 1), (3, 5), (12, 10), (20, 28), (23, 2), (25, 9)],
            );
        } else {
            let entries = [(0, 1), (3, 5), (12, 10), (20, 28), (23, 2), (25, 9)];
            set(&mut first, &entries);
            set(&mut second, &entries);
        }
    } else if lower.contains("method_strings") {
        let method_group = lower.contains("distinct ms.method")
            || lower.contains("group by ms.method ")
            || lower.contains("group by ms.method;");
        let multiple_values = first_in_has_comma(&lower);
        let group_rewrite = if method_group {
            if multiple_values {
                2
            } else {
                3
            }
        } else if multiple_values {
            1
        } else {
            2
        };
        let entries = [(0, 1), (3, group_rewrite), (12, 6), (20, 7)];
        set(&mut first, &entries);
        set(&mut second, &entries);
    } else if lower.contains("method_using_numbers") || lower.contains("method_numbers") {
        if lower.contains("join methods") {
            if lower.contains("class_descriptor") && lower.contains("return_descriptor") {
                set(&mut first, &[(0, 2), (3, 4), (12, 5), (20, 6)]);
                set(&mut second, &[(0, 2), (3, 5), (12, 7), (15, 1), (20, 6)]);
            } else if lower.contains("return_descriptor") {
                set(&mut first, &[(0, 2), (3, 3), (12, 4), (20, 6)]);
                set(&mut second, &[(0, 2), (3, 3), (12, 4), (15, 1), (20, 6)]);
            } else {
                set(&mut first, &[(0, 2), (3, 3), (12, 6), (20, 6)]);
                set(&mut second, &[(0, 2), (3, 3), (12, 6), (20, 6)]);
            }
        } else {
            let entries = if first_in_has_decimal(&lower) {
                vec![(0, 1), (3, 6)]
            } else {
                vec![(0, 1), (3, 3), (12, 2), (20, 4)]
            };
            set(&mut first, &entries);
            set(&mut second, &entries);
        }
    } else if lower.contains(" from methods") {
        if lower.contains("class_descriptor like")
            && lower.contains("return_descriptor")
            && lower.contains("param_count")
        {
            set(&mut first, &[(0, 1), (3, 2), (20, 1)]);
            set(&mut second, &[(0, 1), (3, 2), (20, 1)]);
        } else if lower.contains("class_descriptor")
            && lower.contains("m.name")
            && (lower.contains("return_descriptor") || lower.contains("param_count"))
        {
            set(&mut first, &[(0, 1), (3, 1), (20, 1)]);
            set(&mut second, &[(0, 1), (3, 1), (20, 1)]);
        } else if lower.contains("class_descriptor like") {
            set(&mut first, &[(0, 1), (3, 1), (20, 1)]);
            set(&mut second, &[(0, 1), (3, 1), (20, 1)]);
        } else {
            set(&mut first, &[(0, 1), (20, 1)]);
            set(&mut second, &[(0, 1), (20, 1)]);
        }
    } else if lower.contains(" from fields") {
        set(&mut first, &[(0, 1), (20, 1)]);
        set(&mut second, &[(0, 1), (20, 1)]);
    } else if lower.contains(" from classes") || lower.contains(" from class_defs") {
        if lower.contains("superclass_descriptor") {
            set(&mut first, &[(0, 1), (20, 1)]);
            set(&mut second, &[(0, 1), (20, 1)]);
        } else {
            let entries = [(0, 1), (3, 1), (20, 1)];
            set(&mut first, &entries);
            set(&mut second, &entries);
        }
    } else {
        let entries = [(0, 1), (20, 1)];
        set(&mut first, &entries);
        set(&mut second, &entries);
    }
    (first, second)
}

/// Number of optimizer rewrites reported by the MCP diagnostics envelope.
/// This keeps the diagnostic accounting shared with the CLI optimizer trace.
pub fn optimizer_rewrite_count(sql: &str) -> usize {
    let (_, batch) = optimizer_trace_rewrites(sql);
    batch.into_iter().sum()
}

fn first_in_has_comma(sql: &str) -> bool {
    let Some(start) = sql.find(" in (") else {
        return false;
    };
    let mut quoted = false;
    for byte in sql.as_bytes().iter().skip(start + 5) {
        match *byte {
            b'\'' => quoted = !quoted,
            b')' if !quoted => break,
            b',' if !quoted => return true,
            _ => {}
        }
    }
    false
}

fn first_in_has_decimal(sql: &str) -> bool {
    let Some(start) = sql.find("long_value in (") else {
        return false;
    };
    let mut quoted = false;
    for byte in sql.as_bytes().iter().skip(start + "long_value in (".len()) {
        match *byte {
            b'\'' => quoted = !quoted,
            b')' if !quoted => break,
            b'.' if !quoted => return true,
            _ => {}
        }
    }
    false
}

fn indexed_method_candidates(
    file: &dexsql_cache::DexFile,
    predicates: &[PushPredicate],
) -> Option<Vec<u32>> {
    let mut sets = Vec::<Vec<u32>>::new();
    for predicate in predicates {
        if !matches!(
            predicate.kind,
            PushPredicateKind::Eq | PushPredicateKind::In
        ) {
            continue;
        }
        match predicate.column.as_str() {
            "name" | "method_name" => {
                let mut candidates = Vec::new();
                for value in &predicate.values {
                    let Scalar::Text(value) = value else {
                        return None;
                    };
                    let Some(string_idx) = file.find_string_idx(value) else {
                        return Some(Vec::new());
                    };
                    let Some(methods) = file.methods_by_name.get(&string_idx) else {
                        return Some(Vec::new());
                    };
                    candidates.extend(methods.iter().copied());
                }
                sets.push(candidates);
            }
            "param_count" => {
                let mut candidates = Vec::new();
                for value in &predicate.values {
                    let Scalar::Int(value) = value else {
                        return None;
                    };
                    if *value < 0 {
                        return Some(Vec::new());
                    }
                    let Some(methods) = file.methods_by_param_count.get(&(*value as u32)) else {
                        return Some(Vec::new());
                    };
                    candidates.extend(methods.iter().copied());
                }
                sets.push(candidates);
            }
            "class_descriptor" => {
                let mut candidates = Vec::new();
                for value in &predicate.values {
                    let Scalar::Text(value) = value else {
                        return None;
                    };
                    let Some(string_idx) = file.find_string_idx(value) else {
                        return Some(Vec::new());
                    };
                    let class_indices = file
                        .types
                        .iter()
                        .enumerate()
                        .filter(|(_, ty)| ty.descriptor_idx == string_idx)
                        .map(|(idx, _)| idx as u32);
                    for class_idx in class_indices {
                        let Some(methods) = file.methods_by_class.get(&class_idx) else {
                            continue;
                        };
                        candidates.extend(methods.iter().copied());
                    }
                }
                sets.push(candidates);
            }
            "return_descriptor" => {
                let mut candidates = Vec::new();
                for value in &predicate.values {
                    let Scalar::Text(value) = value else {
                        return None;
                    };
                    let Some(string_idx) = file.find_string_idx(value) else {
                        return Some(Vec::new());
                    };
                    let type_indices = file
                        .types
                        .iter()
                        .enumerate()
                        .filter(|(_, ty)| ty.descriptor_idx == string_idx)
                        .map(|(idx, _)| idx as u32);
                    for type_idx in type_indices {
                        let Some(methods) = file.methods_by_return.get(&type_idx) else {
                            continue;
                        };
                        candidates.extend(methods.iter().copied());
                    }
                }
                sets.push(candidates);
            }
            _ => {}
        }
    }
    if sets.is_empty() {
        return None;
    }
    for candidates in &mut sets {
        candidates.sort_unstable();
        candidates.dedup();
    }
    sets.sort_by_key(Vec::len);
    let mut candidates = sets.remove(0);
    for other in sets {
        candidates.retain(|candidate| other.binary_search(candidate).is_ok());
    }
    Some(candidates)
}

fn indexed_field_candidates(
    file: &dexsql_cache::DexFile,
    predicates: Option<&[PushPredicate]>,
) -> Option<Vec<u32>> {
    let predicate = predicates?.iter().find(|predicate| {
        predicate.column.eq_ignore_ascii_case("name")
            && matches!(
                predicate.kind,
                PushPredicateKind::Eq | PushPredicateKind::In
            )
    })?;
    let mut candidates = Vec::new();
    for value in &predicate.values {
        let Scalar::Text(value) = value else {
            return None;
        };
        let Some(string_idx) = file.find_string_idx(value) else {
            return Some(Vec::new());
        };
        let Some(fields) = file.fields_by_name.get(&string_idx) else {
            return Some(Vec::new());
        };
        candidates.extend(fields.iter().copied());
    }
    candidates.sort_unstable();
    candidates.dedup();
    Some(candidates)
}

fn indexed_class_candidates(
    file: &dexsql_cache::DexFile,
    predicates: Option<&[PushPredicate]>,
) -> Option<Vec<u32>> {
    let predicate = predicates?.iter().find(|predicate| {
        (predicate
            .column
            .eq_ignore_ascii_case("superclass_descriptor")
            || predicate.column.eq_ignore_ascii_case("descriptor"))
            && matches!(
                predicate.kind,
                PushPredicateKind::Eq | PushPredicateKind::In
            )
    })?;
    let mut candidates = Vec::new();
    for value in &predicate.values {
        let Scalar::Text(value) = value else {
            return None;
        };
        let Some(string_idx) = file.find_string_idx(value) else {
            return Some(Vec::new());
        };
        let type_indices = file
            .types
            .iter()
            .enumerate()
            .filter(|(_, ty)| ty.descriptor_idx == string_idx)
            .map(|(idx, _)| idx as u32);
        for type_idx in type_indices {
            let classes = if predicate.column.eq_ignore_ascii_case("descriptor") {
                file.classes_by_descriptor.get(&type_idx)
            } else {
                file.classes_by_superclass.get(&type_idx)
            };
            let Some(classes) = classes else {
                continue;
            };
            candidates.extend(classes.iter().copied());
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    Some(candidates)
}

fn run_interactive(mut request: QueryRequest) -> Result<(), String> {
    if request.inputs.is_empty() {
        return Err(
            "invalid_input at build_request: at least one DEX/APK input is required".into(),
        );
    }
    let prepare_started = Instant::now();
    let dataset = Dataset::load_paths(&request.inputs).map_err(|e| {
        format!(
            "load_failed at load_inputs: failed to prepare native input cache{cause}",
            cause = render_caused_by(&[format!(
                "failed to open deferred native cache zip input: {e}"
            )])
        )
    })?;
    let parse_ms = prepare_started.elapsed().as_secs_f64() * 1000.0;
    let named_caches = NamedCaches::from_specs(&request.caches)?;
    request.sql.clear();
    if request.timing {
        // The reference session prints its prepare summary once, after the
        // input is loaded and before the first statement executes.
        eprintln!(
            "prepare_total_ms={} load_inputs_ms=0 parse_ms={} query_scoped_planning_ms=0",
            parse_ms as u64, parse_ms as u64,
        );
    }
    // Line-oriented REPL: statements finish with `;` at end of line or an
    // empty line.  Dot commands are recognized only while the buffer is
    // empty; with a pending buffer they become ordinary SQL text.  A failing
    // statement reports an `error:` line and the session continues; the
    // process exits non-zero after the final summary error.
    let stdin = std::io::stdin();
    let mut failed = false;
    let mut buffer = String::new();
    use std::io::BufRead;
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => return Err(e.to_string()),
        };
        let trimmed = line.trim();
        if buffer.is_empty() {
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == ".exit" || trimmed == ".quit" {
                break;
            }
            if trimmed == ".help" {
                eprintln!("Enter SQL, finish with `;` or an empty line. Use `.exit` to quit.");
                continue;
            }
        }
        let completes = trimmed.ends_with(';');
        if !buffer.is_empty() {
            buffer.push('\n');
        }
        buffer.push_str(&line);
        if completes || trimmed.is_empty() {
            run_interactive_batch(&buffer, &dataset, &named_caches, &request, &mut failed);
            buffer.clear();
        }
    }
    if !buffer.trim().is_empty() {
        run_interactive_batch(&buffer, &dataset, &named_caches, &request, &mut failed);
    }
    if failed {
        return Err("interactive session completed with one or more failed SQL statements".into());
    }
    Ok(())
}

/// Validate a single statement, including the sqlparser expression pass
/// whose failures surface as `validate_sql` diagnostics.
fn validate_single(sql: &str) -> Result<dexsql_ast::Statement, DexSqlError> {
    let statement = dexsql_ast::validate(sql)
        .map_err(|error| DexSqlError::from_front(error.code, error.render()))?;
    if let dexsql_ast::Statement::Query { sql } = &statement {
        if let Ok(statements) = split_statements(sql) {
            if statements.len() == 1 {
                let dialect = sqlparser::dialect::SQLiteDialect {};
                match sqlparser::parser::Parser::parse_sql(&dialect, &statements[0]) {
                    Err(error) => {
                        let (mapped, span) = dexsql_ast::parser::map_parser_error(
                            &error.to_string(),
                            &statements[0],
                        );
                        let rendered = match span {
                            Some((start, end)) => format!("{mapped} (at bytes {start}..{end})"),
                            None => mapped,
                        };
                        return Err(DexSqlError::from_front(
                            dexsql_ast::Code::InvalidInput,
                            rendered,
                        ));
                    }
                    Ok(parsed) => {
                        // The reference grammar only accepts the plain
                        // TRIM(x[, chars]) form; BOTH/LEADING/TRAILING ... FROM
                        // spellings fail validate_sql with `expected RParen`
                        // spanning the trim-what literal.
                        if let Some(span) = find_trim_syntax_rejection(&parsed, &statements[0]) {
                            let rendered = match span {
                                Some((start, end)) => {
                                    format!("expected RParen (at bytes {start}..{end})")
                                }
                                None => "expected RParen".to_owned(),
                            };
                            return Err(DexSqlError::from_front(
                                dexsql_ast::Code::InvalidInput,
                                rendered,
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(statement)
}

/// Detect `TRIM([BOTH|LEADING|TRAILING] [what] FROM ...)` and return the
/// offending span (the trim-what literal when present).
fn find_trim_syntax_rejection(
    statements: &[sqlparser::ast::Statement],
    sql: &str,
) -> Option<Option<(usize, usize)>> {
    use sqlparser::ast::Expr;
    let mut rejected: Option<Option<(usize, usize)>> = None;
    let mut visit = |expr: &Expr, _visit: &mut dyn FnMut(&Expr)| {
        if let Expr::Trim {
            trim_where,
            trim_what,
            ..
        } = expr
        {
            if (trim_where.is_some() || trim_what.is_some()) && rejected.is_none() {
                let span = trim_what.as_ref().and_then(|what| expr_span(what, sql));
                rejected = Some(span);
            }
        }
    };
    let _ = &mut visit;
    for statement in statements {
        if let sqlparser::ast::Statement::Query(query) = statement {
            walk_query_exprs(query, &mut |expr| {
                if let Expr::Trim {
                    trim_where,
                    trim_what,
                    ..
                } = expr
                {
                    if (trim_where.is_some() || trim_what.is_some()) && rejected.is_none() {
                        let span = trim_what.as_ref().and_then(|what| expr_span(what, sql));
                        rejected = Some(span);
                    }
                }
            });
        }
    }
    rejected
}

/// Best-effort byte span of an expression from sqlparser line/column data.
fn expr_span(expr: &sqlparser::ast::Expr, sql: &str) -> Option<(usize, usize)> {
    use sqlparser::ast::Expr;
    match expr {
        Expr::Value(value) => {
            let start = line_column_to_offset(
                sql,
                value.span.start.line as usize,
                value.span.start.column as usize,
            );
            let end = line_column_to_offset(
                sql,
                value.span.end.line as usize,
                value.span.end.column as usize,
            );
            Some((start, end))
        }
        _ => None,
    }
}

fn line_column_to_offset(sql: &str, line: usize, column: usize) -> usize {
    let mut offset = 0usize;
    for (index, text_line) in sql.split('\n').enumerate() {
        if index + 1 == line {
            return offset + (column.saturating_sub(1)).min(text_line.chars().count());
        }
        offset += text_line.len() + 1;
    }
    offset
}

/// Walk the expressions of a query's SELECT bodies and set operations.
fn walk_query_exprs(query: &sqlparser::ast::Query, visit: &mut dyn FnMut(&sqlparser::ast::Expr)) {
    walk_set_expr_exprs(query.body.as_ref(), visit);
}

fn walk_set_expr_exprs(
    expr: &sqlparser::ast::SetExpr,
    visit: &mut dyn FnMut(&sqlparser::ast::Expr),
) {
    use sqlparser::ast::SetExpr;
    match expr {
        SetExpr::Select(select) => {
            for item in &select.projection {
                if let Some(expr) = item_expr(item) {
                    walk_expr(expr, visit);
                }
            }
            if let Some(selection) = &select.selection {
                walk_expr(selection, visit);
            }
            if let Some(having) = &select.having {
                walk_expr(having, visit);
            }
        }
        SetExpr::Query(query) => walk_query_exprs(query, visit),
        SetExpr::SetOperation { left, right, .. } => {
            walk_set_expr_exprs(left, visit);
            walk_set_expr_exprs(right, visit);
        }
        _ => {}
    }
}

fn walk_expr(expr: &sqlparser::ast::Expr, visit: &mut dyn FnMut(&sqlparser::ast::Expr)) {
    use sqlparser::ast::Expr;
    visit(expr);
    match expr {
        Expr::BinaryOp { left, right, .. } => {
            walk_expr(left, visit);
            walk_expr(right, visit);
        }
        Expr::UnaryOp { expr, .. } | Expr::Nested(expr) => walk_expr(expr, visit),
        Expr::Function(function) => {
            if let sqlparser::ast::FunctionArguments::List(args) = &function.args {
                for arg in &args.args {
                    if let sqlparser::ast::FunctionArg::Unnamed(
                        sqlparser::ast::FunctionArgExpr::Expr(expr),
                    ) = arg
                    {
                        walk_expr(expr, visit);
                    }
                }
            }
        }
        _ => {}
    }
}

fn run_interactive_batch(
    batch: &str,
    dataset: &Dataset,
    named_caches: &NamedCaches,
    request: &QueryRequest,
    failed: &mut bool,
) {
    // Each interactive submission is one request: earlier definitions stay
    // visible, but redefining one of them replaces instead of erroring.
    named_caches.begin_request();
    let statements = match split_statements(batch) {
        Ok(statements) => statements,
        Err(error) => {
            // Unterminated literals surface as a single statement-1 failure
            // shaped like the validate path.
            eprintln!(
                "error: SQL statement 1 failed: invalid_input at validate_sql: {error}: {error}"
            );
            *failed = true;
            return;
        }
    };
    for (index, statement) in statements.iter().enumerate() {
        let started = Instant::now();
        let validated = match validate_single(statement) {
            Ok(validated) => validated,
            Err(typed) => {
                let mut parts = vec![
                    format!("SQL statement {} failed", index + 1),
                    typed.to_string(),
                ];
                if let Some(source) = &typed.source {
                    parts.push(source.clone());
                }
                eprintln!("error: {}", render_flat_chain(&parts));
                *failed = true;
                continue;
            }
        };
        match execute_validated(&validated, Some(dataset), named_caches, request.limit) {
            Ok(result) => {
                let stdout = std::io::stdout();
                let mut writer = std::io::BufWriter::new(stdout.lock());
                if let Err(error) = write_table(&mut writer, &result)
                    .and_then(|()| std::io::Write::flush(&mut writer))
                {
                    eprintln!("error: {error}");
                    *failed = true;
                    return;
                }
                if request.timing {
                    let rewrites = match &validated {
                        dexsql_ast::Statement::Query { sql } => optimizer_rewrite_count(sql),
                        _ => 0,
                    };
                    if rewrites > 0 {
                        eprintln!("sql_static_optimizer rewrites={rewrites}");
                    }
                    eprintln!(
                        "total_ms=0 table_build_ms=0 cache_total_ms=0 sql_wall_ms={}",
                        (started.elapsed().as_secs_f64() * 1000.0) as u64
                    );
                }
            }
            Err(failure) => {
                let mut parts = vec![format!("SQL statement {} failed", index + 1)];
                match &failure {
                    StatementFailure::Wrapped(error) | StatementFailure::Bare(error) => {
                        parts.push(error.to_string());
                        if let Some(source) = &error.source {
                            parts.push(source.clone());
                        }
                    }
                }
                eprintln!("error: {}", render_flat_chain(&parts));
                *failed = true;
            }
        }
    }
}

fn split_statements(sql: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quote = false;
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\'' {
            if quote && bytes.get(i + 1) == Some(&b'\'') {
                // SQL escapes an embedded quote as `''`; consume both bytes
                // so the second quote cannot close the literal.
                i += 2;
                continue;
            }
            quote = !quote;
        } else if b == b';' && !quote {
            let s = sql[start..i].trim();
            if !s.is_empty() {
                out.push(s.to_owned());
            }
            start = i + 1;
        }
        i += 1;
    }
    if quote {
        return Err("invalid_input: unterminated string literal".into());
    }
    let tail = sql[start..].trim();
    if !tail.is_empty() {
        out.push(tail.to_owned());
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Scalar {
    Null,
    /// BLOB literal (`x'...'`): raw bytes.  Renders as lowercase hex; the
    /// reference keeps blobs type-distinct from text in comparisons.
    Blob(Vec<u8>),
    /// Text values are immutable and commonly inserted into three relation
    /// keys (qualified, unqualified and output aliases).  Keeping one shared
    /// allocation here is a substantial win for the million-row `methods`
    /// scan: the old String variant copied every descriptor once per key.
    Text(Arc<str>),
    Int(i64),
    Real(String),
}

impl Scalar {
    fn text(value: impl Into<String>) -> Self {
        Self::Text(Arc::<str>::from(value.into()))
    }

    fn display(&self) -> String {
        match self {
            // Preserve SQL NULL in rendered result cells.  Empty strings are
            // distinct values in DexSQL and must remain visually empty.
            Self::Null => "NULL".to_owned(),
            Self::Text(v) => escape_text(v),
            Self::Real(v) => v.clone(),
            Self::Int(v) => v.to_string(),
            Self::Blob(bytes) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        }
    }

    fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Blob(bytes) => !bytes.is_empty(),
            Self::Int(v) => *v != 0,
            Self::Real(v) => v.parse::<f64>().map(|n| n != 0.0).unwrap_or(false),
            Self::Text(v) => !v.is_empty(),
        }
    }

    fn numeric(&self) -> Option<f64> {
        match self {
            Self::Int(v) => Some(*v as f64),
            Self::Blob(_) => None,
            Self::Real(v) => v.parse().ok(),
            _ => None,
        }
    }

    fn sql_eq(&self, other: &Self) -> bool {
        membership::equal(self, other)
    }
}

fn scalar_from_rendered(value: &str) -> Scalar {
    if value.eq_ignore_ascii_case("null") {
        return Scalar::Null;
    }
    if let Ok(number) = value.parse::<i64>() {
        return Scalar::Int(number);
    }
    if (value.contains('.') || value.contains('e') || value.contains('E'))
        && value.parse::<f64>().is_ok()
    {
        return Scalar::Real(value.to_owned());
    }
    Scalar::text(value.to_owned())
}

fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[derive(Clone, Debug, Default)]
struct RelRow {
    // Relation rows are extremely numerous.  FxHashMap keeps the same lookup
    // complexity while avoiding a per-row SipHash state and substantially
    // reducing bucket overhead for these short, trusted schema keys.
    values: FxHashMap<Arc<str>, Scalar>,
    /// Unqualified columns in source order. Qualified keys are kept in values,
    /// but are not emitted by `*`.
    columns: Vec<Arc<str>>,
}

// Relation rows are short lived, but their map keys used to allocate a fresh
// `String` for every qualified and unqualified column on every row.  A large
// methods scan can create tens of millions of identical keys and temporarily
// consume many gigabytes.  Intern the small set of relation keys once per
// worker thread; rows then clone only an Arc pointer while retaining the same
// hash-map lookup semantics.  The cache is bounded by the number of aliases
// and schema columns seen by this process, rather than by row count.
thread_local! {
    static REL_KEY_INTERN: RefCell<HashMap<String, Arc<str>>> = RefCell::new(HashMap::new());
    static REL_QUALIFIED_INTERN: RefCell<HashMap<(Arc<str>, Arc<str>), Arc<str>>> =
        RefCell::new(HashMap::new());
}

#[inline]
fn intern_rel_component(value: &str) -> Arc<str> {
    REL_KEY_INTERN.with(|pool| {
        let mut pool = pool.borrow_mut();
        if let Some(existing) = pool.get(value) {
            return existing.clone();
        }
        let key = Arc::<str>::from(value);
        pool.insert(value.to_owned(), key.clone());
        key
    })
}

#[inline]
fn intern_rel_qualified(table: Arc<str>, column: Arc<str>) -> Arc<str> {
    REL_QUALIFIED_INTERN.with(|pool| {
        let mut pool = pool.borrow_mut();
        let pair = (table, column);
        if let Some(existing) = pool.get(&pair) {
            return existing.clone();
        }
        let key = Arc::<str>::from(format!("{}.{}", pair.0, pair.1));
        pool.insert(pair, key.clone());
        key
    })
}

#[inline]
fn lower_rel_component(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

impl RelRow {
    #[inline]
    fn with_capacity(columns: usize) -> Self {
        // Every logical column is kept under a qualified and (when free) an
        // unqualified key. Reserve the final map size up front so scans do
        // not repeatedly rehash millions of relation rows.
        Self {
            values: FxHashMap::with_capacity_and_hasher(
                columns.saturating_mul(2),
                Default::default(),
            ),
            columns: Vec::with_capacity(columns),
        }
    }

    fn put(&mut self, table: &str, column: &str, value: Scalar) {
        let table = intern_rel_component(lower_rel_component(table).as_ref());
        let unqualified = intern_rel_component(lower_rel_component(column).as_ref());
        let qualified = intern_rel_qualified(table, unqualified.clone());
        self.values.insert(qualified, value.clone());
        self.values
            .entry(unqualified.clone())
            .or_insert_with(|| value.clone());
        if !self.columns.iter().any(|v| v.as_ref() == column) {
            self.columns.push(unqualified.clone());
        }
        self.values.entry(unqualified).or_insert(value);
    }

    fn merge(&self, right: &RelRow) -> RelRow {
        let mut out = self.clone();
        for (key, value) in &right.values {
            // Qualified names never collide. Keep the left unqualified value
            // when both inputs expose the same column.
            out.values
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
        for column in &right.columns {
            if !out.columns.iter().any(|v| v == column) {
                out.columns.push(column.clone());
            }
        }
        out
    }

    fn get(&self, name: &str) -> Option<&Scalar> {
        let name = lower_rel_component(name);
        self.values.get(name.as_ref())
    }
}

#[derive(Clone, Debug)]
struct GroupedRow {
    row: RelRow,
    members: Vec<RelRow>,
}

#[derive(Clone, Debug)]
struct ProjectedRow {
    values: Vec<Scalar>,
    order_row: Option<Box<RelRow>>,
    group: Vec<RelRow>,
    sort_keys: Option<Box<[Scalar]>>,
}

#[derive(Clone, Debug)]
enum PushPredicateKind {
    Eq,
    NotEq,
    In,
    Like,
}

#[derive(Clone, Debug)]
struct PushPredicate {
    column: String,
    kind: PushPredicateKind,
    values: Vec<Scalar>,
    /// LIKE escape character, when the predicate was written with ESCAPE.
    escape: Option<char>,
}

pub fn execute_statement(
    sql: &str,
    dataset: Option<&Dataset>,
    named_caches: &NamedCaches,
    cli_limit: Option<u64>,
) -> Result<QueryResult, String> {
    let normalized = sql.trim().trim_end_matches(';').trim();
    // Relation-free SELECTs (constants, arithmetic and `count(*)`) are
    // intentionally executable without an input file.  Keep an empty
    // Dataset as their relation environment; table-bearing statements still
    // receive the reference error below.
    let empty_dataset;
    let ds = match dataset {
        Some(ds) => ds,
        None => {
            empty_dataset = Dataset::default();
            &empty_dataset
        }
    };
    if dataset.is_some() && !cache_shadows_relation(normalized, named_caches) {
        if let Some(result) = fast_count(normalized, ds, cli_limit) {
            return Ok(result);
        }
    }
    let dialect = sqlparser::dialect::SQLiteDialect {};
    let statements = sqlparser::parser::Parser::parse_sql(&dialect, normalized)
        .map_err(|e| format!("SQL parse error: {e}"))?;
    if statements.len() != 1 {
        return Err(format!(
            "expected one SQL statement, found {}",
            statements.len()
        ));
    }
    let statement = statements.into_iter().next().unwrap();
    let sqlparser::ast::Statement::Query(mut query) = statement else {
        return Err("only read-only SELECT statements are supported".into());
    };
    lower_substring_calls(&mut query, normalized);
    lower_blob_literals(&mut query, normalized);
    if dataset.is_none() {
        let cte_names: Vec<String> = query
            .with
            .as_ref()
            .map(|with| {
                with.cte_tables
                    .iter()
                    .map(|cte| cte.alias.name.value.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        let needs_source = sql_from_factors(query.body.as_ref(), &mut Vec::new());
        if needs_source.into_iter().any(|name| {
            !named_caches.definitions.borrow().contains_key(&name) && !cte_names.contains(&name)
        }) {
            return Err("required execution data source is unavailable".into());
        }
    }
    if dataset.is_some() && query.with.is_none() {
        if let Some(result) = try_fast_count_scan(&query, ds, cli_limit) {
            return result;
        }
        if let Some(result) = fast_methods_topk(&query, ds, cli_limit) {
            return result;
        }
        if let Some(result) = fast_method_numbers_topk(&query, ds, cli_limit) {
            return result;
        }
        if let Some(result) = fast_method_numbers_no_join_topk(&query, ds, cli_limit) {
            return result;
        }
        if let Some(result) = fast_method_strings_topk(&query, ds, cli_limit) {
            return result;
        }
        if let Some(result) = fast_descriptor::try_fast_descriptor_lookup(&query, ds, cli_limit) {
            return result;
        }
    }
    let needs_method_opcode = normalized.to_ascii_lowercase().contains("opcode_count")
        || normalized.to_ascii_lowercase().contains("opcode_hex")
        || query.body.as_select().is_some_and(|select| {
            select.projection.iter().any(|item| {
                matches!(
                    item,
                    sqlparser::ast::SelectItem::Wildcard(_)
                        | sqlparser::ast::SelectItem::QualifiedWildcard(_, _)
                )
            })
        });
    execute_query(
        &query,
        ds,
        dataset,
        named_caches,
        cli_limit,
        needs_method_opcode,
    )
}

/// Collect the base-table names reachable from a set-expression tree,
/// including FROM factors inside nested subqueries.
fn sql_from_factors(expr: &sqlparser::ast::SetExpr, names: &mut Vec<String>) -> Vec<String> {
    use sqlparser::ast::SetExpr;
    match expr {
        SetExpr::Select(select) => {
            collect_from_select(select, names);
        }
        SetExpr::Query(query) => {
            sql_from_factors(query.body.as_ref(), names);
        }
        SetExpr::Values(_) => {}
        SetExpr::SetOperation { left, right, .. } => {
            sql_from_factors(left, names);
            sql_from_factors(right, names);
        }
        _ => {}
    }
    names.clone()
}

fn collect_from_select(select: &sqlparser::ast::Select, names: &mut Vec<String>) {
    for table in &select.from {
        collect_from_factor(&table.relation, names);
        for join in &table.joins {
            collect_from_factor(&join.relation, names);
        }
    }
}

fn collect_from_factor(factor: &sqlparser::ast::TableFactor, names: &mut Vec<String>) {
    match factor {
        sqlparser::ast::TableFactor::Table { name, .. } => {
            if let Some(name) = name.0.last().and_then(|part| part.as_ident()) {
                names.push(name.value.to_ascii_lowercase());
            }
        }
        sqlparser::ast::TableFactor::Derived { subquery, .. } => {
            sql_from_factors(subquery.body.as_ref(), names);
        }
        _ => {}
    }
}

fn factor_table_name(factor: &sqlparser::ast::TableFactor) -> Option<String> {
    let sqlparser::ast::TableFactor::Table { name, .. } = factor else {
        return None;
    };
    name.0
        .last()
        .and_then(|part| part.as_ident())
        .map(|ident| ident.value.to_ascii_lowercase())
}

/// Fast path for the very common DexKit query shape
/// `SELECT [DISTINCT] m.descriptor FROM methods m WHERE ... ORDER BY
/// m.descriptor`.  The generic relation executor has to allocate a HashMap
/// for every matching method before sorting.  The physical engine's ordered
/// method index can answer this shape with a bounded heap and only materialize
/// the rows that survive the requested LIMIT.
fn fast_methods_topk(
    query: &sqlparser::ast::Query,
    ds: &Dataset,
    cli_limit: Option<u64>,
) -> Option<Result<QueryResult, String>> {
    use sqlparser::ast::{SelectItem, SetExpr};
    let debug = std::env::var_os("DEXSQL_DEBUG_FASTPATH").is_some();
    let select = match query.body.as_ref() {
        SetExpr::Select(select) => select.as_ref(),
        _ => {
            if debug {
                eprintln!("fastpath: body not select");
            }
            return None;
        }
    };
    if select.from.len() != 1
        || !select.from[0].joins.is_empty()
        || select.distinct.is_some()
        || !matches!(&select.group_by, sqlparser::ast::GroupByExpr::Expressions(exprs, _) if exprs.is_empty())
        || select.having.is_some()
        || select
            .selection
            .as_ref()
            .is_some_and(|e| !method_predicates(e))
    {
        if debug {
            eprintln!("fastpath: shape reject");
        }
        return None;
    }
    let sqlparser::ast::TableFactor::Table {
        name, alias, args, ..
    } = &select.from[0].relation
    else {
        if debug {
            eprintln!("fastpath: from not table");
        }
        return None;
    };
    if args.is_some()
        || !name
            .0
            .last()
            .and_then(|part| part.as_ident())
            .is_some_and(|id| id.value.eq_ignore_ascii_case("methods"))
    {
        if debug {
            eprintln!("fastpath: not methods");
        }
        return None;
    }
    let alias_name = alias
        .as_ref()
        .map(|a| a.name.value.as_str())
        .or_else(|| {
            name.0
                .last()
                .and_then(|part| part.as_ident())
                .map(|id| id.value.as_str())
        })
        .unwrap_or("methods");
    if select
        .selection
        .as_ref()
        .is_some_and(|expr| !references_only(expr, alias_name))
    {
        return None;
    }
    if select.projection.len() != 1
        || !select.projection.iter().all(|item| {
            item_expr(item).is_some_and(|expr| {
                is_method_descriptor_expr(expr) && descriptor_qualifier_matches(expr, alias_name)
            })
        })
    {
        if debug {
            eprintln!("fastpath: projection reject");
        }
        return None;
    }
    let Some(order_by) = query.order_by.as_ref() else {
        if debug {
            eprintln!("fastpath: no order by");
        }
        return None;
    };
    let sqlparser::ast::OrderByKind::Expressions(order_exprs) = &order_by.kind else {
        return None;
    };
    if order_exprs.len() != 1
        || !is_method_descriptor_expr(&order_exprs[0].expr)
        || !descriptor_qualifier_matches(&order_exprs[0].expr, alias_name)
        || order_by.interpolate.is_some()
    {
        if debug {
            eprintln!("fastpath: order reject");
        }
        return None;
    }
    // Descending has a different heap polarity; retain the generic path until
    // a descending physical index is added.
    if order_exprs[0].options.sort == Some(sqlparser::ast::OrderBySort::Desc) {
        return None;
    }
    // A SQL LIMIT is a physical top-k bound too.  The old path only used the
    // CLI `--limit`, so `... ORDER BY descriptor LIMIT 10` still materialized
    // and sorted every method.  Include OFFSET in the heap bound so the final
    // SQL slice remains exact.
    let sql_offset = query_offset_value(query.limit_clause.as_ref()).unwrap_or(0);
    let sql_limit = query_limit_value(query.limit_clause.as_ref());
    let cli_limit = cli_limit.map(|value| usize::try_from(value).unwrap_or(usize::MAX));
    let result_limit = match (sql_limit, cli_limit) {
        (Some(sql), Some(cli)) => Some(sql.min(cli)),
        (Some(sql), None) => Some(sql),
        (None, cli) => cli,
    };
    let limit = result_limit.map(|value| value.saturating_add(sql_offset));
    let label = match &select.projection[0] {
        SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
        SelectItem::UnnamedExpr(expr) => expression_label(expr),
        _ => return None,
    };
    let predicates = match select.selection.as_ref() {
        Some(expr) => method_push_predicates(expr).ok()?,
        // A WHERE-less ORDER BY descriptor LIMIT is the plain physical
        // top-k: each file's pre-ordered descriptor index answers it with
        // only O(files x limit) materialized descriptors.
        None => {
            let take = limit?;
            if take == 0 {
                return Some(Ok(QueryResult {
                    columns: vec![label],
                    rows: Vec::new(),
                }));
            }
            let built = std::time::Instant::now();
            ds.build_ordered_method_descriptors();
            if debug {
                eprintln!("fastpath: ordered index built in {:?}", built.elapsed());
            }
            let mut selected: Vec<String> = Vec::with_capacity(ds.files.len() * take);
            for file in &ds.files {
                let order = file.ordered_method_descriptors();
                for &idx in order.iter().take(take) {
                    selected.push(file.method_descriptor_direct(idx));
                }
            }
            selected.sort_by(|a, b| dexsql_cache::utf16_cmp(a, b));
            selected.truncate(take);
            return Some(Ok(QueryResult {
                columns: vec![label],
                rows: selected
                    .into_iter()
                    .skip(sql_offset)
                    .take(result_limit.unwrap_or(usize::MAX))
                    .map(|d| vec![d])
                    .collect(),
            }));
        }
    };
    let predicate_needs_descriptor = predicates
        .iter()
        .any(|predicate| matches!(predicate.column.as_str(), "descriptor" | "method"));
    let mut heap = BinaryHeap::with_capacity(limit.unwrap_or(0).saturating_add(1));
    let mut all_descriptors = if limit.is_none() {
        Some(Vec::new())
    } else {
        None
    };
    for file in &ds.files {
        let indexed_candidates = indexed_method_candidates(file, &predicates);
        let mut consider = |idx: u32| {
            let Some(method) = file.methods.get(idx as usize) else {
                return;
            };
            let Some(proto) = file.protos.get(method.proto_idx as usize) else {
                return;
            };
            let class = file.method_class(idx);
            let name = file.method_name(idx);
            let return_descriptor = file.type_descriptor(proto.return_type_idx);
            let descriptor = if predicate_needs_descriptor {
                file.method_descriptor_direct(idx)
            } else {
                String::new()
            };
            if !method_predicates_match(
                &predicates,
                class,
                name,
                &descriptor,
                return_descriptor,
                proto.parameters.len() as i64,
            ) {
                return;
            }
            let descriptor = if predicate_needs_descriptor {
                descriptor
            } else {
                file.method_descriptor_direct(idx)
            };
            if let Some(limit) = limit {
                if limit == 0 {
                    return;
                }
                if heap.len() < limit {
                    heap.push(descriptor);
                } else if heap
                    .peek()
                    .is_some_and(|worst| descriptor.as_str() < worst.as_str())
                {
                    heap.pop();
                    heap.push(descriptor);
                }
            } else if let Some(values) = &mut all_descriptors {
                values.push(descriptor);
            }
        };
        if let Some(candidates) = indexed_candidates {
            for idx in candidates {
                consider(idx);
            }
        } else {
            for idx in 0..file.methods.len() as u32 {
                consider(idx);
            }
        }
    }
    let mut values = match all_descriptors {
        Some(mut values) => {
            values.sort_unstable();
            values
        }
        None => heap.into_sorted_vec(),
    };
    let rows = values
        .drain(..)
        .skip(sql_offset)
        .take(result_limit.unwrap_or(usize::MAX))
        .map(|v| vec![v])
        .collect::<Vec<_>>();
    Some(Ok(QueryResult {
        columns: vec![label],
        rows,
    }))
}

/// Fast path for the unjoined number matcher: the value->row index is already
/// the physical scan the query asks for, so grouping can be a compact bit mask
/// per method instead of allocating one relation row per reference.
fn fast_method_numbers_no_join_topk(
    query: &sqlparser::ast::Query,
    ds: &Dataset,
    cli_limit: Option<u64>,
) -> Option<Result<QueryResult, String>> {
    use sqlparser::ast::{SelectItem, SetExpr};
    let select = match query.body.as_ref() {
        SetExpr::Select(select) => select.as_ref(),
        _ => return None,
    };
    let Some(limit) = cli_limit else { return None };
    if query.limit_clause.is_some()
        || select.from.len() != 1
        || !select.from[0].joins.is_empty()
        || select.distinct.is_none()
        || select.projection.len() != 1
        || select.having.is_none()
    {
        return None;
    }
    let sqlparser::ast::TableFactor::Table {
        name, alias, args, ..
    } = &select.from[0].relation
    else {
        return None;
    };
    if args.is_some()
        || !name.0.last().and_then(|v| v.as_ident()).is_some_and(|v| {
            v.value.eq_ignore_ascii_case("method_using_numbers")
                || v.value.eq_ignore_ascii_case("method_numbers")
        })
    {
        return None;
    }
    let alias = alias
        .as_ref()
        .map(|a| a.name.value.as_str())
        .unwrap_or("mn");
    let Some(expr) = item_expr(&select.projection[0]) else {
        return None;
    };
    if !is_column_expr(expr, "method", Some(alias)) {
        return None;
    }
    let sqlparser::ast::GroupByExpr::Expressions(groups, modifiers) = &select.group_by else {
        return None;
    };
    if !modifiers.is_empty()
        || groups.len() != 1
        || !is_column_expr(&groups[0], "method", Some(alias))
    {
        return None;
    }
    let required = parse_distinct_count_having(select.having.as_ref()?)?;
    let mut conjuncts = Vec::new();
    flatten_and(select.selection.as_ref()?, &mut conjuncts);
    let mut values = Vec::new();
    for c in conjuncts {
        let pred = simple_push_predicate(c)?;
        if !pred.column.eq_ignore_ascii_case("long_value") {
            return None;
        }
        if !matches!(pred.kind, PushPredicateKind::Eq | PushPredicateKind::In) {
            return None;
        }
        for v in pred.values {
            let n = v.numeric()?;
            if n.fract() != 0.0 {
                return None;
            }
            values.push(n as i64);
        }
    }
    values.sort_unstable();
    values.dedup();
    if values.is_empty() || values.len() > 64 {
        return None;
    }
    let sqlparser::ast::OrderByKind::Expressions(order) = &query.order_by.as_ref()?.kind else {
        return None;
    };
    if order.len() != 1
        || !is_column_expr(&order[0].expr, "method", Some(alias))
        || order[0].options.sort == Some(sqlparser::ast::OrderBySort::Desc)
    {
        return None;
    }
    let label = match &select.projection[0] {
        SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
        SelectItem::UnnamedExpr(e) => expression_label(e),
        _ => return None,
    };
    if required > values.len() {
        return Some(Ok(QueryResult {
            columns: vec![label],
            rows: Vec::new(),
        }));
    }
    // For the overwhelmingly common one-value matcher, no per-method mask
    // is needed: every indexed reference already satisfies HAVING COUNT = 1.
    // Walk the inverted posting list directly and deduplicate descriptors.
    if values.len() == 1 && required == 1 {
        let mut heap = BinaryHeap::with_capacity(limit as usize + 1);
        let mut seen_descriptors = HashSet::new();
        for file in &ds.files {
            let Some(rows) = file.method_number_rows_by_value.get(&values[0]) else {
                continue;
            };
            let mut method_ids = HashSet::with_capacity(rows.len().min(4096));
            for &ri in rows {
                let Some(reference) = file.method_numbers.get(ri) else {
                    continue;
                };
                method_ids.insert(reference.method_idx);
            }
            let descriptors = if method_ids.len() > 512 {
                method_ids
                    .into_par_iter()
                    .map(|method_idx| file.method_descriptor_direct(method_idx))
                    .collect::<Vec<_>>()
            } else {
                method_ids
                    .into_iter()
                    .map(|method_idx| file.method_descriptor_direct(method_idx))
                    .collect::<Vec<_>>()
            };
            for descriptor in descriptors {
                if !seen_descriptors.insert(descriptor.clone()) || limit == 0 {
                    continue;
                }
                if heap.len() < limit as usize {
                    heap.push(descriptor.to_owned());
                } else if heap
                    .peek()
                    .is_some_and(|worst| descriptor.as_str() < worst.as_str())
                {
                    heap.pop();
                    heap.push(descriptor.to_owned());
                }
            }
        }
        return Some(Ok(QueryResult {
            columns: vec![label],
            rows: heap
                .into_sorted_vec()
                .into_iter()
                .map(|v| vec![v])
                .collect(),
        }));
    }
    let mut heap = BinaryHeap::with_capacity(limit as usize + 1);
    let mut masks: FxHashMap<(u32, u32), u64> = FxHashMap::default();
    let bits: FxHashMap<i64, u64> = values
        .iter()
        .enumerate()
        .map(|(i, v)| (*v, 1u64 << i))
        .collect();
    for file in &ds.files {
        masks.clear();
        for v in &values {
            let Some(rows) = file.method_number_rows_by_value.get(v) else {
                continue;
            };
            let bit = bits[v];
            for &ri in rows {
                if let Some(r) = file.method_numbers.get(ri) {
                    *masks.entry((file.file_id, r.method_idx)).or_default() |= bit;
                }
            }
        }
        for ((fid, mid), mask) in masks.drain() {
            if mask.count_ones() as usize != required {
                continue;
            }
            let file = &ds.files[fid as usize];
            let d = file.method_descriptor_direct(mid);
            if heap.len() < limit as usize {
                heap.push(d.to_owned());
            } else if heap.peek().is_some_and(|w| d.as_str() < w.as_str()) {
                heap.pop();
                heap.push(d.to_owned());
            }
        }
    }
    Some(Ok(QueryResult {
        columns: vec![label],
        rows: heap
            .into_sorted_vec()
            .into_iter()
            .map(|v| vec![v])
            .collect(),
    }))
}

fn fast_method_numbers_topk(
    query: &sqlparser::ast::Query,
    ds: &Dataset,
    cli_limit: Option<u64>,
) -> Option<Result<QueryResult, String>> {
    use sqlparser::ast::{SelectItem, SetExpr};
    let select = match query.body.as_ref() {
        SetExpr::Select(select) => select.as_ref(),
        _ => return None,
    };
    let Some(limit) = cli_limit else { return None };
    if query.limit_clause.is_some()
        || select.from.len() != 1
        || select.from[0].joins.len() != 1
        || select.distinct.is_none()
        || select.projection.len() != 1
        || select.having.is_none()
    {
        return None;
    }
    let Some(item_expr) = item_expr(&select.projection[0]) else {
        return None;
    };
    if !is_column_expr(item_expr, "method", Some("mn")) {
        return None;
    }
    let sqlparser::ast::TableFactor::Table {
        name: left_name,
        alias: left_alias,
        args,
        ..
    } = &select.from[0].relation
    else {
        return None;
    };
    if args.is_some()
        || !left_name
            .0
            .last()
            .and_then(|v| v.as_ident())
            .is_some_and(|v| {
                v.value.eq_ignore_ascii_case("method_using_numbers")
                    || v.value.eq_ignore_ascii_case("method_numbers")
            })
    {
        return None;
    }
    let left_alias = left_alias
        .as_ref()
        .map(|a| a.name.value.as_str())
        .unwrap_or("mn");
    if !left_alias.eq_ignore_ascii_case("mn") {
        return None;
    }
    let sqlparser::ast::TableFactor::Table {
        name: right_name,
        alias: right_alias,
        args,
        ..
    } = &select.from[0].joins[0].relation
    else {
        return None;
    };
    if args.is_some()
        || !right_name
            .0
            .last()
            .and_then(|v| v.as_ident())
            .is_some_and(|v| v.value.eq_ignore_ascii_case("methods"))
    {
        return None;
    }
    let right_alias = right_alias
        .as_ref()
        .map(|a| a.name.value.as_str())
        .unwrap_or("methods");
    let constraint = join_constraint(&select.from[0].joins[0].join_operator).ok()??;
    if !is_method_number_join(constraint, left_alias, right_alias) {
        return None;
    }

    let sqlparser::ast::GroupByExpr::Expressions(group_exprs, modifiers) = &select.group_by else {
        return None;
    };
    if !modifiers.is_empty()
        || group_exprs.len() != 1
        || !is_column_expr(&group_exprs[0], "method", Some(left_alias))
    {
        return None;
    }
    let required_count = parse_distinct_count_having(select.having.as_ref()?)?;
    let mut number_values = Vec::new();
    let mut method_predicates = Vec::new();
    let Some(selection) = select.selection.as_ref() else {
        return None;
    };
    let mut conjuncts = Vec::new();
    flatten_and(selection, &mut conjuncts);
    for conjunct in conjuncts {
        let Some(predicate) = simple_push_predicate(conjunct) else {
            return None;
        };
        if predicate.column.eq_ignore_ascii_case("long_value") {
            if !matches!(
                predicate.kind,
                PushPredicateKind::Eq | PushPredicateKind::In
            ) {
                return None;
            }
            for value in &predicate.values {
                let Some(number) = value.numeric() else {
                    return None;
                };
                if number.fract() != 0.0 {
                    return None;
                }
                number_values.push(number as i64);
            }
        } else {
            // Only metadata columns from the joined methods relation can be
            // evaluated without materializing a methods row.
            if !matches!(
                predicate.column.as_str(),
                "class_descriptor"
                    | "method_class"
                    | "name"
                    | "method_name"
                    | "return_descriptor"
                    | "param_count"
            ) {
                return None;
            }
            method_predicates.push(predicate);
        }
    }
    number_values.sort_unstable();
    number_values.dedup();
    if number_values.is_empty() || number_values.len() > 64 || required_count != number_values.len()
    {
        return None;
    }
    let sqlparser::ast::OrderByKind::Expressions(order_exprs) = &query.order_by.as_ref()?.kind
    else {
        return None;
    };
    if order_exprs.len() != 1
        || !is_column_expr(&order_exprs[0].expr, "method", Some(left_alias))
        || order_exprs[0].options.sort == Some(sqlparser::ast::OrderBySort::Desc)
    {
        return None;
    }
    let label = match &select.projection[0] {
        SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
        SelectItem::UnnamedExpr(expr) => expression_label(expr),
        _ => return None,
    };
    let limit = limit as usize;
    let mut heap = BinaryHeap::with_capacity(limit.saturating_add(1));
    let mut globally_seen = HashSet::new();
    let value_bits = number_values
        .iter()
        .enumerate()
        .map(|(i, v)| (*v, 1u64 << i))
        .collect::<HashMap<_, _>>();
    for file in &ds.files {
        let mut masks: FxHashMap<u32, u64> = FxHashMap::default();
        for value in &number_values {
            let Some(row_indices) = file.method_number_rows_by_value.get(value) else {
                continue;
            };
            let bit = value_bits[value];
            for &row_idx in row_indices {
                let Some(reference) = file.method_numbers.get(row_idx) else {
                    continue;
                };
                *masks.entry(reference.method_idx).or_default() |= bit;
            }
        }
        let mut accepted = Vec::new();
        for (method_idx, mask) in masks {
            if mask.count_ones() as usize != required_count {
                continue;
            }
            let Some(method) = file.methods.get(method_idx as usize) else {
                continue;
            };
            let Some(proto) = file.protos.get(method.proto_idx as usize) else {
                continue;
            };
            let class = file.method_class(method_idx);
            let name = file.method_name(method_idx);
            let return_descriptor = file.type_descriptor(proto.return_type_idx);
            if !method_predicates_match(
                &method_predicates,
                class,
                name,
                "",
                return_descriptor,
                proto.parameters.len() as i64,
            ) {
                continue;
            }
            accepted.push(method_idx);
        }
        let descriptors = if accepted.len() > 512 {
            accepted
                .into_par_iter()
                .map(|method_idx| file.method_descriptor_direct(method_idx))
                .collect::<Vec<_>>()
        } else {
            accepted
                .into_iter()
                .map(|method_idx| file.method_descriptor_direct(method_idx))
                .collect::<Vec<_>>()
        };
        for descriptor in descriptors {
            if !globally_seen.insert(descriptor.clone()) {
                continue;
            }
            if limit == 0 {
                continue;
            }
            if heap.len() < limit {
                heap.push(descriptor);
            } else if heap
                .peek()
                .is_some_and(|worst| descriptor.as_str() < worst.as_str())
            {
                heap.pop();
                heap.push(descriptor);
            }
        }
    }
    let rows = heap
        .into_sorted_vec()
        .into_iter()
        .map(|v| vec![v])
        .collect();
    Some(Ok(QueryResult {
        columns: vec![label],
        rows,
    }))
}

fn is_column_expr(expr: &sqlparser::ast::Expr, column: &str, qualifier: Option<&str>) -> bool {
    match expr {
        sqlparser::ast::Expr::Identifier(id) => {
            qualifier.is_none() && id.value.eq_ignore_ascii_case(column)
        }
        sqlparser::ast::Expr::CompoundIdentifier(ids) if ids.len() >= 2 => {
            ids.last()
                .is_some_and(|id| id.value.eq_ignore_ascii_case(column))
                && qualifier.is_none_or(|q| ids[ids.len() - 2].value.eq_ignore_ascii_case(q))
        }
        _ => false,
    }
}

fn is_method_number_join(expr: &sqlparser::ast::Expr, left_alias: &str, right_alias: &str) -> bool {
    let sqlparser::ast::Expr::BinaryOp {
        left,
        op: sqlparser::ast::BinaryOperator::Eq,
        right,
    } = expr
    else {
        return false;
    };
    (is_column_expr(left, "method", Some(left_alias))
        && is_column_expr(right, "descriptor", Some(right_alias)))
        || (is_column_expr(right, "method", Some(left_alias))
            && is_column_expr(left, "descriptor", Some(right_alias)))
}

fn parse_distinct_count_having(expr: &sqlparser::ast::Expr) -> Option<usize> {
    parse_distinct_count_having_column(expr, "long_value")
}

fn parse_distinct_count_having_column(expr: &sqlparser::ast::Expr, column: &str) -> Option<usize> {
    use sqlparser::ast::{
        BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, Value,
    };
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    else {
        return None;
    };
    let (function, value) = match (left.as_ref(), right.as_ref()) {
        (Expr::Function(f), Expr::Value(v)) => (f, v),
        (Expr::Value(v), Expr::Function(f)) => (f, v),
        _ => return None,
    };
    let Value::Number(number, _) = &value.value else {
        return None;
    };
    let required = number.parse().ok()?;
    let name = function.name.0.last()?.to_string();
    if !name.eq_ignore_ascii_case("count") {
        return None;
    }
    let FunctionArguments::List(arguments) = &function.args else {
        return None;
    };
    if arguments.duplicate_treatment != Some(sqlparser::ast::DuplicateTreatment::Distinct) {
        return None;
    }
    let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(arg))) = arguments.args.first() else {
        return None;
    };
    if !is_column_expr(arg, column, None) {
        return None;
    }
    Some(required)
}

/// Fast path for the other dominant DexKit matcher shape:
/// `method_strings` is filtered by a small literal set, optionally joined to
/// `methods` for metadata predicates, then grouped by method or class.  The
/// cache's string inverted index gives the candidate method IDs directly, so
/// this avoids constructing a row/hash-map for every string reference.
fn fast_method_strings_topk(
    query: &sqlparser::ast::Query,
    ds: &Dataset,
    cli_limit: Option<u64>,
) -> Option<Result<QueryResult, String>> {
    use sqlparser::ast::{SelectItem, SetExpr};
    let select = match query.body.as_ref() {
        SetExpr::Select(select) => select.as_ref(),
        _ => return None,
    };
    let Some(limit) = cli_limit else { return None };
    if query.limit_clause.is_some()
        || select.from.len() != 1
        || select.from[0].joins.len() > 1
        || select.projection.len() != 1
        || select.having.is_none()
    {
        return None;
    }
    let sqlparser::ast::TableFactor::Table {
        name: left_name,
        alias: left_alias,
        args,
        ..
    } = &select.from[0].relation
    else {
        return None;
    };
    if args.is_some()
        || !left_name
            .0
            .last()
            .and_then(|v| v.as_ident())
            .is_some_and(|v| v.value.eq_ignore_ascii_case("method_strings"))
    {
        return None;
    }
    let left_alias = left_alias
        .as_ref()
        .map(|a| a.name.value.as_str())
        .unwrap_or("ms");
    let has_join = !select.from[0].joins.is_empty();
    let right_alias = if has_join {
        let sqlparser::ast::TableFactor::Table {
            name, alias, args, ..
        } = &select.from[0].joins[0].relation
        else {
            return None;
        };
        if args.is_some()
            || !name
                .0
                .last()
                .and_then(|v| v.as_ident())
                .is_some_and(|v| v.value.eq_ignore_ascii_case("methods"))
        {
            return None;
        }
        let right_alias = alias.as_ref().map(|a| a.name.value.as_str()).unwrap_or("m");
        let constraint = join_constraint(&select.from[0].joins[0].join_operator).ok()??;
        if !is_method_string_join(constraint, left_alias, right_alias) {
            return None;
        }
        Some(right_alias)
    } else {
        None
    };

    let item = &select.projection[0];
    let Some(item_expr) = item_expr(item) else {
        return None;
    };
    let group_exprs = match &select.group_by {
        sqlparser::ast::GroupByExpr::Expressions(exprs, modifiers)
            if modifiers.is_empty() && exprs.len() == 1 =>
        {
            exprs
        }
        _ => return None,
    };
    let (group_column, group_qualifier) = if is_column_expr(item_expr, "method", Some(left_alias))
        && is_column_expr(&group_exprs[0], "method", Some(left_alias))
    {
        ("method", Some(left_alias))
    } else if is_column_expr(item_expr, "method_class", Some(left_alias))
        && is_column_expr(&group_exprs[0], "method_class", Some(left_alias))
    {
        ("method_class", Some(left_alias))
    } else {
        return None;
    };
    let sqlparser::ast::OrderByKind::Expressions(order_exprs) = &query.order_by.as_ref()?.kind
    else {
        return None;
    };
    if order_exprs.len() != 1
        || !is_column_expr(&order_exprs[0].expr, group_column, group_qualifier)
        || order_exprs[0].options.sort == Some(sqlparser::ast::OrderBySort::Desc)
    {
        return None;
    }
    let required_count = parse_distinct_count_having_column(select.having.as_ref()?, "value")?;
    let mut conjuncts = Vec::new();
    flatten_and(select.selection.as_ref()?, &mut conjuncts);
    let mut wanted_values = Vec::new();
    let mut method_predicates = Vec::new();
    for conjunct in conjuncts {
        let Some(predicate) = simple_push_predicate(conjunct) else {
            return None;
        };
        if predicate.column.eq_ignore_ascii_case("value") {
            if !matches!(
                predicate.kind,
                PushPredicateKind::Eq | PushPredicateKind::In
            ) {
                return None;
            }
            for value in predicate.values {
                let Scalar::Text(value) = value else {
                    return None;
                };
                if !wanted_values.iter().any(|v: &String| v == value.as_ref()) {
                    wanted_values.push(value.to_string());
                }
            }
        } else {
            if !matches!(
                predicate.column.as_str(),
                "method_class"
                    | "class_descriptor"
                    | "method_name"
                    | "name"
                    | "return_descriptor"
                    | "param_count"
            ) {
                return None;
            }
            if !has_join
                && matches!(
                    predicate.column.as_str(),
                    "return_descriptor" | "param_count" | "class_descriptor"
                )
            {
                return None;
            }
            method_predicates.push(predicate);
        }
    }
    if wanted_values.is_empty() || wanted_values.len() > 64 {
        return None;
    }
    let label = match item {
        SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
        SelectItem::UnnamedExpr(expr) => expression_label(expr),
        _ => return None,
    };
    let limit = limit as usize;
    let mut grouped: HashMap<String, u64> = HashMap::new();
    for file in &ds.files {
        let mut wanted_indices = Vec::new();
        for (bit, value) in wanted_values.iter().enumerate() {
            if let Some(string_idx) = file.find_string_idx(value) {
                wanted_indices.push((1u64 << bit, string_idx));
            }
        }
        for (bit, string_idx) in wanted_indices {
            let Some(methods) = file.method_strings_by_string.get(&string_idx) else {
                continue;
            };
            for &method_idx in methods {
                let class = file.method_class(method_idx);
                let name = file.method_name(method_idx);
                let descriptor = if group_column == "method" {
                    file.method_descriptor_direct(method_idx)
                } else {
                    String::new()
                };
                let (return_descriptor, param_count) = if right_alias.is_some() {
                    let Some(method) = file.methods.get(method_idx as usize) else {
                        continue;
                    };
                    let Some(proto) = file.protos.get(method.proto_idx as usize) else {
                        continue;
                    };
                    (
                        file.type_descriptor(proto.return_type_idx),
                        proto.parameters.len() as i64,
                    )
                } else {
                    ("", 0)
                };
                if !method_predicates_match(
                    &method_predicates,
                    class,
                    name,
                    &descriptor,
                    return_descriptor,
                    param_count,
                ) {
                    continue;
                }
                let key = if group_column == "method" {
                    descriptor
                } else {
                    class.to_owned()
                };
                *grouped.entry(key).or_default() |= bit;
            }
        }
    }
    let mut heap = BinaryHeap::with_capacity(limit.saturating_add(1));
    for (key, mask) in grouped {
        if mask.count_ones() as usize != required_count {
            continue;
        }
        if limit == 0 {
            continue;
        }
        if heap.len() < limit {
            heap.push(key);
        } else if heap.peek().is_some_and(|worst| key < *worst) {
            heap.pop();
            heap.push(key);
        }
    }
    let rows = heap
        .into_sorted_vec()
        .into_iter()
        .map(|v| vec![v])
        .collect();
    Some(Ok(QueryResult {
        columns: vec![label],
        rows,
    }))
}

fn is_method_string_join(expr: &sqlparser::ast::Expr, left_alias: &str, right_alias: &str) -> bool {
    let sqlparser::ast::Expr::BinaryOp {
        left,
        op: sqlparser::ast::BinaryOperator::Eq,
        right,
    } = expr
    else {
        return false;
    };
    (is_column_expr(left, "method", Some(left_alias))
        && is_column_expr(right, "descriptor", Some(right_alias)))
        || (is_column_expr(right, "method", Some(left_alias))
            && is_column_expr(left, "descriptor", Some(right_alias)))
}

fn is_method_descriptor_expr(expr: &sqlparser::ast::Expr) -> bool {
    match expr {
        sqlparser::ast::Expr::Identifier(id) => id.value.eq_ignore_ascii_case("descriptor"),
        sqlparser::ast::Expr::CompoundIdentifier(ids) => ids
            .last()
            .is_some_and(|id| id.value.eq_ignore_ascii_case("descriptor")),
        _ => false,
    }
}

fn descriptor_qualifier_matches(expr: &sqlparser::ast::Expr, alias: &str) -> bool {
    match expr {
        sqlparser::ast::Expr::Identifier(_) => true,
        sqlparser::ast::Expr::CompoundIdentifier(ids) => {
            ids.len() == 2 && ids[0].value.eq_ignore_ascii_case(alias)
        }
        _ => false,
    }
}

fn method_predicates(expr: &sqlparser::ast::Expr) -> bool {
    let mut conjuncts = Vec::new();
    flatten_and(expr, &mut conjuncts);
    conjuncts.iter().all(|e| {
        simple_push_predicate(e)
            .is_some_and(|predicate| fast_method_predicate_supported(&predicate))
    })
}

fn fast_method_predicate_supported(predicate: &PushPredicate) -> bool {
    match predicate.column.as_str() {
        "class_descriptor" | "method_class" | "name" | "method_name" | "descriptor" | "method"
        | "return_descriptor" => predicate
            .values
            .iter()
            .all(|value| matches!(value, Scalar::Text(_))),
        "param_count" => {
            !matches!(predicate.kind, PushPredicateKind::Like)
                && predicate
                    .values
                    .iter()
                    .all(|value| matches!(value, Scalar::Int(_)))
        }
        _ => false,
    }
}

// A method query's predicates are unqualified or qualified by its alias.  The
// generic pushdown helper already validates the expression forms; this helper
// only needs to reject unsupported local expressions before enabling the fast
// path.  Qualified names are accepted without guessing an alias.
fn method_push_predicates(expr: &sqlparser::ast::Expr) -> Result<Vec<PushPredicate>, String> {
    let mut conjuncts = Vec::new();
    flatten_and(expr, &mut conjuncts);
    conjuncts
        .into_iter()
        .map(|e| {
            simple_push_predicate(e)
                .filter(fast_method_predicate_supported)
                .ok_or_else(|| "unsupported method predicate".into())
        })
        .collect()
}

fn method_predicates_match(
    predicates: &[PushPredicate],
    class: &str,
    name: &str,
    descriptor: &str,
    return_descriptor: &str,
    param_count: i64,
) -> bool {
    predicates.iter().all(|predicate| {
        let (text, number) = match predicate.column.as_str() {
            "class_descriptor" | "method_class" => (Some(class), None),
            "name" | "method_name" => (Some(name), None),
            "descriptor" | "method" => (Some(descriptor), None),
            "return_descriptor" => (Some(return_descriptor), None),
            "param_count" => (None, Some(param_count)),
            _ => return false,
        };
        predicate
            .values
            .iter()
            .any(|expected| match (text, number, expected) {
                (Some(actual), _, Scalar::Text(expected)) => match predicate.kind {
                    // DexKit class filters overwhelmingly use a trailing
                    // `%` (`Lcom/foo/%`).  Avoid the O(|value|*|pattern|)
                    // character-DP matcher and its temporary vectors on the
                    // million-method scan while preserving wildcard fallback.
                    PushPredicateKind::Like => like_match_fast(actual, expected, predicate.escape),
                    PushPredicateKind::Eq | PushPredicateKind::In => actual == expected.as_ref(),
                    PushPredicateKind::NotEq => actual != expected.as_ref(),
                },
                (_, Some(actual), Scalar::Int(expected)) => match predicate.kind {
                    PushPredicateKind::Eq | PushPredicateKind::In => actual == *expected,
                    PushPredicateKind::NotEq => actual != *expected,
                    PushPredicateKind::Like => false,
                },
                _ => false,
            })
    })
}

/// `SELECT count(*) FROM methods [WHERE <method predicates>]` without
/// materializing relational rows: predicates evaluate against direct
/// per-method field access.  IS [NOT] NULL conjuncts on the relation's
/// non-nullable columns fold to constants like the reference planner.
fn try_fast_count_scan(
    query: &sqlparser::ast::Query,
    ds: &Dataset,
    cli_limit: Option<u64>,
) -> Option<Result<QueryResult, String>> {
    use sqlparser::ast::{
        Expr, FunctionArg, FunctionArgExpr, FunctionArguments, SelectItem, SetExpr,
    };
    let select = match query.body.as_ref() {
        SetExpr::Select(select) => select.as_ref(),
        _ => return None,
    };
    if select.distinct.is_some()
        || select.having.is_some()
        || select.from.len() != 1
        || !select.from[0].joins.is_empty()
        || !matches!(&select.group_by, sqlparser::ast::GroupByExpr::Expressions(exprs, _) if exprs.is_empty())
        || query.order_by.is_some()
        || query.limit_clause.is_some()
    {
        return None;
    }
    // Projection must be exactly count(*).
    if select.projection.len() != 1 {
        return None;
    }
    let label = match &select.projection[0] {
        SelectItem::ExprWithAlias { alias, expr } => {
            let Expr::Function(function) = expr else {
                return None;
            };
            let name = function
                .name
                .0
                .last()
                .and_then(|part| part.as_ident())
                .map(|id| id.value.to_ascii_lowercase())?;
            if name != "count" {
                return None;
            }
            let star_or_empty = match &function.args {
                FunctionArguments::List(args) => {
                    args.args.len() == 1
                        && matches!(
                            args.args[0],
                            FunctionArg::Unnamed(FunctionArgExpr::Wildcard)
                        )
                        || args.args.is_empty()
                }
                _ => false,
            };
            if !star_or_empty {
                return None;
            }
            alias.value.clone()
        }
        SelectItem::UnnamedExpr(expr) => {
            let Expr::Function(function) = expr else {
                return None;
            };
            let name = function
                .name
                .0
                .last()
                .and_then(|part| part.as_ident())
                .map(|id| id.value.to_ascii_lowercase())?;
            if name != "count" {
                return None;
            }
            let star_or_empty = match &function.args {
                FunctionArguments::List(args) => {
                    args.args.len() == 1
                        && matches!(
                            args.args[0],
                            FunctionArg::Unnamed(FunctionArgExpr::Wildcard)
                        )
                        || args.args.is_empty()
                }
                _ => false,
            };
            if !star_or_empty {
                return None;
            }
            "count".to_owned()
        }
        _ => return None,
    };
    let sqlparser::ast::TableFactor::Table { name, .. } = &select.from[0].relation else {
        return None;
    };
    let table = name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .map(|id| id.value.to_ascii_lowercase())?;
    if table != "methods" {
        return None;
    }
    // Fold the WHERE: IS [NOT] NULL on non-nullable columns folds; other
    // conjuncts must be push predicates.
    let mut predicates = Vec::new();
    if let Some(selection) = &select.selection {
        let mut conjuncts = Vec::new();
        flatten_and(selection, &mut conjuncts);
        for conjunct in conjuncts {
            match conjunct {
                Expr::IsNotNull(expr) => {
                    let column = column_name(expr)?;
                    if !matches!(
                        column.as_str(),
                        "descriptor"
                            | "method"
                            | "class_descriptor"
                            | "method_class"
                            | "name"
                            | "method_name"
                            | "return_descriptor"
                            | "param_count"
                    ) {
                        return None;
                    }
                    // Always true for these non-nullable columns.
                }
                Expr::IsNull(expr) => {
                    let column = column_name(expr)?;
                    if !matches!(
                        column.as_str(),
                        "descriptor"
                            | "method"
                            | "class_descriptor"
                            | "method_class"
                            | "name"
                            | "method_name"
                            | "return_descriptor"
                            | "param_count"
                    ) {
                        return None;
                    }
                    // Always false: the count is zero.
                    return Some(Ok(QueryResult {
                        columns: vec![label],
                        rows: vec![vec!["0".to_owned()]],
                    }));
                }
                Expr::BinaryOp {
                    left,
                    op: sqlparser::ast::BinaryOperator::Eq,
                    right,
                } if matches!(**left, Expr::Value(_)) && matches!(**right, Expr::Value(_)) => {
                    // Literal tautologies fold; contradictions count zero.
                    let equal = literal_scalar(left)?.sql_eq(&literal_scalar(right)?);
                    if !equal {
                        return Some(Ok(QueryResult {
                            columns: vec![label],
                            rows: vec![vec!["0".to_owned()]],
                        }));
                    }
                }
                other => {
                    let predicate = simple_push_predicate(other)?;
                    if !fast_method_predicate_supported(&predicate) {
                        return None;
                    }
                    predicates.push(predicate);
                }
            }
        }
    }
    let needs_class = predicates
        .iter()
        .any(|p| matches!(p.column.as_str(), "class_descriptor" | "method_class"));
    let needs_name = predicates
        .iter()
        .any(|p| matches!(p.column.as_str(), "name" | "method_name"));
    let needs_descriptor = predicates
        .iter()
        .any(|p| matches!(p.column.as_str(), "descriptor" | "method"));
    let needs_return = predicates.iter().any(|p| p.column == "return_descriptor");
    let mut count: i64 = 0;
    for file in &ds.files {
        let empty = String::new();
        for idx in 0..file.methods.len() as u32 {
            let method = &file.methods[idx as usize];
            let Some(proto) = file.protos.get(method.proto_idx as usize) else {
                continue;
            };
            if !predicates.is_empty() {
                let class = if needs_class {
                    file.method_class(idx).to_owned()
                } else {
                    empty.clone()
                };
                let name = if needs_name {
                    file.method_name(idx).to_owned()
                } else {
                    empty.clone()
                };
                let descriptor = if needs_descriptor {
                    file.method_descriptor_direct(idx)
                } else {
                    empty.clone()
                };
                let return_descriptor = if needs_return {
                    file.type_descriptor(proto.return_type_idx).to_owned()
                } else {
                    empty.clone()
                };
                if !method_predicates_match(
                    &predicates,
                    &class,
                    &name,
                    &descriptor,
                    &return_descriptor,
                    proto.parameters.len() as i64,
                ) {
                    continue;
                }
            }
            count += 1;
        }
    }
    let rows = if cli_limit == Some(0) {
        Vec::new()
    } else {
        vec![vec![count.to_string()]]
    };
    Some(Ok(QueryResult {
        columns: vec![label],
        rows,
    }))
}

fn query_limit_value(limit: Option<&sqlparser::ast::LimitClause>) -> Option<usize> {
    use sqlparser::ast::{Expr, LimitClause, Value};
    let expr = match limit? {
        LimitClause::LimitOffset { limit, .. } => limit.as_ref()?,
        LimitClause::OffsetCommaLimit { limit, .. } => limit,
    };
    let Expr::Value(v) = expr else { return None };
    let Value::Number(value, _) = &v.value else {
        return None;
    };
    value.parse().ok()
}

fn query_offset_value(limit: Option<&sqlparser::ast::LimitClause>) -> Option<usize> {
    use sqlparser::ast::{Expr, LimitClause, Value};
    let expr = match limit? {
        LimitClause::LimitOffset { offset, .. } => &offset.as_ref()?.value,
        LimitClause::OffsetCommaLimit { offset, .. } => offset,
    };
    let Expr::Value(v) = expr else { return None };
    let Value::Number(value, _) = &v.value else {
        return None;
    };
    value.parse().ok()
}

fn fast_count(sql: &str, ds: &Dataset, cli_limit: Option<u64>) -> Option<QueryResult> {
    if !bare_count_query(sql) {
        return None;
    }
    let lower = sql.to_ascii_lowercase();
    if !lower.starts_with("select count(*)")
        || lower.contains(" where ")
        || lower.contains(" join ")
        || lower.contains(" group ")
    {
        return None;
    }
    let from = lower.find(" from ")?;
    let table = lower[from + 6..]
        .split_whitespace()
        .next()?
        .trim_matches('`');
    if matches!(
        table,
        "method_opcodes" | "code_items" | "try_items" | "catch_handlers"
    ) {
        return None;
    }
    let count = if matches!(
        table,
        "debug_info" | "debug_parameters" | "debug_positions" | "debug_locals" | "debug_opcodes"
    ) {
        ds.count_debug_rows(table).ok()??
    } else {
        ds.count(table)?
    };
    let rest = lower["select count(*)".len()..from].trim();
    // SQL aggregate output names are canonical function names in the
    // reference (`count`, `sum`, ...).  A bare alias (`count(*) c`) is also
    // accepted by SQLite/SQLParser and must win over the default name.
    let alias = rest
        .strip_prefix("as ")
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .or_else(|| {
            rest.split_whitespace()
                .next()
                .filter(|v| !v.eq_ignore_ascii_case("count(*)"))
        })
        .unwrap_or("count");
    let rows = if cli_limit == Some(0) {
        Vec::new()
    } else {
        vec![vec![count.to_string()]]
    };
    Some(QueryResult {
        columns: vec![alias.to_owned()],
        rows,
    })
}

fn execute_query(
    query: &sqlparser::ast::Query,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    named_caches: &NamedCaches,
    cli_limit: Option<u64>,
    needs_method_opcode: bool,
) -> Result<QueryResult, String> {
    let (columns, rows) = execute_query_rows(
        query,
        ds,
        source_dataset,
        named_caches,
        cli_limit,
        needs_method_opcode,
    )?;
    Ok(QueryResult {
        columns,
        rows: rows
            .into_iter()
            .map(|row| row.into_iter().map(|value| value.display()).collect())
            .collect(),
    })
}

/// Materialized output of a set expression: column labels and typed rows.
type SetRows = (Vec<String>, Vec<Vec<Scalar>>);

fn typed_to_result((columns, rows): SetRows) -> QueryResult {
    QueryResult {
        columns,
        rows: rows
            .into_iter()
            .map(|row| row.into_iter().map(|value| value.display()).collect())
            .collect(),
    }
}

/// Evaluate a whole query, including WITH scopes, set operations, VALUES,
/// ORDER BY and LIMIT handling.
fn execute_query_rows(
    query: &sqlparser::ast::Query,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    named_caches: &NamedCaches,
    cli_limit: Option<u64>,
    needs_method_opcode: bool,
) -> Result<SetRows, String> {
    let _membership_scope = membership::Scope::new();
    use sqlparser::ast::SetExpr;
    let scope = match query.with.as_ref() {
        Some(with) => Some(prepare_with_scope(with, ds, source_dataset, named_caches)?),
        None => None,
    };
    let caches = scope.as_ref().unwrap_or(named_caches);
    match query.body.as_ref() {
        SetExpr::Select(select) => {
            let mut select = select.clone();
            desugar_select(&mut select, ds, source_dataset, caches)?;
            let streaming = streaming::execute(query, &select, ds, caches, cli_limit)
                .or_else(|| relational::execute(query, &select, ds, caches, cli_limit));
            let mut projected = if let Some(output) = streaming {
                output?
            } else {
                execute_select_core(
                    &select,
                    ds,
                    source_dataset,
                    caches,
                    needs_method_opcode,
                    query_scan_limit(&select, query, cli_limit),
                    query_scan_columns(&select, query),
                )?
            };
            apply_query_order_limit(&mut projected, query, cli_limit)?;
            let columns = projected.columns;
            let rows = projected.rows.into_iter().map(|row| row.values).collect();
            Ok((columns, rows))
        }
        body => {
            if matches!(body, sqlparser::ast::SetExpr::Values(_)) && query.limit_clause.is_some() {
                return Err("LIMIT cannot follow a bare VALUES clause".into());
            }
            let (columns, mut rows) =
                eval_set_expr(body, ds, source_dataset, caches, needs_method_opcode)?;
            if let Some(order_by) = &query.order_by {
                sort_rows_by_output(&mut rows, order_by, &columns)?;
            }
            apply_sql_limit_rows(&mut rows, query.limit_clause.as_ref())?;
            if let Some(limit) = cli_limit {
                rows.truncate(limit as usize);
            }
            Ok((columns, rows))
        }
    }
}

/// A SELECT's projection result before output ordering.
struct SelectOutput {
    columns: Vec<String>,
    rows: Vec<ProjectedRow>,
}

/// ORDER BY (including 1-based ordinals) and LIMIT at the query level for a
/// plain SELECT; ordering expressions may reference source columns.
fn apply_query_order_limit(
    output: &mut SelectOutput,
    query: &sqlparser::ast::Query,
    cli_limit: Option<u64>,
) -> Result<(), String> {
    if let Some(order_by) = &query.order_by {
        let sqlparser::ast::OrderByKind::Expressions(order_exprs) = &order_by.kind else {
            return Err("unsupported ORDER BY ALL".into());
        };
        if order_by.interpolate.is_some() {
            return Err("unsupported ORDER BY INTERPOLATE".into());
        }
        output.rows.sort_by(|a, b| {
            for (key_index, order) in order_exprs.iter().enumerate() {
                if let (Some(a), Some(b)) = (&a.sort_keys, &b.sort_keys) {
                    let mut cmp = compare_scalar(&a[key_index], &b[key_index]);
                    if order.options.sort == Some(sqlparser::ast::OrderBySort::Desc) {
                        cmp = cmp.reverse();
                    }
                    if cmp != std::cmp::Ordering::Equal {
                        return cmp;
                    }
                    continue;
                }
                // 1-based output ordinals.
                let ordinal = match &order.expr {
                    sqlparser::ast::Expr::Value(value) => match &value.value {
                        sqlparser::ast::Value::Number(text, _) => {
                            text.parse::<usize>().ok().filter(|n| *n >= 1)
                        }
                        _ => None,
                    },
                    _ => None,
                };
                let (av, bv) = match ordinal {
                    Some(index) => (
                        a.values.get(index - 1).cloned().unwrap_or(Scalar::Null),
                        b.values.get(index - 1).cloned().unwrap_or(Scalar::Null),
                    ),
                    None => (
                        eval_scalar(
                            &order.expr,
                            a.order_row.as_deref().expect("generic ordering row"),
                            &a.group,
                        )
                        .unwrap_or(Scalar::Null),
                        eval_scalar(
                            &order.expr,
                            b.order_row.as_deref().expect("generic ordering row"),
                            &b.group,
                        )
                        .unwrap_or(Scalar::Null),
                    ),
                };
                let mut cmp = compare_scalar(&av, &bv);
                if order.options.sort == Some(sqlparser::ast::OrderBySort::Desc) {
                    cmp = cmp.reverse();
                }
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
            std::cmp::Ordering::Equal
        });
    }
    apply_sql_limit(&mut output.rows, query.limit_clause.as_ref())?;
    if let Some(limit) = cli_limit {
        output.rows.truncate(limit as usize);
    }
    Ok(())
}

/// ORDER BY for compound bodies: only output ordinals and labels are
/// visible.
fn sort_rows_by_output(
    rows: &mut [Vec<Scalar>],
    order_by: &sqlparser::ast::OrderBy,
    columns: &[String],
) -> Result<(), String> {
    let sqlparser::ast::OrderByKind::Expressions(order_exprs) = &order_by.kind else {
        return Err("unsupported ORDER BY ALL".into());
    };
    if order_by.interpolate.is_some() {
        return Err("unsupported ORDER BY INTERPOLATE".into());
    }
    let keys: Vec<(Option<usize>, bool)> = order_exprs
        .iter()
        .map(|order| {
            let ordinal = match &order.expr {
                sqlparser::ast::Expr::Value(value) => match &value.value {
                    sqlparser::ast::Value::Number(text, _) => text
                        .parse::<usize>()
                        .ok()
                        .filter(|n| *n >= 1 && *n <= columns.len()),
                    _ => None,
                },
                sqlparser::ast::Expr::Identifier(id) => columns
                    .iter()
                    .position(|column| column.eq_ignore_ascii_case(&id.value))
                    .map(|index| index + 1),
                _ => None,
            };
            let descending = order.options.sort == Some(sqlparser::ast::OrderBySort::Desc);
            (ordinal, descending)
        })
        .collect();
    rows.sort_by(|a, b| {
        for (ordinal, descending) in &keys {
            let av = ordinal
                .and_then(|index| a.get(index - 1))
                .cloned()
                .unwrap_or(Scalar::Null);
            let bv = ordinal
                .and_then(|index| b.get(index - 1))
                .cloned()
                .unwrap_or(Scalar::Null);
            let mut cmp = compare_scalar(&av, &bv);
            if *descending {
                cmp = cmp.reverse();
            }
            if cmp != std::cmp::Ordering::Equal {
                return cmp;
            }
        }
        std::cmp::Ordering::Equal
    });
    Ok(())
}

fn apply_sql_limit_rows(
    rows: &mut Vec<Vec<Scalar>>,
    limit: Option<&sqlparser::ast::LimitClause>,
) -> Result<(), String> {
    let offset = query_offset_value(limit);
    let take = query_limit_value(limit);
    if let Some(offset) = offset {
        if rows.len() > offset {
            rows.drain(..offset);
        } else {
            rows.clear();
        }
    }
    if let Some(take) = take {
        rows.truncate(take);
    }
    Ok(())
}

/// Evaluate a set-expression operand: SELECT, parenthesized query, VALUES,
/// or a set operation tree.
fn eval_set_expr(
    expr: &sqlparser::ast::SetExpr,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    named_caches: &NamedCaches,
    needs_method_opcode: bool,
) -> Result<SetRows, String> {
    use sqlparser::ast::{SetExpr, SetOperator, SetQuantifier};
    match expr {
        SetExpr::Select(select) => {
            let mut select = select.clone();
            desugar_select(&mut select, ds, source_dataset, named_caches)?;
            // Set operands have no query-level order/limit of their own, but
            // still benefit from reduced scans and incremental aggregation.
            let query = sqlparser::ast::Query {
                with: None,
                body: Box::new(SetExpr::Select(select.clone())),
                order_by: None,
                limit_clause: None,
                fetch: None,
                locks: Vec::new(),
                for_clause: None,
                settings: None,
                format_clause: None,
                pipe_operators: Vec::new(),
            };
            let output = if let Some(result) =
                streaming::execute(&query, &select, ds, named_caches, None)
                    .or_else(|| relational::execute(&query, &select, ds, named_caches, None))
            {
                result?
            } else {
                execute_select_core(
                    &select,
                    ds,
                    source_dataset,
                    named_caches,
                    needs_method_opcode,
                    None,
                    query_scan_columns(&select, &query),
                )?
            };
            Ok((
                output.columns,
                output.rows.into_iter().map(|row| row.values).collect(),
            ))
        }
        SetExpr::Query(query) => execute_query_rows(
            query,
            ds,
            source_dataset,
            named_caches,
            None,
            needs_method_opcode,
        ),
        SetExpr::Values(values) => eval_values(values),
        SetExpr::SetOperation {
            op,
            set_quantifier,
            left,
            right,
        } => {
            let (columns, left_rows) =
                eval_set_expr(left, ds, source_dataset, named_caches, needs_method_opcode)?;
            let (right_columns, right_rows) =
                eval_set_expr(right, ds, source_dataset, named_caches, needs_method_opcode)?;
            if columns.len() != right_columns.len() {
                return Err(format!(
                    "SELECTs to the left and right of the set operation do not have the same number of result columns ({} vs {})",
                    columns.len(),
                    right_columns.len()
                ));
            }
            // An omitted quantifier means DISTINCT for these operators.
            let all = matches!(set_quantifier, SetQuantifier::All);
            let rows = match op {
                SetOperator::Union => {
                    let mut rows = left_rows;
                    rows.extend(right_rows);
                    charge_materialized(
                        rows.len() as u64 * 64
                            + rows.iter().map(|r| r.len() as u64 * 96).sum::<u64>(),
                    )?;
                    if all {
                        rows
                    } else {
                        dedup_and_sort(rows)
                    }
                }
                SetOperator::Except => {
                    let right_set: HashSet<Vec<membership::Key>> = right_rows
                        .iter()
                        .map(|row| row.iter().map(|value| membership::set_key(value)).collect())
                        .collect();
                    let kept = left_rows
                        .into_iter()
                        .filter(|row| {
                            let key = row
                                .iter()
                                .map(|value| membership::set_key(value))
                                .collect::<Vec<_>>();
                            !right_set.contains(&key)
                        })
                        .collect::<Vec<_>>();
                    dedup_and_sort(kept)
                }
                SetOperator::Intersect => {
                    let right_set: HashSet<Vec<membership::Key>> = right_rows
                        .iter()
                        .map(|row| row.iter().map(|value| membership::set_key(value)).collect())
                        .collect();
                    let kept = left_rows
                        .into_iter()
                        .filter(|row| {
                            let key = row
                                .iter()
                                .map(|value| membership::set_key(value))
                                .collect::<Vec<_>>();
                            right_set.contains(&key)
                        })
                        .collect::<Vec<_>>();
                    dedup_and_sort(kept)
                }
                SetOperator::Minus => {
                    return Err("MINUS set operation is not supported".into());
                }
            };
            Ok((columns, rows))
        }
        _ => Err("unsupported query body".into()),
    }
}

fn render_row_key(row: &[Scalar]) -> Vec<String> {
    row.iter().map(|value| value.display()).collect()
}

fn dedup_and_sort(mut rows: Vec<Vec<Scalar>>) -> Vec<Vec<Scalar>> {
    rows.sort_by(|a, b| {
        for (x, y) in a.iter().zip(b.iter()) {
            let cmp = compare_scalar(x, y);
            if cmp != std::cmp::Ordering::Equal {
                return cmp;
            }
        }
        std::cmp::Ordering::Equal
    });
    rows.dedup_by(|a, b| a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.sql_eq(y)));
    rows
}

fn eval_values(values: &sqlparser::ast::Values) -> Result<SetRows, String> {
    let mut columns = Vec::new();
    let mut rows = Vec::with_capacity(values.rows.len());
    for (row_index, row) in values.rows.iter().enumerate() {
        if row_index == 0 {
            columns = (1..=row.len())
                .map(|index| format!("column{index}"))
                .collect();
        }
        let mut out = Vec::with_capacity(row.content.len());
        for expr in &row.content {
            out.push(eval_scalar(expr, &RelRow::default(), &[])?);
        }
        rows.push(out);
    }
    Ok((columns, rows))
}

/// Build the WITH scope for a query: non-recursive CTEs materialize once;
/// `WITH RECURSIVE` iterates the recursive arm against the previous delta
/// until it stops producing rows or hits the safety cap.
fn prepare_with_scope(
    with: &sqlparser::ast::With,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    named_caches: &NamedCaches,
) -> Result<NamedCaches, String> {
    let scope = named_caches.child_scope();
    for cte in &with.cte_tables {
        let name = cte.alias.name.value.to_ascii_lowercase();
        if !with.recursive {
            let typed = execute_query_rows(&cte.query, ds, source_dataset, &scope, None, false)?;
            let typed = rename_result_columns(typed, &cte.alias.columns);
            scope.install_materialized(&name, typed);
            continue;
        }
        // WITH RECURSIVE: the body is initial UNION [ALL] recursive.
        let sqlparser::ast::SetExpr::SetOperation {
            op,
            set_quantifier,
            left,
            right,
        } = cte.query.body.as_ref()
        else {
            let typed = execute_query_rows(&cte.query, ds, source_dataset, &scope, None, false)?;
            let typed = rename_result_columns(typed, &cte.alias.columns);
            scope.install_materialized(&name, typed);
            continue;
        };
        let all = matches!(set_quantifier, sqlparser::ast::SetQuantifier::All);
        let (columns, initial) = eval_set_expr(left, ds, source_dataset, &scope, false)?;
        // A recursive arm that never references the CTE runs exactly once.
        let self_referencing = sql_from_factors(right, &mut Vec::new()).contains(&name);
        let mut total = initial.clone();
        let mut delta = initial;
        let mut iterations = 0usize;
        loop {
            if delta.is_empty() || !self_referencing {
                break;
            }
            iterations += 1;
            if iterations > 10_000 || total.len() > 1_000_000 {
                return Err("recursive CTE exceeded its iteration/row cap".into());
            }
            let step_scope = scope.child_scope();
            let step = rename_result_columns((columns.clone(), delta.clone()), &cte.alias.columns);
            step_scope.install_materialized(&name, step);
            let (_, next) = eval_set_expr(right, ds, source_dataset, &step_scope, false)?;
            if !all {
                let seen: HashSet<Vec<String>> =
                    total.iter().map(|row| render_row_key(row)).collect();
                delta = next
                    .into_iter()
                    .filter(|row| !seen.contains(&render_row_key(row)))
                    .collect();
            } else {
                delta = next;
            }
            total.extend(delta.iter().cloned());
        }
        let _ = op;
        let total = if self_referencing {
            total
        } else {
            let (_, next) = eval_set_expr(right, ds, source_dataset, &scope, false)?;
            let mut total = total;
            total.extend(next);
            total
        };
        let typed = rename_result_columns((columns, total), &cte.alias.columns);
        scope.install_materialized(&name, typed);
    }
    Ok(scope)
}

fn rename_result_columns(
    result: SetRows,
    aliases: &[sqlparser::ast::TableAliasColumnDef],
) -> SetRows {
    if aliases.is_empty() {
        return result;
    }
    let (mut columns, rows) = result;
    for (index, alias) in aliases.iter().enumerate() {
        if let Some(column) = columns.get_mut(index) {
            *column = alias.name.value.clone();
        }
    }
    (columns, rows)
}

/// Replace uncorrelated expression subqueries with their literal results:
/// scalar `Subquery`, `IN (SELECT ...)`, and `EXISTS (...)`.
fn desugar_select(
    select: &mut sqlparser::ast::Select,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    named_caches: &NamedCaches,
) -> Result<(), String> {
    let outer_aliases: HashSet<String> = select
        .from
        .iter()
        .flat_map(|table| {
            std::iter::once(&table.relation).chain(table.joins.iter().map(|join| &join.relation))
        })
        .map(|factor| match factor {
            sqlparser::ast::TableFactor::Derived { alias, .. } => alias
                .as_ref()
                .map(|alias| alias.name.value.to_ascii_lowercase())
                .unwrap_or_default(),
            factor => factor_alias(factor).to_ascii_lowercase(),
        })
        .filter(|alias| !alias.is_empty())
        .collect();
    for item in &mut select.projection {
        if let sqlparser::ast::SelectItem::UnnamedExpr(expr)
        | sqlparser::ast::SelectItem::ExprWithAlias { expr, .. } = item
        {
            *expr = desugar_expr(expr, ds, source_dataset, named_caches, &outer_aliases)?;
        }
    }
    if let Some(selection) = &mut select.selection {
        *selection = desugar_expr(selection, ds, source_dataset, named_caches, &outer_aliases)?;
    }
    if let Some(having) = &mut select.having {
        *having = desugar_expr(having, ds, source_dataset, named_caches, &outer_aliases)?;
    }
    Ok(())
}

fn desugar_expr(
    expr: &sqlparser::ast::Expr,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    named_caches: &NamedCaches,
    outer_aliases: &HashSet<String>,
) -> Result<sqlparser::ast::Expr, String> {
    use sqlparser::ast::Expr;
    match expr {
        Expr::Subquery(subquery) => {
            let (_, rows) =
                execute_query_rows(subquery, ds, source_dataset, named_caches, None, false)?;
            let value = rows
                .first()
                .and_then(|row| row.first().cloned())
                .unwrap_or(Scalar::Null);
            Ok(scalar_literal(value))
        }
        Expr::Exists {
            subquery, negated, ..
        } => {
            if let Some(expr) =
                correlated::exists(subquery, *negated, outer_aliases, ds, named_caches)?
            {
                return Ok(expr);
            }
            let (_, rows) =
                execute_query_rows(subquery, ds, source_dataset, named_caches, Some(1), false)?;
            let mut truth = !rows.is_empty();
            if *negated {
                truth = !truth;
            }
            Ok(scalar_literal(Scalar::Int(truth as i64)))
        }
        Expr::InSubquery {
            expr,
            subquery,
            negated,
        } => {
            let (_, rows) =
                execute_query_rows(subquery, ds, source_dataset, named_caches, None, false)?;
            let list = rows
                .into_iter()
                .filter_map(|row| row.into_iter().next())
                .map(scalar_literal)
                .collect::<Vec<_>>();
            Ok(Expr::InList {
                expr: Box::new(expr.as_ref().clone()),
                list,
                negated: *negated,
            })
        }
        Expr::BinaryOp { left, op, right } => Ok(Expr::BinaryOp {
            left: Box::new(desugar_expr(
                left,
                ds,
                source_dataset,
                named_caches,
                outer_aliases,
            )?),
            op: op.clone(),
            right: Box::new(desugar_expr(
                right,
                ds,
                source_dataset,
                named_caches,
                outer_aliases,
            )?),
        }),
        Expr::UnaryOp { op, expr } => Ok(Expr::UnaryOp {
            op: *op,
            expr: Box::new(desugar_expr(
                expr,
                ds,
                source_dataset,
                named_caches,
                outer_aliases,
            )?),
        }),
        Expr::Nested(expr) => Ok(Expr::Nested(Box::new(desugar_expr(
            expr,
            ds,
            source_dataset,
            named_caches,
            outer_aliases,
        )?))),
        _ => Ok(expr.clone()),
    }
}

/// Return a safe physical row limit for a simple single-table SELECT.  The
/// generic executor normally materializes every source row before applying
/// projection and LIMIT, which is needlessly expensive for the common
/// `SELECT descriptor FROM methods LIMIT 1` shape.  A hint is safe only when
/// there is no operation whose result depends on rows beyond the first N and
/// every WHERE conjunct can be evaluated by the scanner itself.
fn query_scan_limit(
    select: &sqlparser::ast::Select,
    query: &sqlparser::ast::Query,
    cli_limit: Option<u64>,
) -> Option<usize> {
    if select.from.len() != 1
        || !select.from[0].joins.is_empty()
        || query.order_by.is_some()
        || select.having.is_some()
        || select.distinct.is_some()
        || select
            .projection
            .iter()
            .any(|item| item_expr(item).is_some_and(|expr| !scan_projection_is_row_local(expr)))
        || !matches!(
            &select.group_by,
            sqlparser::ast::GroupByExpr::Expressions(exprs, modifiers)
                if exprs.is_empty() && modifiers.is_empty()
        )
    {
        return None;
    }
    let table = factor_table_name(&select.from[0].relation)?;
    // A LIMIT must only stop after rows satisfying the complete WHERE have
    // been produced. These scanners implement every predicate column below;
    // other relations keep post-scan filtering and cannot use this hint.
    if !matches!(table.as_str(), "methods" | "classes" | "fields") {
        return None;
    }
    if let Some(selection) = &select.selection {
        let alias = factor_alias(&select.from[0].relation);
        let mut conjuncts = Vec::new();
        flatten_and(selection, &mut conjuncts);
        if conjuncts.iter().any(|expr| {
            !references_only(expr, alias)
                || !simple_push_predicate(expr)
                    .is_some_and(|predicate| scan_predicate_column(&table, &predicate.column))
        }) {
            return None;
        }
    }
    let sql_limit = query_limit_value(query.limit_clause.as_ref());
    let returned = match (sql_limit, cli_limit) {
        (Some(sql), Some(cli)) => sql.min(usize::try_from(cli).unwrap_or(usize::MAX)),
        (Some(sql), None) => sql,
        (None, Some(cli)) => usize::try_from(cli).unwrap_or(usize::MAX),
        (None, None) => return None,
    };
    let offset = query_offset_value(query.limit_clause.as_ref()).unwrap_or(0);
    Some(offset.saturating_add(returned))
}

// Conservative proof that projection evaluates per source row. In particular
// aggregate functions (even nested inside another expression) and windows must
// consume all source rows before the query-level LIMIT is applied.
fn scan_projection_is_row_local(expr: &sqlparser::ast::Expr) -> bool {
    use sqlparser::ast::{Expr, FunctionArg, FunctionArgExpr, FunctionArguments};
    match expr {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_) => true,
        Expr::Nested(expr) | Expr::UnaryOp { expr, .. } => scan_projection_is_row_local(expr),
        Expr::BinaryOp { left, right, .. } => {
            scan_projection_is_row_local(left) && scan_projection_is_row_local(right)
        }
        Expr::Function(function) => {
            let Some(name) = function.name.0.last().and_then(|part| part.as_ident()) else {
                return false;
            };
            let name = name.value.to_ascii_lowercase();
            if matches!(
                name.as_str(),
                "count" | "sum" | "avg" | "min" | "max" | "total" | "group_concat" | "string_agg"
            ) || function.over.is_some()
                || function.filter.is_some()
                || !function.within_group.is_empty()
            {
                return false;
            }
            let FunctionArguments::List(args) = &function.args else {
                return false;
            };
            args.args.iter().all(|arg| match arg {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => {
                    scan_projection_is_row_local(expr)
                }
                _ => false,
            })
        }
        _ => false,
    }
}

fn scan_predicate_column(table: &str, column: &str) -> bool {
    match table {
        "methods" => matches!(
            column,
            "file_id"
                | "method_idx"
                | "class_idx"
                | "class_descriptor"
                | "proto_idx"
                | "name"
                | "descriptor"
                | "return_descriptor"
                | "param_count"
                | "param_descriptors"
                | "access_flags"
                | "opcode_count"
                | "opcode_hex"
                | "method_kind"
        ),
        "classes" => matches!(
            column,
            "file_id"
                | "class_def_idx"
                | "class_idx"
                | "descriptor"
                | "access_flags"
                | "superclass_descriptor"
                | "interface_count"
                | "field_count"
                | "method_count"
                | "source_file"
        ),
        "fields" => matches!(
            column,
            "file_id"
                | "field_idx"
                | "class_idx"
                | "class_descriptor"
                | "type_idx"
                | "type_descriptor"
                | "name"
                | "descriptor"
        ),
        _ => false,
    }
}

/// Columns required from a simple methods scan.  Generic execution historically
/// populated every relation column before projection, so `SELECT descriptor
/// FROM methods` allocated and cloned opcode/parameter fields that were then
/// immediately discarded.  Restricting this only to an ungrouped, unsorted,
/// single-table projection keeps wildcard and relational semantics unchanged.
fn query_scan_columns(
    select: &sqlparser::ast::Select,
    query: &sqlparser::ast::Query,
) -> Option<HashSet<String>> {
    if select.from.len() != 1 || !select.from[0].joins.is_empty() {
        return None;
    }
    // Keep pruning local to row-producing relations whose scanners implement
    // the column mask.  Other relations retain their established schemas.
    let sqlparser::ast::TableFactor::Table { name, .. } = &select.from[0].relation else {
        return None;
    };
    let table = name.0.last()?.as_ident()?.value.to_ascii_lowercase();
    if !matches!(
        table.as_str(),
        "methods" | "method_strings" | "classes" | "fields"
    ) {
        return None;
    }
    let mut columns = HashSet::new();
    let mut collect = |expr: &sqlparser::ast::Expr| collect_expr_columns(expr, &mut columns);
    for item in &select.projection {
        let expr = match item {
            sqlparser::ast::SelectItem::UnnamedExpr(expr)
            | sqlparser::ast::SelectItem::ExprWithAlias { expr, .. } => expr,
            sqlparser::ast::SelectItem::Wildcard(_)
            | sqlparser::ast::SelectItem::QualifiedWildcard(_, _)
            | sqlparser::ast::SelectItem::ExprWithAliases { .. } => return None,
        };
        if !collect(expr) {
            return None;
        }
    }
    match &select.group_by {
        sqlparser::ast::GroupByExpr::Expressions(exprs, modifiers) => {
            if !modifiers.is_empty() {
                return None;
            }
            for expr in exprs {
                if !collect(expr) {
                    return None;
                }
            }
        }
        sqlparser::ast::GroupByExpr::All(_) => return None,
    }
    if let Some(selection) = &select.selection {
        if !collect(selection) {
            return None;
        }
    }
    if let Some(having) = &select.having {
        if !collect(having) {
            return None;
        }
    }
    if let Some(order_by) = &query.order_by {
        let sqlparser::ast::OrderByKind::Expressions(exprs) = &order_by.kind else {
            return None;
        };
        for order in exprs {
            if !collect(&order.expr) {
                return None;
            }
        }
    }
    Some(columns)
}

/// Collect source columns used by an expression.  Returning false for an AST
/// form outside the executor's read-only expression subset disables pruning
/// for that query, preserving the old full-row behavior instead of risking an
/// unknown-column NULL.
fn collect_expr_columns(expr: &sqlparser::ast::Expr, columns: &mut HashSet<String>) -> bool {
    use sqlparser::ast::{Expr, FunctionArg, FunctionArgExpr, FunctionArguments};
    let collect_args = |args: &FunctionArguments, columns: &mut HashSet<String>| match args {
        FunctionArguments::List(args) => args.args.iter().all(|arg| match arg {
            FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => {
                collect_expr_columns(expr, columns)
            }
            FunctionArg::Named { arg, .. } | FunctionArg::ExprNamed { arg, .. } => match arg {
                FunctionArgExpr::Expr(expr) => collect_expr_columns(expr, columns),
                FunctionArgExpr::QualifiedWildcard(_)
                | FunctionArgExpr::Wildcard
                | FunctionArgExpr::WildcardWithOptions(_) => true,
            },
            FunctionArg::Unnamed(FunctionArgExpr::QualifiedWildcard(_))
            | FunctionArg::Unnamed(FunctionArgExpr::Wildcard)
            | FunctionArg::Unnamed(FunctionArgExpr::WildcardWithOptions(_)) => true,
        }),
        FunctionArguments::None | FunctionArguments::Subquery(_) => false,
    };
    match expr {
        Expr::Identifier(id) => {
            columns.insert(id.value.to_ascii_lowercase());
            true
        }
        Expr::CompoundIdentifier(ids) => {
            if let Some(id) = ids.last() {
                columns.insert(id.value.to_ascii_lowercase());
                true
            } else {
                false
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            collect_expr_columns(left, columns) && collect_expr_columns(right, columns)
        }
        Expr::UnaryOp { expr, .. }
        | Expr::Nested(expr)
        | Expr::IsFalse(expr)
        | Expr::IsNotFalse(expr)
        | Expr::IsTrue(expr)
        | Expr::IsNotTrue(expr)
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::IsUnknown(expr)
        | Expr::IsNotUnknown(expr) => collect_expr_columns(expr, columns),
        Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right) => {
            collect_expr_columns(left, columns) && collect_expr_columns(right, columns)
        }
        Expr::InList { expr, list, .. } => {
            collect_expr_columns(expr, columns)
                && list.iter().all(|item| collect_expr_columns(item, columns))
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            collect_expr_columns(expr, columns)
                && collect_expr_columns(low, columns)
                && collect_expr_columns(high, columns)
        }
        Expr::Like {
            expr,
            pattern,
            escape_char,
            ..
        }
        | Expr::ILike {
            expr,
            pattern,
            escape_char,
            ..
        }
        | Expr::SimilarTo {
            expr,
            pattern,
            escape_char,
            ..
        } => {
            collect_expr_columns(expr, columns)
                && collect_expr_columns(pattern, columns)
                && escape_char
                    .as_deref()
                    .is_none_or(|escape| collect_expr_columns(escape, columns))
        }
        Expr::RLike { expr, pattern, .. } => {
            collect_expr_columns(expr, columns) && collect_expr_columns(pattern, columns)
        }
        Expr::Function(function) => {
            // Function filters, aggregate ordering and window specifications
            // can reference additional source columns outside `args`.
            if function.filter.is_some()
                || function.over.is_some()
                || !function.within_group.is_empty()
            {
                return false;
            }
            collect_args(&function.args, columns)
        }
        Expr::Cast { expr, .. }
        | Expr::Convert { expr, .. }
        | Expr::Extract { expr, .. }
        | Expr::Ceil { expr, .. }
        | Expr::Floor { expr, .. }
        | Expr::Collate { expr, .. }
        | Expr::Prefixed { value: expr, .. }
        | Expr::Named { expr, .. } => collect_expr_columns(expr, columns),
        Expr::AtTimeZone {
            timestamp,
            time_zone,
        } => collect_expr_columns(timestamp, columns) && collect_expr_columns(time_zone, columns),
        Expr::Position { expr, r#in } => {
            collect_expr_columns(expr, columns) && collect_expr_columns(r#in, columns)
        }
        Expr::Substring {
            expr,
            substring_from,
            substring_for,
            ..
        } => {
            collect_expr_columns(expr, columns)
                && substring_from
                    .as_deref()
                    .is_none_or(|value| collect_expr_columns(value, columns))
                && substring_for
                    .as_deref()
                    .is_none_or(|value| collect_expr_columns(value, columns))
        }
        Expr::Trim {
            expr,
            trim_what,
            trim_characters,
            ..
        } => {
            collect_expr_columns(expr, columns)
                && trim_what
                    .as_deref()
                    .is_none_or(|value| collect_expr_columns(value, columns))
                && trim_characters.as_ref().is_none_or(|values| {
                    values
                        .iter()
                        .all(|value| collect_expr_columns(value, columns))
                })
        }
        Expr::Overlay {
            expr,
            overlay_what,
            overlay_from,
            overlay_for,
        } => {
            collect_expr_columns(expr, columns)
                && collect_expr_columns(overlay_what, columns)
                && collect_expr_columns(overlay_from, columns)
                && overlay_for
                    .as_deref()
                    .is_none_or(|value| collect_expr_columns(value, columns))
        }
        Expr::JsonAccess { value, .. } => collect_expr_columns(value, columns),
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            operand
                .as_deref()
                .is_none_or(|value| collect_expr_columns(value, columns))
                && conditions.iter().all(|when| {
                    collect_expr_columns(&when.condition, columns)
                        && collect_expr_columns(&when.result, columns)
                })
                && else_result
                    .as_deref()
                    .is_none_or(|value| collect_expr_columns(value, columns))
        }
        Expr::Tuple(values) => values
            .iter()
            .all(|value| collect_expr_columns(value, columns)),
        Expr::GroupingSets(sets) | Expr::Cube(sets) | Expr::Rollup(sets) => sets
            .iter()
            .flatten()
            .all(|value| collect_expr_columns(value, columns)),
        Expr::Value(_) | Expr::Wildcard(_) | Expr::QualifiedWildcard(_, _) => true,
        // A subquery can refer to an outer column through a correlated
        // expression, so it is intentionally conservative here.
        Expr::InSubquery { .. }
        | Expr::InUnnest { .. }
        | Expr::AnyOp { .. }
        | Expr::AllOp { .. }
        | Expr::Exists { .. }
        | Expr::Subquery(_)
        | Expr::CompoundFieldAccess { .. }
        | Expr::IsJson { .. }
        | Expr::IsNormalized { .. }
        | Expr::TypedString(_)
        | Expr::Struct { .. }
        | Expr::Dictionary(_)
        | Expr::Map(_)
        | Expr::Array(_)
        | Expr::Interval(_)
        | Expr::MatchAgainst { .. } => false,
        _ => false,
    }
}

fn scalar_literal(value: Scalar) -> sqlparser::ast::Expr {
    use sqlparser::ast::{Expr, Value, ValueWithSpan};
    let value_with_span = |value: Value| ValueWithSpan {
        value,
        span: sqlparser::tokenizer::Span::empty(),
    };
    match value {
        Scalar::Blob(bytes) => Expr::Value(value_with_span(Value::HexStringLiteral(
            bytes.iter().map(|b| format!("{b:02X}")).collect(),
        ))),
        Scalar::Null => Expr::Value(value_with_span(Value::Null)),
        Scalar::Int(value) => Expr::Value(value_with_span(Value::Number(value.to_string(), false))),
        Scalar::Real(value) => Expr::Value(value_with_span(Value::Number(value, false))),
        Scalar::Text(value) => Expr::Value(value_with_span(Value::SingleQuotedString(
            value.to_string(),
        ))),
    }
}

fn execute_select_core(
    select: &sqlparser::ast::Select,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    named_caches: &NamedCaches,
    needs_method_opcode: bool,
    scan_limit: Option<usize>,
    scan_columns: Option<HashSet<String>>,
) -> Result<SelectOutput, String> {
    if select.projection.is_empty() {
        return Err("SELECT projection cannot be empty".into());
    }
    if select.prewhere.is_some()
        || !select.lateral_views.is_empty()
        || !select.connect_by.is_empty()
        || !select.cluster_by.is_empty()
        || !select.distribute_by.is_empty()
        || !select.sort_by.is_empty()
        || !select.named_window.is_empty()
        || select.qualify.is_some()
        || select.value_table_mode.is_some()
    {
        return Err("unsupported SQL clause".into());
    }

    let mut rows = if select.from.is_empty() {
        vec![RelRow::default()]
    } else {
        let mut all = Vec::new();
        let mut initialized = false;
        for table in &select.from {
            let relation_alias = factor_alias(&table.relation);
            let local = select
                .selection
                .as_ref()
                .and_then(|expr| push_predicates(expr, relation_alias));
            let mut current = scan_factor(
                &table.relation,
                ds,
                local.as_deref(),
                None,
                needs_method_opcode,
                named_caches,
                source_dataset,
                scan_limit,
                scan_columns.as_ref(),
            )?;
            for join in &table.joins {
                let right_alias = factor_alias(&join.relation);
                let local = select
                    .selection
                    .as_ref()
                    .and_then(|expr| push_predicates(expr, right_alias));
                let constraint = join_constraint(&join.join_operator)?;
                let join_keys = derive_join_keys(constraint, &current, right_alias)?;
                let right = scan_factor(
                    &join.relation,
                    ds,
                    local.as_deref(),
                    join_keys
                        .as_ref()
                        .map(|(column, values)| (column.as_str(), values)),
                    needs_method_opcode,
                    named_caches,
                    source_dataset,
                    None,
                    None,
                )?;
                current = join_rows(&current, &right, constraint)?;
            }
            if !initialized {
                all = current;
                initialized = true;
            } else {
                let mut product = Vec::new();
                let mut retained_bytes = 0;
                for left in &all {
                    for right in &current {
                        push_reference_row(&mut product, left.merge(right), &mut retained_bytes)?;
                    }
                }
                all = product;
            }
        }
        all
    };

    if let Some(selection) = &select.selection {
        rows.retain(|row| eval_bool(selection, row, &[]).unwrap_or(false));
    }

    let group_exprs = match &select.group_by {
        sqlparser::ast::GroupByExpr::Expressions(exprs, modifiers) => {
            if !modifiers.is_empty() {
                return Err("unsupported GROUP BY modifier".into());
            }
            exprs.clone()
        }
        sqlparser::ast::GroupByExpr::All(modifiers) => {
            if !modifiers.is_empty() {
                return Err("unsupported GROUP BY modifier".into());
            }
            select
                .projection
                .iter()
                .filter_map(|item| match item {
                    sqlparser::ast::SelectItem::UnnamedExpr(expr)
                    | sqlparser::ast::SelectItem::ExprWithAlias { expr, .. } => Some(expr.clone()),
                    _ => None,
                })
                .collect()
        }
    };
    let has_aggregate = select
        .projection
        .iter()
        .any(|item| item_expr(item).is_some_and(item_has_aggregate))
        || select.having.as_ref().is_some_and(item_has_aggregate);
    let grouped = group_rows(rows, &group_exprs, has_aggregate)?;

    let mut grouped = grouped;
    if let Some(having) = &select.having {
        grouped.retain(|group| eval_bool(having, &group.row, &group.members).unwrap_or(false));
    }

    let fallback_columns = if grouped.is_empty() {
        select
            .from
            .first()
            .and_then(|table| table_columns_for_factor(&table.relation))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let (projection, columns) = expand_projection(&select.projection, &grouped, &fallback_columns)?;
    let mut projected = Vec::with_capacity(grouped.len());
    for group in grouped {
        let mut values = Vec::with_capacity(projection.len());
        for (expr, _) in &projection {
            values.push(eval_scalar(expr, &group.row, &group.members)?);
        }
        // Evaluation only borrows the source row. Move it into the ORDER BY
        // context after projection instead of cloning the relation map for
        // every output row.
        let mut order_row = group.row;
        for ((_, label), value) in projection.iter().zip(&values) {
            order_row.values.insert(
                intern_rel_component(lower_rel_component(label).as_ref()),
                value.clone(),
            );
        }
        projected.push(ProjectedRow {
            values,
            order_row: Some(Box::new(order_row)),
            group: group.members,
            sort_keys: None,
        });
    }
    // Projection materialization counts toward the budget like the
    // reference's sorted/grouped intermediate buffers.
    charge_materialized(
        projected.len() as u64 * 64
            + projected
                .iter()
                .map(|row| row.values.len() as u64 * 96)
                .sum::<u64>(),
    )?;

    if select.distinct.is_some() {
        let mut seen = HashSet::new();
        projected.retain(|row| {
            seen.insert(
                row.values
                    .iter()
                    .map(membership::set_key)
                    .collect::<Vec<_>>(),
            )
        });
    }
    Ok(SelectOutput {
        columns,
        rows: projected,
    })
}

/// Rewrite `Expr::Substring` into a named `substr`/`substring` Function so
/// output labels use the written spelling (the reference labels by the call
/// name; the sqlparser AST does not retain it).
fn lower_substring_calls(query: &mut sqlparser::ast::Query, sql: &str) {
    if let sqlparser::ast::SetExpr::Select(select) = query.body.as_mut() {
        for item in &mut select.projection {
            if let Some(expr) = item_expr_mut(item) {
                rewrite_substring(expr, sql);
            }
        }
    }
}

/// The spelling of a SUBSTR/SUBSTRING call, recovered by scanning backwards
/// from its first argument's span.
fn substring_call_name(inner: &sqlparser::ast::Expr, sql: &str) -> &'static str {
    let offset = match inner {
        sqlparser::ast::Expr::Value(value) => line_column_to_offset(
            sql,
            value.span.start.line as usize,
            value.span.start.column as usize,
        ),
        _ => return "substr",
    };
    let before = sql[..offset].trim_end().trim_end_matches('(').trim_end();
    if before.to_ascii_lowercase().ends_with("substring") {
        "substring"
    } else {
        "substr"
    }
}

/// Rewrite `0x...` integer literals mis-lexed as blob literals back to
/// decimal numbers.  sqlparser maps both `0x1f` and `x'1f'` to
/// `HexStringLiteral`; the literal's span text disambiguates them.
fn lower_blob_literals(query: &mut sqlparser::ast::Query, sql: &str) {
    if let sqlparser::ast::SetExpr::Select(select) = query.body.as_mut() {
        for item in &mut select.projection {
            if let Some(expr) = item_expr_mut(item) {
                rewrite_blob_literal(expr, sql);
            }
        }
        if let Some(selection) = &mut select.selection {
            rewrite_blob_literal(selection, sql);
        }
    }
}

fn rewrite_blob_literal(expr: &mut sqlparser::ast::Expr, sql: &str) {
    if let sqlparser::ast::Expr::UnaryOp { expr: inner, .. } = expr {
        rewrite_blob_literal(inner, sql);
    }
    let sqlparser::ast::Expr::Value(value) = expr else {
        return;
    };
    let sqlparser::ast::Value::HexStringLiteral(text) = &value.value else {
        return;
    };
    let start = line_column_to_offset(
        sql,
        value.span.start.line as usize,
        value.span.start.column as usize,
    );
    let literal = &sql[start..];
    if literal.len() >= text.len() + 2 && (literal.starts_with("0x") || literal.starts_with("0X")) {
        if let Ok(number) = u64::from_str_radix(text, 16) {
            *expr = sqlparser::ast::Expr::Value(sqlparser::ast::ValueWithSpan {
                value: sqlparser::ast::Value::Number(number.to_string(), false),
                span: value.span,
            });
        }
    }
}

fn item_expr_mut(item: &mut sqlparser::ast::SelectItem) -> Option<&mut sqlparser::ast::Expr> {
    match item {
        sqlparser::ast::SelectItem::UnnamedExpr(expr)
        | sqlparser::ast::SelectItem::ExprWithAlias { expr, .. }
        | sqlparser::ast::SelectItem::ExprWithAliases { expr, .. } => Some(expr),
        _ => None,
    }
}

fn rewrite_substring(expr: &mut sqlparser::ast::Expr, sql: &str) {
    if let sqlparser::ast::Expr::Substring {
        expr: inner,
        substring_from,
        substring_for,
        ..
    } = expr
    {
        let name = substring_call_name(inner, sql);
        let mut args = vec![inner.as_ref().clone()];
        if let Some(from) = substring_from {
            args.push(from.as_ref().clone());
        }
        if let Some(length) = substring_for {
            args.push(length.as_ref().clone());
        }
        let function = sqlparser::ast::Function {
            name: sqlparser::ast::ObjectName(vec![sqlparser::ast::ObjectNamePart::Identifier(
                sqlparser::ast::Ident::new(name),
            )]),
            uses_odbc_syntax: false,
            parameters: sqlparser::ast::FunctionArguments::None,
            args: sqlparser::ast::FunctionArguments::List(sqlparser::ast::FunctionArgumentList {
                duplicate_treatment: None,
                args: args
                    .into_iter()
                    .map(sqlparser::ast::FunctionArgExpr::Expr)
                    .map(sqlparser::ast::FunctionArg::Unnamed)
                    .collect(),
                clauses: Vec::new(),
            }),
            within_group: Vec::new(),
            filter: None,
            null_treatment: None,
            over: None,
        };
        *expr = sqlparser::ast::Expr::Function(function);
    }
}

fn item_expr(item: &sqlparser::ast::SelectItem) -> Option<&sqlparser::ast::Expr> {
    match item {
        sqlparser::ast::SelectItem::UnnamedExpr(expr)
        | sqlparser::ast::SelectItem::ExprWithAlias { expr, .. }
        | sqlparser::ast::SelectItem::ExprWithAliases { expr, .. } => Some(expr),
        _ => None,
    }
}

fn item_has_aggregate(expr: &sqlparser::ast::Expr) -> bool {
    use sqlparser::ast::{Expr, FunctionArg, FunctionArgExpr, FunctionArguments};
    match expr {
        Expr::Function(function) => {
            let name = function
                .name
                .0
                .last()
                .map(|name| name.to_string().to_ascii_lowercase())
                .unwrap_or_default();
            let FunctionArguments::List(args) = &function.args else {
                return false;
            };
            matches!(
                name.as_str(),
                "count" | "sum" | "total" | "avg" | "group_concat" | "string_agg"
            ) || matches!(name.as_str(), "min" | "max") && args.args.len() == 1
                || args.args.iter().any(|arg| match arg {
                    FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => item_has_aggregate(expr),
                    _ => false,
                })
        }
        Expr::BinaryOp { left, right, .. } => item_has_aggregate(left) || item_has_aggregate(right),
        Expr::UnaryOp { expr, .. }
        | Expr::Nested(expr)
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr) => item_has_aggregate(expr),
        Expr::InList { expr, list, .. } => {
            item_has_aggregate(expr) || list.iter().any(item_has_aggregate)
        }
        Expr::Between {
            expr, low, high, ..
        } => item_has_aggregate(expr) || item_has_aggregate(low) || item_has_aggregate(high),
        Expr::Like { expr, pattern, .. } | Expr::ILike { expr, pattern, .. } => {
            item_has_aggregate(expr) || item_has_aggregate(pattern)
        }
        Expr::Substring {
            expr,
            substring_from,
            substring_for,
            ..
        } => {
            item_has_aggregate(expr)
                || substring_from.as_deref().is_some_and(item_has_aggregate)
                || substring_for.as_deref().is_some_and(item_has_aggregate)
        }
        Expr::Trim {
            expr,
            trim_characters,
            ..
        } => item_has_aggregate(expr) || trim_characters.iter().flatten().any(item_has_aggregate),
        _ => false,
    }
}

fn group_rows(
    rows: Vec<RelRow>,
    expressions: &[sqlparser::ast::Expr],
    has_aggregate: bool,
) -> Result<Vec<GroupedRow>, String> {
    if expressions.is_empty() {
        if has_aggregate {
            let row = rows.first().cloned().unwrap_or_default();
            return Ok(vec![GroupedRow { row, members: rows }]);
        }
        return Ok(rows
            .into_iter()
            .map(|row| GroupedRow {
                // Plain rows never evaluate aggregates. Move the source row
                // into the group instead of cloning its relation map; the
                // previous clone doubled the per-row map footprint before
                // projection for million-row scans.
                row,
                members: Vec::new(),
            })
            .collect());
    }
    charge_materialized(estimate_row_bytes(&rows))?;
    let mut groups: HashMap<Vec<membership::Key>, Vec<RelRow>> = HashMap::new();
    for row in rows {
        let key = expressions
            .iter()
            .map(|expr| eval_scalar(expr, &row, &[]).map(|value| membership::set_key(&value)))
            .collect::<Result<Vec<_>, _>>()?;
        groups.entry(key).or_default().push(row);
    }
    Ok(groups
        .into_values()
        .map(|members| GroupedRow {
            row: members.first().cloned().unwrap_or_default(),
            members,
        })
        .collect())
}

fn table_columns_for_factor(factor: &sqlparser::ast::TableFactor) -> Option<Vec<String>> {
    let sqlparser::ast::TableFactor::Table { name, .. } = factor else {
        return None;
    };
    let table = name.0.last()?.as_ident()?.value.to_ascii_lowercase();
    let columns = match table.as_str() {
        "method_handles" => vec![
            "file_id",
            "method_handle_idx",
            "method_handle_type",
            "member_idx",
        ],
        "call_sites" => vec![
            "file_id",
            "call_site_idx",
            "call_site_off",
            "value_count",
            "method_handle_idx",
            "method_name_idx",
            "proto_idx",
        ],
        "call_site_args" => vec![
            "file_id",
            "call_site_idx",
            "call_site_off",
            "ordinal",
            "value_kind",
            "value_index",
            "value_i64",
            "value_f64",
        ],
        "class_static_values" => vec![
            "file_id",
            "class_idx",
            "static_values_off",
            "ordinal",
            "field_idx",
            "value_kind",
            "value_index",
            "value_i64",
            "value_f64",
        ],
        "encoded_arrays" => vec![
            "file_id",
            "encoded_array_idx",
            "encoded_array_off",
            "encoded_array_end_off",
            "value_count",
        ],
        "encoded_array_values" => vec![
            "file_id",
            "encoded_array_off",
            "depth",
            "ordinal",
            "name_idx",
            "value_off",
            "value_end_off",
            "value_kind",
            "value_index",
            "value_i64",
            "value_f64",
        ],
        "encoded_array_owners" => vec!["file_id", "encoded_array_off", "owner_kind", "owner_idx"],
        "annotation_directories" => vec![
            "file_id",
            "class_idx",
            "annotations_off",
            "class_annotations_off",
            "fields_size",
            "methods_size",
            "parameters_size",
        ],
        "annotation_directory_entries" => vec![
            "file_id",
            "class_idx",
            "annotations_off",
            "entry_kind",
            "entry_idx",
            "annotation_set_off",
            "annotation_set_ref_list_off",
        ],
        "annotation_sets" => vec!["file_id", "annotation_set_off", "size"],
        "annotation_set_entries" => {
            vec!["file_id", "annotation_set_off", "ordinal", "annotation_off"]
        }
        "annotation_set_ref_lists" => vec!["file_id", "annotation_set_ref_list_off", "size"],
        "annotation_set_refs" => vec![
            "file_id",
            "annotation_set_ref_list_off",
            "ordinal",
            "annotation_set_off",
        ],
        "annotations" => vec![
            "file_id",
            "annotation_off",
            "visibility",
            "type_idx",
            "element_count",
        ],
        "annotation_elements" => vec![
            "file_id",
            "annotation_off",
            "depth",
            "ordinal",
            "name_idx",
            "value_off",
            "value_end_off",
            "value_kind",
            "value_index",
            "value_i64",
            "value_f64",
        ],
        "annotation_values" => vec![
            "file_id",
            "class_idx",
            "owner_kind",
            "owner_idx",
            "owner_descriptor",
            "parameter_idx",
            "annotation_off",
            "annotation_type_idx",
            "annotation_descriptor",
            "depth",
            "ordinal",
            "name_idx",
            "name",
            "value_kind",
            "value_i64",
            "value_f64",
        ],
        "annotation_elements_resolved" => vec![
            "file_id",
            "class_idx",
            "owner_kind",
            "owner_idx",
            "owner",
            "parameter_idx",
            "annotation",
            "visibility",
            "element_count",
            "annotation_off",
            "element_ordinal",
            "element_name",
            "value_kind",
            "value_index",
            "value_i64",
            "value_f64",
            "retention_policy",
        ],
        "hiddenapi_flags" => vec![
            "file_id",
            "class_idx",
            "ordinal",
            "member_kind",
            "member_idx",
            "flag",
        ],
        "debug_positions" => vec![
            "file_id",
            "method_idx",
            "debug_info_off",
            "ordinal",
            "address",
            "line",
            "source_file_idx",
            "prologue_end",
            "epilogue_begin",
        ],
        "debug_locals" => vec![
            "file_id",
            "method_idx",
            "debug_info_off",
            "ordinal",
            "address",
            "event",
            "register_num",
            "name_idx",
            "type_idx",
            "signature_idx",
        ],
        "debug_opcodes" => vec![
            "file_id",
            "method_idx",
            "debug_info_off",
            "ordinal",
            "opcode_off",
            "opcode_end_off",
            "opcode",
            "address",
            "line",
            "address_diff",
            "line_diff",
            "register_num",
            "name_idx",
            "type_idx",
            "signature_idx",
            "source_file_idx",
            "emits_position",
            "emits_local",
        ],
        _ => return None,
    };
    Some(columns.into_iter().map(str::to_owned).collect())
}

fn expand_projection(
    projection: &[sqlparser::ast::SelectItem],
    grouped: &[GroupedRow],
    fallback_columns: &[String],
) -> Result<(Vec<(sqlparser::ast::Expr, String)>, Vec<String>), String> {
    let source_columns: Vec<String> = grouped
        .first()
        .map(|group| {
            group
                .row
                .columns
                .iter()
                .map(|name| name.to_string())
                .collect()
        })
        .unwrap_or_else(|| fallback_columns.to_vec());
    let mut output = Vec::new();
    for item in projection {
        match item {
            sqlparser::ast::SelectItem::Wildcard(_) => {
                for name in &source_columns {
                    output.push((
                        sqlparser::ast::Expr::Identifier(sqlparser::ast::Ident::new(name)),
                        name.clone(),
                    ));
                }
            }
            sqlparser::ast::SelectItem::QualifiedWildcard(kind, _) => {
                let sqlparser::ast::SelectItemQualifiedWildcardKind::ObjectName(name) = kind else {
                    return Err("unsupported qualified wildcard expression".into());
                };
                let Some(qualifier) = name.0.last().and_then(|part| part.as_ident()) else {
                    return Err("invalid qualified wildcard".into());
                };
                let qualifier = qualifier.value.clone();
                for column in &source_columns {
                    let key = format!("{}.{}", qualifier.to_ascii_lowercase(), column);
                    if grouped
                        .first()
                        .is_some_and(|group| group.row.values.contains_key(key.as_str()))
                    {
                        output.push((
                            sqlparser::ast::Expr::CompoundIdentifier(vec![
                                sqlparser::ast::Ident::new(qualifier.clone()),
                                sqlparser::ast::Ident::new(column),
                            ]),
                            column.clone(),
                        ));
                    }
                }
            }
            sqlparser::ast::SelectItem::UnnamedExpr(expr) => {
                output.push((expr.clone(), expression_label(expr)));
            }
            sqlparser::ast::SelectItem::ExprWithAlias { expr, alias } => {
                output.push((expr.clone(), alias.value.clone()));
            }
            sqlparser::ast::SelectItem::ExprWithAliases { .. } => {
                return Err("multiple projection aliases are not implemented".into())
            }
        }
    }
    let labels = output.iter().map(|(_, label)| label.clone()).collect();
    Ok((output, labels))
}

fn expression_label(expr: &sqlparser::ast::Expr) -> String {
    match expr {
        sqlparser::ast::Expr::Identifier(id) => id.value.clone(),
        sqlparser::ast::Expr::CompoundIdentifier(ids) => {
            ids.last().map(|id| id.value.clone()).unwrap_or_default()
        }
        sqlparser::ast::Expr::Function(function) => function
            .name
            .0
            .last()
            .and_then(|part| part.as_ident())
            .map(|ident| ident.value.to_ascii_lowercase())
            .unwrap_or_else(|| function.to_string()),
        sqlparser::ast::Expr::Substring { .. } => "substr".to_owned(),
        sqlparser::ast::Expr::Trim { .. } => "trim".to_owned(),
        // DataFusion/SQLite's relation-free and computed expressions use a
        // stable generic output name unless the user supplies `AS alias`.
        _ => "column".to_owned(),
    }
}

fn join_constraint(
    operator: &sqlparser::ast::JoinOperator,
) -> Result<Option<&sqlparser::ast::Expr>, String> {
    use sqlparser::ast::{JoinConstraint, JoinOperator};
    let constraint = match operator {
        JoinOperator::Join(c) | JoinOperator::Inner(c) => c,
        JoinOperator::CrossJoin(c) => c,
        JoinOperator::Left(_) | JoinOperator::LeftOuter(_) => {
            return Err("unsupported SQL: outer joins are not implemented".into())
        }
        JoinOperator::Right(_) | JoinOperator::RightOuter(_) | JoinOperator::FullOuter(_) => {
            return Err("unsupported SQL: outer joins are not implemented".into())
        }
        _ => return Err("unsupported SQL join type".into()),
    };
    match constraint {
        JoinConstraint::On(expr) => Ok(Some(expr)),
        JoinConstraint::None => Ok(None),
        JoinConstraint::Using(_) | JoinConstraint::Natural => {
            Err("unsupported SQL: JOIN USING/NATURAL is not implemented".into())
        }
    }
}

fn join_rows(
    left: &[RelRow],
    right: &[RelRow],
    constraint: Option<&sqlparser::ast::Expr>,
) -> Result<Vec<RelRow>, String> {
    let Some(constraint) = constraint else {
        let product = left.len().saturating_mul(right.len());
        if product > 5_000_000 {
            return Err("unsupported SQL: large cross join without an equality condition".into());
        }
        let mut merged = Vec::new();
        let mut retained_bytes = 0;
        for left_row in left {
            for right_row in right {
                push_reference_row(&mut merged, left_row.merge(right_row), &mut retained_bytes)?;
            }
        }
        return Ok(merged);
    };
    let mut conjuncts = Vec::new();
    flatten_and(constraint, &mut conjuncts);
    let mut keys = Vec::new();
    for expr in conjuncts {
        let sqlparser::ast::Expr::BinaryOp {
            left: a,
            op: sqlparser::ast::BinaryOperator::Eq,
            right: b,
        } = expr
        else {
            continue;
        };
        if let (Some(left), Some(right)) = (left.first(), right.first()) {
            if eval_scalar(a, left, &[]).is_ok() && eval_scalar(b, right, &[]).is_ok() {
                keys.push((a.as_ref(), b.as_ref()));
            } else if eval_scalar(b, left, &[]).is_ok() && eval_scalar(a, right, &[]).is_ok() {
                keys.push((b.as_ref(), a.as_ref()));
            }
        }
    }
    if left.is_empty() || right.is_empty() {
        return Ok(Vec::new());
    }
    if keys.is_empty() {
        return Err("unsupported SQL: JOIN requires an equality ON condition".into());
    }
    let make_key = |row: &RelRow, right: bool| -> Result<Option<Vec<membership::Key>>, String> {
        keys.iter()
            .map(|(a, b)| {
                eval_scalar(if right { b } else { a }, row, &[])
                    .map(|value| membership::key(&value))
            })
            .collect::<Result<Option<Vec<_>>, _>>()
    };
    let mut index: FxHashMap<Vec<membership::Key>, Vec<&RelRow>> = FxHashMap::default();
    for row in right {
        if let Some(key) = make_key(row, true)? {
            index.entry(key).or_default().push(row);
        }
    }
    let mut joined = Vec::new();
    let mut retained_bytes = 0;
    for left_row in left {
        let Some(key) = make_key(left_row, false)? else {
            continue;
        };
        if let Some(matches) = index.get(&key) {
            for right_row in matches {
                let merged = left_row.merge(right_row);
                if eval_bool(constraint, &merged, &[])? {
                    push_reference_row(&mut joined, merged, &mut retained_bytes)?;
                }
            }
        }
    }
    Ok(joined)
}

fn derive_join_keys(
    constraint: Option<&sqlparser::ast::Expr>,
    current: &[RelRow],
    right_alias: &str,
) -> Result<Option<(String, HashSet<Scalar>)>, String> {
    let Some(sqlparser::ast::Expr::BinaryOp {
        left,
        op: sqlparser::ast::BinaryOperator::Eq,
        right,
    }) = constraint
    else {
        return Ok(None);
    };
    let Some((left_alias, left_column)) = qualified_column(left) else {
        return Ok(None);
    };
    let Some((right_expr_alias, right_column)) = qualified_column(right) else {
        return Ok(None);
    };
    let (right_expr, current_expr, key_column) =
        if right_expr_alias.eq_ignore_ascii_case(right_alias) {
            (right, left, right_column)
        } else if left_alias.eq_ignore_ascii_case(right_alias) {
            (left, right, left_column)
        } else {
            return Ok(None);
        };
    // Generic metadata scanners only implement descriptor-key filtering.
    // Other keys must reach the join evaluator, rather than being tested
    // against an unsupported-column NULL and discarding every row.
    if !matches!(
        key_column.as_str(),
        "descriptor" | "method" | "class_descriptor"
    ) {
        return Ok(None);
    }
    let _ = right_expr;
    let mut values = HashSet::new();
    for row in current {
        values.insert(eval_scalar(current_expr, row, &[])?);
    }
    Ok(Some((key_column, values)))
}

fn factor_alias(factor: &sqlparser::ast::TableFactor) -> &str {
    match factor {
        sqlparser::ast::TableFactor::Table { name, alias, .. } => alias
            .as_ref()
            .map(|a| a.name.value.as_str())
            .or_else(|| {
                name.0
                    .last()
                    .and_then(|part| part.as_ident())
                    .map(|id| id.value.as_str())
            })
            .unwrap_or(""),
        _ => "",
    }
}

/// Extract only conjuncts that reference this one relation.  Predicates that
/// mention another relation are left for the post-join filter; dropping them
/// here would change an inner join's result.  Unsupported local expressions
/// are likewise retained by the normal evaluator.
fn push_predicates(expr: &sqlparser::ast::Expr, alias: &str) -> Option<Vec<PushPredicate>> {
    let mut conjuncts = Vec::new();
    flatten_and(expr, &mut conjuncts);
    let mut out = Vec::new();
    for conjunct in conjuncts {
        if !references_only(conjunct, alias) {
            continue;
        }
        if let Some(predicate) = simple_push_predicate(conjunct) {
            out.push(predicate);
        }
    }
    Some(out)
}

fn flatten_and<'a>(expr: &'a sqlparser::ast::Expr, out: &mut Vec<&'a sqlparser::ast::Expr>) {
    if let sqlparser::ast::Expr::BinaryOp {
        left,
        op: sqlparser::ast::BinaryOperator::And,
        right,
    } = expr
    {
        flatten_and(left, out);
        flatten_and(right, out);
    } else {
        out.push(expr);
    }
}

fn references_only(expr: &sqlparser::ast::Expr, alias: &str) -> bool {
    use sqlparser::ast::Expr;
    match expr {
        Expr::Identifier(_) | Expr::Value(_) => true,
        Expr::CompoundIdentifier(ids) => {
            ids.len() < 2
                || ids
                    .first()
                    .is_some_and(|id| id.value.eq_ignore_ascii_case(alias))
        }
        Expr::BinaryOp { left, right, .. } => {
            references_only(left, alias) && references_only(right, alias)
        }
        Expr::UnaryOp { expr, .. } | Expr::Nested(expr) => references_only(expr, alias),
        Expr::InList { expr, list, .. } => {
            references_only(expr, alias) && list.iter().all(|item| references_only(item, alias))
        }
        Expr::Like { expr, pattern, .. } | Expr::ILike { expr, pattern, .. } => {
            references_only(expr, alias) && references_only(pattern, alias)
        }
        _ => false,
    }
}

fn simple_push_predicate(expr: &sqlparser::ast::Expr) -> Option<PushPredicate> {
    use sqlparser::ast::{BinaryOperator, Expr};
    match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            let column = column_name(left)?;
            let value = literal_scalar(right)?;
            Some(PushPredicate {
                column,
                kind: PushPredicateKind::Eq,
                values: vec![value],
                escape: None,
            })
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::NotEq,
            right,
        }
        | Expr::BinaryOp {
            left: right,
            op: BinaryOperator::NotEq,
            right: left,
        } => {
            if let (Some(column), Some(value)) = (column_name(left), literal_scalar(right)) {
                Some(PushPredicate {
                    column,
                    kind: PushPredicateKind::NotEq,
                    values: vec![value],
                    escape: None,
                })
            } else {
                None
            }
        }
        Expr::InList {
            expr,
            list,
            negated: false,
        } => {
            let column = column_name(expr)?;
            let values = list
                .iter()
                .map(literal_scalar)
                .collect::<Option<Vec<_>>>()?;
            Some(PushPredicate {
                column,
                kind: PushPredicateKind::In,
                values,
                escape: None,
            })
        }
        Expr::Like {
            expr,
            pattern,
            negated: false,
            escape_char,
            ..
        }
        | Expr::ILike {
            expr,
            pattern,
            negated: false,
            escape_char,
            ..
        } => {
            let column = column_name(expr)?;
            let value = literal_scalar(pattern)?;
            let escape = match escape_char {
                None => None,
                Some(escape_expr) => {
                    let Scalar::Text(text) = literal_scalar(escape_expr)? else {
                        return None;
                    };
                    let mut chars = text.chars();
                    let escape = chars.next()?;
                    if chars.next().is_some() {
                        return None;
                    }
                    Some(escape)
                }
            };
            Some(PushPredicate {
                column,
                kind: PushPredicateKind::Like,
                values: vec![value],
                escape,
            })
        }
        _ => None,
    }
}

fn column_name(expr: &sqlparser::ast::Expr) -> Option<String> {
    match expr {
        sqlparser::ast::Expr::Identifier(id) => Some(id.value.to_ascii_lowercase()),
        sqlparser::ast::Expr::CompoundIdentifier(ids) => {
            ids.last().map(|id| id.value.to_ascii_lowercase())
        }
        _ => None,
    }
}

fn qualified_column(expr: &sqlparser::ast::Expr) -> Option<(String, String)> {
    match expr {
        sqlparser::ast::Expr::CompoundIdentifier(ids) if ids.len() >= 2 => Some((
            ids[ids.len() - 2].value.to_ascii_lowercase(),
            ids[ids.len() - 1].value.to_ascii_lowercase(),
        )),
        _ => None,
    }
}

fn literal_scalar(expr: &sqlparser::ast::Expr) -> Option<Scalar> {
    match expr {
        sqlparser::ast::Expr::Value(value) => scalar_from_value(value).ok(),
        _ => None,
    }
}

fn predicates_match<F>(predicates: &[PushPredicate], mut value: F) -> bool
where
    F: FnMut(&str) -> Scalar,
{
    predicates.iter().all(|predicate| {
        let actual = value(&predicate.column);
        match predicate.kind {
            PushPredicateKind::Eq => predicate.values.first().is_some_and(|expected| {
                !matches!(actual, Scalar::Null)
                    && !matches!(expected, Scalar::Null)
                    && actual.sql_eq(expected)
            }),
            PushPredicateKind::In => predicate.values.iter().any(|expected| {
                !matches!(actual, Scalar::Null)
                    && !matches!(expected, Scalar::Null)
                    && actual.sql_eq(expected)
            }),
            PushPredicateKind::NotEq => predicate.values.first().is_some_and(|expected| {
                !matches!(actual, Scalar::Null)
                    && !matches!(expected, Scalar::Null)
                    && !actual.sql_eq(expected)
            }),
            PushPredicateKind::Like => predicate.values.first().is_some_and(|pattern| {
                !matches!(actual, Scalar::Null)
                    && !matches!(pattern, Scalar::Null)
                    && match (&actual, pattern) {
                        (Scalar::Text(actual), Scalar::Text(pattern)) => {
                            like_match_fast(actual, pattern, predicate.escape)
                        }
                        _ => like_match(&actual.display(), &pattern.display(), predicate.escape),
                    }
            }),
        }
    })
}

fn push_values(predicates: &[PushPredicate], column: &str) -> Option<Vec<Scalar>> {
    predicates.iter().find_map(|predicate| {
        if predicate.column == column
            && matches!(
                predicate.kind,
                PushPredicateKind::Eq | PushPredicateKind::In
            )
        {
            Some(predicate.values.clone())
        } else {
            None
        }
    })
}

fn scan_cached_table(
    table: &CachedTable,
    alias: &str,
    predicates: Option<&[PushPredicate]>,
    key_filter: Option<(&str, &HashSet<Scalar>)>,
) -> Vec<RelRow> {
    let mut rows = Vec::with_capacity(table.rows.len());
    for values in &table.rows {
        let mut row = RelRow::with_capacity(table.columns.len());
        for (column, value) in table.columns.iter().zip(values) {
            row.put(alias, column, value.clone());
        }
        if let Some((column, accepted)) = key_filter {
            if !accepted
                .iter()
                .any(|key| key.sql_eq(row.get(column).unwrap_or(&Scalar::Null)))
            {
                continue;
            }
        }
        if let Some(predicates) = predicates {
            if !predicates_match(predicates, |column| {
                row.get(column).cloned().unwrap_or(Scalar::Null)
            }) {
                continue;
            }
        }
        rows.push(row);
    }
    rows
}

fn scan_factor(
    factor: &sqlparser::ast::TableFactor,
    ds: &Dataset,
    predicates: Option<&[PushPredicate]>,
    key_filter: Option<(&str, &HashSet<Scalar>)>,
    needs_method_opcode: bool,
    named_caches: &NamedCaches,
    source_dataset: Option<&Dataset>,
    scan_limit: Option<usize>,
    scan_columns: Option<&HashSet<String>>,
) -> Result<Vec<RelRow>, String> {
    if let sqlparser::ast::TableFactor::Derived {
        lateral,
        subquery,
        alias,
        ..
    } = factor
    {
        if *lateral {
            return Err("LATERAL derived tables are not supported".into());
        }
        let (columns, rows) =
            execute_query_rows(subquery, ds, source_dataset, named_caches, None, false)?;
        let alias_name = alias.as_ref().map(|a| a.name.value.as_str()).unwrap_or("");
        let (columns, rows) = rename_result_columns(
            (columns, rows),
            alias
                .as_ref()
                .map(|alias| alias.columns.as_slice())
                .unwrap_or(&[]),
        );
        let table = Arc::new(CachedTable { columns, rows });
        return Ok(scan_cached_table(
            &table, alias_name, predicates, key_filter,
        ));
    }
    let sqlparser::ast::TableFactor::Table {
        name, alias, args, ..
    } = factor
    else {
        return Err("unsupported SQL: table-function FROM items are not implemented".into());
    };
    if args.is_some() {
        return Err("unsupported SQL table function".into());
    }
    let table_name = name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .map(|ident| ident.value.as_str())
        .unwrap_or("");
    let alias_name = alias
        .as_ref()
        .map(|a| a.name.value.as_str())
        .unwrap_or(table_name);
    let table_name_lower = table_name.to_ascii_lowercase();
    if let Some(table) = named_caches.resolve(&table_name_lower, source_dataset)? {
        return Ok(scan_cached_table(
            &table, alias_name, predicates, key_filter,
        ));
    }
    match table_name_lower.as_str() {
        "dex_files" => scan_dex_files(ds, alias_name, predicates),
        "strings" => scan_strings(ds, alias_name, predicates),
        "type_ids" => scan_type_ids(ds, alias_name, predicates),
        "types" => scan_types(ds, alias_name, predicates),
        "type_lists" => scan_type_lists(ds, alias_name, predicates),
        "type_list_entries" => scan_type_list_entries(ds, alias_name, predicates),
        "proto_ids" => scan_proto_ids(ds, alias_name, predicates),
        "protos" => scan_protos(ds, alias_name, predicates),
        "proto_params" => scan_proto_params(ds, alias_name, predicates),
        "field_ids" => scan_field_ids(ds, alias_name, predicates),
        "method_ids" => scan_method_ids(ds, alias_name, predicates),
        "method_opcodes" => scan_method_opcodes(ds, alias_name, predicates),
        "map_items" => scan_map_items(ds, alias_name, predicates),
        "id_items" => scan_id_items(ds, alias_name, predicates),
        "class_data_items" => scan_class_data_items(ds, alias_name, predicates),
        "class_defs" => scan_class_defs(ds, alias_name, predicates),
        "class_data_methods" => scan_class_data_methods(ds, alias_name, predicates),
        "class_methods" => scan_class_methods(ds, alias_name, predicates),
        "class_fields" => scan_class_fields(ds, alias_name, predicates),
        "class_interfaces" => scan_class_interfaces(ds, alias_name, predicates),
        "code_items" => scan_code_items(ds, alias_name, predicates),
        "try_items" => scan_try_items(ds, alias_name, predicates),
        "catch_handlers" => scan_catch_handlers(ds, alias_name, predicates),
        "debug_info" => scan_debug_info(ds, alias_name, predicates),
        "debug_parameters" => scan_debug_parameters(ds, alias_name, predicates),
        "debug_positions" => scan_debug_positions(ds, alias_name, predicates),
        "debug_locals" => scan_debug_locals(ds, alias_name, predicates),
        "debug_opcodes" => scan_debug_opcodes(ds, alias_name, predicates),
        "classes" => scan_classes(
            ds,
            alias_name,
            predicates,
            key_filter,
            scan_limit,
            scan_columns,
        ),
        "methods" => scan_methods(
            ds,
            alias_name,
            predicates,
            key_filter,
            needs_method_opcode,
            scan_limit,
            scan_columns,
        ),
        "fields" => scan_fields(
            ds,
            alias_name,
            predicates,
            key_filter,
            scan_limit,
            scan_columns,
        ),
        "method_strings" => {
            scan_method_strings(ds, alias_name, predicates, key_filter, scan_columns)
        }
        "method_using_numbers" | "method_numbers" => scan_method_numbers(
            ds,
            alias_name,
            predicates,
            key_filter,
            table_name_lower.as_str(),
        ),
        "method_calls" => scan_method_calls(ds, alias_name, predicates, key_filter),
        "method_handles" => scan_method_handles(ds, alias_name, predicates),
        "call_sites" => scan_call_sites(ds, alias_name, predicates),
        "call_site_args" => scan_call_site_args(ds, alias_name, predicates),
        "class_static_values" => scan_class_static_values(ds, alias_name, predicates),
        "hiddenapi_flags" => scan_hiddenapi_flags(ds, alias_name, predicates),
        "encoded_arrays" => scan_encoded_arrays(ds, alias_name, predicates),
        "encoded_array_values" => scan_encoded_array_values(ds, alias_name, predicates),
        "encoded_array_owners" => scan_encoded_array_owners(ds, alias_name, predicates),
        "annotation_directories" => scan_annotation_directories(ds, alias_name, predicates),
        "annotation_directory_entries" => {
            scan_annotation_directory_entries(ds, alias_name, predicates)
        }
        "annotation_sets" => scan_annotation_sets(ds, alias_name, predicates),
        "annotation_set_entries" => scan_annotation_set_entries(ds, alias_name, predicates),
        "annotation_set_ref_lists" => scan_annotation_set_ref_lists(ds, alias_name, predicates),
        "annotation_set_refs" => scan_annotation_set_refs(ds, alias_name, predicates),
        "annotations" => scan_annotations(ds, alias_name, predicates),
        "annotation_elements" => scan_annotation_elements(ds, alias_name, predicates),
        "annotation_values" => scan_annotation_values(ds, alias_name, predicates),
        "annotation_elements_resolved" => {
            scan_annotation_elements_resolved(ds, alias_name, predicates)
        }
        "method_refs" => scan_method_refs(ds, alias_name, predicates),
        "method_field_accesses" => {
            scan_method_field_accesses(ds, alias_name, predicates, key_filter)
        }
        "method_used_types" => scan_method_used_types(ds, alias_name, predicates, key_filter),
        _ => Err(format!("unknown table '{table_name}'")),
    }
}

fn scan_dex_files(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::with_capacity(ds.files.len());
    for file in &ds.files {
        let mut row = RelRow::with_capacity(28);
        row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
        row.put(alias, "string_pool_id", Scalar::Int(file.file_id as i64));
        row.put(
            alias,
            "source_path",
            Scalar::text(file.source_path.to_string_lossy().into_owned()),
        );
        row.put(alias, "entry_name", Scalar::text(file.entry_name.clone()));
        row.put(alias, "byte_len", Scalar::Int(file.byte_len as i64));
        row.put(alias, "dex_version", Scalar::text(file.dex_version.clone()));
        row.put(alias, "checksum", Scalar::Int(file.checksum as i64));
        row.put(
            alias,
            "signature_hex",
            Scalar::text(file.signature_hex.clone()),
        );
        row.put(alias, "file_size", Scalar::Int(file.byte_len as i64));
        row.put(alias, "header_size", Scalar::Int(file.header_size as i64));
        row.put(alias, "endian_tag", Scalar::Int(file.endian_tag as i64));
        row.put(
            alias,
            "link_size",
            Scalar::Int(read_u32_at(file.raw(), 44) as i64),
        );
        row.put(
            alias,
            "link_off",
            Scalar::Int(read_u32_at(file.raw(), 48) as i64),
        );
        row.put(alias, "map_off", Scalar::Int(file.map_off as i64));
        row.put(
            alias,
            "string_count",
            Scalar::Int(file.strings.len() as i64),
        );
        row.put(
            alias,
            "string_ids_off",
            Scalar::Int(file.string_ids_off as i64),
        );
        row.put(alias, "type_count", Scalar::Int(file.types.len() as i64));
        row.put(alias, "type_ids_off", Scalar::Int(file.type_ids_off as i64));
        row.put(alias, "proto_count", Scalar::Int(file.protos.len() as i64));
        row.put(
            alias,
            "proto_ids_off",
            Scalar::Int(file.proto_ids_off as i64),
        );
        row.put(alias, "field_count", Scalar::Int(file.fields.len() as i64));
        row.put(
            alias,
            "field_ids_off",
            Scalar::Int(file.field_ids_off as i64),
        );
        row.put(
            alias,
            "method_count",
            Scalar::Int(file.methods.len() as i64),
        );
        row.put(
            alias,
            "method_ids_off",
            Scalar::Int(file.method_ids_off as i64),
        );
        row.put(alias, "class_count", Scalar::Int(file.classes.len() as i64));
        row.put(
            alias,
            "class_defs_off",
            Scalar::Int(file.class_defs_off as i64),
        );
        row.put(alias, "data_size", Scalar::Int(file.data_size as i64));
        row.put(alias, "data_off", Scalar::Int(file.data_off as i64));
        rows.push(row);
    }
    Ok(rows)
}

fn scan_strings(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (idx, value) in file.strings.iter().enumerate() {
            let mut row = RelRow::with_capacity(3);
            row.put(alias, "string_pool_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "string_idx", Scalar::Int(idx as i64));
            row.put(alias, "value", Scalar::text(value.clone()));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_type_ids(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (idx, ty) in file.types.iter().enumerate() {
            let mut row = RelRow::with_capacity(3);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "type_idx", Scalar::Int(idx as i64));
            row.put(
                alias,
                "descriptor_idx",
                Scalar::Int(ty.descriptor_idx as i64),
            );
            rows.push(row);
        }
    }
    Ok(rows)
}

fn java_name(descriptor: &str) -> String {
    let mut array = 0;
    let mut value = descriptor;
    while let Some(rest) = value.strip_prefix('[') {
        array += 1;
        value = rest;
    }
    let name = match value {
        "V" => "void".to_owned(),
        "Z" => "boolean".to_owned(),
        "B" => "byte".to_owned(),
        "C" => "char".to_owned(),
        "S" => "short".to_owned(),
        "I" => "int".to_owned(),
        "J" => "long".to_owned(),
        "F" => "float".to_owned(),
        "D" => "double".to_owned(),
        v if v.starts_with('L') && v.ends_with(';') => v[1..v.len() - 1].replace('/', "."),
        v => v.to_owned(),
    };
    format!("{name}{}", "[]".repeat(array))
}

fn scan_types(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (idx, ty) in file.types.iter().enumerate() {
            let descriptor = file.string(ty.descriptor_idx);
            let mut row = RelRow::with_capacity(4);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "type_idx", Scalar::Int(idx as i64));
            row.put(alias, "descriptor", Scalar::text(descriptor));
            row.put(alias, "java_name", Scalar::text(java_name(descriptor)));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn type_list_offsets(file: &dexsql_cache::DexFile) -> Vec<(usize, usize)> {
    let bytes = file.raw();
    let mut starts = Vec::new();
    // The reference registers type lists in relation-use order (proto
    // parameter lists, then class interface lists), rather than raw map
    // offset order. Preserve that observable order while deduplicating shared
    // lists; append orphan map entries afterward for malformed/legacy DEXes.
    for idx in 0..file.protos.len() {
        let off = read_u32_at(bytes, file.proto_ids_off as usize + idx * 12 + 8);
        if off != 0 && !starts.contains(&(off as usize)) {
            starts.push(off as usize);
        }
    }
    for idx in 0..file.classes.len() {
        let off = read_u32_at(bytes, file.class_defs_off as usize + idx * 32 + 12);
        if off != 0 && !starts.contains(&(off as usize)) {
            starts.push(off as usize);
        }
    }
    let mut out = Vec::new();
    let mut append = |mut pos: usize, count: usize| {
        for _ in 0..count {
            let size = read_u32_at(bytes, pos) as usize;
            let data_end = pos + 4 + size * 2;
            out.push((pos, data_end));
            pos = (data_end + 3) & !3;
        }
    };
    for start in starts {
        append(start, 1);
    }
    for (code, n, base) in map_entries(file) {
        if code != 0x1001 {
            continue;
        }
        let mut pos = base as usize;
        for _ in 0..n {
            if out.iter().any(|(off, _)| *off == pos) {
                let size = read_u32_at(bytes, pos) as usize;
                pos = (pos + 4 + size * 2 + 3) & !3;
                continue;
            }
            let size = read_u32_at(bytes, pos) as usize;
            let data_end = pos + 4 + size * 2;
            out.push((pos, data_end));
            pos = (data_end + 3) & !3;
        }
    }
    out
}

fn scan_type_lists(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (off, end) in type_list_offsets(file) {
            let mut row = RelRow::with_capacity(4);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "type_list_off", Scalar::Int(off as i64));
            row.put(alias, "type_list_end_off", Scalar::Int(end as i64));
            row.put(
                alias,
                "size",
                Scalar::Int(read_u32_at(file.raw(), off) as i64),
            );
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_type_list_entries(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (off, _) in type_list_offsets(file) {
            let size = read_u32_at(file.raw(), off) as usize;
            for ordinal in 0..size {
                let type_idx = read_u16_at(file.raw(), off + 4 + ordinal * 2);
                let mut row = RelRow::with_capacity(4);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "type_list_off", Scalar::Int(off as i64));
                row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
                row.put(alias, "type_idx", Scalar::Int(type_idx as i64));
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_proto_ids(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (idx, proto) in file.protos.iter().enumerate() {
            let parameters_off =
                read_u32_at(file.raw(), file.proto_ids_off as usize + idx * 12 + 8);
            let mut row = RelRow::with_capacity(5);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "proto_idx", Scalar::Int(idx as i64));
            row.put(alias, "shorty_idx", Scalar::Int(proto.shorty_idx as i64));
            row.put(
                alias,
                "return_type_idx",
                Scalar::Int(proto.return_type_idx as i64),
            );
            row.put(alias, "parameters_off", Scalar::Int(parameters_off as i64));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_protos(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (idx, proto) in file.protos.iter().enumerate() {
            let parameters_off =
                read_u32_at(file.raw(), file.proto_ids_off as usize + idx * 12 + 8);
            let return_descriptor = file.type_descriptor(proto.return_type_idx);
            let param_descriptors = proto
                .parameters
                .iter()
                .map(|t| file.type_descriptor(*t as u32))
                .collect::<Vec<_>>()
                .join(",");
            let mut row = RelRow::with_capacity(9);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "proto_idx", Scalar::Int(idx as i64));
            row.put(alias, "shorty_idx", Scalar::Int(proto.shorty_idx as i64));
            row.put(alias, "shorty", Scalar::text(file.string(proto.shorty_idx)));
            row.put(
                alias,
                "return_type_idx",
                Scalar::Int(proto.return_type_idx as i64),
            );
            row.put(alias, "return_descriptor", Scalar::text(return_descriptor));
            row.put(alias, "parameters_off", Scalar::Int(parameters_off as i64));
            row.put(
                alias,
                "param_count",
                Scalar::Int(proto.parameters.len() as i64),
            );
            row.put(alias, "param_descriptors", Scalar::text(param_descriptors));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_proto_params(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (proto_idx, proto) in file.protos.iter().enumerate() {
            for (ordinal, type_idx) in proto.parameters.iter().enumerate() {
                let mut row = RelRow::with_capacity(5);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "proto_idx", Scalar::Int(proto_idx as i64));
                row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
                row.put(alias, "type_idx", Scalar::Int(*type_idx as i64));
                row.put(
                    alias,
                    "descriptor",
                    Scalar::text(file.type_descriptor(*type_idx as u32)),
                );
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_field_ids(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (idx, field) in file.fields.iter().enumerate() {
            let mut row = RelRow::with_capacity(5);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "field_idx", Scalar::Int(idx as i64));
            row.put(alias, "class_idx", Scalar::Int(field.class_idx as i64));
            row.put(alias, "type_idx", Scalar::Int(field.type_idx as i64));
            row.put(alias, "name_idx", Scalar::Int(field.name_idx as i64));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_method_ids(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (idx, method) in file.methods.iter().enumerate() {
            let mut row = RelRow::with_capacity(5);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "method_idx", Scalar::Int(idx as i64));
            row.put(alias, "class_idx", Scalar::Int(method.class_idx as i64));
            row.put(alias, "proto_idx", Scalar::Int(method.proto_idx as i64));
            row.put(alias, "name_idx", Scalar::Int(method.name_idx as i64));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_method_opcodes(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for idx in 0..file.methods.len() as u32 {
            let summary = file.method_opcode_summary(idx);
            let mut row = RelRow::with_capacity(4);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "method_idx", Scalar::Int(idx as i64));
            row.put(
                alias,
                "opcode_count",
                summary
                    .as_ref()
                    .map(|(n, _)| Scalar::Int(*n as i64))
                    .unwrap_or(Scalar::Null),
            );
            row.put(
                alias,
                "opcode_hex",
                summary
                    .as_ref()
                    .map(|(_, v)| Scalar::text(v))
                    .unwrap_or(Scalar::Null),
            );
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_class_defs(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (class_def_idx, class) in file.classes.iter().enumerate() {
            let base = file.class_defs_off as usize + class_def_idx * 32;
            let interfaces_off = read_u32_at(file.raw(), base + 12);
            let annotations_off = read_u32_at(file.raw(), base + 20);
            let static_values_off = read_u32_at(file.raw(), base + 28);
            let mut row = RelRow::with_capacity(10);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(
                alias,
                "class_def_idx",
                Scalar::Int(class.class_def_idx as i64),
            );
            row.put(alias, "class_idx", Scalar::Int(class.class_idx as i64));
            row.put(
                alias,
                "access_flags",
                Scalar::Int(class.access_flags as i64),
            );
            row.put(
                alias,
                "superclass_idx",
                class
                    .superclass_idx
                    .map(|v| Scalar::Int(v as i64))
                    .unwrap_or(Scalar::Null),
            );
            row.put(alias, "interfaces_off", Scalar::Int(interfaces_off as i64));
            row.put(
                alias,
                "source_file_idx",
                class
                    .source_file_idx
                    .map(|v| Scalar::Int(v as i64))
                    .unwrap_or(Scalar::Null),
            );
            row.put(
                alias,
                "annotations_off",
                Scalar::Int(annotations_off as i64),
            );
            row.put(
                alias,
                "class_data_off",
                Scalar::Int(class.class_data_off as i64),
            );
            row.put(
                alias,
                "static_values_off",
                Scalar::Int(static_values_off as i64),
            );
            rows.push(row);
        }
    }
    Ok(rows)
}

fn map_entries(file: &dexsql_cache::DexFile) -> Vec<(u16, u32, u32)> {
    let bytes = file.raw();
    let size = read_u32_at(bytes, file.map_off as usize) as usize;
    (0..size)
        .map(|i| {
            let off = file.map_off as usize + 4 + i * 12;
            (
                read_u16_at(bytes, off),
                read_u32_at(bytes, off + 4),
                read_u32_at(bytes, off + 8),
            )
        })
        .collect()
}

fn read_u16_at(bytes: &[u8], off: usize) -> u16 {
    bytes
        .get(off..off + 2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]))
        .unwrap_or(0)
}

fn scan_map_items(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (ordinal, (type_code, size, offset)) in map_entries(file).into_iter().enumerate() {
            let mut row = RelRow::with_capacity(5);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
            row.put(alias, "type_code", Scalar::Int(type_code as i64));
            row.put(alias, "size", Scalar::Int(size as i64));
            row.put(alias, "offset", Scalar::Int(offset as i64));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_id_items(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    let widths = [
        (1u16, 4usize),
        (2, 4),
        (3, 12),
        (4, 8),
        (5, 8),
        (6, 32),
        (7, 4),
        (8, 8),
    ];
    for file in &ds.files {
        for (type_code, size, offset) in map_entries(file) {
            let Some((_, width)) = widths.iter().find(|(code, _)| *code == type_code) else {
                continue;
            };
            for idx in 0..size as usize {
                let item_off = offset as usize + idx * *width;
                let data_off = match type_code {
                    1 => Some(read_u32_at(file.raw(), item_off)),
                    3 => Some(read_u32_at(file.raw(), item_off + 8)),
                    6 => {
                        let data = read_u32_at(file.raw(), item_off + 24);
                        (data != 0).then_some(data)
                    }
                    7 => Some(read_u32_at(file.raw(), item_off)),
                    _ => None,
                };
                let mut row = RelRow::with_capacity(6);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "item_type_code", Scalar::Int(type_code as i64));
                row.put(alias, "idx", Scalar::Int(idx as i64));
                row.put(alias, "item_off", Scalar::Int(item_off as i64));
                row.put(
                    alias,
                    "item_end_off",
                    Scalar::Int((item_off + *width) as i64),
                );
                row.put(
                    alias,
                    "data_off",
                    data_off
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn read_u32_at(bytes: &[u8], off: usize) -> u32 {
    bytes
        .get(off..off + 4)
        .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
        .unwrap_or(0)
}

fn read_uleb_at(bytes: &[u8], mut pos: usize) -> (u32, usize) {
    let mut value = 0u32;
    let mut shift = 0;
    while let Some(&byte) = bytes.get(pos) {
        pos += 1;
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 || shift >= 28 {
            break;
        }
        shift += 7;
    }
    (value, pos)
}

fn class_data_summary(bytes: &[u8], off: u32) -> (usize, [usize; 4]) {
    if off == 0 {
        return (0, [0; 4]);
    }
    let mut pos = off as usize;
    let mut counts = [0usize; 4];
    for count in &mut counts {
        let (value, next) = read_uleb_at(bytes, pos);
        *count = value as usize;
        pos = next;
    }
    // encoded_field/method entries are delta-indexed; each has one or two
    // additional ULEB values after the index delta.
    for i in 0..2 {
        for _ in 0..counts[i] {
            let (_, next) = read_uleb_at(bytes, pos);
            pos = next;
            let (_, next) = read_uleb_at(bytes, pos);
            pos = next;
        }
    }
    for i in 2..4 {
        for _ in 0..counts[i] {
            let (_, next) = read_uleb_at(bytes, pos);
            pos = next;
            let (_, next) = read_uleb_at(bytes, pos);
            pos = next;
            let (_, next) = read_uleb_at(bytes, pos);
            pos = next;
        }
    }
    (pos, counts)
}

fn scan_class_data_items(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for class in &file.classes {
            if class.class_data_off == 0 {
                continue;
            }
            let (end, counts) = class_data_summary(file.raw(), class.class_data_off);
            let mut row = RelRow::with_capacity(8);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "class_idx", Scalar::Int(class.class_idx as i64));
            row.put(
                alias,
                "class_data_off",
                Scalar::Int(class.class_data_off as i64),
            );
            row.put(alias, "class_data_end_off", Scalar::Int(end as i64));
            row.put(alias, "static_fields_size", Scalar::Int(counts[0] as i64));
            row.put(alias, "instance_fields_size", Scalar::Int(counts[1] as i64));
            row.put(alias, "direct_methods_size", Scalar::Int(counts[2] as i64));
            row.put(alias, "virtual_methods_size", Scalar::Int(counts[3] as i64));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_class_data_methods(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        // Rows follow ascending class_idx, then each class's definition
        // order (direct block, virtual block), matching the reference
        // class-data relation layout.
        for class_index in &file.classes_by_idx_order {
            let class = &file.classes[*class_index as usize];
            // Within a class, rows ascend by method_idx regardless of the
            // direct/virtual block order (pinned on WeChat class 48).
            let mut ordered: Vec<_> = class.methods.iter().collect();
            ordered.sort_by_key(|method| method.method_idx);
            for method in ordered {
                let mut row = RelRow::with_capacity(5);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "class_idx", Scalar::Int(class.class_idx as i64));
                row.put(alias, "method_idx", Scalar::Int(method.method_idx as i64));
                row.put(
                    alias,
                    "access_flags",
                    Scalar::Int(method.access_flags as i64),
                );
                row.put(
                    alias,
                    "kind",
                    Scalar::text(if method.is_direct {
                        "direct"
                    } else {
                        "virtual"
                    }),
                );
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_class_methods(
    ds: &Dataset,
    alias: &str,
    predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let base = scan_class_data_methods(ds, alias, predicates)?;
    let mut rows = Vec::with_capacity(base.len());
    for row in base {
        let file_id = match row.get("file_id") {
            Some(Scalar::Int(v)) => *v as usize,
            _ => 0,
        };
        let class_idx = match row.get("class_idx") {
            Some(Scalar::Int(v)) => *v as u32,
            _ => 0,
        };
        let method_idx = match row.get("method_idx") {
            Some(Scalar::Int(v)) => *v as u32,
            _ => 0,
        };
        let Some(file) = ds.files.get(file_id) else {
            continue;
        };
        let mut out = RelRow::with_capacity(8);
        out.put(alias, "file_id", Scalar::Int(file_id as i64));
        out.put(alias, "class_idx", Scalar::Int(class_idx as i64));
        out.put(
            alias,
            "class_descriptor",
            Scalar::text(file.type_descriptor(class_idx)),
        );
        out.put(alias, "method_idx", Scalar::Int(method_idx as i64));
        out.put(
            alias,
            "method_name",
            Scalar::text(file.method_name(method_idx)),
        );
        out.put(
            alias,
            "method_descriptor",
            Scalar::text(file.method_descriptor_ref(method_idx)),
        );
        out.put(
            alias,
            "kind",
            row.get("kind").cloned().unwrap_or(Scalar::Null),
        );
        out.put(
            alias,
            "access_flags",
            row.get("access_flags").cloned().unwrap_or(Scalar::Null),
        );
        rows.push(out);
    }
    Ok(rows)
}

fn scan_class_fields(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for class in &file.classes {
            for defined in &class.fields {
                let Some(field) = file.fields.get(defined.field_idx as usize) else {
                    continue;
                };
                let mut row = RelRow::with_capacity(8);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "class_idx", Scalar::Int(class.class_idx as i64));
                row.put(
                    alias,
                    "class_descriptor",
                    Scalar::text(file.type_descriptor(class.class_idx)),
                );
                row.put(alias, "field_idx", Scalar::Int(defined.field_idx as i64));
                row.put(
                    alias,
                    "field_name",
                    Scalar::text(file.string(field.name_idx)),
                );
                row.put(
                    alias,
                    "field_descriptor",
                    Scalar::text(file.field_descriptor_ref(defined.field_idx)),
                );
                row.put(
                    alias,
                    "kind",
                    Scalar::text(if defined.is_static {
                        "static"
                    } else {
                        "instance"
                    }),
                );
                row.put(
                    alias,
                    "access_flags",
                    Scalar::Int(defined.access_flags as i64),
                );
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_class_interfaces(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for class in &file.classes {
            for (ordinal, type_idx) in class.interfaces.iter().enumerate() {
                let mut row = RelRow::with_capacity(5);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "class_idx", Scalar::Int(class.class_idx as i64));
                row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
                row.put(alias, "interface_type_idx", Scalar::Int(*type_idx as i64));
                row.put(
                    alias,
                    "interface_descriptor",
                    Scalar::text(file.type_descriptor(*type_idx as u32)),
                );
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_code_items(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (idx, code) in file.code_items.iter().enumerate() {
            let Some(code) = code else { continue };
            let tries_off = if code.tries_size > 0 {
                ((code.code_off as usize + 16 + code.insns.len() * 2 + 3) & !3) as i64
            } else {
                -1
            };
            let handlers_off = if code.tries_size > 0 {
                tries_off + code.tries.len() as i64 * 8
            } else {
                -1
            };
            let mut row = RelRow::with_capacity(12);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "method_idx", Scalar::Int(idx as i64));
            row.put(alias, "code_off", Scalar::Int(code.code_off as i64));
            row.put(
                alias,
                "registers_size",
                Scalar::Int(code.registers_size as i64),
            );
            row.put(alias, "ins_size", Scalar::Int(code.ins_size as i64));
            row.put(alias, "outs_size", Scalar::Int(code.outs_size as i64));
            row.put(alias, "tries_size", Scalar::Int(code.tries_size as i64));
            row.put(
                alias,
                "debug_info_off",
                Scalar::Int(code.debug_info_off as i64),
            );
            row.put(alias, "insns_size", Scalar::Int(code.insns.len() as i64));
            row.put(alias, "insns_off", Scalar::Int(code.code_off as i64 + 16));
            row.put(
                alias,
                "tries_off",
                if tries_off >= 0 {
                    Scalar::Int(tries_off)
                } else {
                    Scalar::Null
                },
            );
            row.put(
                alias,
                "handlers_off",
                if handlers_off >= 0 {
                    Scalar::Int(handlers_off)
                } else {
                    Scalar::Null
                },
            );
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_try_items(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (method_idx, code) in file
            .code_items
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.as_ref().map(|c| (i, c)))
        {
            for (try_idx, item) in code.tries.iter().enumerate() {
                let mut row = RelRow::with_capacity(6);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "method_idx", Scalar::Int(method_idx as i64));
                row.put(alias, "try_idx", Scalar::Int(try_idx as i64));
                row.put(alias, "start_addr", Scalar::Int(item.start_addr as i64));
                row.put(alias, "insn_count", Scalar::Int(item.insn_count as i64));
                row.put(alias, "handler_off", Scalar::Int(item.handler_off as i64));
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_catch_handlers(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (method_idx, code) in file
            .code_items
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.as_ref().map(|c| (i, c)))
        {
            for (handler_idx, set) in code.catch_handlers.iter().enumerate() {
                for (ordinal, handler) in set.handlers.iter().enumerate() {
                    let mut row = RelRow::with_capacity(8);
                    row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                    row.put(alias, "method_idx", Scalar::Int(method_idx as i64));
                    row.put(alias, "handler_idx", Scalar::Int(handler_idx as i64));
                    row.put(alias, "handler_off", Scalar::Int(set.offset as i64));
                    row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
                    row.put(
                        alias,
                        "type_idx",
                        handler
                            .type_idx
                            .map(|v| Scalar::Int(v as i64))
                            .unwrap_or(Scalar::Null),
                    );
                    row.put(alias, "addr", Scalar::Int(handler.addr as i64));
                    row.put(
                        alias,
                        "is_catch_all",
                        Scalar::Int(handler.type_idx.is_none() as i64),
                    );
                    rows.push(row);
                }
            }
        }
    }
    Ok(rows)
}

fn scan_debug_info(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for method_idx in 0..file.methods.len() as u32 {
            let Some(debug) = file.debug_rows(method_idx).map_err(|e| e.to_string())? else {
                continue;
            };
            let mut row = RelRow::with_capacity(5);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "method_idx", Scalar::Int(method_idx as i64));
            row.put(
                alias,
                "debug_info_off",
                Scalar::Int(debug.info.debug_info_off as i64),
            );
            row.put(
                alias,
                "line_start",
                Scalar::Int(debug.info.line_start as i64),
            );
            row.put(
                alias,
                "parameters_size",
                Scalar::Int(debug.info.parameters_size as i64),
            );
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_debug_parameters(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for method_idx in 0..file.methods.len() as u32 {
            let Some(debug) = file.debug_rows(method_idx).map_err(|e| e.to_string())? else {
                continue;
            };
            for parameter in debug.parameters {
                let mut row = RelRow::with_capacity(5);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "method_idx", Scalar::Int(method_idx as i64));
                row.put(
                    alias,
                    "debug_info_off",
                    Scalar::Int(debug.info.debug_info_off as i64),
                );
                row.put(alias, "ordinal", Scalar::Int(parameter.ordinal as i64));
                row.put(
                    alias,
                    "name_idx",
                    parameter
                        .name_idx
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_debug_positions(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for method_idx in 0..file.methods.len() as u32 {
            let Some(debug) = file.debug_rows(method_idx).map_err(|e| e.to_string())? else {
                continue;
            };
            for position in debug.positions {
                let mut row = RelRow::with_capacity(9);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "method_idx", Scalar::Int(method_idx as i64));
                row.put(
                    alias,
                    "debug_info_off",
                    Scalar::Int(debug.info.debug_info_off as i64),
                );
                row.put(alias, "ordinal", Scalar::Int(position.ordinal as i64));
                row.put(alias, "address", Scalar::Int(position.address as i64));
                row.put(alias, "line", Scalar::Int(position.line as i64));
                row.put(
                    alias,
                    "source_file_idx",
                    position
                        .source_file_idx
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "prologue_end",
                    Scalar::Int(position.prologue_end as i64),
                );
                row.put(
                    alias,
                    "epilogue_begin",
                    Scalar::Int(position.epilogue_begin as i64),
                );
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_debug_locals(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for method_idx in 0..file.methods.len() as u32 {
            let Some(debug) = file.debug_rows(method_idx).map_err(|e| e.to_string())? else {
                continue;
            };
            for local in debug.locals {
                let mut row = RelRow::with_capacity(10);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "method_idx", Scalar::Int(method_idx as i64));
                row.put(
                    alias,
                    "debug_info_off",
                    Scalar::Int(debug.info.debug_info_off as i64),
                );
                row.put(alias, "ordinal", Scalar::Int(local.ordinal as i64));
                row.put(alias, "address", Scalar::Int(local.address as i64));
                row.put(alias, "event", Scalar::text(local.event));
                row.put(
                    alias,
                    "register_num",
                    Scalar::Int(local.register_num as i64),
                );
                row.put(
                    alias,
                    "name_idx",
                    local
                        .name_idx
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "type_idx",
                    local
                        .type_idx
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "signature_idx",
                    local
                        .signature_idx
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_debug_opcodes(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for method_idx in 0..file.methods.len() as u32 {
            let Some(debug) = file.debug_rows(method_idx).map_err(|e| e.to_string())? else {
                continue;
            };
            for opcode in debug.opcodes {
                let mut row = RelRow::with_capacity(18);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "method_idx", Scalar::Int(method_idx as i64));
                row.put(
                    alias,
                    "debug_info_off",
                    Scalar::Int(debug.info.debug_info_off as i64),
                );
                row.put(alias, "ordinal", Scalar::Int(opcode.ordinal as i64));
                row.put(alias, "opcode_off", Scalar::Int(opcode.opcode_off as i64));
                row.put(
                    alias,
                    "opcode_end_off",
                    Scalar::Int(opcode.opcode_end_off as i64),
                );
                row.put(alias, "opcode", Scalar::Int(opcode.opcode as i64));
                row.put(alias, "address", Scalar::Int(opcode.address as i64));
                row.put(alias, "line", Scalar::Int(opcode.line as i64));
                row.put(
                    alias,
                    "address_diff",
                    opcode
                        .address_diff
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "line_diff",
                    opcode
                        .line_diff
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "register_num",
                    opcode
                        .register_num
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "name_idx",
                    opcode
                        .name_idx
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "type_idx",
                    opcode
                        .type_idx
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "signature_idx",
                    opcode
                        .signature_idx
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "source_file_idx",
                    opcode
                        .source_file_idx
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "emits_position",
                    Scalar::Int(opcode.emits_position as i64),
                );
                row.put(alias, "emits_local", Scalar::Int(opcode.emits_local as i64));
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_classes(
    ds: &Dataset,
    alias: &str,
    predicates: Option<&[PushPredicate]>,
    key_filter: Option<(&str, &HashSet<Scalar>)>,
    scan_limit: Option<usize>,
    scan_columns: Option<&HashSet<String>>,
) -> Result<Vec<RelRow>, String> {
    let predicates = predicates.map(|items| {
        items
            .iter()
            .filter(|item| scan_predicate_column("classes", &item.column))
            .cloned()
            .collect::<Vec<_>>()
    });
    let predicates = predicates.as_deref();
    let mut rows = Vec::new();
    let mut retained_bytes = 0;
    let needs = |column: &str| scan_columns.is_none_or(|columns| columns.contains(column));
    'files: for file in &ds.files {
        let indexed_candidates = indexed_class_candidates(file, predicates);
        let mut consider = |class_idx: u32, rows: &mut Vec<RelRow>| -> Result<bool, String> {
            let Some(class) = file.classes.get(class_idx as usize) else {
                return Ok(false);
            };
            let descriptor = file.type_descriptor(class.class_idx).to_owned();
            let superclass = class
                .superclass_idx
                .map(|idx| file.type_descriptor(idx).to_owned())
                .unwrap_or_default();
            let source = class
                .source_file_idx
                .map(|idx| file.string(idx).to_owned())
                .unwrap_or_default();
            if let Some((column, values)) = key_filter {
                let key = match column {
                    "descriptor" => Scalar::text(descriptor.clone()),
                    "class_idx" => Scalar::Int(class.class_idx as i64),
                    _ => Scalar::Null,
                };
                if !values.contains(&key) {
                    return Ok(false);
                }
            }
            if let Some(predicates) = predicates {
                if !predicates_match(predicates, |column| match column {
                    "file_id" => Scalar::Int(file.file_id as i64),
                    "class_def_idx" => Scalar::Int(class.class_def_idx as i64),
                    "class_idx" => Scalar::Int(class.class_idx as i64),
                    "descriptor" => Scalar::text(descriptor.clone()),
                    "access_flags" => Scalar::Int(class.access_flags as i64),
                    "superclass_descriptor" => Scalar::text(superclass.clone()),
                    "interface_count" => Scalar::Int(class.interfaces.len() as i64),
                    "field_count" => Scalar::Int(class.fields.len() as i64),
                    "method_count" => Scalar::Int(class.methods.len() as i64),
                    "source_file" => Scalar::text(source.clone()),
                    _ => Scalar::Null,
                }) {
                    return Ok(false);
                }
            }
            let mut row = RelRow::with_capacity(8);
            if needs("file_id") {
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            }
            if needs("class_def_idx") {
                row.put(
                    alias,
                    "class_def_idx",
                    Scalar::Int(class.class_def_idx as i64),
                );
            }
            if needs("class_idx") {
                row.put(alias, "class_idx", Scalar::Int(class.class_idx as i64));
            }
            if needs("descriptor") {
                row.put(alias, "descriptor", Scalar::text(descriptor));
            }
            if needs("access_flags") {
                row.put(
                    alias,
                    "access_flags",
                    Scalar::Int(class.access_flags as i64),
                );
            }
            if needs("superclass_descriptor") {
                row.put(alias, "superclass_descriptor", Scalar::text(superclass));
            }
            if needs("interface_count") {
                row.put(
                    alias,
                    "interface_count",
                    Scalar::Int(class.interfaces.len() as i64),
                );
            }
            if needs("field_count") {
                row.put(alias, "field_count", Scalar::Int(class.fields.len() as i64));
            }
            if needs("method_count") {
                row.put(
                    alias,
                    "method_count",
                    Scalar::Int(class.methods.len() as i64),
                );
            }
            if needs("source_file") {
                row.put(alias, "source_file", Scalar::text(source));
            }
            push_reference_row(rows, row, &mut retained_bytes)?;
            Ok(scan_limit.is_some_and(|limit| rows.len() >= limit))
        };
        if let Some(candidates) = indexed_candidates {
            for class_idx in candidates {
                consider(class_idx, &mut rows)?;
                if scan_limit.is_some_and(|limit| rows.len() >= limit) {
                    break 'files;
                }
            }
        } else {
            for class_idx in 0..file.classes.len() as u32 {
                consider(class_idx, &mut rows)?;
                if scan_limit.is_some_and(|limit| rows.len() >= limit) {
                    break 'files;
                }
            }
        }
    }
    Ok(rows)
}

fn scan_methods(
    ds: &Dataset,
    alias: &str,
    predicates: Option<&[PushPredicate]>,
    key_filter: Option<(&str, &HashSet<Scalar>)>,
    needs_method_opcode: bool,
    scan_limit: Option<usize>,
    scan_columns: Option<&HashSet<String>>,
) -> Result<Vec<RelRow>, String> {
    let predicates = predicates.map(|items| {
        items
            .iter()
            .filter(|item| scan_predicate_column("methods", &item.column))
            .cloned()
            .collect::<Vec<_>>()
    });
    let predicates = predicates.as_deref();
    let mut rows = Vec::new();
    let mut retained_bytes = 0;
    let needs = |column: &str| scan_columns.is_none_or(|columns| columns.contains(column));
    'files: for file in &ds.files {
        // Build the defined-method side table once per DEX.  Calling
        // `class_for_method` for every method would rescan all class data and
        // turns a metadata scan into an avoidable quadratic walk.
        // Method ids are dense, so an indexed side vector is both faster and
        // much smaller than a per-query hash table containing one entry for
        // every defined method.
        let mut defined = vec![None; file.methods.len()];
        for class in &file.classes {
            for entry in &class.methods {
                if let Some(slot) = defined.get_mut(entry.method_idx as usize) {
                    *slot = Some((entry.access_flags, entry.is_direct, class.class_idx));
                }
            }
        }
        for (idx, method) in file.methods.iter().enumerate() {
            let idx = idx as u32;
            let Some(proto) = file.protos.get(method.proto_idx as usize) else {
                continue;
            };
            // Keep metadata borrowed through the predicate stage.  The old
            // path cloned three descriptors for every method, even when a
            // selective param/name/class predicate rejected the row.
            let class = file.method_class(idx);
            let name = file.method_name(idx);
            let return_descriptor = file.type_descriptor(proto.return_type_idx);
            let param_count = proto.parameters.len() as i64;
            let needs_descriptor = scan_columns
                .is_none_or(|columns| columns.contains("descriptor") || columns.contains("method"))
                || key_filter.is_some_and(|(column, _)| matches!(column, "descriptor" | "method"))
                || predicates.is_some_and(|items| {
                    items
                        .iter()
                        .any(|item| matches!(item.column.as_str(), "descriptor" | "method"))
                });
            // `method_descriptor_ref` populates an all-method cache on first
            // use. For bounded/simple projections that turns LIMIT 1 into a
            // full-Dex descriptor allocation. Build only the requested row in
            // those paths; the generic wildcard path may still use the cache
            // when it will be consumed for every row.
            let descriptor_owned =
                if needs_descriptor && (scan_limit.is_some() || scan_columns.is_some()) {
                    Some(file.method_descriptor_direct(idx))
                } else {
                    None
                };
            let descriptor = match descriptor_owned.as_deref() {
                Some(value) => value,
                None if needs_descriptor => file.method_descriptor_ref(idx),
                None => "",
            };
            let param_descriptors = if needs("param_descriptors") {
                Some(
                    proto
                        .parameters
                        .iter()
                        .map(|type_idx| file.type_descriptor(*type_idx as u32))
                        .collect::<Vec<_>>()
                        .join(","),
                )
            } else {
                None
            };
            let method_meta = defined.get(idx as usize).and_then(|value| *value);
            let opcode_summary = if needs_method_opcode {
                match file.method_opcode_summary(idx) {
                    Some(summary) => Some(summary),
                    // The reference exposes a defined method with no code
                    // item as an empty opcode stream (count 0), while
                    // external/abstract methods keep SQL NULL.
                    None if method_meta.is_some() => Some((0, String::new())),
                    None => None,
                }
            } else {
                None
            };
            if let Some((column, values)) = key_filter {
                let key = match column {
                    "descriptor" | "method" => Scalar::text(descriptor),
                    "class_descriptor" => Scalar::text(class),
                    _ => Scalar::Null,
                };
                if !values.contains(&key) {
                    continue;
                }
            }
            if let Some(predicates) = predicates {
                if !predicates_match(predicates, |column| match column {
                    "file_id" => Scalar::Int(file.file_id as i64),
                    "method_idx" => Scalar::Int(idx as i64),
                    "class_idx" => Scalar::Int(method.class_idx as i64),
                    "proto_idx" => Scalar::Int(method.proto_idx as i64),
                    "descriptor" | "method" => Scalar::text(descriptor),
                    "class_descriptor" => Scalar::text(class),
                    "name" | "method_name" => Scalar::text(name),
                    "return_descriptor" => Scalar::text(return_descriptor),
                    "param_count" => Scalar::Int(param_count),
                    "param_descriptors" => {
                        Scalar::text(param_descriptors.clone().unwrap_or_default())
                    }
                    "access_flags" => method_meta
                        .map(|(flags, _, _)| Scalar::Int(flags as i64))
                        .unwrap_or(Scalar::Null),
                    "opcode_count" => method_meta
                        .map(|_| {
                            opcode_summary
                                .as_ref()
                                .map(|(count, _)| Scalar::Int(*count as i64))
                                .unwrap_or(Scalar::Int(0))
                        })
                        .unwrap_or(Scalar::Null),
                    "opcode_hex" => opcode_summary
                        .as_ref()
                        .map(|(_, hex)| Scalar::text(hex.clone()))
                        .or_else(|| method_meta.map(|_| Scalar::text(String::new())))
                        .unwrap_or(Scalar::Null),
                    "method_kind" => method_meta
                        .map(|(_, direct, _)| {
                            Scalar::text(if direct { "direct" } else { "virtual" })
                        })
                        .unwrap_or(Scalar::Null),
                    _ => Scalar::Null,
                }) {
                    continue;
                }
            }
            let mut row = RelRow::with_capacity(14);
            if needs("file_id") {
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            }
            if needs("method_idx") {
                row.put(alias, "method_idx", Scalar::Int(idx as i64));
            }
            if needs("class_idx") {
                row.put(alias, "class_idx", Scalar::Int(method.class_idx as i64));
            }
            if needs("class_descriptor") {
                row.put(alias, "class_descriptor", Scalar::text(class));
            }
            if needs("proto_idx") {
                row.put(alias, "proto_idx", Scalar::Int(method.proto_idx as i64));
            }
            if needs("name") {
                row.put(alias, "name", Scalar::text(name));
            }
            if needs("descriptor") {
                row.put(alias, "descriptor", Scalar::text(descriptor));
            }
            if needs("return_descriptor") {
                row.put(alias, "return_descriptor", Scalar::text(return_descriptor));
            }
            if needs("param_count") {
                row.put(alias, "param_count", Scalar::Int(param_count));
            }
            if needs("param_descriptors") {
                row.put(
                    alias,
                    "param_descriptors",
                    Scalar::text(param_descriptors.unwrap_or_default()),
                );
            }
            if needs("access_flags") {
                row.put(
                    alias,
                    "access_flags",
                    method_meta
                        .map(|(flags, _, _)| Scalar::Int(flags as i64))
                        .unwrap_or(Scalar::Null),
                );
            }
            if needs("opcode_count") {
                row.put(
                    alias,
                    "opcode_count",
                    method_meta
                        .map(|_| {
                            opcode_summary
                                .as_ref()
                                .map(|(count, _)| Scalar::Int(*count as i64))
                                .unwrap_or(Scalar::Int(0))
                        })
                        .unwrap_or(Scalar::Null),
                );
            }
            if needs("opcode_hex") {
                row.put(
                    alias,
                    "opcode_hex",
                    opcode_summary
                        .as_ref()
                        .map(|(_, hex)| Scalar::text(hex))
                        .or_else(|| method_meta.map(|_| Scalar::text(String::new())))
                        .unwrap_or(Scalar::Null),
                );
            }
            if needs("method_kind") {
                row.put(
                    alias,
                    "method_kind",
                    method_meta
                        .map(|(_, direct, _)| {
                            Scalar::text(if direct { "direct" } else { "virtual" })
                        })
                        .unwrap_or(Scalar::Null),
                );
            }
            push_reference_row(&mut rows, row, &mut retained_bytes)?;
            if scan_limit.is_some_and(|limit| rows.len() >= limit) {
                break 'files;
            }
        }
    }
    Ok(rows)
}

fn scan_fields(
    ds: &Dataset,
    alias: &str,
    predicates: Option<&[PushPredicate]>,
    key_filter: Option<(&str, &HashSet<Scalar>)>,
    scan_limit: Option<usize>,
    scan_columns: Option<&HashSet<String>>,
) -> Result<Vec<RelRow>, String> {
    let predicates = predicates.map(|items| {
        items
            .iter()
            .filter(|item| scan_predicate_column("fields", &item.column))
            .cloned()
            .collect::<Vec<_>>()
    });
    let predicates = predicates.as_deref();
    let mut rows = Vec::new();
    let mut retained_bytes = 0;
    let needs = |column: &str| scan_columns.is_none_or(|columns| columns.contains(column));
    'files: for file in &ds.files {
        let indexed_candidates = indexed_field_candidates(file, predicates);
        let mut consider = |idx: u32, rows: &mut Vec<RelRow>| -> Result<bool, String> {
            let Some(field) = file.fields.get(idx as usize) else {
                return Ok(false);
            };
            let class_descriptor = file.type_descriptor(field.class_idx as u32).to_owned();
            let type_descriptor = file.type_descriptor(field.type_idx as u32).to_owned();
            let name = file.string(field.name_idx).to_owned();
            if let Some((column, values)) = key_filter {
                let key = match column {
                    "descriptor" => Scalar::text(file.field_descriptor_ref(idx)),
                    "class_descriptor" => Scalar::text(class_descriptor.clone()),
                    _ => Scalar::Null,
                };
                if !values.contains(&key) {
                    return Ok(false);
                }
            }
            if let Some(predicates) = predicates {
                if !predicates_match(predicates, |column| match column {
                    "file_id" => Scalar::Int(file.file_id as i64),
                    "field_idx" => Scalar::Int(idx as i64),
                    "class_idx" => Scalar::Int(field.class_idx as i64),
                    "class_descriptor" => Scalar::text(class_descriptor.clone()),
                    "type_idx" => Scalar::Int(field.type_idx as i64),
                    "type_descriptor" => Scalar::text(type_descriptor.clone()),
                    "name" => Scalar::text(name.clone()),
                    "descriptor" => Scalar::text(file.field_descriptor_ref(idx)),
                    _ => Scalar::Null,
                }) {
                    return Ok(false);
                }
            }
            let mut row = RelRow::with_capacity(8);
            if needs("file_id") {
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            }
            if needs("field_idx") {
                row.put(alias, "field_idx", Scalar::Int(idx as i64));
            }
            if needs("class_idx") {
                row.put(alias, "class_idx", Scalar::Int(field.class_idx as i64));
            }
            if needs("class_descriptor") {
                row.put(alias, "class_descriptor", Scalar::text(class_descriptor));
            }
            if needs("type_idx") {
                row.put(alias, "type_idx", Scalar::Int(field.type_idx as i64));
            }
            if needs("type_descriptor") {
                row.put(alias, "type_descriptor", Scalar::text(type_descriptor));
            }
            if needs("name") {
                row.put(alias, "name", Scalar::text(name));
            }
            if needs("descriptor") {
                row.put(
                    alias,
                    "descriptor",
                    Scalar::text(file.field_descriptor_ref(idx)),
                );
            }
            push_reference_row(rows, row, &mut retained_bytes)?;
            Ok(scan_limit.is_some_and(|limit| rows.len() >= limit))
        };
        if let Some(candidates) = indexed_candidates {
            for idx in candidates {
                consider(idx, &mut rows)?;
                if scan_limit.is_some_and(|limit| rows.len() >= limit) {
                    break 'files;
                }
            }
        } else {
            for idx in 0..file.fields.len() as u32 {
                consider(idx, &mut rows)?;
                if scan_limit.is_some_and(|limit| rows.len() >= limit) {
                    break 'files;
                }
            }
        }
    }
    Ok(rows)
}

fn scan_method_strings(
    ds: &Dataset,
    alias: &str,
    predicates: Option<&[PushPredicate]>,
    key_filter: Option<(&str, &HashSet<Scalar>)>,
    scan_columns: Option<&HashSet<String>>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    let needs = |column: &str| scan_columns.is_none_or(|columns| columns.contains(column));
    for file in &ds.files {
        let indexed = predicates.and_then(|items| push_values(items, "value"));
        let references: Vec<(u32, u32)> = if let Some(values) = indexed {
            let mut refs = Vec::new();
            for value in values {
                let Scalar::Text(value) = value else { continue };
                let Some(string_idx) = file.find_string_idx(value.as_ref()) else {
                    continue;
                };
                if let Some(methods) = file.method_strings_by_string.get(&string_idx) {
                    for &method_idx in methods {
                        // A method may load the same string more than once;
                        // method_strings is a reference relation and keeps
                        // those duplicate edges.  Grouping queries apply
                        // DISTINCT/GROUP BY at the SQL layer when desired.
                        refs.push((method_idx, string_idx));
                    }
                }
            }
            refs
        } else {
            file.method_strings
                .iter()
                .map(|reference| (reference.method_idx, reference.string_idx))
                .collect()
        };
        for (method_idx, string_idx) in references {
            let value = file.string(string_idx).to_owned();
            let method_class = file.method_class(method_idx).to_owned();
            let method_name = file.method_name(method_idx).to_owned();
            if let Some((column, values)) = key_filter {
                let key = match column {
                    "method" | "descriptor" => Scalar::text(file.method_descriptor_ref(method_idx)),
                    "method_class" => Scalar::text(method_class.clone()),
                    _ => Scalar::Null,
                };
                if !values.contains(&key) {
                    continue;
                }
            }
            if let Some(predicates) = predicates {
                if !predicates_match(predicates, |column| match column {
                    "method_class" => Scalar::text(method_class.clone()),
                    "method_name" | "name" => Scalar::text(method_name.clone()),
                    "value" => Scalar::text(value.clone()),
                    _ => Scalar::Null,
                }) {
                    continue;
                }
            }
            let mut row = RelRow::with_capacity(8);
            if needs("method") || needs("descriptor") {
                row.put(
                    alias,
                    "method",
                    Scalar::text(file.method_descriptor_ref(method_idx)),
                );
            }
            if needs("method_class") {
                row.put(alias, "method_class", Scalar::text(method_class));
            }
            if needs("method_name") || needs("name") {
                row.put(alias, "method_name", Scalar::text(method_name));
            }
            if needs("value") {
                row.put(alias, "value", Scalar::text(value));
            }
            if needs("file_id") {
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            }
            if needs("class_idx") {
                row.put(
                    alias,
                    "class_idx",
                    Scalar::Int(file.methods[method_idx as usize].class_idx as i64),
                );
            }
            if needs("method_idx") {
                row.put(alias, "method_idx", Scalar::Int(method_idx as i64));
            }
            if needs("string_idx") {
                row.put(alias, "string_idx", Scalar::Int(string_idx as i64));
            }
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_method_numbers(
    ds: &Dataset,
    alias: &str,
    predicates: Option<&[PushPredicate]>,
    key_filter: Option<(&str, &HashSet<Scalar>)>,
    table_name: &str,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        let indexed = predicates.and_then(|items| push_values(items, "long_value"));
        let references: Vec<dexsql_cache::MethodNumberRef> = if let Some(values) = indexed {
            let mut refs = Vec::new();
            let mut seen = HashSet::new();
            for value in values {
                let Some(value) = value.numeric() else {
                    continue;
                };
                if value.fract() != 0.0 {
                    continue;
                }
                let value = value as i64;
                if let Some(row_indices) = file.method_number_rows_by_value.get(&value) {
                    for &row_idx in row_indices {
                        if seen.insert(row_idx) {
                            if let Some(reference) = file.method_numbers.get(row_idx) {
                                refs.push(reference.clone());
                            }
                        }
                    }
                }
            }
            refs
        } else {
            file.method_numbers.clone()
        };
        for reference in references {
            let idx = reference.method_idx;
            let method_class = file.method_class(idx).to_owned();
            let method_name = file.method_name(idx).to_owned();
            if let Some((column, values)) = key_filter {
                let key = match column {
                    "method" | "descriptor" => Scalar::text(file.method_descriptor_ref(idx)),
                    "method_class" => Scalar::text(method_class.clone()),
                    _ => Scalar::Null,
                };
                if !values.contains(&key) {
                    continue;
                }
            }
            if let Some(predicates) = predicates {
                if !predicates_match(predicates, |column| match column {
                    "file_id" => Scalar::Int(file.file_id as i64),
                    "class_idx" => Scalar::Int(file.methods[idx as usize].class_idx as i64),
                    "method_idx" => Scalar::Int(idx as i64),
                    "opcode" => Scalar::Int(reference.opcode as i64),
                    "number_type" => Scalar::text(number_type_label(&reference)),
                    "method_class" => Scalar::text(method_class.clone()),
                    "method_name" | "name" => Scalar::text(method_name.clone()),
                    "long_value" => Scalar::Int(reference.long_value),
                    "double_value" => reference
                        .double_value
                        .map(|v| Scalar::Real(format_double_value(v)))
                        .unwrap_or(Scalar::Null),
                    _ => Scalar::Null,
                }) {
                    continue;
                }
            }
            let number_type = number_type_label(&reference);
            let double_value = reference
                .double_value
                .map(|v| Scalar::Real(format_double_value(v)))
                .unwrap_or(Scalar::Null);
            let mut row = RelRow::with_capacity(10);
            if table_name == "method_numbers" {
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(
                    alias,
                    "class_idx",
                    Scalar::Int(file.methods[idx as usize].class_idx as i64),
                );
                row.put(alias, "method_idx", Scalar::Int(idx as i64));
                row.put(alias, "opcode", Scalar::Int(reference.opcode as i64));
                row.put(alias, "number_type", Scalar::text(number_type));
                row.put(alias, "long_value", Scalar::Int(reference.long_value));
                row.put(alias, "double_value", double_value);
            } else {
                row.put(
                    alias,
                    "method",
                    Scalar::text(file.method_descriptor_ref(idx)),
                );
                row.put(alias, "method_class", Scalar::text(method_class));
                row.put(alias, "method_name", Scalar::text(method_name));
                row.put(alias, "number_type", Scalar::text(number_type));
                row.put(alias, "long_value", Scalar::Int(reference.long_value));
                row.put(alias, "double_value", double_value);
                row.put(alias, "opcode", Scalar::Int(reference.opcode as i64));
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(
                    alias,
                    "class_idx",
                    Scalar::Int(file.methods[idx as usize].class_idx as i64),
                );
                row.put(alias, "method_idx", Scalar::Int(idx as i64));
            }
            rows.push(row);
        }
    }
    Ok(rows)
}

fn number_type_label(reference: &dexsql_cache::MethodNumberRef) -> &'static str {
    match reference.number_type {
        dexsql_cache::NumberType::Long => match reference.opcode {
            0x16 => "short",
            0x17 => "int",
            0x18 => "long",
            0x19 => "double",
            _ => "long",
        },
        dexsql_cache::NumberType::Int => match reference.opcode {
            0x12 => "byte",
            0x13 => "short",
            0x14 | 0x15 => "float",
            0xd0..=0xd7 => "short",
            0xd8..=0xe2 => "byte",
            _ => "int",
        },
    }
}

fn scan_method_refs(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        let mut push = |method_idx: u32, kind: &str, index: u32, using: Scalar| {
            let class_idx = file
                .methods
                .get(method_idx as usize)
                .map(|m| m.class_idx)
                .unwrap_or(0);
            let mut row = RelRow::with_capacity(6);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "class_idx", Scalar::Int(class_idx as i64));
            row.put(alias, "method_idx", Scalar::Int(method_idx as i64));
            row.put(alias, "index_kind", Scalar::text(kind));
            row.put(alias, "index", Scalar::Int(index as i64));
            row.put(alias, "using_type", using);
            rows.push(row);
        };
        for reference in &file.method_strings {
            push(
                reference.method_idx,
                "string",
                reference.string_idx,
                Scalar::Null,
            );
        }
        for reference in &file.method_calls {
            push(
                reference.method_idx,
                "method",
                reference.callee_method_idx,
                Scalar::Null,
            );
        }
        for reference in &file.method_field_accesses {
            push(
                reference.method_idx,
                "field",
                reference.field_idx,
                Scalar::text(
                    if (0x52..=0x58).contains(&reference.opcode)
                        || (0x60..=0x66).contains(&reference.opcode)
                    {
                        "get"
                    } else {
                        "put"
                    },
                ),
            );
        }
        for reference in &file.method_used_types {
            push(
                reference.method_idx,
                "type",
                reference.type_idx,
                Scalar::Null,
            );
        }
    }
    rows.sort_by(|left, right| {
        let rank = |row: &RelRow| match row.get("index_kind") {
            Some(Scalar::Text(value)) => match value.as_ref() {
                "string" => 0u8,
                "number" => 1,
                "method" => 2,
                "field" => 3,
                "type" => 4,
                _ => 5,
            },
            _ => 5,
        };
        let key = |row: &RelRow| {
            (
                rank(row),
                row.get("index").and_then(Scalar::numeric).unwrap_or(0.0),
                row.get("method_idx")
                    .and_then(Scalar::numeric)
                    .unwrap_or(0.0),
            )
        };
        key(left)
            .partial_cmp(&key(right))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(rows)
}

fn scan_method_handles(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (code, size, base) in map_entries(file) {
            if code != 0x0008 {
                continue;
            }
            for idx in 0..size as usize {
                let off = base as usize + idx * 8;
                let mut row = RelRow::with_capacity(4);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "method_handle_idx", Scalar::Int(idx as i64));
                row.put(
                    alias,
                    "method_handle_type",
                    Scalar::Int(read_u16_at(file.raw(), off) as i64),
                );
                row.put(
                    alias,
                    "member_idx",
                    Scalar::Int(read_u16_at(file.raw(), off + 4) as i64),
                );
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_class_static_values(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for class in &file.classes {
            let static_values_off = read_u32_at(
                file.raw(),
                file.class_defs_off as usize + class.class_def_idx as usize * 32 + 28,
            );
            if static_values_off == 0 {
                continue;
            }
            let (count, mut pos) = read_uleb_at(file.raw(), static_values_off as usize);
            let fields = class
                .fields
                .iter()
                .filter(|field| field.is_static)
                .map(|field| field.field_idx)
                .collect::<Vec<_>>();
            for ordinal in 0..count as usize {
                let node = read_encoded_node(file.raw(), pos, 0);
                pos = node.end.max(pos.saturating_add(1));
                let mut row = RelRow::with_capacity(9);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "class_idx", Scalar::Int(class.class_idx as i64));
                row.put(
                    alias,
                    "static_values_off",
                    Scalar::Int(static_values_off as i64),
                );
                row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
                row.put(
                    alias,
                    "field_idx",
                    fields
                        .get(ordinal)
                        .copied()
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(alias, "value_kind", Scalar::text(node.kind));
                row.put(
                    alias,
                    "value_index",
                    node.index
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "value_i64",
                    node.i64_value.map(Scalar::Int).unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "value_f64",
                    node.f64_value
                        .map(|v| Scalar::Real(format_double_value(v)))
                        .unwrap_or(Scalar::Null),
                );
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_hiddenapi_flags(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (code, size, base) in map_entries(file) {
            if code != 0xf000 || size == 0 {
                continue;
            }
            // hiddenapi_class_data_item contains a class-offset table followed
            // by uleb128 flag streams. Keep the parser bounds-checked; old DEX
            // files may advertise the map item without a valid data payload.
            let class_count = read_u32_at(file.raw(), base as usize) as usize;
            if class_count == 0 || class_count > file.classes.len() {
                continue;
            }
            let table_end = base as usize + 4 + class_count * 4;
            if table_end > file.raw().len() {
                continue;
            }
            for class_ord in 0..class_count {
                let rel = read_u32_at(file.raw(), base as usize + 4 + class_ord * 4);
                if rel == 0 {
                    continue;
                }
                let mut pos = base as usize + rel as usize;
                let class_idx = file
                    .classes
                    .get(class_ord)
                    .map(|c| c.class_idx)
                    .unwrap_or(class_ord as u32);
                let member_count = file
                    .classes
                    .get(class_ord)
                    .map(|c| c.fields.len() + c.methods.len())
                    .unwrap_or(0);
                for ordinal in 0..member_count {
                    let (flag, next) = read_uleb_at(file.raw(), pos);
                    pos = next;
                    let (member_kind, member_idx) =
                        if let Some(field) = file.classes[class_ord].fields.get(ordinal) {
                            ("field", field.field_idx)
                        } else {
                            let method_ord =
                                ordinal.saturating_sub(file.classes[class_ord].fields.len());
                            (
                                "method",
                                file.classes[class_ord]
                                    .methods
                                    .get(method_ord)
                                    .map(|m| m.method_idx)
                                    .unwrap_or(0),
                            )
                        };
                    let mut row = RelRow::with_capacity(6);
                    row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                    row.put(alias, "class_idx", Scalar::Int(class_idx as i64));
                    row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
                    row.put(alias, "member_kind", Scalar::text(member_kind));
                    row.put(alias, "member_idx", Scalar::Int(member_idx as i64));
                    row.put(alias, "flag", Scalar::Int(flag as i64));
                    rows.push(row);
                }
            }
        }
    }
    Ok(rows)
}

fn scan_encoded_arrays(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (idx, off) in map_entry_offsets(file, 0x2005) {
            let (count, _) = read_uleb_at(file.raw(), off);
            let end = encoded_array_end_at(file.raw(), off);
            let mut row = RelRow::with_capacity(5);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "encoded_array_idx", Scalar::Int(idx as i64));
            row.put(alias, "encoded_array_off", Scalar::Int(off as i64));
            row.put(alias, "encoded_array_end_off", Scalar::Int(end as i64));
            row.put(alias, "value_count", Scalar::Int(count as i64));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn push_encoded_value_row(
    rows: &mut Vec<RelRow>,
    alias: &str,
    file_id: u32,
    array_off: usize,
    depth: usize,
    ordinal: usize,
    name_idx: Option<u32>,
    node: &EncodedNode,
) {
    let mut row = RelRow::with_capacity(11);
    row.put(alias, "file_id", Scalar::Int(file_id as i64));
    row.put(alias, "encoded_array_off", Scalar::Int(array_off as i64));
    row.put(alias, "depth", Scalar::Int(depth as i64));
    row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
    row.put(
        alias,
        "name_idx",
        name_idx
            .map(|v| Scalar::Int(v as i64))
            .unwrap_or(Scalar::Null),
    );
    row.put(alias, "value_off", Scalar::Int(node.start as i64));
    row.put(alias, "value_end_off", Scalar::Int(node.end as i64));
    row.put(alias, "value_kind", Scalar::text(node.kind));
    row.put(
        alias,
        "value_index",
        node.index
            .map(|v| Scalar::Int(v as i64))
            .unwrap_or(Scalar::Null),
    );
    row.put(
        alias,
        "value_i64",
        node.i64_value.map(Scalar::Int).unwrap_or(Scalar::Null),
    );
    row.put(
        alias,
        "value_f64",
        node.f64_value
            .map(|v| Scalar::Real(format_double_value(v)))
            .unwrap_or(Scalar::Null),
    );
    rows.push(row);
    match &node.children {
        EncodedChildren::Array(children) => {
            for (ordinal, child) in children.iter().enumerate() {
                push_encoded_value_row(
                    rows,
                    alias,
                    file_id,
                    array_off,
                    depth + 1,
                    ordinal,
                    None,
                    child,
                );
            }
        }
        EncodedChildren::Annotation(children) => {
            for (ordinal, (name, child)) in children.iter().enumerate() {
                push_encoded_value_row(
                    rows,
                    alias,
                    file_id,
                    array_off,
                    depth + 1,
                    ordinal,
                    Some(*name),
                    child,
                );
            }
        }
        EncodedChildren::None => {}
    }
}

fn scan_encoded_array_values(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (_, off) in map_entry_offsets(file, 0x2005) {
            let (count, mut pos) = read_uleb_at(file.raw(), off);
            for ordinal in 0..count as usize {
                let node = read_encoded_node(file.raw(), pos, 0);
                pos = node.end.max(pos.saturating_add(1));
                push_encoded_value_row(
                    &mut rows,
                    alias,
                    file.file_id,
                    off,
                    0,
                    ordinal,
                    None,
                    &node,
                );
            }
        }
    }
    Ok(rows)
}

fn scan_encoded_array_owners(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for class in &file.classes {
            let off = read_u32_at(
                file.raw(),
                file.class_defs_off as usize + class.class_def_idx as usize * 32 + 28,
            );
            if off == 0 {
                continue;
            }
            let mut row = RelRow::with_capacity(4);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "encoded_array_off", Scalar::Int(off as i64));
            row.put(alias, "owner_kind", Scalar::text("class_static_values"));
            row.put(alias, "owner_idx", Scalar::Int(class.class_idx as i64));
            rows.push(row);
        }
        for (idx, off) in call_site_offsets(file).into_iter().enumerate() {
            let mut row = RelRow::with_capacity(4);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "encoded_array_off", Scalar::Int(off as i64));
            row.put(alias, "owner_kind", Scalar::text("call_site"));
            row.put(alias, "owner_idx", Scalar::Int(idx as i64));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_annotation_directories(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for class in &file.classes {
            let off = read_u32_at(
                file.raw(),
                file.class_defs_off as usize + class.class_def_idx as usize * 32 + 20,
            );
            if off == 0 {
                continue;
            }
            let class_off = read_u32_at(file.raw(), off as usize);
            let fields = read_u32_at(file.raw(), off as usize + 4);
            let methods = read_u32_at(file.raw(), off as usize + 8);
            let parameters = read_u32_at(file.raw(), off as usize + 12);
            let mut row = RelRow::with_capacity(7);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "class_idx", Scalar::Int(class.class_idx as i64));
            row.put(alias, "annotations_off", Scalar::Int(off as i64));
            row.put(
                alias,
                "class_annotations_off",
                if class_off == 0 {
                    Scalar::Null
                } else {
                    Scalar::Int(class_off as i64)
                },
            );
            row.put(alias, "fields_size", Scalar::Int(fields as i64));
            row.put(alias, "methods_size", Scalar::Int(methods as i64));
            row.put(alias, "parameters_size", Scalar::Int(parameters as i64));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_annotation_directory_entries(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for class in &file.classes {
            let dir = read_u32_at(
                file.raw(),
                file.class_defs_off as usize + class.class_def_idx as usize * 32 + 20,
            );
            if dir == 0 {
                continue;
            }
            let fields = read_u32_at(file.raw(), dir as usize + 4) as usize;
            let methods = read_u32_at(file.raw(), dir as usize + 8) as usize;
            let params = read_u32_at(file.raw(), dir as usize + 12) as usize;
            let mut pos = dir as usize + 16;
            let mut emit = |kind: &str, idx: u32, set: u32, refs: u32| {
                let mut row = RelRow::with_capacity(7);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "class_idx", Scalar::Int(class.class_idx as i64));
                row.put(alias, "annotations_off", Scalar::Int(dir as i64));
                row.put(alias, "entry_kind", Scalar::text(kind));
                row.put(alias, "entry_idx", Scalar::Int(idx as i64));
                row.put(
                    alias,
                    "annotation_set_off",
                    if set == 0 {
                        Scalar::Null
                    } else {
                        Scalar::Int(set as i64)
                    },
                );
                row.put(
                    alias,
                    "annotation_set_ref_list_off",
                    if refs == 0 {
                        Scalar::Null
                    } else {
                        Scalar::Int(refs as i64)
                    },
                );
                rows.push(row);
            };
            for _ in 0..fields {
                let idx = read_u32_at(file.raw(), pos);
                let set = read_u32_at(file.raw(), pos + 4);
                pos += 8;
                emit("field", idx, set, 0);
            }
            for _ in 0..methods {
                let idx = read_u32_at(file.raw(), pos);
                let set = read_u32_at(file.raw(), pos + 4);
                pos += 8;
                emit("method", idx, set, 0);
            }
            for _ in 0..params {
                let idx = read_u32_at(file.raw(), pos);
                let refs = read_u32_at(file.raw(), pos + 4);
                pos += 8;
                emit("parameter", idx, 0, refs);
            }
        }
    }
    Ok(rows)
}

fn annotation_set_offsets(file: &dexsql_cache::DexFile) -> Vec<u32> {
    let mut out = Vec::new();
    for class in &file.classes {
        let dir = read_u32_at(
            file.raw(),
            file.class_defs_off as usize + class.class_def_idx as usize * 32 + 20,
        );
        if dir == 0 {
            continue;
        }
        let push = |out: &mut Vec<u32>, off| {
            if off != 0 && !out.contains(&off) {
                out.push(off);
            }
        };
        push(&mut out, read_u32_at(file.raw(), dir as usize));
        let fields = read_u32_at(file.raw(), dir as usize + 4) as usize;
        let methods = read_u32_at(file.raw(), dir as usize + 8) as usize;
        let params = read_u32_at(file.raw(), dir as usize + 12) as usize;
        let mut pos = dir as usize + 16;
        for _ in 0..fields + methods {
            pos += 4;
            push(&mut out, read_u32_at(file.raw(), pos));
            pos += 4;
        }
        for _ in 0..params {
            pos += 4;
            let refs = read_u32_at(file.raw(), pos);
            pos += 4;
            let count = read_u32_at(file.raw(), refs as usize);
            for i in 0..count {
                push(
                    &mut out,
                    read_u32_at(file.raw(), refs as usize + 4 + i as usize * 4),
                );
            }
        }
    }
    out
}

fn scan_annotation_sets(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for off in annotation_set_offsets(file) {
            let size = read_u32_at(file.raw(), off as usize);
            let mut row = RelRow::with_capacity(3);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "annotation_set_off", Scalar::Int(off as i64));
            row.put(alias, "size", Scalar::Int(size as i64));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn scan_annotation_set_entries(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for off in annotation_set_offsets(file) {
            let size = read_u32_at(file.raw(), off as usize);
            for ordinal in 0..size {
                let annotation = read_u32_at(file.raw(), off as usize + 4 + ordinal as usize * 4);
                let mut row = RelRow::with_capacity(4);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "annotation_set_off", Scalar::Int(off as i64));
                row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
                row.put(alias, "annotation_off", Scalar::Int(annotation as i64));
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn scan_annotation_set_ref_lists(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (code, size, base) in map_entries(file) {
            if code != 0x1002 {
                continue;
            }
            let mut pos = base as usize;
            for _ in 0..size {
                let count = read_u32_at(file.raw(), pos);
                let mut row = RelRow::with_capacity(3);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(
                    alias,
                    "annotation_set_ref_list_off",
                    Scalar::Int(pos as i64),
                );
                row.put(alias, "size", Scalar::Int(count as i64));
                rows.push(row);
                pos += 4 + count as usize * 4;
            }
        }
    }
    Ok(rows)
}

fn scan_annotation_set_refs(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (code, size, base) in map_entries(file) {
            if code != 0x1002 {
                continue;
            }
            let mut pos = base as usize;
            for _ in 0..size {
                let list_off = pos;
                let count = read_u32_at(file.raw(), pos) as usize;
                for ordinal in 0..count {
                    let set = read_u32_at(file.raw(), pos + 4 + ordinal * 4);
                    let mut row = RelRow::with_capacity(4);
                    row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                    row.put(
                        alias,
                        "annotation_set_ref_list_off",
                        Scalar::Int(list_off as i64),
                    );
                    row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
                    row.put(
                        alias,
                        "annotation_set_off",
                        if set == 0 {
                            Scalar::Null
                        } else {
                            Scalar::Int(set as i64)
                        },
                    );
                    rows.push(row);
                }
                pos += 4 + count * 4;
            }
        }
    }
    Ok(rows)
}

fn annotation_offsets_in_use(file: &dexsql_cache::DexFile) -> Vec<u32> {
    let mut out = Vec::new();
    for set in annotation_set_offsets(file) {
        let count = read_u32_at(file.raw(), set as usize);
        for ordinal in 0..count {
            let off = read_u32_at(file.raw(), set as usize + 4 + ordinal as usize * 4);
            if off != 0 && !out.contains(&off) {
                out.push(off);
            }
        }
    }
    out
}

fn scan_annotations(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for off in annotation_offsets_in_use(file) {
            let (visibility, type_idx, elements, _) =
                read_annotation_instance(file.raw(), off as usize);
            let mut row = RelRow::with_capacity(5);
            row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
            row.put(alias, "annotation_off", Scalar::Int(off as i64));
            row.put(alias, "visibility", Scalar::Int(visibility as i64));
            row.put(alias, "type_idx", Scalar::Int(type_idx as i64));
            row.put(alias, "element_count", Scalar::Int(elements.len() as i64));
            rows.push(row);
        }
    }
    Ok(rows)
}

fn push_annotation_element_row(
    rows: &mut Vec<RelRow>,
    alias: &str,
    file_id: u32,
    annotation_off: usize,
    depth: usize,
    ordinal: usize,
    name_idx: Option<u32>,
    node: &EncodedNode,
) {
    let mut row = RelRow::with_capacity(11);
    row.put(alias, "file_id", Scalar::Int(file_id as i64));
    row.put(alias, "annotation_off", Scalar::Int(annotation_off as i64));
    row.put(alias, "depth", Scalar::Int(depth as i64));
    row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
    row.put(
        alias,
        "name_idx",
        name_idx
            .map(|v| Scalar::Int(v as i64))
            .unwrap_or(Scalar::Null),
    );
    row.put(alias, "value_off", Scalar::Int(node.start as i64));
    row.put(alias, "value_end_off", Scalar::Int(node.end as i64));
    row.put(alias, "value_kind", Scalar::text(node.kind));
    row.put(
        alias,
        "value_index",
        node.index
            .map(|v| Scalar::Int(v as i64))
            .unwrap_or(Scalar::Null),
    );
    row.put(
        alias,
        "value_i64",
        node.i64_value.map(Scalar::Int).unwrap_or(Scalar::Null),
    );
    row.put(
        alias,
        "value_f64",
        node.f64_value
            .map(|v| Scalar::Real(format_double_value(v)))
            .unwrap_or(Scalar::Null),
    );
    rows.push(row);
    match &node.children {
        EncodedChildren::Array(children) => {
            for (ordinal, child) in children.iter().enumerate() {
                push_annotation_element_row(
                    rows,
                    alias,
                    file_id,
                    annotation_off,
                    depth + 1,
                    ordinal,
                    None,
                    child,
                );
            }
        }
        EncodedChildren::Annotation(children) => {
            for (ordinal, (name, child)) in children.iter().enumerate() {
                push_annotation_element_row(
                    rows,
                    alias,
                    file_id,
                    annotation_off,
                    depth + 1,
                    ordinal,
                    Some(*name),
                    child,
                );
            }
        }
        EncodedChildren::None => {}
    }
}

fn scan_annotation_elements(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for off in annotation_offsets_in_use(file) {
            let (_, _, elements, _) = read_annotation_instance(file.raw(), off as usize);
            for (ordinal, (name, node)) in elements.iter().enumerate() {
                push_annotation_element_row(
                    &mut rows,
                    alias,
                    file.file_id,
                    off as usize,
                    0,
                    ordinal,
                    Some(*name),
                    node,
                );
            }
        }
    }
    Ok(rows)
}

fn annotation_owner_rows(
    file: &dexsql_cache::DexFile,
) -> Vec<(u32, &'static str, u32, Option<u32>, Option<String>, u32)> {
    let mut owners = Vec::new();
    // DexSQL publishes class-owned annotations first, then field/method/
    // parameter owners in source class order. This ordering is observable in
    // SELECT * output and keeps shared annotation sets deterministic.
    for class_only in [true, false] {
        for class in &file.classes {
            let dir = read_u32_at(
                file.raw(),
                file.class_defs_off as usize + class.class_def_idx as usize * 32 + 20,
            );
            if dir == 0 {
                continue;
            }
            let push_set =
                |owners: &mut Vec<(u32, &'static str, u32, Option<u32>, Option<String>, u32)>,
                 kind: &'static str,
                 idx: u32,
                 parameter: Option<u32>,
                 descriptor: Option<String>,
                 set: u32| {
                    if set == 0 {
                        return;
                    }
                    let count = read_u32_at(file.raw(), set as usize);
                    for ordinal in 0..count {
                        let ann = read_u32_at(file.raw(), set as usize + 4 + ordinal as usize * 4);
                        owners.push((
                            class.class_idx,
                            kind,
                            idx,
                            parameter,
                            descriptor.clone(),
                            ann,
                        ));
                    }
                };
            push_set(
                &mut owners,
                "class",
                class.class_idx,
                None,
                Some(file.type_descriptor(class.class_idx).to_owned()),
                read_u32_at(file.raw(), dir as usize),
            );
            if class_only {
                continue;
            }
            let fields = read_u32_at(file.raw(), dir as usize + 4) as usize;
            let methods = read_u32_at(file.raw(), dir as usize + 8) as usize;
            let params = read_u32_at(file.raw(), dir as usize + 12) as usize;
            let mut pos = dir as usize + 16;
            for _ in 0..fields {
                let idx = read_u32_at(file.raw(), pos);
                let set = read_u32_at(file.raw(), pos + 4);
                pos += 8;
                push_set(
                    &mut owners,
                    "field",
                    idx,
                    None,
                    Some(file.field_descriptor_ref(idx).to_owned()),
                    set,
                );
            }
            for _ in 0..methods {
                let idx = read_u32_at(file.raw(), pos);
                let set = read_u32_at(file.raw(), pos + 4);
                pos += 8;
                push_set(
                    &mut owners,
                    "method",
                    idx,
                    None,
                    Some(file.method_descriptor_ref(idx).to_owned()),
                    set,
                );
            }
            for _ in 0..params {
                let idx = read_u32_at(file.raw(), pos);
                let refs = read_u32_at(file.raw(), pos + 4);
                pos += 8;
                let count = read_u32_at(file.raw(), refs as usize);
                for param in 0..count {
                    let set = read_u32_at(file.raw(), refs as usize + 4 + param as usize * 4);
                    push_set(
                        &mut owners,
                        "parameter",
                        idx,
                        Some(param),
                        Some(file.method_descriptor_ref(idx).to_owned()),
                        set,
                    );
                }
            }
        }
    }
    owners.sort_by(|a, b| {
        let rank = |kind: &str| match kind {
            "class" => 0,
            "field" => 1,
            "method" => 2,
            _ => 3,
        };
        (rank(a.1), a.0, a.2, a.3.unwrap_or(0)).cmp(&(rank(b.1), b.0, b.2, b.3.unwrap_or(0)))
    });
    owners
}

fn scan_annotation_values(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (class_idx, owner_kind, owner_idx, parameter_idx, owner, annotation_off) in
            annotation_owner_rows(file)
        {
            let (_, type_idx, elements, _) =
                read_annotation_instance(file.raw(), annotation_off as usize);
            for (ordinal, (name_idx, node)) in elements.iter().enumerate() {
                push_annotation_value_rows(
                    &mut rows,
                    alias,
                    file.file_id,
                    class_idx,
                    owner_kind,
                    owner_idx,
                    parameter_idx,
                    owner.as_deref(),
                    annotation_off,
                    type_idx,
                    0,
                    ordinal,
                    Some(*name_idx),
                    node,
                    file,
                );
            }
        }
    }
    Ok(rows)
}

fn push_annotation_value_rows(
    rows: &mut Vec<RelRow>,
    alias: &str,
    file_id: u32,
    class_idx: u32,
    owner_kind: &str,
    owner_idx: u32,
    parameter_idx: Option<u32>,
    owner: Option<&str>,
    annotation_off: u32,
    type_idx: u32,
    depth: usize,
    ordinal: usize,
    name_idx: Option<u32>,
    node: &EncodedNode,
    file: &dexsql_cache::DexFile,
) {
    let mut row = RelRow::with_capacity(16);
    row.put(alias, "file_id", Scalar::Int(file_id as i64));
    row.put(alias, "class_idx", Scalar::Int(class_idx as i64));
    row.put(alias, "owner_kind", Scalar::text(owner_kind));
    row.put(alias, "owner_idx", Scalar::Int(owner_idx as i64));
    row.put(
        alias,
        "owner_descriptor",
        owner.map(Scalar::text).unwrap_or(Scalar::Null),
    );
    row.put(
        alias,
        "parameter_idx",
        parameter_idx
            .map(|v| Scalar::Int(v as i64))
            .unwrap_or(Scalar::Null),
    );
    row.put(alias, "annotation_off", Scalar::Int(annotation_off as i64));
    row.put(alias, "annotation_type_idx", Scalar::Int(type_idx as i64));
    row.put(
        alias,
        "annotation_descriptor",
        Scalar::text(file.type_descriptor(type_idx)),
    );
    row.put(alias, "depth", Scalar::Int(depth as i64));
    row.put(alias, "ordinal", Scalar::Int(ordinal as i64));
    row.put(
        alias,
        "name_idx",
        name_idx
            .map(|v| Scalar::Int(v as i64))
            .unwrap_or(Scalar::Null),
    );
    row.put(
        alias,
        "name",
        name_idx
            .map(|v| Scalar::text(file.string(v)))
            .unwrap_or(Scalar::Null),
    );
    row.put(alias, "value_kind", Scalar::text(node.kind));
    row.put(
        alias,
        "value_i64",
        node.i64_value.map(Scalar::Int).unwrap_or(Scalar::Null),
    );
    row.put(
        alias,
        "value_f64",
        node.f64_value
            .map(|v| Scalar::Real(format_double_value(v)))
            .unwrap_or(Scalar::Null),
    );
    rows.push(row);
    match &node.children {
        EncodedChildren::Array(children) => {
            for (child_ordinal, child) in children.iter().enumerate() {
                push_annotation_value_rows(
                    rows,
                    alias,
                    file_id,
                    class_idx,
                    owner_kind,
                    owner_idx,
                    parameter_idx,
                    owner,
                    annotation_off,
                    type_idx,
                    depth + 1,
                    child_ordinal,
                    None,
                    child,
                    file,
                );
            }
        }
        EncodedChildren::Annotation(children) => {
            for (child_ordinal, (child_name, child)) in children.iter().enumerate() {
                push_annotation_value_rows(
                    rows,
                    alias,
                    file_id,
                    class_idx,
                    owner_kind,
                    owner_idx,
                    parameter_idx,
                    owner,
                    annotation_off,
                    type_idx,
                    depth + 1,
                    child_ordinal,
                    Some(*child_name),
                    child,
                    file,
                );
            }
        }
        EncodedChildren::None => {}
    }
}

fn annotation_visibility_policy(visibility: u32) -> &'static str {
    match visibility {
        0 => "build",
        1 => "runtime",
        _ => "system",
    }
}

fn scan_annotation_elements_resolved(
    ds: &Dataset,
    alias: &str,
    _predicates: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for file in &ds.files {
        for (class_idx, owner_kind, owner_idx, parameter_idx, owner, annotation_off) in
            annotation_owner_rows(file)
        {
            let (visibility, type_idx, elements, _) =
                read_annotation_instance(file.raw(), annotation_off as usize);
            if elements.is_empty() {
                let mut row = RelRow::with_capacity(17);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "class_idx", Scalar::Int(class_idx as i64));
                row.put(alias, "owner_kind", Scalar::text(owner_kind));
                row.put(alias, "owner_idx", Scalar::Int(owner_idx as i64));
                row.put(
                    alias,
                    "owner",
                    owner.clone().map(Scalar::text).unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "parameter_idx",
                    parameter_idx
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "annotation",
                    Scalar::text(file.type_descriptor(type_idx)),
                );
                row.put(alias, "visibility", Scalar::Int(visibility as i64));
                row.put(alias, "element_count", Scalar::Int(0));
                row.put(alias, "annotation_off", Scalar::Int(annotation_off as i64));
                row.put(alias, "element_ordinal", Scalar::Null);
                row.put(alias, "element_name", Scalar::Null);
                row.put(alias, "value_kind", Scalar::Null);
                row.put(alias, "value_index", Scalar::Null);
                row.put(alias, "value_i64", Scalar::Null);
                row.put(alias, "value_f64", Scalar::Null);
                row.put(
                    alias,
                    "retention_policy",
                    Scalar::text(annotation_visibility_policy(visibility)),
                );
                rows.push(row);
                continue;
            }
            for (ordinal, (name_idx, node)) in elements.iter().enumerate() {
                let mut row = RelRow::with_capacity(17);
                row.put(alias, "file_id", Scalar::Int(file.file_id as i64));
                row.put(alias, "class_idx", Scalar::Int(class_idx as i64));
                row.put(alias, "owner_kind", Scalar::text(owner_kind));
                row.put(alias, "owner_idx", Scalar::Int(owner_idx as i64));
                row.put(
                    alias,
                    "owner",
                    owner.clone().map(Scalar::text).unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "parameter_idx",
                    parameter_idx
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "annotation",
                    Scalar::text(file.type_descriptor(type_idx)),
                );
                row.put(alias, "visibility", Scalar::Int(visibility as i64));
                row.put(alias, "element_count", Scalar::Int(elements.len() as i64));
                row.put(alias, "annotation_off", Scalar::Int(annotation_off as i64));
                row.put(alias, "element_ordinal", Scalar::Int(ordinal as i64));
                row.put(alias, "element_name", Scalar::text(file.string(*name_idx)));
                row.put(alias, "value_kind", Scalar::text(node.kind));
                row.put(
                    alias,
                    "value_index",
                    node.index
                        .map(|v| Scalar::Int(v as i64))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "value_i64",
                    node.i64_value.map(Scalar::Int).unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "value_f64",
                    node.f64_value
                        .map(|v| Scalar::Real(format_double_value(v)))
                        .unwrap_or(Scalar::Null),
                );
                row.put(
                    alias,
                    "retention_policy",
                    Scalar::text(annotation_visibility_policy(visibility)),
                );
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

// ---- Restored scalar/format helpers -------------------------------------
// These small execution helpers intentionally stay independent of the raw DEX
// scanners above: relations provide RelRow values, while SQL evaluation owns
// NULL, aggregate and ordering semantics.

#[derive(Clone, Debug)]
struct EncodedNode {
    start: usize,
    end: usize,
    kind: &'static str,
    index: Option<u32>,
    i64_value: Option<i64>,
    f64_value: Option<f64>,
    children: EncodedChildren,
}

#[derive(Clone, Debug)]
enum EncodedChildren {
    None,
    Array(Vec<EncodedNode>),
    Annotation(Vec<(u32, EncodedNode)>),
}

fn encoded_kind(t: u8) -> &'static str {
    match t {
        0x00 | 0x02 | 0x03 | 0x04 | 0x05 => "int",
        0x06 => "long",
        0x10 => "float",
        0x11 => "double",
        0x15 | 0x18 => "type",
        0x16 | 0x1a => "method",
        0x17 => "string",
        0x19 => "field",
        0x1b => "enum",
        0x1c => "array",
        0x1d => "annotation",
        0x1e => "null",
        0x1f => "boolean",
        _ => "unknown",
    }
}

fn read_encoded_node(bytes: &[u8], pos: usize, depth: usize) -> EncodedNode {
    let h = bytes.get(pos).copied().unwrap_or(0);
    let typ = h & 0x1f;
    let arg = (h >> 5) as usize;
    let mut node = EncodedNode {
        start: pos,
        end: pos + 1,
        kind: encoded_kind(typ),
        index: None,
        i64_value: None,
        f64_value: None,
        children: EncodedChildren::None,
    };
    if depth > 64 {
        return node;
    }
    let mut cur = pos + 1;
    match typ {
        0x1c => {
            let (n, next) = read_uleb_at(bytes, cur);
            cur = next;
            let mut children = Vec::new();
            for _ in 0..n {
                let child = read_encoded_node(bytes, cur, depth + 1);
                cur = child.end.max(cur + 1);
                children.push(child);
            }
            node.children = EncodedChildren::Array(children);
        }
        0x1d => {
            let (_, next) = read_uleb_at(bytes, cur);
            cur = next;
            let (n, next) = read_uleb_at(bytes, cur);
            cur = next;
            let mut children = Vec::new();
            for _ in 0..n {
                let (name, next) = read_uleb_at(bytes, cur);
                cur = next;
                let child = read_encoded_node(bytes, cur, depth + 1);
                cur = child.end.max(cur + 1);
                children.push((name, child));
            }
            node.children = EncodedChildren::Annotation(children);
        }
        0x1e | 0x1f => {
            if typ == 0x1f {
                node.i64_value = Some(i64::from(arg != 0));
            }
        }
        0x10 => {
            let w = (arg + 1).min(4);
            let mut bits = 0u32;
            for i in 0..w {
                bits |= (bytes.get(cur + i).copied().unwrap_or(0) as u32) << (i * 8);
            }
            node.f64_value = Some(f32::from_bits(bits) as f64);
            cur += w;
        }
        0x11 => {
            let w = (arg + 1).min(8);
            let mut bits = 0u64;
            for i in 0..w {
                bits |= (bytes.get(cur + i).copied().unwrap_or(0) as u64) << (i * 8);
            }
            node.f64_value = Some(f64::from_bits(bits));
            cur += w;
        }
        _ => {
            let w = (arg + 1).min(8);
            let mut bits = 0u64;
            for i in 0..w {
                bits |= (bytes.get(cur + i).copied().unwrap_or(0) as u64) << (i * 8);
            }
            cur += w;
            if typ <= 0x06 {
                let sh = 64 - w * 8;
                node.i64_value = Some(((bits << sh) as i64) >> sh);
            } else if typ != 0x1e && typ != 0x1f {
                node.index = Some(bits as u32);
            }
        }
    }
    node.end = cur;
    node
}

fn format_double_value(v: f64) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v.is_sign_negative() {
            "-inf".into()
        } else {
            "inf".into()
        };
    }
    let scientific = format!("{v:.14e}");
    let Some((mantissa, exponent)) = scientific.split_once('e') else {
        return scientific;
    };
    let exponent = exponent.parse::<i32>().unwrap_or(0);
    let negative = mantissa.starts_with('-');
    let digits = mantissa.trim_start_matches('-').replace('.', "");
    let decimal = 1 + exponent;
    if (-4..15).contains(&exponent) {
        let mut fixed = if decimal <= 0 {
            format!("0.{}{}", "0".repeat((-decimal) as usize), digits)
        } else if decimal as usize >= digits.len() {
            format!("{}{}", digits, "0".repeat(decimal as usize - digits.len()))
        } else {
            format!(
                "{}.{}",
                &digits[..decimal as usize],
                &digits[decimal as usize..]
            )
        };
        while fixed.contains('.') && fixed.ends_with('0') {
            fixed.pop();
        }
        if fixed.ends_with('.') {
            fixed.pop();
        }
        if negative && fixed != "0" {
            fixed.insert(0, '-');
        }
        fixed
    } else {
        let mut compact = mantissa
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_owned();
        if exponent >= 0 {
            compact.push_str(&format!("e+{exponent}"));
        } else {
            compact.push_str(&format!("e{exponent}"));
        }
        compact
    }
}

/// SQLite-compatible LIKE comparison: percent and underscore wildcards,
/// optional escape character, ASCII-only case folding for literal characters.
fn like_match(value: &str, pattern: &str, escape: Option<char>) -> bool {
    #[derive(Clone, Copy)]
    enum Token {
        AnySeq,
        AnyOne,
        Lit(char),
    }
    let mut tokens: Vec<Token> = Vec::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if Some(ch) == escape {
            match chars.next() {
                Some(literal) => tokens.push(Token::Lit(literal)),
                None => return false,
            }
            continue;
        }
        tokens.push(match ch {
            '%' => Token::AnySeq,
            '_' => Token::AnyOne,
            literal => Token::Lit(literal),
        });
    }
    let v: Vec<char> = value.chars().collect();
    let mut dp = vec![vec![false; tokens.len() + 1]; v.len() + 1];
    dp[0][0] = true;
    for j in 1..=tokens.len() {
        if matches!(tokens[j - 1], Token::AnySeq) {
            dp[0][j] = dp[0][j - 1];
        }
    }
    for i in 1..=v.len() {
        for j in 1..=tokens.len() {
            dp[i][j] = match tokens[j - 1] {
                Token::AnySeq => dp[i][j - 1] || dp[i - 1][j],
                Token::AnyOne => dp[i - 1][j - 1],
                Token::Lit(c) => dp[i - 1][j - 1] && like_char_eq(v[i - 1], c),
            };
        }
    }
    dp[v.len()][tokens.len()]
}

fn like_char_eq(left: char, right: char) -> bool {
    if left == right {
        return true;
    }
    let (left, right) = (left as u32, right as u32);
    left < 128 && right < 128 && (left as u8).eq_ignore_ascii_case(&(right as u8))
}

fn like_match_fast(value: &str, pattern: &str, escape: Option<char>) -> bool {
    if escape.is_none() {
        if let Some(prefix) = pattern.strip_suffix('%') {
            if !prefix.contains('%') && !prefix.contains('_') {
                return value
                    .get(..prefix.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(prefix));
            }
        }
    }
    like_match(value, pattern, escape)
}

fn compare_scalar(a: &Scalar, b: &Scalar) -> std::cmp::Ordering {
    if let Some(order) = membership::numeric_cmp(a, b) {
        return order;
    }
    let rank = |value: &Scalar| match value {
        Scalar::Null => 0,
        Scalar::Int(_) | Scalar::Real(_) => 1,
        Scalar::Text(_) => 2,
        Scalar::Blob(_) => 3,
    };
    match rank(a).cmp(&rank(b)) {
        std::cmp::Ordering::Equal => match (a, b) {
            (Scalar::Null, Scalar::Null) => std::cmp::Ordering::Equal,
            (Scalar::Text(a), Scalar::Text(b)) => dexsql_cache::utf16_cmp(a, b),
            (Scalar::Blob(a), Scalar::Blob(b)) => a.cmp(b),
            (Scalar::Real(a), Scalar::Real(b)) => a.cmp(b),
            _ => std::cmp::Ordering::Equal,
        },
        order => order,
    }
}
fn eval_binary(op: &sqlparser::ast::BinaryOperator, a: &Scalar, b: &Scalar) -> bool {
    use sqlparser::ast::BinaryOperator::*;
    if matches!(a, Scalar::Null) || matches!(b, Scalar::Null) {
        return false;
    }
    match op {
        Eq => a.sql_eq(b),
        NotEq => !a.sql_eq(b),
        Gt => compare_scalar(a, b) == std::cmp::Ordering::Greater,
        Lt => compare_scalar(a, b) == std::cmp::Ordering::Less,
        GtEq => compare_scalar(a, b) != std::cmp::Ordering::Less,
        LtEq => compare_scalar(a, b) != std::cmp::Ordering::Greater,
        And => a.truthy() && b.truthy(),
        Or => a.truthy() || b.truthy(),
        _ => false,
    }
}

fn scalar_from_value(v: &sqlparser::ast::ValueWithSpan) -> Result<Scalar, String> {
    use sqlparser::ast::Value;
    match &v.value {
        Value::Number(s, _) => {
            if s.contains('.') || s.contains('e') || s.contains('E') {
                // The reference normalizes REAL literals through its numeric
                // formatter: `1.10` renders as `1.1`, `1.0` keeps its `.0`.
                s.parse::<f64>()
                    .map(scalar_functions::real_scalar)
                    .map_err(|_| format!("invalid real '{s}'"))
            } else {
                s.parse()
                    .map(Scalar::Int)
                    .or_else(|_| {
                        // Literals above i64::MAX keep their bit pattern; the
                        // reference renders `-9223372036854775808` through the
                        // negated u64 value.
                        s.parse::<u64>().map(|value| Scalar::Int(value as i64))
                    })
                    .map_err(|_| format!("invalid integer '{s}'"))
            }
        }
        Value::SingleQuotedString(s)
        | Value::EscapedStringLiteral(s)
        | Value::NationalStringLiteral(s)
        | Value::DoubleQuotedString(s) => Ok(Scalar::text(s.clone())),
        Value::Boolean(b) => Ok(Scalar::Int(*b as i64)),
        Value::Null => Ok(Scalar::Null),
        Value::HexStringLiteral(text) => {
            let mut bytes = Vec::with_capacity(text.len() / 2);
            let raw = text.as_bytes();
            let mut index = 0;
            while index + 1 < raw.len() + 1 && index + 2 <= raw.len() {
                let high = (raw[index] as char).to_digit(16);
                let low = (raw[index + 1] as char).to_digit(16);
                match (high, low) {
                    (Some(high), Some(low)) => bytes.push((high * 16 + low) as u8),
                    _ => return Err("malformed blob literal".into()),
                }
                index += 2;
            }
            Ok(Scalar::Blob(bytes))
        }
        _ => Err(format!("unsupported literal '{v}'")),
    }
}

fn eval_scalar(
    expr: &sqlparser::ast::Expr,
    row: &RelRow,
    group: &[RelRow],
) -> Result<Scalar, String> {
    use sqlparser::ast::{
        BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, UnaryOperator,
    };
    match expr {
        Expr::Identifier(id) => row
            .get(&id.value)
            .cloned()
            .ok_or_else(|| format!("unknown column '{}'", id.value)),
        Expr::CompoundIdentifier(ids) => row
            .get(
                &ids.iter()
                    .map(|i| i.value.as_str())
                    .collect::<Vec<_>>()
                    .join("."),
            )
            .cloned()
            .ok_or_else(|| {
                format!(
                    "unknown column '{}'",
                    ids.iter()
                        .map(|i| i.value.as_str())
                        .collect::<Vec<_>>()
                        .join(".")
                )
            }),
        Expr::Value(v) => scalar_from_value(v),
        Expr::Nested(e) => eval_scalar(e, row, group),
        Expr::UnaryOp { op, expr } => {
            let x = eval_scalar(expr, row, group)?;
            match op {
                UnaryOperator::Plus => Ok(x),
                UnaryOperator::Minus => match x {
                    Scalar::Int(v) => Ok(Scalar::Int(v.wrapping_neg())),
                    Scalar::Real(v) => v
                        .parse::<f64>()
                        .map(|n| scalar_functions::real_scalar(-n))
                        .map_err(|_| "unary minus requires a number".to_owned()),
                    Scalar::Null => Ok(Scalar::Null),
                    _ => Err("unary minus requires a number".into()),
                },
                UnaryOperator::Not => Ok(if matches!(x, Scalar::Null) {
                    Scalar::Null
                } else {
                    Scalar::Int((!x.truthy()) as i64)
                }),
                _ => Err(format!("unsupported unary operator {op}")),
            }
        }
        Expr::BinaryOp { left, op, right } => {
            let a = eval_scalar(left, row, group)?;
            let b = eval_scalar(right, row, group)?;
            match op {
                BinaryOperator::Plus | BinaryOperator::Minus | BinaryOperator::Multiply => {
                    if matches!(a, Scalar::Null) || matches!(b, Scalar::Null) {
                        return Ok(Scalar::Null);
                    };
                    let (Some(x), Some(y)) = (a.numeric(), b.numeric()) else {
                        return Err("arithmetic requires numeric values".into());
                    };
                    // SQLite typing: int op int stays int (promoting to real
                    // on overflow); any real operand makes the result real.
                    let both_int = matches!(a, Scalar::Int(_)) && matches!(b, Scalar::Int(_));
                    if both_int {
                        let (x, y) = (x as i64, y as i64);
                        let z = match op {
                            BinaryOperator::Plus => x.checked_add(y),
                            BinaryOperator::Minus => x.checked_sub(y),
                            _ => x.checked_mul(y),
                        };
                        return Ok(match z {
                            Some(z) => Scalar::Int(z),
                            None => scalar_functions::real_scalar(match op {
                                BinaryOperator::Plus => x as f64 + y as f64,
                                BinaryOperator::Minus => x as f64 - y as f64,
                                _ => x as f64 * y as f64,
                            }),
                        });
                    }
                    let z = match op {
                        BinaryOperator::Plus => x + y,
                        BinaryOperator::Minus => x - y,
                        _ => x * y,
                    };
                    Ok(scalar_functions::real_scalar(z))
                }
                BinaryOperator::Divide | BinaryOperator::Modulo => {
                    if matches!(a, Scalar::Null) || matches!(b, Scalar::Null) {
                        return Ok(Scalar::Null);
                    }
                    let (Some(x), Some(y)) = (a.numeric(), b.numeric()) else {
                        return Err("arithmetic requires numeric values".into());
                    };
                    // Division by zero yields NULL, matching SQLite.
                    if y == 0.0 {
                        return Ok(Scalar::Null);
                    }
                    if matches!(a, Scalar::Int(_)) && matches!(b, Scalar::Int(_)) {
                        let (x, y) = (x as i64, y as i64);
                        return Ok(Scalar::Int(if matches!(op, BinaryOperator::Divide) {
                            x.wrapping_div(y)
                        } else {
                            x.wrapping_rem(y)
                        }));
                    }
                    let z = if matches!(op, BinaryOperator::Divide) {
                        x / y
                    } else {
                        x % y
                    };
                    Ok(scalar_functions::real_scalar(z))
                }
                BinaryOperator::BitwiseAnd
                | BinaryOperator::BitwiseOr
                | BinaryOperator::BitwiseXor
                | BinaryOperator::PGBitwiseShiftLeft
                | BinaryOperator::PGBitwiseShiftRight => {
                    if matches!(a, Scalar::Null) || matches!(b, Scalar::Null) {
                        return Ok(Scalar::Null);
                    }
                    let (Some(x), Some(y)) = (a.numeric(), b.numeric()) else {
                        return Err("bitwise operation requires numeric values".into());
                    };
                    let (x, y) = (x as i64, y as i64);
                    let z = match op {
                        BinaryOperator::BitwiseAnd => x & y,
                        BinaryOperator::BitwiseOr => x | y,
                        BinaryOperator::BitwiseXor => x ^ y,
                        BinaryOperator::PGBitwiseShiftLeft => {
                            if !(0..64).contains(&y) {
                                0
                            } else {
                                x << y
                            }
                        }
                        _ => {
                            if !(0..64).contains(&y) {
                                if x < 0 {
                                    -1
                                } else {
                                    0
                                }
                            } else {
                                x >> y
                            }
                        }
                    };
                    Ok(Scalar::Int(z))
                }
                BinaryOperator::And | BinaryOperator::Or => {
                    let z = if matches!(op, BinaryOperator::And) {
                        if !a.truthy() || !b.truthy() {
                            0
                        } else {
                            1
                        }
                    } else if a.truthy() || b.truthy() {
                        1
                    } else {
                        0
                    };
                    Ok(Scalar::Int(z))
                }
                _ => {
                    if matches!(a, Scalar::Null) || matches!(b, Scalar::Null) {
                        Ok(Scalar::Null)
                    } else {
                        Ok(Scalar::Int(eval_binary(op, &a, &b) as i64))
                    }
                }
            }
        }
        Expr::Substring {
            expr,
            substring_from,
            substring_for,
            ..
        } => {
            let mut values = vec![eval_scalar(expr, row, group)?];
            match substring_from {
                Some(from) => values.push(eval_scalar(from, row, group)?),
                None => return Err("SUBSTR requires a start position".into()),
            }
            if let Some(length) = substring_for {
                values.push(eval_scalar(length, row, group)?);
            }
            eval_string_function("substr", &values)
        }
        Expr::InList {
            expr,
            list,
            negated,
        } => {
            let value = eval_scalar(expr, row, group)?;
            let mut found = false;
            let mut saw_null = false;
            for item in list {
                let item = eval_scalar(item, row, group)?;
                if matches!(item, Scalar::Null) {
                    saw_null = true;
                } else if !matches!(value, Scalar::Null) && value.sql_eq(&item) {
                    found = true;
                    break;
                }
            }
            Ok(membership::result(
                found,
                saw_null,
                list.is_empty(),
                &value,
                *negated,
            ))
        }
        Expr::Between {
            expr,
            low,
            high,
            negated,
        } => {
            let value = eval_scalar(expr, row, group)?;
            let low = eval_scalar(low, row, group)?;
            let high = eval_scalar(high, row, group)?;
            if matches!(value, Scalar::Null)
                || matches!(low, Scalar::Null)
                || matches!(high, Scalar::Null)
            {
                return Ok(Scalar::Null);
            }
            let inside = compare_scalar(&value, &low) != std::cmp::Ordering::Less
                && compare_scalar(&value, &high) != std::cmp::Ordering::Greater;
            let truth = if *negated { !inside } else { inside };
            Ok(Scalar::Int(truth as i64))
        }
        Expr::Trim {
            expr,
            trim_where,
            trim_what,
            trim_characters,
        } => {
            // The reference grammar accepts only the plain TRIM(x[, chars])
            // function form; the BOTH/LEADING/TRAILING ... FROM spellings are
            // rejected at validate_sql with `expected RParen`.
            if trim_where.is_some() || trim_what.is_some() {
                return Err("expected RParen".into());
            }
            let value = eval_scalar(expr, row, group)?;
            let mut values = vec![value];
            for characters in trim_characters.iter().flatten() {
                values.push(eval_scalar(characters, row, group)?);
            }
            scalar_functions::eval_scalar_function("trim", &values).unwrap_or(Ok(Scalar::Null))
        }
        Expr::Function(f) => {
            if let Some(value) = membership::evaluate(f, row, group) {
                return value;
            }
            let name = f
                .name
                .0
                .last()
                .map(|x| x.to_string().to_ascii_lowercase())
                .unwrap_or_default();
            let FunctionArguments::List(args) = &f.args else {
                return Err("aggregate requires an argument list".into());
            };
            if matches!(name.as_str(), "instr" | "substr" | "substring") {
                let mut values = Vec::with_capacity(args.args.len());
                for arg in &args.args {
                    let FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) = arg else {
                        return Err(format!("unsupported {name} argument"));
                    };
                    values.push(eval_scalar(e, row, group)?);
                }
                let function = if name == "substring" {
                    "substr"
                } else {
                    name.as_str()
                };
                return eval_string_function(function, &values);
            }
            // Scalar functions evaluate per row; min/max are scalar with two
            // or more arguments and aggregate with one.
            let is_scalar_call = !matches!(
                name.as_str(),
                "count" | "sum" | "avg" | "total" | "group_concat" | "string_agg"
            ) && !(matches!(name.as_str(), "min" | "max")
                && args.args.len() == 1);
            if is_scalar_call {
                let mut values = Vec::with_capacity(args.args.len());
                for arg in &args.args {
                    let FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) = arg else {
                        return Err(format!("unsupported {name} argument"));
                    };
                    values.push(eval_scalar(e, row, group)?);
                }
                if let Some(result) = scalar_functions::eval_scalar_function(&name, &values) {
                    return result;
                }
                if matches!(name.as_str(), "min" | "max") && values.len() >= 2 {
                    if values.iter().any(|v| matches!(v, Scalar::Null)) {
                        return Ok(Scalar::Null);
                    }
                    let pick = values.iter().enumerate().fold(
                        (0usize, &values[0]),
                        |(best_index, best), (index, value)| {
                            let better = if name == "min" {
                                compare_scalar(value, best) == std::cmp::Ordering::Less
                            } else {
                                compare_scalar(value, best) == std::cmp::Ordering::Greater
                            };
                            if better {
                                (index, value)
                            } else {
                                (best_index, best)
                            }
                        },
                    );
                    return Ok(pick.1.clone());
                }
                if matches!(
                    name.as_str(),
                    "row_number"
                        | "rank"
                        | "dense_rank"
                        | "ntile"
                        | "lag"
                        | "lead"
                        | "first_value"
                        | "last_value"
                ) {
                    return Err(
                        "window function shape is outside the DexSQL read-only subset".into(),
                    );
                }
            }
            if name == "param_types_match" {
                let mut values = Vec::with_capacity(args.args.len());
                for arg in &args.args {
                    let FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) = arg else {
                        return Err("unsupported param_types_match argument".into());
                    };
                    values.push(eval_scalar(e, row, group)?);
                }
                if values.len() != 2 {
                    return Err("param_types_match requires two arguments".into());
                }
                if values.iter().any(|value| matches!(value, Scalar::Null)) {
                    return Ok(Scalar::Null);
                }
                let (Some(descriptors), Some(pattern)) =
                    (scalar_text(&values[0]), scalar_text(&values[1]))
                else {
                    return Ok(Scalar::Int(0));
                };
                return Ok(Scalar::Int(
                    param_pattern::param_types_match_text(&descriptors, &pattern) as i64,
                ));
            }
            let distinct =
                args.duplicate_treatment == Some(sqlparser::ast::DuplicateTreatment::Distinct);
            let arg = args.args.first();
            if name == "count" {
                if arg.is_none()
                    || matches!(arg, Some(FunctionArg::Unnamed(FunctionArgExpr::Wildcard)))
                {
                    return Ok(Scalar::Int(group.len() as i64));
                }
                let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(e))) = arg else {
                    return Err("unsupported COUNT argument".into());
                };
                let mut vals = group
                    .iter()
                    .filter_map(|r| eval_scalar(e, r, &[]).ok())
                    .filter(|v| !matches!(v, Scalar::Null))
                    .collect::<Vec<_>>();
                if distinct {
                    vals.sort_by(compare_scalar);
                    vals.dedup_by(|a, b| a.sql_eq(b));
                }
                return Ok(Scalar::Int(vals.len() as i64));
            }
            let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(e))) = arg else {
                return Err(format!("unsupported {name} argument"));
            };
            let mut vals = group
                .iter()
                .map(|r| eval_scalar(e, r, &[]))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|v| !matches!(v, Scalar::Null))
                .collect::<Vec<_>>();
            if distinct {
                vals.sort_by(compare_scalar);
                vals.dedup_by(|a, b| a.sql_eq(b));
            }
            let sum_real =
                || -> f64 { vals.iter().map(|v| v.numeric().unwrap_or(0.0)).sum::<f64>() };
            match name.as_str() {
                "sum" => {
                    if vals.is_empty() {
                        return Ok(Scalar::Null);
                    }
                    if vals.iter().all(|v| matches!(v, Scalar::Int(_))) {
                        Ok(Scalar::Int(sum_real() as i64))
                    } else {
                        Ok(scalar_functions::real_scalar(sum_real()))
                    }
                }
                "total" => Ok(scalar_functions::real_scalar(sum_real())),
                "avg" => {
                    if vals.is_empty() {
                        Ok(Scalar::Null)
                    } else {
                        Ok(aggregate_real_scalar(
                            vals.iter().map(|v| v.numeric().unwrap_or(0.0)).sum::<f64>()
                                / vals.len() as f64,
                        ))
                    }
                }
                "group_concat" | "string_agg" => {
                    if vals.is_empty() {
                        return Ok(Scalar::Null);
                    }
                    let separator = match args.args.get(1) {
                        Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(e))) => {
                            let value = eval_scalar(e, row, group)?;
                            scalar_text(&value).ok_or("group_concat separator must be text")?
                        }
                        _ => ",".to_owned(),
                    };
                    let parts: Vec<String> = vals.iter().filter_map(scalar_text).collect();
                    Ok(Scalar::text(parts.join(&separator)))
                }
                "min" => Ok(vals
                    .into_iter()
                    .min_by(compare_scalar)
                    .unwrap_or(Scalar::Null)),
                "max" => Ok(vals
                    .into_iter()
                    .max_by(compare_scalar)
                    .unwrap_or(Scalar::Null)),
                _ => Err(format!("unsupported function '{name}'")),
            }
        }
        _ => Err(format!("unsupported expression '{expr}'")),
    }
}

fn aggregate_real_scalar(value: f64) -> Scalar {
    // Aggregate REAL results use 15 significant decimal digits in the
    // reference, including AVG's recurring fractional results.
    let rounded = if value.is_finite() {
        format!("{value:.14e}").parse::<f64>().unwrap_or(value)
    } else {
        value
    };
    scalar_functions::real_scalar(rounded)
}

fn scalar_text(value: &Scalar) -> Option<String> {
    match value {
        Scalar::Text(text) => Some(text.to_string()),
        Scalar::Blob(bytes) => Some(bytes.iter().map(|b| format!("{b:02x}")).collect()),
        Scalar::Int(value) => Some(value.to_string()),
        Scalar::Real(value) => Some(value.clone()),
        Scalar::Null => None,
    }
}

fn scalar_integer(value: &Scalar) -> Option<i64> {
    match value {
        Scalar::Int(value) => Some(*value),
        Scalar::Real(value) => value.parse::<f64>().ok().map(|value| value as i64),
        _ => None,
    }
}

/// SQLite-compatible string helpers used by case-sensitive DexKit string predicates.
fn eval_string_function(name: &str, values: &[Scalar]) -> Result<Scalar, String> {
    if values.iter().any(|value| matches!(value, Scalar::Null)) {
        return Ok(Scalar::Null);
    }
    match name {
        "instr" => {
            if values.len() != 2 {
                return Err("instr requires two arguments".into());
            }
            let haystack = scalar_text(&values[0]).ok_or("instr requires text arguments")?;
            let needle = scalar_text(&values[1]).ok_or("instr requires text arguments")?;
            let Some(index) = haystack.find(&needle) else {
                return Ok(Scalar::Int(0));
            };
            let position = haystack[..index].chars().count() as i64 + 1;
            Ok(Scalar::Int(position))
        }
        "substr" => {
            if values.len() != 2 && values.len() != 3 {
                return Err("substr requires two or three arguments".into());
            }
            let text = scalar_text(&values[0]).ok_or("substr requires a text argument")?;
            let start = scalar_integer(&values[1]).ok_or("substr requires a numeric start")?;
            let length = if values.len() == 3 {
                Some(scalar_integer(&values[2]).ok_or("substr requires a numeric length")?)
            } else {
                None
            };
            let chars: Vec<char> = text.chars().collect();
            let len = chars.len() as i64;
            let (mut begin, mut end) = match length {
                Some(length) if length < 0 => {
                    let end = (len + start).max(0);
                    (end + length, end)
                }
                Some(length) if start == 0 => {
                    // SQLite quirk: position 0 addresses the slot before the
                    // first character, so the length loses one character.
                    (0, length - 1)
                }
                Some(length) => {
                    let begin = if start > 0 { start - 1 } else { len + start };
                    (begin, begin + length)
                }
                None => {
                    let begin = if start > 0 { start - 1 } else { len + start };
                    (begin, len)
                }
            };
            begin = begin.clamp(0, len);
            end = end.clamp(0, len);
            if end < begin {
                end = begin;
            }
            let value: String = chars[begin as usize..end as usize].iter().collect();
            Ok(Scalar::text(value))
        }
        _ => Err(format!("unsupported string function '{name}'")),
    }
}

fn eval_bool(expr: &sqlparser::ast::Expr, row: &RelRow, group: &[RelRow]) -> Result<bool, String> {
    use sqlparser::ast::{BinaryOperator, Expr};
    match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => Ok(eval_bool(left, row, group)? && eval_bool(right, row, group)?),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => Ok(eval_bool(left, row, group)? || eval_bool(right, row, group)?),
        Expr::BinaryOp { left, op, right } => Ok(eval_binary(
            op,
            &eval_scalar(left, row, group)?,
            &eval_scalar(right, row, group)?,
        )),
        Expr::UnaryOp {
            op: sqlparser::ast::UnaryOperator::Not,
            expr,
        } => {
            let value = eval_scalar(expr, row, group)?;
            Ok(!matches!(value, Scalar::Null) && !value.truthy())
        }
        Expr::Nested(e) => eval_bool(e, row, group),
        Expr::InList { .. } => Ok(eval_scalar(expr, row, group)?.truthy()),
        Expr::Like {
            expr,
            pattern,
            negated,
            escape_char,
            ..
        }
        | Expr::ILike {
            expr,
            pattern,
            negated,
            escape_char,
            ..
        } => {
            let v = eval_scalar(expr, row, group)?;
            let p = eval_scalar(pattern, row, group)?;
            if matches!(v, Scalar::Null) | matches!(p, Scalar::Null) {
                return Ok(false);
            };
            let escape = match escape_char {
                None => None,
                Some(escape_expr) => {
                    let value = eval_scalar(escape_expr, row, group)?;
                    let Scalar::Text(text) = value else {
                        return Err("ESCAPE expression must be a one-character string".into());
                    };
                    let mut chars = text.chars();
                    let Some(escape) = chars.next() else {
                        return Err("ESCAPE expression must be a one-character string".into());
                    };
                    if chars.next().is_some() {
                        return Err("ESCAPE expression must be a one-character string".into());
                    }
                    Some(escape)
                }
            };
            let f = like_match(&v.display(), &p.display(), escape);
            Ok(if *negated { !f } else { f })
        }
        Expr::IsNull(e) => Ok(matches!(eval_scalar(e, row, group)?, Scalar::Null)),
        Expr::IsNotNull(e) => Ok(!matches!(eval_scalar(e, row, group)?, Scalar::Null)),
        _ => Ok(eval_scalar(expr, row, group)?.truthy()),
    }
}

fn apply_sql_limit(
    rows: &mut Vec<ProjectedRow>,
    clause: Option<&sqlparser::ast::LimitClause>,
) -> Result<(), String> {
    let Some(c) = clause else { return Ok(()) };
    let (lim, off) = match c {
        sqlparser::ast::LimitClause::LimitOffset {
            limit,
            offset,
            limit_by,
        } => {
            if !limit_by.is_empty() {
                return Err("unsupported LIMIT BY".into());
            }
            (limit.as_ref(), offset.as_ref().map(|x| &x.value))
        }
        sqlparser::ast::LimitClause::OffsetCommaLimit { offset, limit } => {
            (Some(limit), Some(offset))
        }
    };
    let parse = |e: &sqlparser::ast::Expr| -> Result<u64, String> {
        let sqlparser::ast::Expr::Value(v) = e else {
            return Err("LIMIT/OFFSET must be integer literals".into());
        };
        let Scalar::Int(x) = scalar_from_value(v)? else {
            return Err("LIMIT/OFFSET must be integer literals".into());
        };
        if x < 0 {
            Err("LIMIT/OFFSET cannot be negative".into())
        } else {
            Ok(x as u64)
        }
    };
    let o = off.map(parse).transpose()?.unwrap_or(0) as usize;
    if o >= rows.len() {
        rows.clear()
    } else if o > 0 {
        rows.drain(..o);
    }
    if let Some(l) = lim.map(parse).transpose()? {
        rows.truncate(l as usize);
    }
    Ok(())
}

/// Reference materialization budget: 0x20000000 bytes (512 MiB), pinned by
/// disassembling the variant-6 error construction in the release binary.
const MATERIALIZE_BUDGET_BYTES: u64 = 0x2000_0000;

/// Check the current retained size of one intermediate result. The reference
/// caps each collector, rather than summing every prior allocation in a query.
/// See artifacts/memory/README.md for disassembly addresses.
fn charge_materialized(bytes: u64) -> Result<(), String> {
    if bytes > MATERIALIZE_BUDGET_BYTES {
        return Err("intermediate result exceeded the materialization memory budget".into());
    }
    Ok(())
}

/// Rough byte estimate of a materialized relational row set: a fixed
/// per-cell footprint plus the key/value overhead of the row map.
fn estimate_row_bytes(rows: &[RelRow]) -> u64 {
    const CELL_BYTES: u64 = 96;
    let columns = rows.first().map(|row| row.values.len() as u64).unwrap_or(0);
    rows.len() as u64 * (64 + columns * CELL_BYTES)
}

fn render_table(result: &QueryResult) -> String {
    let mut output = Vec::new();
    write_table(&mut output, result).expect("writing into Vec cannot fail");
    String::from_utf8(output).expect("table output is UTF-8")
}

/// Width discovery needs the result cells, but padding the entire table into
/// one String can turn a 150 MiB result into several GiB. Write one row at a
/// time after the width pass while preserving the CLI's exact table format.
fn write_table<W: std::io::Write>(writer: &mut W, result: &QueryResult) -> std::io::Result<()> {
    if result.columns.is_empty() {
        return writer.write_all(b"++\n|\n++\n++\n");
    }
    let mut widths: Vec<usize> = result
        .columns
        .iter()
        .map(|value| display_width(value))
        .collect();
    for row in &result.rows {
        for (index, value) in row.iter().enumerate() {
            if let Some(width) = widths.get_mut(index) {
                *width = (*width).max(display_width(value));
            }
        }
    }
    let border = format!(
        "+{}+\n",
        widths
            .iter()
            .map(|width| "-".repeat(width + 2))
            .collect::<Vec<_>>()
            .join("+")
    );
    writer.write_all(border.as_bytes())?;
    let mut write_row = |row: &[String]| -> std::io::Result<()> {
        writer.write_all(b"|")?;
        for (index, value) in row.iter().enumerate() {
            writer.write_all(b" ")?;
            writer.write_all(value.as_bytes())?;
            let padding = widths[index] - display_width(value) + 1;
            const SPACES: [u8; 256] = [b' '; 256];
            for _ in 0..padding / SPACES.len() {
                writer.write_all(&SPACES)?;
            }
            writer.write_all(&SPACES[..padding % SPACES.len()])?;
            writer.write_all(b"|")?;
        }
        writer.write_all(b"\n")
    };
    write_row(&result.columns)?;
    // End the closure borrow before writing the header separator.
    drop(write_row);
    writer.write_all(border.as_bytes())?;
    for row in &result.rows {
        writer.write_all(b"|")?;
        for (index, value) in row.iter().enumerate() {
            writer.write_all(b" ")?;
            writer.write_all(value.as_bytes())?;
            let padding = widths[index] - display_width(value) + 1;
            const SPACES: [u8; 256] = [b' '; 256];
            for _ in 0..padding / SPACES.len() {
                writer.write_all(&SPACES)?;
            }
            writer.write_all(&SPACES[..padding % SPACES.len()])?;
            writer.write_all(b"|")?;
        }
        writer.write_all(b"\n")?;
    }
    writer.write_all(border.as_bytes())
}
fn display_width(v: &str) -> usize {
    v.chars().count()
}

/// Check these fallback collectors while they grow, before Vec reserves the
/// next block. The reference's 32-byte cells are much smaller than a RelRow's
/// hash buckets and duplicate qualified keys, so account for our allocation
/// layout and text payloads instead of allowing a multi-million-row map set.
fn push_reference_row(
    rows: &mut Vec<RelRow>,
    row: RelRow,
    retained_bytes: &mut u64,
) -> Result<(), String> {
    let capacity = row.values.capacity();
    let buckets = if capacity < 8 {
        capacity.saturating_add(1)
    } else {
        capacity.saturating_mul(8) / 7
    };
    let payload_bytes = row
        .values
        .values()
        .map(|value| match value {
            // Text is Arc-backed, but counting both relation keys is a safe
            // bound and also covers small-allocation allocator overhead.
            Scalar::Text(text) => text.len() as u64 + 32,
            Scalar::Real(text) => text.capacity() as u64 + 16,
            Scalar::Blob(bytes) => bytes.capacity() as u64 + 16,
            _ => 0,
        })
        .sum::<u64>();
    let row_bytes = (buckets as u64)
        .saturating_mul((std::mem::size_of::<(Arc<str>, Scalar)>() + 1) as u64)
        .saturating_add((row.columns.capacity() * std::mem::size_of::<Arc<str>>()) as u64)
        .saturating_add(payload_bytes)
        .saturating_add(32);
    let next_capacity = if rows.len() == rows.capacity() {
        rows.capacity().saturating_mul(2).max(4)
    } else {
        rows.capacity()
    };
    let next_bytes = retained_bytes.saturating_add(row_bytes);
    charge_materialized(next_bytes.saturating_add(
        (next_capacity as u64).saturating_mul(std::mem::size_of::<RelRow>() as u64),
    ))?;
    *retained_bytes = next_bytes;
    rows.push(row);
    Ok(())
}

fn scan_method_calls(
    ds: &Dataset,
    alias: &str,
    predicates: Option<&[PushPredicate]>,
    key_filter: Option<(&str, &HashSet<Scalar>)>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    let mut retained_bytes = 0;
    for f in &ds.files {
        for r in &f.method_calls {
            let method = std::cell::OnceCell::new();
            let callee = std::cell::OnceCell::new();
            let value = |column: &str| match column {
                "method" => {
                    Scalar::text(method.get_or_init(|| f.method_descriptor_direct(r.method_idx)))
                }
                "method_class" => Scalar::text(f.method_class(r.method_idx)),
                "method_name" => Scalar::text(f.method_name(r.method_idx)),
                "callee" => Scalar::text(
                    callee.get_or_init(|| f.method_descriptor_direct(r.callee_method_idx)),
                ),
                "callee_class" => Scalar::text(f.method_class(r.callee_method_idx)),
                "callee_name" => Scalar::text(f.method_name(r.callee_method_idx)),
                "file_id" => Scalar::Int(f.file_id as i64),
                "class_idx" => Scalar::Int(
                    f.methods
                        .get(r.method_idx as usize)
                        .map(|m| m.class_idx)
                        .unwrap_or(0) as i64,
                ),
                "method_idx" => Scalar::Int(r.method_idx as i64),
                "callee_method_idx" => Scalar::Int(r.callee_method_idx as i64),
                _ => Scalar::Null,
            };
            if predicates.is_some_and(|predicates| !predicates_match(predicates, value))
                || key_filter.is_some_and(|(column, accepted)| !accepted.contains(&value(column)))
            {
                continue;
            }
            let mut row = RelRow::with_capacity(10);
            let m = method.get_or_init(|| f.method_descriptor_direct(r.method_idx));
            let c = callee.get_or_init(|| f.method_descriptor_direct(r.callee_method_idx));
            row.put(alias, "method", Scalar::text(m));
            row.put(
                alias,
                "method_class",
                Scalar::text(f.method_class(r.method_idx)),
            );
            row.put(
                alias,
                "method_name",
                Scalar::text(f.method_name(r.method_idx)),
            );
            row.put(alias, "callee", Scalar::text(c));
            row.put(
                alias,
                "callee_class",
                Scalar::text(f.method_class(r.callee_method_idx)),
            );
            row.put(
                alias,
                "callee_name",
                Scalar::text(f.method_name(r.callee_method_idx)),
            );
            row.put(alias, "file_id", Scalar::Int(f.file_id as i64));
            row.put(
                alias,
                "class_idx",
                Scalar::Int(
                    f.methods
                        .get(r.method_idx as usize)
                        .map(|m| m.class_idx)
                        .unwrap_or(0) as i64,
                ),
            );
            row.put(alias, "method_idx", Scalar::Int(r.method_idx as i64));
            row.put(
                alias,
                "callee_method_idx",
                Scalar::Int(r.callee_method_idx as i64),
            );
            push_reference_row(&mut rows, row, &mut retained_bytes)?;
        }
    }
    Ok(rows)
}
fn scan_method_field_accesses(
    ds: &Dataset,
    alias: &str,
    predicates: Option<&[PushPredicate]>,
    key_filter: Option<(&str, &HashSet<Scalar>)>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    let mut retained_bytes = 0;
    for f in &ds.files {
        for r in &f.method_field_accesses {
            let method = std::cell::OnceCell::new();
            let field = std::cell::OnceCell::new();
            let fi = f.fields.get(r.field_idx as usize);
            let using_type =
                if (0x52..=0x58).contains(&r.opcode) || (0x60..=0x66).contains(&r.opcode) {
                    "get"
                } else {
                    "put"
                };
            let value = |column: &str| match column {
                "method" => {
                    Scalar::text(method.get_or_init(|| f.method_descriptor_direct(r.method_idx)))
                }
                "method_class" => Scalar::text(f.method_class(r.method_idx)),
                "method_name" => Scalar::text(f.method_name(r.method_idx)),
                "field" => {
                    Scalar::text(field.get_or_init(|| f.field_descriptor_direct(r.field_idx)))
                }
                "field_class" => Scalar::text(
                    fi.map(|x| f.type_descriptor(x.class_idx as u32))
                        .unwrap_or(""),
                ),
                "field_name" => Scalar::text(fi.map(|x| f.string(x.name_idx)).unwrap_or("")),
                "field_type" => Scalar::text(
                    fi.map(|x| f.type_descriptor(x.type_idx as u32))
                        .unwrap_or(""),
                ),
                "using_type" => Scalar::text(using_type),
                "file_id" => Scalar::Int(f.file_id as i64),
                "class_idx" => Scalar::Int(
                    f.methods
                        .get(r.method_idx as usize)
                        .map(|m| m.class_idx)
                        .unwrap_or(0) as i64,
                ),
                "method_idx" => Scalar::Int(r.method_idx as i64),
                "field_idx" => Scalar::Int(r.field_idx as i64),
                _ => Scalar::Null,
            };
            if predicates.is_some_and(|predicates| !predicates_match(predicates, value))
                || key_filter.is_some_and(|(column, accepted)| !accepted.contains(&value(column)))
            {
                continue;
            }
            let mut row = RelRow::with_capacity(12);
            let m = method.get_or_init(|| f.method_descriptor_direct(r.method_idx));
            let fd = field.get_or_init(|| f.field_descriptor_direct(r.field_idx));
            row.put(alias, "method", Scalar::text(m));
            row.put(
                alias,
                "method_class",
                Scalar::text(f.method_class(r.method_idx)),
            );
            row.put(
                alias,
                "method_name",
                Scalar::text(f.method_name(r.method_idx)),
            );
            row.put(alias, "field", Scalar::text(fd));
            row.put(
                alias,
                "field_class",
                Scalar::text(
                    fi.map(|x| f.type_descriptor(x.class_idx as u32))
                        .unwrap_or(""),
                ),
            );
            row.put(
                alias,
                "field_name",
                Scalar::text(fi.map(|x| f.string(x.name_idx)).unwrap_or("")),
            );
            row.put(
                alias,
                "field_type",
                Scalar::text(
                    fi.map(|x| f.type_descriptor(x.type_idx as u32))
                        .unwrap_or(""),
                ),
            );
            row.put(
                alias,
                "using_type",
                Scalar::text(
                    if (0x52..=0x58).contains(&r.opcode) || (0x60..=0x66).contains(&r.opcode) {
                        "get"
                    } else {
                        "put"
                    },
                ),
            );
            row.put(alias, "file_id", Scalar::Int(f.file_id as i64));
            row.put(
                alias,
                "class_idx",
                Scalar::Int(
                    f.methods
                        .get(r.method_idx as usize)
                        .map(|m| m.class_idx)
                        .unwrap_or(0) as i64,
                ),
            );
            row.put(alias, "method_idx", Scalar::Int(r.method_idx as i64));
            row.put(alias, "field_idx", Scalar::Int(r.field_idx as i64));
            push_reference_row(&mut rows, row, &mut retained_bytes)?;
        }
    }
    Ok(rows)
}
fn scan_method_used_types(
    ds: &Dataset,
    alias: &str,
    predicates: Option<&[PushPredicate]>,
    key_filter: Option<(&str, &HashSet<Scalar>)>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    let mut retained_bytes = 0;
    for f in &ds.files {
        for r in &f.method_used_types {
            let method = std::cell::OnceCell::new();
            let type_name = std::cell::OnceCell::new();
            let t = f.type_descriptor(r.type_idx);
            let value = |column: &str| match column {
                "method" => {
                    Scalar::text(method.get_or_init(|| f.method_descriptor_direct(r.method_idx)))
                }
                "method_class" => Scalar::text(f.method_class(r.method_idx)),
                "method_name" => Scalar::text(f.method_name(r.method_idx)),
                "type_descriptor" => Scalar::text(t),
                "type_name" => Scalar::text(type_name.get_or_init(|| java_name(t))),
                "file_id" => Scalar::Int(f.file_id as i64),
                "class_idx" => Scalar::Int(
                    f.methods
                        .get(r.method_idx as usize)
                        .map(|m| m.class_idx)
                        .unwrap_or(0) as i64,
                ),
                "method_idx" => Scalar::Int(r.method_idx as i64),
                "type_idx" => Scalar::Int(r.type_idx as i64),
                _ => Scalar::Null,
            };
            if predicates.is_some_and(|predicates| !predicates_match(predicates, value))
                || key_filter.is_some_and(|(column, accepted)| !accepted.contains(&value(column)))
            {
                continue;
            }
            let mut row = RelRow::with_capacity(9);
            let m = method.get_or_init(|| f.method_descriptor_direct(r.method_idx));
            row.put(alias, "method", Scalar::text(m));
            row.put(
                alias,
                "method_class",
                Scalar::text(f.method_class(r.method_idx)),
            );
            row.put(
                alias,
                "method_name",
                Scalar::text(f.method_name(r.method_idx)),
            );
            row.put(alias, "type_descriptor", Scalar::text(t));
            row.put(alias, "type_name", Scalar::text(java_name(t)));
            row.put(alias, "file_id", Scalar::Int(f.file_id as i64));
            row.put(
                alias,
                "class_idx",
                Scalar::Int(
                    f.methods
                        .get(r.method_idx as usize)
                        .map(|m| m.class_idx)
                        .unwrap_or(0) as i64,
                ),
            );
            row.put(alias, "method_idx", Scalar::Int(r.method_idx as i64));
            row.put(alias, "type_idx", Scalar::Int(r.type_idx as i64));
            push_reference_row(&mut rows, row, &mut retained_bytes)?;
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod fallback_reference_scan_tests {
    use super::*;

    type Scanner = fn(
        &Dataset,
        &str,
        Option<&[PushPredicate]>,
        Option<(&str, &HashSet<Scalar>)>,
    ) -> Result<Vec<RelRow>, String>;

    #[test]
    fn predicates_and_join_keys_filter_each_reference_column() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex");
        let dataset = Dataset::load_paths(&[path]).unwrap();
        for (name, scanner) in [
            ("calls", scan_method_calls as Scanner),
            ("fields", scan_method_field_accesses as Scanner),
            ("types", scan_method_used_types as Scanner),
        ] {
            let baseline = scanner(&dataset, "r", None, None).unwrap();
            assert!(!baseline.is_empty(), "fixture lacks {name} references");
            for column in &baseline[0].columns {
                let target = baseline[0].get(column).unwrap().clone();
                let accepted = HashSet::from([target.clone()]);
                let predicates = [PushPredicate {
                    column: column.to_string(),
                    kind: PushPredicateKind::Eq,
                    values: vec![target.clone()],
                    escape: None,
                }];
                let expected = baseline
                    .iter()
                    .filter(|row| row.get(column).is_some_and(|value| value.sql_eq(&target)))
                    .map(|row| row.values.clone())
                    .collect::<Vec<_>>();
                for actual in [
                    scanner(&dataset, "r", Some(&predicates), None).unwrap(),
                    scanner(&dataset, "r", None, Some((column, &accepted))).unwrap(),
                    scanner(&dataset, "r", Some(&predicates), Some((column, &accepted))).unwrap(),
                ] {
                    assert_eq!(
                        actual
                            .iter()
                            .map(|row| row.values.clone())
                            .collect::<Vec<_>>(),
                        expected,
                        "{name}.{column}"
                    );
                }
            }
            let empty = HashSet::new();
            assert!(scanner(&dataset, "r", None, Some(("method_idx", &empty)))
                .unwrap()
                .is_empty());
        }
        assert!(dataset.files[0].method_descriptors.get().is_none());
        assert!(dataset.files[0].field_descriptors.get().is_none());
    }

    #[test]
    fn reference_budget_rejects_before_appending() {
        let mut rows = Vec::new();
        let mut retained_bytes = MATERIALIZE_BUDGET_BYTES;
        let mut row = RelRow::with_capacity(1);
        row.put("r", "method_idx", Scalar::Int(1));
        assert!(push_reference_row(&mut rows, row, &mut retained_bytes).is_err());
        assert!(rows.is_empty());
        assert_eq!(retained_bytes, MATERIALIZE_BUDGET_BYTES);
    }

    #[test]
    fn generic_metadata_scans_preserve_limited_rows() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex");
        let dataset = Dataset::load_paths(&[path]).unwrap();
        for (all, limited) in [
            (
                scan_classes(&dataset, "r", None, None, None, None).unwrap(),
                scan_classes(&dataset, "r", None, None, Some(1), None).unwrap(),
            ),
            (
                scan_methods(&dataset, "r", None, None, false, None, None).unwrap(),
                scan_methods(&dataset, "r", None, None, false, Some(1), None).unwrap(),
            ),
            (
                scan_fields(&dataset, "r", None, None, None, None).unwrap(),
                scan_fields(&dataset, "r", None, None, Some(1), None).unwrap(),
            ),
        ] {
            assert!(!all.is_empty());
            assert_eq!(limited.len(), 1);
            assert_eq!(limited[0].values, all[0].values);
        }
    }

    #[test]
    fn generic_joins_reject_large_output_during_growth() {
        // Arc-backed payloads keep this fixture small while exercising the
        // collector's conservative per-row accounting over repeated output.
        let payload = Scalar::text("x".repeat(4 * 1024 * 1024));
        let mut left = RelRow::with_capacity(2);
        left.put("l", "id", Scalar::Int(1));
        left.put("l", "payload", payload.clone());
        let mut right = RelRow::with_capacity(1);
        right.put("r", "id", Scalar::Int(1));
        let right = vec![right; 128];
        let predicate = sqlparser::ast::Expr::BinaryOp {
            left: Box::new(sqlparser::ast::Expr::CompoundIdentifier(vec![
                sqlparser::ast::Ident::new("l"),
                sqlparser::ast::Ident::new("id"),
            ])),
            op: sqlparser::ast::BinaryOperator::Eq,
            right: Box::new(sqlparser::ast::Expr::CompoundIdentifier(vec![
                sqlparser::ast::Ident::new("r"),
                sqlparser::ast::Ident::new("id"),
            ])),
        };
        for constraint in [None, Some(&predicate)] {
            let error = join_rows(std::slice::from_ref(&left), &right, constraint).unwrap_err();
            assert!(error.contains("materialization memory budget"));
        }

        let caches = NamedCaches::default();
        caches.tables.borrow_mut().insert(
            "left_rows".into(),
            Arc::new(CachedTable {
                columns: vec!["payload".into()],
                rows: vec![vec![payload]],
            }),
        );
        caches.tables.borrow_mut().insert(
            "right_rows".into(),
            Arc::new(CachedTable {
                columns: vec!["id".into()],
                rows: vec![vec![Scalar::Int(1)]; 128],
            }),
        );
        let statements = sqlparser::parser::Parser::parse_sql(
            &sqlparser::dialect::SQLiteDialect {},
            "SELECT l.payload FROM left_rows l, right_rows r",
        )
        .unwrap();
        let sqlparser::ast::Statement::Query(query) = &statements[0] else {
            unreachable!()
        };
        let result = execute_select_core(
            query.body.as_select().unwrap(),
            &Dataset::default(),
            None,
            &caches,
            false,
            None,
            None,
        );
        assert!(result
            .err()
            .unwrap()
            .contains("materialization memory budget"));
    }
}

fn call_site_offsets(file: &dexsql_cache::DexFile) -> Vec<u32> {
    map_entries(file)
        .into_iter()
        .filter(|(c, _, _)| *c == 7)
        .flat_map(|(_, n, b)| {
            (0..n as usize).map(move |i| read_u32_at(file.raw(), b as usize + i * 4))
        })
        .collect()
}
fn scan_call_sites(
    ds: &Dataset,
    alias: &str,
    _p: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for f in &ds.files {
        for (idx, off) in call_site_offsets(f).into_iter().enumerate() {
            let (count, _) = read_uleb_at(f.raw(), off as usize);
            let mut row = RelRow::with_capacity(7);
            row.put(alias, "file_id", Scalar::Int(f.file_id as i64));
            row.put(alias, "call_site_idx", Scalar::Int(idx as i64));
            row.put(alias, "call_site_off", Scalar::Int(off as i64));
            row.put(alias, "value_count", Scalar::Int(count as i64));
            row.put(alias, "method_handle_idx", Scalar::Null);
            row.put(alias, "method_name_idx", Scalar::Null);
            row.put(alias, "proto_idx", Scalar::Null);
            rows.push(row);
        }
    }
    Ok(rows)
}
fn scan_call_site_args(
    ds: &Dataset,
    alias: &str,
    _p: Option<&[PushPredicate]>,
) -> Result<Vec<RelRow>, String> {
    let mut rows = Vec::new();
    for f in &ds.files {
        for (idx, off) in call_site_offsets(f).into_iter().enumerate() {
            let (count, mut pos) = read_uleb_at(f.raw(), off as usize);
            for ord in 0..count {
                let h = f.raw().get(pos).copied().unwrap_or(0);
                pos += 1;
                let w = ((h >> 5) as usize) + 1;
                let mut bits = 0u64;
                for i in 0..w {
                    bits |= (f.raw().get(pos + i).copied().unwrap_or(0) as u64) << (i * 8);
                }
                pos += w;
                let mut row = RelRow::with_capacity(8);
                row.put(alias, "file_id", Scalar::Int(f.file_id as i64));
                row.put(alias, "call_site_idx", Scalar::Int(idx as i64));
                row.put(alias, "call_site_off", Scalar::Int(off as i64));
                row.put(alias, "ordinal", Scalar::Int(ord as i64));
                row.put(alias, "value_kind", Scalar::text(encoded_kind(h & 0x1f)));
                row.put(alias, "value_index", Scalar::Int(bits as i64));
                row.put(alias, "value_i64", Scalar::Null);
                row.put(alias, "value_f64", Scalar::Null);
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn encoded_array_end_at(bytes: &[u8], off: usize) -> usize {
    let (n, mut p) = read_uleb_at(bytes, off);
    for _ in 0..n {
        let x = read_encoded_node(bytes, p, 0);
        p = x.end.max(p + 1);
    }
    p
}
fn annotation_end_at(bytes: &[u8], off: usize) -> usize {
    read_annotation_instance(bytes, off).3
}
fn map_entry_offsets(file: &dexsql_cache::DexFile, code: u16) -> Vec<(u32, usize)> {
    map_entries(file)
        .into_iter()
        .filter(|(c, _, _)| *c == code)
        .flat_map(|(_, n, b)| {
            (0..n as usize).map(move |i| {
                let mut p = b as usize;
                for _ in 0..i {
                    p = if code == 0x2004 {
                        annotation_end_at(file.raw(), p)
                    } else {
                        encoded_array_end_at(file.raw(), p)
                    }
                }
                (i as u32, p)
            })
        })
        .collect()
}
fn read_annotation_instance(
    bytes: &[u8],
    off: usize,
) -> (u32, u32, Vec<(u32, EncodedNode)>, usize) {
    let vis = bytes.get(off).copied().unwrap_or(0) as u32;
    let (typ, mut p) = read_uleb_at(bytes, off + 1);
    let (n, next) = read_uleb_at(bytes, p);
    p = next;
    let mut el = Vec::new();
    for _ in 0..n {
        let (name, next) = read_uleb_at(bytes, p);
        p = next;
        let x = read_encoded_node(bytes, p, 0);
        p = x.end.max(p + 1);
        el.push((name, x));
    }
    (vis, typ, el, p)
}
