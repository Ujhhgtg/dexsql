//! Stable embedded API for querying DEX files and APKs.
//!
//! The command line and MCP crates intentionally remain outside this API.  An
//! [`Engine`] owns one immutable [`dexsql_cache::Dataset`] and can be shared by
//! callers that need to resolve many descriptors from the same host APK.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use dexsql_cache::metadata::CrossRefCache;
pub use dexsql_cache::IndexNeeds;
pub use dexsql_cache::MetaQuery;
use dexsql_cache::{Dataset, LoadError};
use dexsql_query::{execute_statement, NamedCaches};

mod annotations;
mod metadata;
mod opcodes;

/// Options controlling the amount of DEX data retained by a session.
///
/// The default is deliberately metadata-only.  Reference indexes and code
/// items are opt-in because a WeChat APK can contain many large DEX files and
/// most descriptor lookups only need IDs, signatures, and class definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineOptions {
    pub index_needs: IndexNeeds,
    pub eager_code_items: bool,
    pub full_code_items: bool,
    pub retain_classes: bool,
    pub threads: Option<usize>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            index_needs: IndexNeeds::default(),
            eager_code_items: false,
            full_code_items: false,
            retain_classes: true,
            threads: Some(1),
        }
    }
}

/// A query result with stable, allocation-owned text cells.
///
/// The text representation is independent of the query executor's scalar type so
/// the public crate can evolve its typed result model without exposing IR
/// implementation details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultSet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl From<dexsql_query::QueryResult> for ResultSet {
    fn from(value: dexsql_query::QueryResult) -> Self {
        Self {
            columns: value.columns,
            rows: value.rows,
        }
    }
}

/// Errors returned by the embedded engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Load(String),
    Query(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(message) => write!(f, "load failed: {message}"),
            Self::Query(message) => write!(f, "query failed: {message}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<LoadError> for Error {
    fn from(value: LoadError) -> Self {
        Self::Load(value.to_string())
    }
}

/// Immutable DEX/APK analysis session.
pub struct Engine {
    dataset: Arc<Dataset>,
    named_caches: Mutex<NamedCaches>,
    result_cache: Mutex<HashMap<String, ResultSet>>,
    /// Lazy DexKit-compatible cross-DEX bindings for nested metadata refs.
    metadata_cross_refs: OnceLock<CrossRefCache>,
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("files", &self.dataset.files.len())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Open one or more `.dex`, `.apk`, `.jar`, or `.zip` paths.
    pub fn open<P>(paths: impl IntoIterator<Item = P>) -> Result<Self, Error>
    where
        P: Into<PathBuf>,
    {
        Self::open_with_options(paths, EngineOptions::default())
    }

    /// Open paths with explicit loader/index requirements.
    pub fn open_with_options<P>(
        paths: impl IntoIterator<Item = P>,
        options: EngineOptions,
    ) -> Result<Self, Error>
    where
        P: Into<PathBuf>,
    {
        let paths = paths.into_iter().map(Into::into).collect::<Vec<_>>();
        if paths.is_empty() {
            return Err(Error::Load("at least one input path is required".into()));
        }
        dexsql_cache::configure_thread_pool(options.threads);
        let dataset = Dataset::load_paths_with_requirements(
            &paths,
            options.index_needs,
            options.eager_code_items,
            options.full_code_items,
            options.retain_classes,
        )?;
        Ok(Self {
            dataset: Arc::new(dataset),
            named_caches: Mutex::new(NamedCaches::default()),
            result_cache: Mutex::new(HashMap::new()),
            metadata_cross_refs: OnceLock::new(),
        })
    }

    /// Return the number of logical DEX files in this session.
    pub fn dex_count(&self) -> usize {
        self.dataset.files.len()
    }

    /// Read the typed metadata document for one class, method, or field.
    ///
    /// This is the engine entry point used by WeKit's DexKit-Data replacement.
    /// It resolves the descriptor through per-file indexes (no relation scans
    /// per call) and returns the stable JSON document documented in
    /// `dexsql::metadata`:
    ///
    /// * a well-formed descriptor that no input DEX matches yields
    ///   `Ok(serde_json::Value::Null)`,
    /// * a malformed descriptor yields `Err(String)`,
    /// * metadata loaded without relation indexes returns empty relation lists
    ///   instead of failing.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dexsql::{Engine, EngineOptions, IndexNeeds, MetaQuery};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = Engine::open_with_options(
    ///     ["app.apk"],
    ///     EngineOptions {
    ///         index_needs: IndexNeeds::all(),
    ///         eager_code_items: true,
    ///         ..EngineOptions::default()
    ///     },
    /// )?;
    /// let document = engine.metadata(&MetaQuery::method(
    ///     "Lcom/example/Foo;->bar(ILjava/lang/String;)V",
    /// ))?;
    /// println!("{document}");
    /// # Ok(())
    /// # }
    /// ```
    pub fn metadata(&self, query: &MetaQuery) -> Result<serde_json::Value, String> {
        let cross = self
            .metadata_cross_refs
            .get_or_init(|| CrossRefCache::new(self.dataset.files.len()));
        metadata::metadata_json(&self.dataset, cross, query)
    }

    /// Alias for [`Engine::metadata`]; kept as an explicit name for the JNI
    /// bridge, which distinguishes metadata reads from SQL queries.
    pub fn metadata_json(&self, query: &MetaQuery) -> Result<serde_json::Value, String> {
        self.metadata(query)
    }

    /// Read the caller list of one method descriptor as a JSON array.
    ///
    /// Callers are not part of [`Engine::metadata`] documents because a single
    /// host method can have tens of thousands of callers and WeKit resolution
    /// does not read them. Consumers that need the DexKit
    /// `MethodData.callers` view (for example Phase 4 runtime evidence
    /// collection) can request it explicitly. Entries are method refs in
    /// DexKit order: the defining DEX's own callers first, then cross-DEX
    /// imports in the bridge's numeric multidex order. A well-formed method
    /// descriptor that no input DEX matches yields JSON `null`; a malformed
    /// descriptor yields `Err(String)`.
    pub fn metadata_callers(&self, descriptor: &str) -> Result<serde_json::Value, String> {
        let cross = self
            .metadata_cross_refs
            .get_or_init(|| CrossRefCache::new(self.dataset.files.len()));
        metadata::callers_json_for_descriptor(&self.dataset, cross, descriptor)
    }

    /// Execute a read-only SQL statement against this session.
    pub fn query(&self, sql: &str) -> Result<ResultSet, Error> {
        if let Some(cached) = self
            .result_cache
            .lock()
            .expect("DexSQL result cache mutex poisoned")
            .get(sql)
            .cloned()
        {
            return Ok(cached);
        }
        let result = execute_statement(
            sql,
            Some(&self.dataset),
            &self
                .named_caches
                .lock()
                .expect("DexSQL named cache mutex poisoned"),
            None,
        )
        .map(ResultSet::from)
        .map_err(Error::Query)?;
        self.result_cache
            .lock()
            .expect("DexSQL result cache mutex poisoned")
            .insert(sql.to_owned(), result.clone());
        Ok(result)
    }

    /// Check whether a path is one of the paths this session was opened from.
    /// This is useful to reject a stale NPatch/LSPatch origin path before a
    /// resolver starts using cached descriptors.
    pub fn input_exists(path: impl AsRef<Path>) -> bool {
        path.as_ref().is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_metadata_only_by_default() {
        let options = EngineOptions::default();
        assert_eq!(options.index_needs, IndexNeeds::default());
        assert!(!options.eager_code_items);
        assert!(!options.full_code_items);
        assert!(options.retain_classes);
    }
}
