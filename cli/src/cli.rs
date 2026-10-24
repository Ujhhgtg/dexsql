use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand};
use dexsql::{Engine, EngineOptions, IndexNeeds, MetaQuery};
use dexsql_cache::decode;
use dexsql_cache::Dataset;
use dexsql_schema::render_tables;

use crate::query::{self, QueryRequest};

const ROOT_LONG_ABOUT: &str = r#"Examples:
  dexsql query --input app.apk --sql "SELECT count(*) FROM methods"
  dexsql query --input app.apk --interactive
  dexsql tables --input app.apk
  dexsql prepare-cache --input app.apk --output app-cache
  dexsql query-cache --cache-file app-cache/cache.dxc2 --sql "SELECT count(*) FROM methods"
  dexsql mcp
  dexsql extract licenses --output THIRD_PARTY_NOTICES

Global options can appear before or after the subcommand.
Use 'dexsql <command> --help' for command-specific options and examples.

Trusted inputs:
  Use --trusted-input only with inputs from a controlled build pipeline.
  Memory-safety checks remain, but some input consistency checks may be skipped.
  For query-cache, it also skips revalidating the cache's recorded source inputs.
  Invalid inputs or stale caches can produce incorrect query results."#;

const QUERY_LONG_ABOUT: &str = r#"Examples:
  dexsql query --input app.apk --sql "SELECT count(*) FROM methods"
  dexsql query -i classes.dex -i classes2.dex -s "SELECT count(*) FROM class_defs"
  dexsql query -i app.apk -s "SELECT count(*) FROM methods" -s "SELECT count(*) FROM fields"
  dexsql query --input app.apk --interactive --timing
  dexsql query --cache "nums=SELECT 1 AS n" --sql "SELECT n FROM nums"
  dexsql query --sql "SELECT 1"

Query behavior:
  Choose --sql or --interactive. Repeat --sql to run statements in order;
  pass one statement per --sql. Inputs share one dataset; repeat --input
  for multiple files. Input is optional for SQL that needs no DEX/APK data.
  With --sql, --cache defines temporary tables for this invocation only.
  --limit caps returned rows per statement, not the work done by the query.
  Results are printed as text tables to stdout; timing goes to stderr.

Build modes:
  By default, build only the data needed by the supplied SQL. --full builds
  all metadata, references, and opcode data; query results are the same.
  Interactive mode always builds the full dataset, so --full has no effect.

Interactive input:
  Requires at least one --input file.
  Reuse the loaded dataset for SQL read from the terminal or piped stdin.
  Submit with a trailing ';' or a blank line. Use .help for help and .exit
  or .quit to quit. EOF also finishes the session.
  --cache, TEMP TABLE, and VIEW definitions are lazy and persist until DROP,
  redefinition, or session exit; query results are not cached across submissions."#;

const TABLES_LONG_ABOUT: &str = r#"Example:
  dexsql tables --input app.apk

The schema is fixed. --input is required for CLI compatibility, but its
files are not opened or read."#;

const META_LONG_ABOUT: &str = r#"Examples:
  dexsql meta --input app.apk --kind method --descriptor 'Lcom/example/Foo;->bar(I)V'
  dexsql meta -i app.apk --descriptor-file descriptors.txt --json
  dexsql meta -i app.apk --descriptor 'Lcom/example/Foo;' --json

Descriptors are DEX descriptors; class descriptors may also be given as dotted
names (converted to Lpkg/Class; for this command only). For --descriptor-file,
each non-empty line is either a descriptor or "kind|descriptor" where kind is
class, method, or field; lines starting with '#' are ignored.

Without --json each document is pretty-printed. With --json each document is
printed on one line (JSONL), which is the format used for DexKit snapshot
validation. Missing descriptors print "null"; malformed descriptors are
reported on stderr and make the command exit non-zero.

--callers adds the DexKit caller list to method documents. It is off by
default because some host methods have tens of thousands of callers.

Metadata uses the same dataset as query: relation fields (invokes,
using_strings, using_numbers, using_fields) are populated when reference
indexes were requested. This command always requests all indexes. Callers are
available separately through --callers (or Engine::metadata_callers)."#;

const PREPARE_CACHE_LONG_ABOUT: &str = r#"Examples:
  dexsql prepare-cache --input app.apk --output app-cache --timing
  dexsql prepare-cache -i classes.dex -i classes2.dex -o app-cache
  dexsql query-cache --cache-file app-cache/cache.dxc2 --sql "SELECT count(*) FROM methods"

Always builds the full dataset, including method references and opcode data.
--output is a directory; the prepared container is written as cache.dxc2
inside it. Pass that file to query-cache --cache-file."#;

const QUERY_CACHE_LONG_ABOUT: &str = r#"Examples:
  dexsql query-cache --cache-file app-cache/cache.dxc2 --sql "SELECT count(*) FROM methods"
  dexsql query-cache --cache-file app-cache/cache.dxc2 -s "SELECT * FROM class_defs" --limit 20

Create the cache first with prepare-cache. --cache-file takes the container
file, not its directory. Source inputs are revalidated unless --trusted-input
is set (see 'dexsql --help').

Repeat --sql to run statements in order; pass one statement per --sql.
--cache creates named temporary tables for the request, not a disk cache.
--limit caps returned rows per statement, not the work done by the query.
Results are printed as text tables to stdout; timing goes to stderr."#;

const DECODE_LONG_ABOUT: &str = r#"Examples:
  dexsql decode --input app.apk --method 'Lcom/example/Foo;->bar(I)V'
  dexsql decode --input app.apk --file-id 0 --method-idx 123
  dexsql decode --input app.apk --class 'Lcom/example/Foo;'

Descriptors are exact DEX descriptors. Use --file-id to disambiguate multiple DEX files.
Outputs complete method blocks to stdout after the whole selection succeeds.
Class selection includes all defined methods, without class/field/annotation/debug directives.
Original DEX bytes are loaded only for this command. Quickened/odex opcodes are unsupported."#;

#[derive(Debug)]
pub enum CliError {
    Usage(i32),
    Runtime(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(code) => *code,
            Self::Runtime(_) => 1,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(_) => Ok(()),
            Self::Runtime(msg) => f.write_str(msg),
        }
    }
}
impl std::error::Error for CliError {}

#[derive(Debug, Parser)]
#[command(
    name = "dexsql",
    version,
    about = "Query DEX/APK metadata and bytecode with SQL",
    after_help = ROOT_LONG_ABOUT,
    propagate_version = true,
    arg_required_else_help = true,
    subcommand_required = true,
    infer_subcommands = false,
    disable_help_subcommand = true
)]
struct Cli {
    #[arg(
        short = 't',
        long,
        global = true,
        help_heading = "Global options",
        value_name = "N",
        help = "Worker threads; 0 = auto (defaults to available logical CPUs)"
    )]
    threads: Option<usize>,
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        help = "Trust input validity and cache freshness; see 'dexsql --help'"
    )]
    trusted_input: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Extract resources embedded in this executable")]
    Extract(ExtractArgs),
    #[command(about = "Disassemble a method or a class's method blocks as smali")]
    Decode(DecodeArgs),
    #[command(
        about = "Run SQL on DEX/APK files, or start an interactive session",
        name = "query"
    )]
    Query(QueryArgs),
    #[command(
        about = "Read indexed class/method/field metadata (JSON)",
        name = "meta"
    )]
    Meta(MetaArgs),
    #[command(
        about = "List built-in tables, columns, and SQL types",
        name = "tables"
    )]
    Tables(TablesArgs),
    #[command(
        about = "Build a persistent cache for repeated queries",
        name = "prepare-cache"
    )]
    PrepareCache(PrepareCacheArgs),
    #[command(about = "Run SQL on a prepared cache.dxc2 file", name = "query-cache")]
    QueryCache(QueryCacheArgs),
    #[command(about = "Start an MCP server over stdin/stdout", name = "mcp")]
    Mcp(McpArgs),
    #[command(
        name = "help",
        about = "Print this message or the help of the given subcommand(s)"
    )]
    Help(HelpArgs),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("query-input").required(true).args(["sql", "interactive"])), after_help = QUERY_LONG_ABOUT)]
struct QueryArgs {
    #[arg(
        short = 'i',
        long,
        value_name = "FILE",
        help = "DEX/APK file to load (repeat for multiple files)"
    )]
    input: Vec<PathBuf>,
    #[arg(
        short = 's',
        long,
        value_name = "SQL",
        help = "SQL statement to execute (repeat to run multiple statements)"
    )]
    sql: Vec<String>,
    #[arg(
        long,
        visible_alias = "repl",
        help = "Read SQL from stdin and keep the dataset loaded"
    )]
    interactive: bool,
    #[arg(
        long,
        value_name = "NAME=SQL",
        help = "Create a named temporary table from a SELECT (repeatable)"
    )]
    cache: Vec<String>,
    #[arg(
        long,
        value_name = "N",
        help = "Maximum returned rows per statement (default: unlimited)"
    )]
    limit: Option<u64>,
    #[arg(
        long,
        help = "Build all query data (interactive mode always does this)"
    )]
    full: bool,
    #[arg(long, help = "Print preparation and query timings to stderr")]
    timing: bool,
}

#[derive(Debug, Args)]
#[command(after_help = TABLES_LONG_ABOUT)]
struct TablesArgs {
    #[arg(
        short = 'i',
        long,
        value_name = "FILE",
        required = true,
        help = "Compatibility input path; data is not read (repeatable)"
    )]
    input: Vec<PathBuf>,
}

#[derive(Debug, Args)]
#[command(after_help = META_LONG_ABOUT)]
struct MetaArgs {
    #[arg(
        short = 'i',
        long,
        value_name = "FILE",
        required = true,
        help = "DEX/APK input (repeat for multiple files)"
    )]
    input: Vec<PathBuf>,
    #[arg(
        long,
        value_name = "KIND",
        value_parser = ["class", "method", "field"],
        help = "Descriptor kind for --descriptor values (inferred when omitted)"
    )]
    kind: Option<String>,
    #[arg(
        long,
        value_name = "DESCRIPTOR",
        help = "Descriptor to read (repeatable)"
    )]
    descriptor: Vec<String>,
    #[arg(
        long,
        value_name = "FILE",
        help = "File with one descriptor or kind|descriptor per line"
    )]
    descriptor_file: Option<PathBuf>,
    #[arg(long, help = "Print one compact JSON document per line (JSONL)")]
    json: bool,
    #[arg(
        long,
        help = "Add DexKit caller lists to method documents (Phase 4 helper)"
    )]
    callers: bool,
    #[arg(long, help = "Print load and per-document timings to stderr")]
    timing: bool,
}

#[derive(Debug, Args)]
struct ExtractArgs {
    #[command(subcommand)]
    command: Option<ExtractCommand>,
}
#[derive(Debug, Subcommand)]
enum ExtractCommand {
    #[command(
        name = "licenses",
        about = "Export this executable's third-party copyright and license notices"
    )]
    Licenses,
}

#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("decode-selector")
            .required(true)
            .args(["method", "method_idx", "class"])
    ),
    after_help = DECODE_LONG_ABOUT
)]
struct DecodeArgs {
    #[arg(
        short = 'i',
        long,
        value_name = "FILE",
        required = true,
        help = "DEX/APK input (repeat for multiple files)"
    )]
    input: Vec<PathBuf>,
    #[arg(
        long,
        value_name = "FILE_ID",
        help = "Logical DEX file id, as reported by SQL"
    )]
    file_id: Option<u32>,
    #[arg(
        long,
        value_name = "METHOD",
        help = "Full method descriptor, e.g. Lcom/example/Foo;->bar(I)V"
    )]
    method: Option<String>,
    #[arg(
        long,
        value_name = "METHOD_IDX",
        requires = "file_id",
        help = "DEX-local method index (requires --file-id)"
    )]
    method_idx: Option<u32>,
    #[arg(
        long,
        value_name = "CLASS",
        help = "Full class descriptor, e.g. Lcom/example/Foo;"
    )]
    class: Option<String>,
}
#[derive(Debug, Args)]
#[command(after_help = PREPARE_CACHE_LONG_ABOUT)]
struct PrepareCacheArgs {
    #[arg(
        short = 'i',
        long,
        value_name = "FILE",
        required = true,
        help = "DEX/APK file to load (repeat for multiple files)"
    )]
    input: Vec<PathBuf>,
    #[arg(
        short = 'o',
        long,
        value_name = "DIR",
        required = true,
        help = "Output directory for the prepared cache.dxc2 container"
    )]
    output: PathBuf,
    #[arg(long, help = "Print cache build timings to stderr")]
    timing: bool,
}
#[derive(Debug, Args)]
#[command(after_help = QUERY_CACHE_LONG_ABOUT)]
struct QueryCacheArgs {
    #[arg(
        long,
        value_name = "FILE",
        required = true,
        help = "Prepared cache container file, e.g. app-cache/cache.dxc2"
    )]
    cache_file: PathBuf,
    #[arg(
        short = 's',
        long,
        value_name = "SQL",
        required = true,
        help = "SQL statement to execute (repeat to run multiple statements)"
    )]
    sql: Vec<String>,
    #[arg(
        long,
        value_name = "NAME=SQL",
        help = "Create a named temporary table from a SELECT (repeatable)"
    )]
    cache: Vec<String>,
    #[arg(
        long,
        value_name = "N",
        help = "Maximum returned rows per statement (default: unlimited)"
    )]
    limit: Option<u64>,
    #[arg(long, help = "Print preparation and query timings to stderr")]
    timing: bool,
}
#[derive(Debug, Args)]
struct HelpArgs {
    command: Option<String>,
}

#[derive(Debug, Args)]
struct McpArgs {
    #[arg(
        long,
        default_value_t = 60_000,
        help = "Maximum duration of an MCP operation, including queue time"
    )]
    timeout_ms: u64,
    #[arg(
        long,
        default_value_t = 4,
        help = "Maximum number of open or opening datasets"
    )]
    max_datasets: usize,
    #[arg(
        long,
        default_value_t = 16,
        help = "Maximum number of admitted heavy requests, including the running request"
    )]
    max_pending: usize,
    #[arg(long, default_value_t = 1 << 30, help = "Maximum total source-file bytes in one dataset")]
    max_input_bytes: u64,
    #[arg(long, default_value_t = 1 << 30, help = "Maximum uncompressed DEX bytes in one dataset")]
    max_dex_bytes: u64,
    #[arg(long, default_value_t = 2 << 30, help = "Maximum total source-file bytes across open datasets")]
    max_total_input_bytes: u64,
    #[arg(long, default_value_t = 128 << 10, help = "Maximum serialized data-tool result bytes")]
    max_output_bytes: u64,
    #[arg(long, default_value_t = 64 << 20, help = "Maximum uncompressed APK resource entry bytes")]
    max_resource_bytes: u64,
}

pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut argv = vec![OsString::from("dexsql")];
    argv.extend(args);
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return Err(CliError::Usage(code));
        }
    };
    match cli.command {
        Command::Query(args) => run_query(args, cli.threads, cli.trusted_input),
        Command::Meta(args) => run_meta(args, cli.threads),
        Command::Tables(args) => {
            print!("{}", render_tables());
            let _ = args;
            Ok(())
        }
        Command::Help(args) => print_help(args.command.as_deref()),
        Command::PrepareCache(args) => run_prepare_cache(args, cli.threads, cli.trusted_input),
        Command::QueryCache(args) => run_query_cache(args, cli.threads, cli.trusted_input),
        Command::Decode(args) => run_decode(args),
        Command::Mcp(args) => dexsql_mcp::serve_stdio(dexsql_mcp::Config {
            timeout_ms: args.timeout_ms,
            max_datasets: args.max_datasets,
            max_pending: args.max_pending,
            max_input_bytes: args.max_input_bytes,
            max_dex_bytes: args.max_dex_bytes,
            max_total_input_bytes: args.max_total_input_bytes,
            max_output_bytes: args.max_output_bytes,
            max_resource_bytes: args.max_resource_bytes,
        })
        .map_err(|e| CliError::Runtime(e.to_string())),
        Command::Extract(_) => Err(CliError::Runtime(
            "command is not implemented in this restoration build".into(),
        )),
    }
}

fn run_decode(args: DecodeArgs) -> Result<(), CliError> {
    let dataset = match args.file_id {
        Some(file_id) => Dataset::load_paths_for_decode_file(&args.input, file_id),
        None => Dataset::load_paths_for_decode(&args.input),
    }
    .map_err(|e| CliError::Runtime(e.to_string()))?;
    if let Some(method_idx) = args.method_idx {
        let Some(file) = args
            .file_id
            .and_then(|id| dataset.files.iter().find(|file| file.file_id == id))
        else {
            return Err(CliError::Runtime(
                "not_found: selected file, method, or class not found".into(),
            ));
        };
        if method_idx as usize >= file.methods.len() {
            return Err(CliError::Runtime(format!(
                "invalid_input file_id={} method_idx={}: reference index {} exceeds table size {}",
                file.file_id,
                method_idx,
                method_idx,
                file.methods.len()
            )));
        }
        let defined = file
            .class_for_method(method_idx)
            .and_then(|c| c.methods.iter().find(|m| m.method_idx == method_idx));
        if defined.is_none()
            || defined.is_some_and(|m| m.code_off == 0 && (m.access_flags & (0x100 | 0x400)) == 0)
        {
            return Err(CliError::Runtime(format!(
                "not_found file_id={} method_idx={}: method has no definition in this DEX",
                file.file_id, method_idx
            )));
        }
        return print_decode_block(file, method_idx);
    }

    if let Some(method) = args.method {
        let mut matches = Vec::new();
        for file in &dataset.files {
            if args.file_id.is_some_and(|id| id != file.file_id) {
                continue;
            }
            if let Some(idx) = decode::method_index_for_descriptor(file, &method) {
                let defined = file
                    .class_for_method(idx)
                    .and_then(|c| c.methods.iter().find(|m| m.method_idx == idx));
                if defined
                    .is_some_and(|m| m.code_off != 0 || (m.access_flags & (0x100 | 0x400)) != 0)
                {
                    matches.push((file, idx));
                }
            }
        }
        if matches.is_empty() {
            return Err(CliError::Runtime(
                "not_found: selected file, method, or class not found".into(),
            ));
        }
        if args.file_id.is_none() && matches.len() > 1 {
            let ids = matches
                .iter()
                .map(|(f, _)| f.file_id.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(CliError::Runtime(format!(
                "ambiguous: descriptor matches file_ids [{ids}]; specify file_id"
            )));
        }
        return print_decode_block(matches[0].0, matches[0].1);
    }

    let class = args.class.expect("clap selector group ensures class");
    let mut out = String::new();
    let mut matched = false;
    for file in &dataset.files {
        if args.file_id.is_some_and(|id| id != file.file_id) {
            continue;
        }
        for method in decode::method_definitions_for_class(file, &class) {
            let idx = method.method_idx;
            matched = true;
            out.push_str(
                &decode::render_method_with_flags(file, idx, Some(method.access_flags))
                    .map_err(|e| CliError::Runtime(e.to_string()))?,
            );
        }
    }
    if !matched {
        return Err(CliError::Runtime(
            "not_found: selected file, method, or class not found".into(),
        ));
    }
    print!("{out}");
    Ok(())
}

fn print_decode_block(file: &dexsql_cache::DexFile, method_idx: u32) -> Result<(), CliError> {
    let rendered =
        decode::render_method(file, method_idx).map_err(|e| CliError::Runtime(e.to_string()))?;
    print!("{rendered}");
    Ok(())
}

fn run_prepare_cache(
    args: PrepareCacheArgs,
    threads: Option<usize>,
    _trusted_input: bool,
) -> Result<(), CliError> {
    let started = Instant::now();
    dexsql_cache::configure_thread_pool(threads);
    let dataset = dexsql_cache::Dataset::load_paths(&args.input)
        .map_err(|e| CliError::Runtime(format!("load_failed: {e}")))?;
    std::fs::create_dir_all(&args.output).map_err(|e| {
        CliError::Runtime(format!(
            "failed to create output directory {}: {e}",
            args.output.display()
        ))
    })?;
    let cache_file = args.output.join("cache.dxc2");
    let parse_ms = started.elapsed().as_secs_f64() * 1000.0;
    dataset
        .write_native_cache(&cache_file)
        .map_err(|e| CliError::Runtime(format!("write_failed: {e}")))?;
    let write_ms = started.elapsed().as_secs_f64() * 1000.0 - parse_ms;
    if args.timing {
        let cached_rows: u64 = dataset
            .files
            .iter()
            .map(|f| {
                f.strings.len() as u64
                    + f.types.len() as u64
                    + f.protos.len() as u64
                    + f.fields.len() as u64
                    + f.methods.len() as u64
                    + f.classes.len() as u64
                    + f.method_strings.len() as u64
                    + f.method_numbers.len() as u64
                    + f.method_calls.len() as u64
                    + f.method_field_accesses.len() as u64
                    + f.method_used_types.len() as u64
            })
            .sum();
        eprintln!(
            "load_inputs_ms=0 parse_ms={} write_cache_ms={} cached_rows={} input_mmap_ms=0 zip_scan_ms=0 zip_inflate_ms=0 zip_inflate_wall_ms=0 zip_inflate_entry_max_ms=0 zip_inflate_cache_hits=0 zip_inflate_cache_misses=0 raw_dex_entries=0 stored_dex_entries=0 deflated_dex_entries=0 raw_dex_bytes=0 stored_dex_bytes=0 deflated_compressed_bytes=0 deflated_uncompressed_bytes=0 skipped_malformed_dex_entries=0 first_malformed_dex_error=None vmhwm_kb=0 cache_file={}",
            parse_ms.round() as u64,
            write_ms.round() as u64,
            cached_rows,
            cache_file.display()
        );
    }
    Ok(())
}

fn run_query_cache(
    args: QueryCacheArgs,
    threads: Option<usize>,
    trusted_input: bool,
) -> Result<(), CliError> {
    query::run_cache(
        QueryRequest {
            inputs: Vec::new(),
            sql: args.sql,
            interactive: false,
            caches: args.cache,
            limit: args.limit,
            full: true,
            timing: args.timing,
            threads,
            trusted_input,
        },
        &args.cache_file,
    )
    .map_err(CliError::Runtime)
}

fn run_query(args: QueryArgs, threads: Option<usize>, trusted_input: bool) -> Result<(), CliError> {
    if args.sql.is_empty() && !args.interactive {
        let mut command = Cli::command();
        if let Some(query) = command.find_subcommand_mut("query") {
            let _ = query.print_help();
        }
        return Err(CliError::Usage(2));
    }
    if args.interactive && args.input.is_empty() {
        return Err(CliError::Runtime(
            "invalid_input at build_request: at least one DEX/APK input is required".into(),
        ));
    }
    query::run(QueryRequest {
        inputs: args.input,
        sql: args.sql,
        interactive: args.interactive,
        caches: args.cache,
        limit: args.limit,
        full: args.full,
        timing: args.timing,
        threads,
        trusted_input,
    })
    .map_err(CliError::Runtime)
}

fn run_meta(args: MetaArgs, threads: Option<usize>) -> Result<(), CliError> {
    let requests = meta_requests(&args)?;
    let started = Instant::now();
    let engine = Engine::open_with_options(
        args.input.iter().cloned(),
        EngineOptions {
            index_needs: IndexNeeds::all(),
            eager_code_items: true,
            full_code_items: false,
            retain_classes: true,
            threads,
        },
    )
    .map_err(|error| CliError::Runtime(error.to_string()))?;
    let load_ms = started.elapsed().as_secs_f64() * 1000.0;
    let mut failures = 0usize;
    for query in &requests {
        let begin = Instant::now();
        match engine.metadata(query) {
            Ok(mut value) => {
                if args.callers && query.kind() == "method" && !value.is_null() {
                    let callers = engine
                        .metadata_callers(query.descriptor())
                        .map_err(CliError::Runtime)?;
                    if let serde_json::Value::Object(object) = &mut value {
                        object.insert("callers".to_owned(), callers);
                    }
                }
                let rendered = if args.json {
                    value.to_string()
                } else {
                    serde_json::to_string_pretty(&value)
                        .map_err(|error| CliError::Runtime(error.to_string()))?
                };
                println!("{rendered}");
            }
            Err(error) => {
                failures += 1;
                eprintln!(
                    "metadata failed for {} {}: {error}",
                    query.kind(),
                    query.descriptor()
                );
            }
        }
        if args.timing {
            eprintln!(
                "meta_ms={:.3} kind={} descriptor={}",
                begin.elapsed().as_secs_f64() * 1000.0,
                query.kind(),
                query.descriptor()
            );
        }
    }
    if args.timing {
        eprintln!(
            "load_ms={load_ms:.1} documents={} failures={failures}",
            requests.len()
        );
    }
    if failures > 0 {
        return Err(CliError::Runtime(format!(
            "{failures} metadata request(s) failed"
        )));
    }
    Ok(())
}

fn meta_requests(args: &MetaArgs) -> Result<Vec<MetaQuery>, CliError> {
    let mut requests = Vec::new();
    if let Some(path) = &args.descriptor_file {
        let text = std::fs::read_to_string(path).map_err(|error| {
            CliError::Runtime(format!(
                "failed to read descriptor file {}: {error}",
                path.display()
            ))
        })?;
        for (line_index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (kind, descriptor) = match line.split_once('|') {
                Some((kind, descriptor)) => (Some(kind.trim()), descriptor.trim()),
                None => (None, line),
            };
            requests.push(build_meta_query(
                kind.or(args.kind.as_deref()),
                descriptor,
                Some(line_index + 1),
            )?);
        }
    }
    for descriptor in &args.descriptor {
        requests.push(build_meta_query(args.kind.as_deref(), descriptor, None)?);
    }
    if requests.is_empty() {
        return Err(CliError::Runtime(
            "invalid_input: at least one --descriptor or --descriptor-file entry is required"
                .into(),
        ));
    }
    Ok(requests)
}

fn build_meta_query(
    kind: Option<&str>,
    descriptor: &str,
    line: Option<usize>,
) -> Result<MetaQuery, CliError> {
    let context = match line {
        Some(line) => format!("descriptor file line {line}: "),
        None => String::new(),
    };
    let descriptor = descriptor.trim();
    if descriptor.is_empty() {
        return Err(CliError::Runtime(format!("{context}empty descriptor")));
    }
    let kind = match kind {
        Some(kind) => kind.to_ascii_lowercase(),
        None => infer_meta_kind(descriptor),
    };
    match kind.as_str() {
        "class" => {
            let descriptor = if descriptor.starts_with('L') && descriptor.ends_with(';') {
                descriptor.to_owned()
            } else {
                format!("L{};", descriptor.replace('.', "/"))
            };
            dexsql_cache::metadata::class_descriptor_body(&descriptor)
                .map_err(|error| CliError::Runtime(format!("{context}{error}")))?;
            Ok(MetaQuery::class(descriptor))
        }
        "method" => Ok(MetaQuery::method(descriptor)),
        "field" => Ok(MetaQuery::field(descriptor)),
        other => Err(CliError::Runtime(format!(
            "{context}unknown descriptor kind {other:?} (expected class, method, or field)"
        ))),
    }
}

fn infer_meta_kind(descriptor: &str) -> String {
    if descriptor.contains("->") {
        if descriptor.contains('(') {
            "method"
        } else {
            "field"
        }
    } else {
        "class"
    }
    .to_owned()
}

fn print_help(command: Option<&str>) -> Result<(), CliError> {
    let mut app = Cli::command();
    match command {
        Some(name) => {
            if let Some(sub) = app.find_subcommand_mut(name) {
                let _ = sub.print_help();
            } else {
                let _ = app.error(
                    clap::error::ErrorKind::InvalidSubcommand,
                    format!("unrecognized subcommand '{name}'"),
                );
            }
        }
        None => {
            let _ = app.print_help();
        }
    }
    Ok(())
}
