//! Reference-pinned validation cases.  Every expectation was captured from
//! the release binary `dexsql-linux-amd64-0.1.1` (`--sql` one-shot mode).

use dexsql_ast::front::{Code, Statement};
use dexsql_ast::{tokenize, validate};

fn err(sql: &str) -> (Code, String) {
    let error = validate(sql).expect_err("expected validation failure");
    (error.code, error.render())
}

#[test]
fn tokenizer_point_errors() {
    assert_eq!(err("##").1, "unexpected byte 0x23 (at bytes 0..0)");
    assert_eq!(
        err("SELECT 1 !").1,
        "unexpected '!' (only '!=' is valid) (at bytes 9..9)"
    );
    assert_eq!(
        err("SELECT 'abc").1,
        "unterminated string literal (at bytes 7..7)"
    );
    assert_eq!(
        err("SELECT \"abc").1,
        "unterminated quoted identifier (at bytes 7..7)"
    );
    assert_eq!(
        err("SELECT [abc").1,
        "unterminated '[' identifier (at bytes 7..7)"
    );
    assert_eq!(
        err("SELECT x'ab").1,
        "unterminated blob literal (at bytes 7..7)"
    );
    assert_eq!(
        err("SELECT x'zz'").1,
        "non-hex byte in blob literal (at bytes 9..9)"
    );
    assert_eq!(
        err("SELECT 0x").1,
        "hex literal has no digits (at bytes 7..7)"
    );
    assert_eq!(
        err("SELECT N'abc'").1,
        "prefixed string literals are outside the DexSQL read-only subset (at bytes 7..13)"
    );
    assert_eq!(
        err("SELECT b'010'").1,
        "prefixed string literals are outside the DexSQL read-only subset (at bytes 7..13)"
    );
}

#[test]
fn statement_count_errors() {
    assert_eq!(err("").1, "expected exactly one SQL statement");
    assert_eq!(err("   ").1, "expected exactly one SQL statement");
    assert_eq!(err("/* comment */").1, "expected exactly one SQL statement");
    assert_eq!(
        err("SELECT 1; SELECT 2").1,
        "expected exactly one SQL statement, found 2 (at bytes 0..18)"
    );
}

#[test]
fn classification_errors() {
    for (sql, code, message) in [
        (
            "SELEC 1",
            Code::InvalidInput,
            "SELEC statement is outside the read-only SQLite subset (at bytes 0..5)",
        ),
        (
            "foobar 1",
            Code::InvalidInput,
            "FOOBAR statement is outside the read-only SQLite subset (at bytes 0..6)",
        ),
        (
            "123",
            Code::InvalidInput,
            "UNKNOWN statement is outside the read-only SQLite subset (at bytes 0..3)",
        ),
        (
            ".foobar",
            Code::InvalidInput,
            "UNKNOWN statement is outside the read-only SQLite subset (at bytes 0..1)",
        ),
        (
            "TABLE t",
            Code::InvalidInput,
            "TABLE statement is outside the read-only SQLite subset (at bytes 0..5)",
        ),
        (
            "TRANSACTION",
            Code::InvalidInput,
            "TRANSACTION statement is outside the read-only SQLite subset (at bytes 0..11)",
        ),
        (
            "INDEXED",
            Code::InvalidInput,
            "INDEXED statement is outside the read-only SQLite subset (at bytes 0..7)",
        ),
        (
            "DROP TABLE t",
            Code::ReadOnlyViolation,
            "DROP statement is outside the read-only SQLite subset (at bytes 0..4)",
        ),
        (
            "drop table t",
            Code::ReadOnlyViolation,
            "DROP statement is outside the read-only SQLite subset (at bytes 0..4)",
        ),
        (
            "Replace into t values (1)",
            Code::ReadOnlyViolation,
            "REPLACE statement is outside the read-only SQLite subset (at bytes 0..7)",
        ),
        (
            "ROLLBACK",
            Code::ReadOnlyViolation,
            "ROLLBACK statement is outside the read-only SQLite subset (at bytes 0..8)",
        ),
        (
            "END",
            Code::ReadOnlyViolation,
            "END statement is outside the read-only SQLite subset (at bytes 0..3)",
        ),
        (
            "EXPLAIN SELECT 1",
            Code::ReadOnlyViolation,
            "EXPLAIN statement is outside the read-only SQLite subset (at bytes 0..7)",
        ),
    ] {
        let (actual_code, actual_message) = err(sql);
        assert_eq!(actual_code, code, "code for {sql}");
        assert_eq!(actual_message, message, "message for {sql}");
    }
}

#[test]
fn create_statement_errors() {
    for (sql, code, message) in [
        (
            "CREATE TABLE t AS SELECT 1",
            Code::ReadOnlyViolation,
            "only CREATE TEMP TABLE name AS query is inside the read-only subset (at bytes 0..6)",
        ),
        (
            "CREATE TEMP INDEX i ON t(x)",
            Code::ReadOnlyViolation,
            "only CREATE TEMP TABLE name AS query is inside the read-only subset (at bytes 0..6)",
        ),
        (
            "CREATE TEMP TABLE main.t AS SELECT 1",
            Code::ReadOnlyViolation,
            "CREATE TEMP TABLE names must be unqualified or use the temp schema (at bytes 0..36)",
        ),
        (
            "CREATE TEMP TABLE \"weird name\" AS SELECT 1",
            Code::ReadOnlyViolation,
            "CREATE TEMP TABLE names must be simple SQLite identifiers (at bytes 0..42)",
        ),
        (
            "CREATE TEMP TABLE 123 AS SELECT 1",
            Code::InvalidInput,
            "expected an identifier (at bytes 22..24)",
        ),
        (
            "CREATE TEMP TABLE IF NOT EXISTS t SELECT 1",
            Code::InvalidInput,
            "expected keyword as (at bytes 34..40)",
        ),
        (
            "CREATE TEMP TABLE t AS",
            Code::InvalidInput,
            "expected keyword select",
        ),
    ] {
        let (actual_code, actual_message) = err(sql);
        assert_eq!(actual_code, code, "code for {sql}");
        assert_eq!(actual_message, message, "message for {sql}");
    }
}

#[test]
fn query_statement_errors() {
    for (sql, code, message) in [
        (
            "SELECT DISTINCT ON (1) 2",
            Code::InvalidInput,
            "DISTINCT ON is not supported (outside the read-only SQLite subset) (at bytes 16..18)",
        ),
        (
            "SELECT foo(1)",
            Code::ReadOnlyViolation,
            "function call is outside the DexSQL read-only subset (at bytes 0..13)",
        ),
        (
            "SELECT foo(1)  ",
            Code::ReadOnlyViolation,
            "function call is outside the DexSQL read-only subset (at bytes 0..13)",
        ),
        (
            "SELECT round(1.5)",
            Code::ReadOnlyViolation,
            "function call is outside the DexSQL read-only subset (at bytes 0..17)",
        ),
        (
            "SELECT random()",
            Code::ReadOnlyViolation,
            "function call is outside the DexSQL read-only subset (at bytes 0..15)",
        ),
        (
            "SELECT date('now')",
            Code::ReadOnlyViolation,
            "function call is outside the DexSQL read-only subset (at bytes 0..18)",
        ),
    ] {
        let (actual_code, actual_message) = err(sql);
        assert_eq!(actual_code, code, "code for {sql}");
        assert_eq!(actual_message, message, "message for {sql}");
    }
}

#[test]
fn accepted_statements() {
    assert!(validate("SELECT 1").is_ok());
    assert!(validate("select 1;").is_ok());
    assert!(validate("SELECT 1;;").is_ok());
    assert!(validate("SELECT 1 ").is_ok());
    assert!(validate("(SELECT 1)").is_ok());
    assert!(validate("VALUES (1),(2)").is_ok());
    assert!(validate("WITH x AS (SELECT 1) SELECT * FROM x").is_ok());
    assert!(validate("SELECT abs(-1), hex('a'), typeof(1)").is_ok());
    assert!(validate("SELECT 1 IN (SELECT 1)").is_ok());
    assert!(validate("SELECT EXISTS (SELECT 1)").is_ok());
    assert!(validate("SELECT count(*) FILTER (WHERE 1)").is_ok());
    assert!(validate("SELECT 1 UNION SELECT 2").is_ok());
    assert!(validate("SELECT a NOT BETWEEN 1 AND 2").is_ok());

    match validate("CREATE TEMP TABLE t AS SELECT 1").unwrap() {
        Statement::CreateDefinition {
            name,
            table,
            replace,
            query,
        } => {
            assert_eq!(name, "t");
            assert!(table);
            assert!(replace);
            assert_eq!(query, "SELECT 1");
        }
        other => panic!("unexpected statement: {other:?}"),
    }
    match validate("CREATE TEMP VIEW IF NOT EXISTS v AS VALUES (1)").unwrap() {
        Statement::CreateDefinition {
            name,
            table,
            replace,
            query,
        } => {
            assert_eq!(name, "v");
            assert!(!table);
            assert!(!replace);
            assert_eq!(query, "VALUES (1)");
        }
        other => panic!("unexpected statement: {other:?}"),
    }
    match validate("CREATE VIEW v AS SELECT 1").unwrap() {
        Statement::CreateDefinition { name, table, .. } => {
            assert_eq!(name, "v");
            assert!(!table);
        }
        other => panic!("unexpected statement: {other:?}"),
    }
    match validate("CREATE TEMPORARY TABLE temp.t2 AS SELECT 2").unwrap() {
        Statement::CreateDefinition { name, table, .. } => {
            assert_eq!(name, "t2");
            assert!(table);
        }
        other => panic!("unexpected statement: {other:?}"),
    }
}

#[test]
fn tokenizer_shapes() {
    let sql = "SELECT 1.5e3, .5, 0x1f, x'ab', [b], a.b";
    let tokens = tokenize(sql).unwrap();
    let kinds: Vec<&str> = tokens
        .iter()
        .map(|token| match token.kind {
            dexsql_ast::TokenKind::Ident { .. } => "ident",
            dexsql_ast::TokenKind::Number => "number",
            dexsql_ast::TokenKind::Str => "str",
            dexsql_ast::TokenKind::Blob => "blob",
            dexsql_ast::TokenKind::QuotedIdent => "quoted",
            dexsql_ast::TokenKind::LParen => "(",
            dexsql_ast::TokenKind::RParen => ")",
            dexsql_ast::TokenKind::Semicolon => ";",
            dexsql_ast::TokenKind::Comma => ",",
            dexsql_ast::TokenKind::Dot => ".",
            dexsql_ast::TokenKind::Op(ref op) => op.as_str(),
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            "ident", "number", ",", "number", ",", "number", ",", "blob", ",", "quoted", ",",
            "ident", ".", "ident"
        ]
    );
}
