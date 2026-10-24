//! Command-line contract tests for `dexsql meta`.
//!
//! Desktop DexKit-snapshot validation drives the command with
//! `--descriptor-file FILE --json` and expects one JSON document per input line,
//! in input order, with `null` for missing descriptors.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/dex")
        .join(name)
}

fn descriptor_file(name: &str, lines: &[&str]) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("dexsql-meta-cli-{}-{name}.txt", std::process::id()));
    let mut file = std::fs::File::create(&path).expect("create descriptor file");
    for line in lines {
        writeln!(file, "{line}").expect("write descriptor line");
    }
    path
}

fn run_meta(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dexsql"))
        .arg("meta")
        .args(["-i", fixture("alpha.dex").to_str().unwrap()])
        .args(["-i", fixture("beta.dex").to_str().unwrap()])
        .args(args)
        .output()
        .expect("run dexsql meta")
}

#[test]
fn meta_emits_one_document_per_input_in_order() {
    let descriptors = descriptor_file(
        "order",
        &[
            "# comment lines are ignored",
            "class|fixtures.Alpha",
            "method|Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I",
            "Lfixtures/Alpha;->name:Ljava/lang/String;",
            "class|does.Not.Exist",
        ],
    );
    let output = run_meta(&["--descriptor-file", descriptors.to_str().unwrap(), "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 4, "one compact JSON document per input line");
    let class: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(class["kind"], "class");
    assert_eq!(class["name"], "fixtures.Alpha");
    let method: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(method["kind"], "method");
    assert_eq!(method["method_sign"], "(IJLjava/lang/String;[I)I");
    let field: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(field["kind"], "field");
    assert_eq!(field["type_name"], "java.lang.String");
    assert!(serde_json::from_str::<serde_json::Value>(lines[3])
        .unwrap()
        .is_null());

    std::fs::remove_file(descriptors).ok();
}

#[test]
fn meta_accepts_repeated_descriptor_flags() {
    let output = run_meta(&[
        "--kind",
        "method",
        "--descriptor",
        "Lfixtures/Alpha;->greet(Ljava/lang/String;)Ljava/lang/String;",
        "--descriptor",
        "Lfixtures/Alpha;->helper()I",
        "--json",
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert_eq!(stdout.lines().count(), 2);
    assert!(stdout.lines().all(|line| line.starts_with('{')));
}

#[test]
fn meta_reports_malformed_requests_and_keeps_other_documents() {
    let descriptors = descriptor_file(
        "malformed",
        &[
            "method|Lfixtures/Alpha;->helper()I",
            "method|definitely not a descriptor",
        ],
    );
    let output = run_meta(&["--descriptor-file", descriptors.to_str().unwrap(), "--json"]);
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert_eq!(stdout.lines().count(), 1);
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("metadata failed for method definitely not a descriptor"),
        "stderr: {stderr}"
    );
    std::fs::remove_file(descriptors).ok();
}

#[test]
fn meta_requires_at_least_one_descriptor() {
    let output = run_meta(&["--json"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("at least one --descriptor or --descriptor-file entry is required"),
        "stderr: {stderr}"
    );
}

#[test]
fn meta_callers_flag_adds_the_caller_list() {
    let output = run_meta(&[
        "--kind",
        "method",
        "--descriptor",
        "Lfixtures/Alpha;->add(IJLjava/lang/String;[I)I",
        "--callers",
        "--json",
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let method: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let callers = method["callers"].as_array().expect("callers array");
    let descriptors = callers
        .iter()
        .map(|caller| caller["descriptor"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        descriptors,
        ["Lfixtures/Alpha;->doIt()V", "Lfixtures/Beta;->run()V"]
    );
}
