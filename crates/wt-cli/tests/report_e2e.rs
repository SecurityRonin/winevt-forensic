//! End-to-end tests for `wt report` — the one-click triage command.
//!
//! `wt report <path> [--carved] [--output <dir>] [--hayabusa-bin <bin>]`
//!
//! Input detection:
//!   *.E01 / *.Ex01  →  NTFS filesystem extraction; `--carved` adds full-image carve
//!   *.evtx          →  direct pass-through to Hayabusa
//!   directory       →  all *.evtx in the tree
//!   any other blob  →  raw carve for ElfChnk magic
//!
//! Tests that require the MaxPowersCDrive.E01 image or the fox-it corpus skip
//! gracefully when the files are absent.

use std::process::Command;

fn wt_bin() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../target/debug/wt");
    p
}

fn workspace_root() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn foxitdata_path(name: &str) -> std::path::PathBuf {
    workspace_root().join("tests/data/fox-it-danderspritz").join(name)
}

fn maxpowers_e01() -> std::path::PathBuf {
    workspace_root().join("tests/data/DEF CON DFIR CTF 2018/MaxPowersCDrive.E01")
}

macro_rules! require_foxitdata {
    ($name:expr) => {{
        let p = foxitdata_path($name);
        if !p.exists() {
            eprintln!("SKIP: {} not found", p.display());
            return;
        }
        p
    }};
}

macro_rules! require_maxpowers {
    () => {{
        let p = maxpowers_e01();
        if !p.exists() {
            eprintln!("SKIP: MaxPowersCDrive.E01 not found");
            return;
        }
        p
    }};
}

// ── always-run tests ──────────────────────────────────────────────────────────

/// `wt report` with no arguments must exit non-zero (clap usage error).
#[test]
fn report_no_args_exits_nonzero() {
    let status = Command::new(wt_bin())
        .arg("report")
        .status()
        .expect("run wt report");
    assert!(!status.success(), "expected non-zero exit for missing path arg");
}

/// `wt report /nonexistent/path.E01` must exit 2.
#[test]
fn report_nonexistent_file_exits_2() {
    let status = Command::new(wt_bin())
        .args(["report", "/nonexistent/evidence.E01"])
        .status()
        .expect("run wt report nonexistent");
    assert_eq!(status.code(), Some(2), "expected exit code 2 for missing file");
}

// ── EVTX pass-through ─────────────────────────────────────────────────────────

/// `wt report <file.evtx>` must exit 0 and output a JSON object.
#[test]
fn report_single_evtx_outputs_json() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let out = tempfile::tempdir().expect("tempdir");

    let output = Command::new(wt_bin())
        .args([
            "report",
            evtx.to_str().unwrap(),
            "--output",
            out.path().to_str().unwrap(),
        ])
        .output()
        .expect("run wt report evtx");

    assert_eq!(output.status.code(), Some(0), "expected exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr));

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    assert!(json.get("input").is_some(), "JSON must have 'input' field");
    assert!(json.get("evtx_files").is_some(), "JSON must have 'evtx_files' field");
}

// ── directory input ───────────────────────────────────────────────────────────

/// `wt report <dir>` containing EVTX files must exit 0 and list them.
#[test]
fn report_evtx_directory_outputs_json() {
    let dir = foxitdata_path(".");
    if !dir.exists() {
        eprintln!("SKIP: fox-it corpus dir not found");
        return;
    }

    let out = tempfile::tempdir().expect("tempdir");

    let output = Command::new(wt_bin())
        .args([
            "report",
            dir.to_str().unwrap(),
            "--output",
            out.path().to_str().unwrap(),
        ])
        .output()
        .expect("run wt report dir");

    assert_eq!(output.status.code(), Some(0), "expected exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr));

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    let files = json["evtx_files"].as_array().expect("evtx_files must be array");
    assert!(!files.is_empty(), "expected at least one EVTX file from directory");
}

// ── raw blob input ────────────────────────────────────────────────────────────

/// `wt report <file.evtx renamed to .bin>` must carve and exit 0.
#[test]
fn report_raw_blob_carves_evtx() {
    let evtx = require_foxitdata!("post-Security.evtx");
    let out = tempfile::tempdir().expect("tempdir");

    // Copy the EVTX to a .bin file so it's treated as a raw blob.
    let blob = out.path().join("evidence.bin");
    std::fs::copy(&evtx, &blob).expect("copy evtx to blob");

    let output = Command::new(wt_bin())
        .args([
            "report",
            blob.to_str().unwrap(),
            "--output",
            out.path().to_str().unwrap(),
        ])
        .output()
        .expect("run wt report blob");

    assert_eq!(output.status.code(), Some(0), "expected exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr));

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    assert_eq!(json["input"]["kind"].as_str(), Some("RawBlob"));
    let files = json["evtx_files"].as_array().expect("evtx_files must be array");
    assert!(!files.is_empty(), "expected carved EVTX chunks from blob");
}

// ── E01 filesystem extraction ─────────────────────────────────────────────────

/// `wt report <image.E01>` must exit 0, output JSON with evtx_files including
/// Security.evtx and System.evtx.
#[test]
fn report_e01_filesystem_finds_security_and_system() {
    let e01 = require_maxpowers!();
    let out = tempfile::tempdir().expect("tempdir");

    let output = Command::new(wt_bin())
        .args([
            "report",
            e01.to_str().unwrap(),
            "--output",
            out.path().to_str().unwrap(),
        ])
        .output()
        .expect("run wt report E01");

    assert_eq!(output.status.code(), Some(0), "expected exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr));

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    assert_eq!(json["input"]["kind"].as_str(), Some("E01"));

    let files = json["evtx_files"].as_array().expect("evtx_files must be array");
    let names: Vec<_> = files
        .iter()
        .filter_map(|f| f["name"].as_str())
        .collect();
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("Security.evtx")),
        "expected Security.evtx; got {names:?}"
    );
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("System.evtx")),
        "expected System.evtx; got {names:?}"
    );
}

/// `wt report <image.E01> --carved` adds carved results on top of NTFS extraction.
#[test]
fn report_e01_carved_flag_includes_carved_source() {
    let e01 = require_maxpowers!();
    let out = tempfile::tempdir().expect("tempdir");

    let output = Command::new(wt_bin())
        .args([
            "report",
            e01.to_str().unwrap(),
            "--carved",
            "--output",
            out.path().to_str().unwrap(),
        ])
        .output()
        .expect("run wt report E01 --carved");

    assert_eq!(output.status.code(), Some(0), "expected exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr));

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    let files = json["evtx_files"].as_array().expect("evtx_files must be array");

    // At least one entry should be sourced from carving.
    let has_carved = files.iter().any(|f| f["source"].as_str() == Some("carved"));
    assert!(has_carved, "expected at least one carved entry with --carved flag; got {files:?}");
}

/// Each EVTX in the report should have an `integrity_indicators` array field.
#[test]
fn report_e01_evtx_files_have_integrity_indicators() {
    let e01 = require_maxpowers!();
    let out = tempfile::tempdir().expect("tempdir");

    let output = Command::new(wt_bin())
        .args([
            "report",
            e01.to_str().unwrap(),
            "--output",
            out.path().to_str().unwrap(),
        ])
        .output()
        .expect("run wt report E01");

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    let files = json["evtx_files"].as_array().expect("evtx_files must be array");
    for f in files {
        assert!(
            f.get("integrity_indicators").is_some(),
            "every evtx_file entry must have integrity_indicators: {f}"
        );
    }
}
