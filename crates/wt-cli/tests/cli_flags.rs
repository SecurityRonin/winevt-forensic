//! Tests for exit-code semantics, --stream NDJSON mode, and --sort asc (LFO).

use std::path::PathBuf;
use std::process::Command;

fn wt_bin() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../target/debug/wt");
    p
}

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn foxitdata(name: &str) -> PathBuf {
    workspace_root().join("tests/data/fox-it-danderspritz").join(name)
}

macro_rules! require_foxitdata {
    ($name:expr) => {{
        let p = foxitdata($name);
        if !p.exists() {
            eprintln!("SKIP: {} not found", p.display());
            return;
        }
        p
    }};
}

// ── Exit code 3: path not found ───────────────────────────────────────────────

#[test]
fn verify_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["verify", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt verify nonexistent");
    assert_eq!(status.code(), Some(3), "nonexistent path must exit 3, not 2");
}

#[test]
fn timeline_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["timeline", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt timeline nonexistent");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn ioc_extract_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["ioc-extract", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt ioc-extract nonexistent");
    assert_eq!(status.code(), Some(3));
}

// ── Exit code 1: detections found ────────────────────────────────────────────

#[test]
fn ioc_extract_with_iocs_exits_1() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let status = Command::new(wt_bin())
        .args(["ioc-extract", evtx.to_str().unwrap()])
        .status()
        .expect("run wt ioc-extract");
    assert_eq!(
        status.code(),
        Some(1),
        "ioc-extract with IOCs present must exit 1"
    );
}

// ── --stream: NDJSON (one JSON object per line) ───────────────────────────────

#[test]
fn timeline_stream_is_ndjson() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["timeline", "--stream", evtx.to_str().unwrap()])
        .output()
        .expect("run wt timeline --stream");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.trim_start().starts_with('['),
        "--stream output must not start with '['"
    );
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let _: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}"));
    }
}

#[test]
fn frequency_stream_is_ndjson() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["frequency", "--stream", evtx.to_str().unwrap()])
        .output()
        .expect("run wt frequency --stream");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim_start().starts_with('['));
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|_| panic!("not JSON: {line}"));
        assert!(v.get("event_id").is_some(), "each line must have event_id");
    }
}

#[test]
fn sessions_stream_exits_0() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let status = Command::new(wt_bin())
        .args(["sessions", "--stream", evtx.to_str().unwrap()])
        .status()
        .expect("run wt sessions --stream");
    assert_eq!(status.code(), Some(0));
}

// ── --sort asc (LFO: least-frequent-first) ───────────────────────────────────

#[test]
fn frequency_sort_asc_is_ascending() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["frequency", "--sort", "asc", evtx.to_str().unwrap()])
        .output()
        .expect("run wt frequency --sort asc");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let freqs = json["by_event_id"].as_array().expect("by_event_id array");
    if freqs.len() >= 2 {
        let first = freqs[0]["count"].as_u64().unwrap_or(0);
        let last = freqs[freqs.len() - 1]["count"].as_u64().unwrap_or(0);
        assert!(first <= last, "LFO: first ({first}) must be <= last ({last})");
    }
}

#[test]
fn frequency_sort_desc_is_descending() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["frequency", "--sort", "desc", evtx.to_str().unwrap()])
        .output()
        .expect("run wt frequency --sort desc");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let freqs = json["by_event_id"].as_array().expect("by_event_id array");
    if freqs.len() >= 2 {
        let first = freqs[0]["count"].as_u64().unwrap_or(0);
        let last = freqs[freqs.len() - 1]["count"].as_u64().unwrap_or(0);
        assert!(first >= last, "desc: first ({first}) must be >= last ({last})");
    }
}
