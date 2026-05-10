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
        .args(["extract", "--ioc", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt extract --ioc nonexistent");
    assert_eq!(status.code(), Some(3));
}

// ── Exit code 1: detections found ────────────────────────────────────────────

#[test]
fn ioc_extract_with_iocs_exits_1() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let status = Command::new(wt_bin())
        .args(["extract", "--ioc", evtx.to_str().unwrap()])
        .status()
        .expect("run wt extract --ioc");
    assert_eq!(
        status.code(),
        Some(1),
        "extract --ioc with IOCs present must exit 1"
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
fn login_stream_exits_0() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let status = Command::new(wt_bin())
        .args(["login", "--stream", evtx.to_str().unwrap()])
        .status()
        .expect("run wt login --stream");
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

// ── wt timeline --filter-eid ──────────────────────────────────────────────────

#[test]
fn timeline_filter_eid_returns_only_matching_events() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["timeline", "--filter-eid", "4624", evtx.to_str().unwrap()])
        .output()
        .expect("run wt timeline --filter-eid 4624");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be JSON array");
    assert!(!arr.is_empty(), "4624 (logon) must appear in Security log");
    for entry in arr {
        assert_eq!(
            entry["event_id"].as_u64().unwrap_or(0),
            4624,
            "all events must have event_id 4624; got: {entry}"
        );
    }
}

#[test]
fn timeline_filter_eid_unknown_returns_empty() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["timeline", "--filter-eid", "9999999", evtx.to_str().unwrap()])
        .output()
        .expect("run wt timeline --filter-eid 9999999");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert_eq!(
        json.as_array().unwrap().len(),
        0,
        "EID 9999999 must return empty array"
    );
}

// ── wt timeline --limit ───────────────────────────────────────────────────────

#[test]
fn timeline_limit_caps_output() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["timeline", "--limit", "5", evtx.to_str().unwrap()])
        .output()
        .expect("run wt timeline --limit 5");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(
        json.as_array().unwrap().len() <= 5,
        "--limit 5 must return at most 5 events"
    );
}

// ── wt login --logon-type ─────────────────────────────────────────────────────

#[test]
fn login_logon_type_filters_results() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["login", "--logon-type", "3", evtx.to_str().unwrap()])
        .output()
        .expect("run wt login --logon-type 3");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(json.is_array());
    for session in json.as_array().unwrap() {
        assert_eq!(
            session["logon_type"].as_u64().unwrap_or(999),
            3,
            "all returned sessions must have logon_type 3"
        );
    }
}

#[test]
fn login_logon_type_999_returns_empty() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["login", "--logon-type", "999", evtx.to_str().unwrap()])
        .output()
        .expect("run wt login --logon-type 999");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert_eq!(
        json.as_array().unwrap().len(),
        0,
        "logon_type 999 must return empty array"
    );
}

// ── wt timeline --after / --before ───────────────────────────────────────────

#[test]
fn timeline_after_before_filters_time_range() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    // Request a narrow window in 2017
    let output = Command::new(wt_bin())
        .args([
            "timeline",
            "--after",
            "2017-12-01T00:00:00Z",
            "--before",
            "2018-01-01T00:00:00Z",
            evtx.to_str().unwrap(),
        ])
        .output()
        .expect("run wt timeline --after --before");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(json.is_array());
    // All returned events must fall within the requested range.
    for entry in json.as_array().unwrap() {
        let ts = entry["timestamp"].as_str().unwrap_or("");
        assert!(
            ts >= "2017-12-01T00:00:00Z",
            "timestamp {ts} is before --after bound"
        );
        assert!(
            ts < "2018-01-01T00:00:00Z",
            "timestamp {ts} is at/after --before bound"
        );
    }
}

#[test]
fn timeline_before_epoch_returns_empty() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args([
            "timeline",
            "--before",
            "1970-01-01T00:00:00Z",
            evtx.to_str().unwrap(),
        ])
        .output()
        .expect("run wt timeline --before epoch");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert_eq!(
        json.as_array().unwrap().len(),
        0,
        "--before 1970 must return empty array"
    );
}

// ── wt frequency --top ────────────────────────────────────────────────────────

#[test]
fn frequency_top_caps_results() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["frequency", "--top", "3", evtx.to_str().unwrap()])
        .output()
        .expect("run wt frequency --top 3");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json["by_event_id"].as_array().expect("by_event_id");
    assert!(arr.len() <= 3, "--top 3 must return at most 3 entries");
}

#[test]
fn frequency_top_0_returns_no_entries() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["frequency", "--top", "0", evtx.to_str().unwrap()])
        .output()
        .expect("run wt frequency --top 0");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json["by_event_id"].as_array().expect("by_event_id");
    assert_eq!(arr.len(), 0, "--top 0 must return empty by_event_id");
}
