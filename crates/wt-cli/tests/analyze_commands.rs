//! Integration tests for new analysis subcommands:
//! pivot, diff, process-tree, logon-graph, rare-process, hunt.

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

// ── wt pivot ─────────────────────────────────────────────────────────────────

#[test]
fn pivot_finds_matching_events() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    // "Security" appears in channel/provider fields of almost every Security event
    let output = Command::new(wt_bin())
        .args(["pivot", "Security", evtx.to_str().unwrap()])
        .output()
        .expect("run wt pivot");
    assert_eq!(
        output.status.code(),
        Some(1),
        "pivot with matches must exit 1; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("pivot must output JSON");
    assert!(json.is_array(), "pivot output must be array");
    assert!(!json.as_array().unwrap().is_empty(), "expected matches");
}

#[test]
fn pivot_no_match_exits_0() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["pivot", "ZZZTHISSHOULDNOTMATCHANYTHING_XYZ_9999", evtx.to_str().unwrap()])
        .output()
        .expect("run wt pivot no-match");
    assert_eq!(output.status.code(), Some(0), "no-match pivot must exit 0");
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[test]
fn pivot_stream_flag() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["pivot", "--stream", "Security", evtx.to_str().unwrap()])
        .output()
        .expect("run wt pivot --stream");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim_start().starts_with('['), "--stream must not be a JSON array");
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let _: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|_| panic!("not JSON: {line}"));
    }
}

#[test]
fn pivot_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["pivot", "anything", "/nonexistent/file.evtx"])
        .status()
        .expect("run wt pivot nonexistent");
    assert_eq!(status.code(), Some(3));
}

// ── wt diff ──────────────────────────────────────────────────────────────────

#[test]
fn diff_identical_file_exits_0() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["diff", evtx.to_str().unwrap(), evtx.to_str().unwrap()])
        .output()
        .expect("run wt diff identical");
    assert_eq!(
        output.status.code(),
        Some(0),
        "diffing a file with itself must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert_eq!(json["added"].as_array().unwrap().len(), 0);
    assert_eq!(json["removed"].as_array().unwrap().len(), 0);
}

#[test]
fn diff_different_files_exits_1() {
    let a = require_foxitdata!("pre-Security.evtx");
    let b = require_foxitdata!("post-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["diff", a.to_str().unwrap(), b.to_str().unwrap()])
        .output()
        .expect("run wt diff different");
    assert_eq!(
        output.status.code(),
        Some(1),
        "diffing different files must exit 1; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(json.get("added").is_some() && json.get("removed").is_some());
}

// ── wt process-tree ───────────────────────────────────────────────────────────

#[test]
fn process_tree_json_output() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["process-tree", evtx.to_str().unwrap()])
        .output()
        .expect("run wt process-tree");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(json.is_array(), "process-tree must output JSON array");
}

#[test]
fn process_tree_mermaid_flag() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["process-tree", "--mermaid", evtx.to_str().unwrap()])
        .output()
        .expect("run wt process-tree --mermaid");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("graph"),
        "mermaid output must contain 'graph'; got: {stdout}"
    );
}

// ── wt logon-graph ────────────────────────────────────────────────────────────

#[test]
fn logon_graph_json_output() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["logon-graph", evtx.to_str().unwrap()])
        .output()
        .expect("run wt logon-graph");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(json.get("nodes").is_some(), "logon-graph must have 'nodes'");
    assert!(json.get("edges").is_some(), "logon-graph must have 'edges'");
}

#[test]
fn logon_graph_mermaid_flag() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["logon-graph", "--mermaid", evtx.to_str().unwrap()])
        .output()
        .expect("run wt logon-graph --mermaid");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("graph"), "mermaid output must contain 'graph'");
}

// ── wt frequency --by process ─────────────────────────────────────────────────

#[test]
fn rare_process_json_output() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["frequency", "--by", "process", evtx.to_str().unwrap()])
        .output()
        .expect("run wt frequency --by process");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(json.is_array(), "frequency --by process must output JSON array");
}

#[test]
fn rare_process_threshold_999_returns_all() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let low = Command::new(wt_bin())
        .args(["frequency", "--by", "process", "--threshold", "3", evtx.to_str().unwrap()])
        .output()
        .expect("threshold 3");
    let high = Command::new(wt_bin())
        .args(["frequency", "--by", "process", "--threshold", "999999", evtx.to_str().unwrap()])
        .output()
        .expect("threshold 999999");
    let low_json: serde_json::Value = serde_json::from_slice(&low.stdout).unwrap();
    let high_json: serde_json::Value = serde_json::from_slice(&high.stdout).unwrap();
    let low_len = low_json.as_array().unwrap().len();
    let high_len = high_json.as_array().unwrap().len();
    assert!(
        high_len >= low_len,
        "higher threshold must return >= results ({high_len} vs {low_len})"
    );
}

// ── wt hunt (removed — detection delegated to hayabusa/chainsaw) ─────────────

#[test]
fn wt_hunt_is_removed() {
    let status = Command::new(wt_bin())
        .args(["hunt", "--help"])
        .status()
        .expect("run wt hunt --help");
    assert!(!status.success(), "wt hunt must no longer exist");
}

// ── wt frequency --anomaly ────────────────────────────────────────────────────

#[test]
fn anomaly_json_output() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["frequency", "--anomaly", evtx.to_str().unwrap()])
        .output()
        .expect("run wt frequency --anomaly");
    let code = output.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 1, "frequency --anomaly must exit 0 or 1, got {code}");
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("frequency --anomaly must output JSON");
    assert!(json.is_array(), "frequency --anomaly must output JSON array");
    if let Some(arr) = json.as_array() {
        if !arr.is_empty() {
            let first = &arr[0];
            assert!(first.get("event_id").is_some(), "must have event_id");
            assert!(first.get("count").is_some(), "must have count");
            assert!(first.get("z_score").is_some(), "must have z_score");
        }
    }
}

#[test]
fn anomaly_high_min_z_returns_fewer_results() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let low = Command::new(wt_bin())
        .args(["frequency", "--anomaly", "--min-z", "0", evtx.to_str().unwrap()])
        .output()
        .expect("frequency --anomaly min-z 0");
    let high = Command::new(wt_bin())
        .args(["frequency", "--anomaly", "--min-z", "999", evtx.to_str().unwrap()])
        .output()
        .expect("frequency --anomaly min-z 999");
    let low_json: serde_json::Value = serde_json::from_slice(&low.stdout).unwrap();
    let high_json: serde_json::Value = serde_json::from_slice(&high.stdout).unwrap();
    assert!(
        high_json.as_array().unwrap().len() <= low_json.as_array().unwrap().len(),
        "higher min-z must return <= results"
    );
}

#[test]
fn anomaly_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["frequency", "--anomaly", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt frequency --anomaly nonexistent");
    assert_eq!(status.code(), Some(3));
}

// ── wt extract ────────────────────────────────────────────────────────────────

#[test]
fn extract_known_field_returns_json_array() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["extract", "SubjectUserName", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract");
    assert_eq!(
        output.status.code(),
        Some(0),
        "extract must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("extract must output JSON");
    assert!(json.is_array(), "extract must output JSON array");
}

#[test]
fn extract_unknown_field_returns_empty_array() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["extract", "ZZZNOFIELD999XYZ", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract unknown field");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert_eq!(
        json.as_array().unwrap().len(),
        0,
        "unknown field must return empty array"
    );
}

#[test]
fn extract_nonexistent_file_exits_3() {
    let status = Command::new(wt_bin())
        .args(["extract", "SubjectUserName", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt extract nonexistent");
    assert_eq!(status.code(), Some(3));
}

// ── wt info ───────────────────────────────────────────────────────────────────

#[test]
fn summary_json_has_required_fields() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["info", evtx.to_str().unwrap()])
        .output()
        .expect("run wt info");
    assert_eq!(
        output.status.code(),
        Some(0),
        "info must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("info must output JSON");
    assert!(json.get("file").is_some(), "must have 'file'");
    assert!(json.get("total_events").is_some(), "must have 'total_events'");
    assert!(json.get("time_range").is_some(), "must have 'time_range'");
    assert!(json.get("top_event_ids").is_some(), "must have 'top_event_ids'");
    assert!(json.get("integrity_indicators").is_some(), "must have 'integrity_indicators'");
    assert!(json.get("ioc_count").is_some(), "must have 'ioc_count'");
}

#[test]
fn summary_top_event_ids_has_at_most_5() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["info", evtx.to_str().unwrap()])
        .output()
        .expect("run wt info");
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let top = json["top_event_ids"].as_array().expect("top_event_ids must be array");
    assert!(top.len() <= 5, "top_event_ids must have at most 5 entries, got {}", top.len());
}

#[test]
fn summary_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["info", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt info nonexistent");
    assert_eq!(status.code(), Some(3));
}
