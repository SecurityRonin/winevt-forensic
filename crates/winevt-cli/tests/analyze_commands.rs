//! Integration tests for new analysis subcommands:
//! pivot, diff, process-tree, logon-graph, rare-process, hunt.

use std::path::PathBuf;
use std::process::Command;

fn wt_bin() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../target/debug/ev4n6");
    p
}

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn foxitdata(name: &str) -> PathBuf {
    workspace_root()
        .join("tests/data/fox-it-danderspritz")
        .join(name)
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

// ── wt pivot removed: replaced by wt search ──────────────────────────────────

#[test]
fn wt_pivot_is_removed() {
    let status = Command::new(wt_bin())
        .args(["pivot", "--help"])
        .status()
        .expect("run wt pivot --help");
    assert!(
        !status.success(),
        "wt pivot must no longer exist (use wt search)"
    );
}

// ── wt search (replaces pivot, adds --regex) ──────────────────────────────────

#[test]
fn search_finds_matching_events() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["search", "Security", evtx.to_str().unwrap()])
        .output()
        .expect("run wt search");
    assert_eq!(
        output.status.code(),
        Some(1),
        "search with matches must exit 1; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("search must output JSON");
    assert!(json.is_array(), "search output must be array");
    assert!(!json.as_array().unwrap().is_empty(), "expected matches");
}

#[test]
fn search_no_match_exits_0() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args([
            "search",
            "ZZZTHISSHOULDNOTMATCHANYTHING_XYZ_9999",
            evtx.to_str().unwrap(),
        ])
        .output()
        .expect("run wt search no-match");
    assert_eq!(output.status.code(), Some(0), "no-match search must exit 0");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[test]
fn search_stream_flag() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["search", "--stream", "Security", evtx.to_str().unwrap()])
        .output()
        .expect("run wt search --stream");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.trim_start().starts_with('['),
        "--stream must not be a JSON array"
    );
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let _: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}"));
    }
}

#[test]
fn search_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["search", "anything", "/nonexistent/file.evtx"])
        .status()
        .expect("run wt search nonexistent");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn search_regex_matches_pattern() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["search", "--regex", "Secur.*", evtx.to_str().unwrap()])
        .output()
        .expect("run wt search --regex");
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "search --regex must exit 0 or 1, got {code}; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("search --regex must output JSON");
    assert!(json.is_array(), "search --regex output must be array");
}

#[test]
fn search_regex_no_match_exits_0() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args([
            "search",
            "--regex",
            "^ZZZIMPOSSIBLE_PATTERN_9{50}$",
            evtx.to_str().unwrap(),
        ])
        .output()
        .expect("run wt search --regex no-match");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert_eq!(json.as_array().unwrap().len(), 0);
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
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
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
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
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
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
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

// ── wt logon-graph removed: wt login --graph replaces it ─────────────────────

#[test]
fn wt_logon_graph_is_removed() {
    let status = Command::new(wt_bin())
        .args(["logon-graph", "--help"])
        .status()
        .expect("run wt logon-graph --help");
    assert!(
        !status.success(),
        "wt logon-graph must no longer exist (use wt login --graph)"
    );
}

#[test]
fn login_graph_json_output() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["login", "--graph", evtx.to_str().unwrap()])
        .output()
        .expect("run wt login --graph");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(
        json.get("nodes").is_some(),
        "login --graph must have 'nodes'"
    );
    assert!(
        json.get("edges").is_some(),
        "login --graph must have 'edges'"
    );
}

#[test]
fn login_mermaid_flag() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["login", "--mermaid", evtx.to_str().unwrap()])
        .output()
        .expect("run wt login --mermaid");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("graph"),
        "mermaid output must contain 'graph'"
    );
}

// ── wt frequency --process (replaces --by process; --threshold dropped) ──────

#[test]
fn frequency_by_flag_is_rejected() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let status = Command::new(wt_bin())
        .args(["frequency", "--by", "process", evtx.to_str().unwrap()])
        .status()
        .expect("run wt frequency --by process");
    assert!(
        !status.success(),
        "--by is no longer supported; use --process"
    );
}

#[test]
fn frequency_threshold_flag_is_rejected() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let status = Command::new(wt_bin())
        .args([
            "frequency",
            "--process",
            "--threshold",
            "3",
            evtx.to_str().unwrap(),
        ])
        .status()
        .expect("run wt frequency --process --threshold 3");
    assert!(
        !status.success(),
        "--threshold is no longer supported; pipe to head/jq instead"
    );
}

#[test]
fn frequency_process_flag_returns_json_array() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["frequency", "--process", evtx.to_str().unwrap()])
        .output()
        .expect("run wt frequency --process");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("frequency --process must output JSON");
    assert!(
        json.is_array(),
        "frequency --process output must be JSON array"
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
    assert!(
        code == 0 || code == 1,
        "frequency --anomaly must exit 0 or 1, got {code}"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("frequency --anomaly must output JSON");
    assert!(
        json.is_array(),
        "frequency --anomaly must output JSON array"
    );
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
        .args([
            "frequency",
            "--anomaly",
            "--min-z",
            "0",
            evtx.to_str().unwrap(),
        ])
        .output()
        .expect("frequency --anomaly min-z 0");
    let high = Command::new(wt_bin())
        .args([
            "frequency",
            "--anomaly",
            "--min-z",
            "999",
            evtx.to_str().unwrap(),
        ])
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
        .args([
            "extract",
            "--field",
            "SubjectUserName",
            evtx.to_str().unwrap(),
        ])
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
        .args([
            "extract",
            "--field",
            "ZZZNOFIELD999XYZ",
            evtx.to_str().unwrap(),
        ])
        .output()
        .expect("run wt extract unknown field");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert_eq!(
        json.as_array().unwrap().len(),
        0,
        "unknown field must return empty array"
    );
}

#[test]
fn extract_nonexistent_file_exits_3() {
    let status = Command::new(wt_bin())
        .args([
            "extract",
            "--field",
            "SubjectUserName",
            "/nonexistent/Security.evtx",
        ])
        .status()
        .expect("run wt extract nonexistent");
    assert_eq!(status.code(), Some(3));
}

// ── wt extract --powershell (replaces wt powershell) ─────────────────────────

#[test]
fn extract_powershell_json_output() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["extract", "--powershell", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --powershell");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("extract --powershell must output JSON");
    assert!(
        json.is_array(),
        "extract --powershell output must be JSON array"
    );
}

#[test]
fn extract_powershell_no_deobfuscate_accepted() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args([
            "extract",
            "--powershell",
            "--no-deobfuscate",
            evtx.to_str().unwrap(),
        ])
        .output()
        .expect("run wt extract --powershell --no-deobfuscate");
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(json.is_array());
}

#[test]
fn extract_powershell_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["extract", "--powershell", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt extract --powershell nonexistent");
    assert_eq!(status.code(), Some(3));
}

// ── wt extract --wmi (EID 5857-5861: WMI provider/subscription events) ────────

#[test]
fn extract_wmi_json_output() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["extract", "--wmi", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --wmi");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("extract --wmi must output JSON");
    assert!(json.is_array(), "extract --wmi output must be JSON array");
}

#[test]
fn extract_wmi_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["extract", "--wmi", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt extract --wmi nonexistent");
    assert_eq!(status.code(), Some(3));
}

// ── wt extract --scheduled-task (EID 4698/4702) ───────────────────────────────

#[test]
fn extract_scheduled_task_json_output() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["extract", "--scheduled-task", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --scheduled-task");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("extract --scheduled-task must output JSON");
    assert!(
        json.is_array(),
        "extract --scheduled-task output must be JSON array"
    );
}

#[test]
fn extract_scheduled_task_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["extract", "--scheduled-task", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt extract --scheduled-task nonexistent");
    assert_eq!(status.code(), Some(3));
}

// ── wt extract --cmdline (EID 4688, LOLBin detection) ────────────────────────

#[test]
fn extract_cmdline_json_output() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["extract", "--cmdline", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --cmdline");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("extract --cmdline must output JSON");
    assert!(
        json.is_array(),
        "extract --cmdline output must be JSON array"
    );
}

#[test]
fn extract_cmdline_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["extract", "--cmdline", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt extract --cmdline nonexistent");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn extract_cmdline_entries_have_required_fields() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["extract", "--cmdline", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --cmdline");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    if let Some(arr) = json.as_array() {
        if !arr.is_empty() {
            let first = &arr[0];
            assert!(first.get("timestamp").is_some(), "must have timestamp");
            assert!(first.get("image").is_some(), "must have image");
            assert!(
                first.get("command_line").is_some(),
                "must have command_line"
            );
            assert!(first.get("is_lolbin").is_some(), "must have is_lolbin");
        }
    }
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
    assert!(
        json.get("total_events").is_some(),
        "must have 'total_events'"
    );
    assert!(json.get("time_range").is_some(), "must have 'time_range'");
    assert!(
        json.get("top_event_ids").is_some(),
        "must have 'top_event_ids'"
    );
    assert!(
        json.get("integrity_indicators").is_some(),
        "must have 'integrity_indicators'"
    );
    assert!(json.get("ioc_count").is_some(), "must have 'ioc_count'");
}

#[test]
fn summary_top_event_ids_has_at_most_5() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["info", evtx.to_str().unwrap()])
        .output()
        .expect("run wt info");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    let top = json["top_event_ids"]
        .as_array()
        .expect("top_event_ids must be array");
    assert!(
        top.len() <= 5,
        "top_event_ids must have at most 5 entries, got {}",
        top.len()
    );
}

#[test]
fn summary_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["info", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt info nonexistent");
    assert_eq!(status.code(), Some(3));
}

// ── wt extract-all ────────────────────────────────────────────────────────────

#[test]
fn extract_all_nonexistent_exits_3() {
    let status = Command::new(wt_bin())
        .args(["extract-all", "/nonexistent/Security.evtx"])
        .status()
        .expect("run wt extract-all");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn extract_all_outputs_json_array() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["extract-all", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract-all");
    assert!(
        output.status.success(),
        "exit code: {:?}",
        output.status.code()
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must output JSON array");
    assert!(json.is_array(), "output must be a JSON array");
}

#[test]
fn extract_all_events_have_kind_field() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["extract-all", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract-all");
    assert!(output.status.success());
    let events: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("JSON array");
    if events.is_empty() {
        eprintln!("SKIP: no events extracted from corpus file");
        return;
    }
    for ev in &events {
        assert!(
            ev.get("kind").is_some(),
            "each event must have a 'kind' field: {ev}"
        );
    }
}

#[test]
fn extract_all_stream_flag_outputs_ndjson() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["extract-all", "--stream", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract-all --stream");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    // Every non-empty line must be a valid JSON object.
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value =
            serde_json::from_str(line).expect("each NDJSON line must be valid JSON");
        assert!(v.is_object(), "each NDJSON line must be an object: {line}");
    }
}

// ── Multi-input (RED: directory and multiple-path support not yet wired) ──────

#[test]
fn login_with_directory_returns_sessions_json() {
    // wt login <dir> must walk the directory and return sessions from all EVTX files.
    // RED: currently wt login passes the dir directly to winevt_extract::sessions()
    // which fails because a directory is not a valid EVTX file.
    let dir = foxitdata(".");
    if !dir.exists() {
        return;
    }
    let output = Command::new(wt_bin())
        .args(["login", dir.to_str().unwrap()])
        .output()
        .expect("run wt login <dir>");
    assert!(
        output.status.success(),
        "wt login <dir> must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be a JSON array");
    assert!(
        json.is_array(),
        "login output must be a JSON array of sessions"
    );
}

#[test]
fn timeline_accepts_two_file_arguments() {
    // wt timeline file1 file2 must merge and sort events from both files.
    // RED: clap currently rejects a second positional argument.
    let pre = require_foxitdata!("pre-Security.evtx");
    let post = require_foxitdata!("post-Security.evtx");
    let output = Command::new(wt_bin())
        .args(["timeline", pre.to_str().unwrap(), post.to_str().unwrap()])
        .output()
        .expect("run wt timeline pre post");
    assert!(
        output.status.success(),
        "wt timeline with two files must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("must be a JSON array");
    // pre-Security has 123 events, post-Security has 126; combined = 249
    assert_eq!(events.len(), 249, "must merge events from both files");
    // Result must be timestamp-sorted (no regressions)
    let timestamps: Vec<&str> = events
        .iter()
        .filter_map(|e| e.get("timestamp").and_then(|t| t.as_str()))
        .collect();
    let mut sorted = timestamps.clone();
    sorted.sort_unstable();
    assert_eq!(timestamps, sorted, "timeline must be sorted across files");
}

#[test]
fn login_graph_with_directory_merges_graphs() {
    // wt login --graph <dir> must return a merged graph from all EVTX files in dir.
    // RED: currently passes dir directly to logon_graph() which errors.
    let dir = foxitdata(".");
    if !dir.exists() {
        return;
    }
    let output = Command::new(wt_bin())
        .args(["login", "--graph", dir.to_str().unwrap()])
        .output()
        .expect("run wt login --graph <dir>");
    assert!(
        output.status.success(),
        "wt login --graph <dir> must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(json.get("nodes").is_some(), "must have 'nodes'");
    assert!(json.get("edges").is_some(), "must have 'edges'");
}

#[test]
fn extract_lateral_with_directory_succeeds() {
    // wt extract --lateral <dir> must walk directory and union results.
    // RED: currently passes dir directly to lateral_movement() which errors.
    let dir = foxitdata(".");
    if !dir.exists() {
        return;
    }
    let output = Command::new(wt_bin())
        .args(["extract", "--lateral", dir.to_str().unwrap()])
        .output()
        .expect("run wt extract --lateral <dir>");
    // Exit 0 (no hits) or 1 (hits found) — either is OK; crash/error is not.
    let code = output.status.code().unwrap_or(99);
    assert!(
        code == 0 || code == 1,
        "wt extract --lateral <dir> must not crash (got exit {code}); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Output must be valid JSON
    let _: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("lateral output must be JSON even for directories");
}

#[test]
fn frequency_with_directory_returns_valid_report() {
    // wt frequency <dir> must aggregate frequency across all EVTX files.
    // RED: currently passes dir directly to frequency() which errors.
    let dir = foxitdata(".");
    if !dir.exists() {
        return;
    }
    let output = Command::new(wt_bin())
        .args(["frequency", dir.to_str().unwrap()])
        .output()
        .expect("run wt frequency <dir>");
    assert!(
        output.status.success(),
        "wt frequency <dir> must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(
        json.get("total_events").is_some(),
        "must have 'total_events'"
    );
    let total = json["total_events"].as_u64().unwrap_or(0);
    // fox-it dir has pre + post = 249 events total
    assert_eq!(
        total, 249,
        "frequency total_events must sum across all files in dir"
    );
}
