#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::process::Command;
use winevt_writer::{records_to_evtx, WriteRecord};

fn wt_bin() -> Command {
    // CARGO_BIN_EXE_<name> points at the binary actually built for this run;
    // a hardcoded target/debug path breaks under cargo llvm-cov's redirected
    // target dir.
    let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_ev4n6"));
    Command::new(bin)
}

/// Unique temp path for test files.
fn temp_evtx(label: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "wt_test_{}_{}.evtx",
        label,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));
    path
}

/// Build a valid EVTX file with N records via winevt-writer (DRY: no hand-rolled binary).
fn write_evtx_with_records(label: &str, count: usize) -> std::path::PathBuf {
    let records: Vec<WriteRecord> = (1..=count as u64)
        .map(|id| WriteRecord {
            record_id: id,
            timestamp: 132_700_000_000_000_000 + id * 1_000_000,
            payload: vec![0x0fu8, 0x01, 0x02], // minimal BinXml fragment header
        })
        .collect();
    let bytes = records_to_evtx(&records);
    let path = temp_evtx(label);
    std::fs::write(&path, &bytes).expect("write evtx");
    path
}

/// Build a minimal valid EVTX file with no records (for integrity/stats tests).
fn write_valid_evtx() -> std::path::PathBuf {
    write_evtx_with_records("valid", 1)
}

/// Build a minimal EVTX with a tampered chunk checksum.
fn write_tampered_evtx() -> std::path::PathBuf {
    let mut chunk = vec![0u8; 0x10000];
    chunk[0..8].copy_from_slice(b"ElfChnk\0");
    chunk[8..16].copy_from_slice(&1u64.to_le_bytes());
    chunk[16..24].copy_from_slice(&1u64.to_le_bytes());
    chunk[24..32].copy_from_slice(&1u64.to_le_bytes());
    chunk[32..40].copy_from_slice(&1u64.to_le_bytes());
    chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes());
    chunk[44..48].copy_from_slice(&0x200u32.to_le_bytes());
    chunk[48..52].copy_from_slice(&0x200u32.to_le_bytes());
    chunk[52..56].copy_from_slice(&0u32.to_le_bytes());
    // WRONG checksum
    chunk[0x78..0x7C].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());

    let mut path = std::env::temp_dir();
    path.push(format!(
        "wt_test_tampered_{}.evtx",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));
    let mut f = std::fs::File::create(&path).expect("create temp");
    f.write_all(&chunk).expect("write chunk");
    path
}

#[test]
fn wt_help_exits_success() {
    let status = wt_bin()
        .arg("--help")
        .status()
        .expect("failed to run wt --help");
    assert!(status.success());
}

#[test]
fn wt_version_exits_success() {
    let status = wt_bin()
        .arg("--version")
        .status()
        .expect("failed to run wt --version");
    assert!(status.success());
}

#[test]
fn wt_verify_help_exits_success() {
    let status = wt_bin()
        .args(["verify", "--help"])
        .status()
        .expect("failed to run wt verify --help");
    assert!(status.success());
}

#[test]
fn wt_verify_nonexistent_path_exits_nonzero() {
    let status = wt_bin()
        .args(["verify", "/tmp/does_not_exist_evtx_12345.evtx"])
        .status()
        .expect("failed to run wt verify");
    assert!(
        !status.success(),
        "wt verify on nonexistent file should fail"
    );
}

// ── carve-ewf removed: wt carve auto-detects EWF ────────────────────────────

#[test]
fn wt_carve_ewf_is_removed() {
    let status = wt_bin()
        .args(["carve-ewf", "--help"])
        .status()
        .expect("run wt carve-ewf --help");
    assert!(
        !status.success(),
        "wt carve-ewf must no longer exist (EWF auto-detected by carve)"
    );
}

// ── stats removed: info absorbs file statistics ───────────────────────────────

#[test]
fn wt_stats_is_removed() {
    let status = wt_bin()
        .args(["stats", "--help"])
        .status()
        .expect("run wt stats --help");
    assert!(
        !status.success(),
        "wt stats must no longer exist (merged into wt info)"
    );
}

#[test]
fn wt_info_includes_stats_fields() {
    let path = write_valid_evtx();
    let output = wt_bin()
        .args(["info", path.to_str().unwrap()])
        .output()
        .expect("run wt info");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("info must output JSON");
    assert!(
        json.get("hash").is_some(),
        "info must include 'hash' (was stats)"
    );
    assert!(
        json.get("chunks").is_some(),
        "info must include 'chunks' (was stats)"
    );
    assert!(
        json.get("records").is_some(),
        "info must include 'records' (was stats)"
    );
}

// ---- Feature 9: Meaningful exit codes ----

#[test]
fn wt_verify_valid_file_exits_code_0() {
    let path = write_valid_evtx();
    let status = wt_bin()
        .args(["verify", path.to_str().unwrap()])
        .status()
        .expect("run wt verify");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status.code(),
        Some(0),
        "wt verify on valid file should exit 0 (no indicators)"
    );
}

#[test]
fn wt_verify_tampered_file_exits_code_1() {
    let path = write_tampered_evtx();
    let status = wt_bin()
        .args(["verify", path.to_str().unwrap()])
        .status()
        .expect("run wt verify");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status.code(),
        Some(1),
        "wt verify on tampered file should exit 1 (indicators present)"
    );
}

#[test]
fn wt_verify_nonexistent_exits_code_3() {
    let status = wt_bin()
        .args(["verify", "/nonexistent/path/feature9.evtx"])
        .status()
        .expect("run wt verify");
    assert_eq!(
        status.code(),
        Some(3),
        "wt verify on nonexistent path should exit 3 (path not found)"
    );
}

// ── wt carve: subcommand removed — auto-detected by all commands ─────────────

#[test]
fn wt_carve_is_no_longer_a_subcommand() {
    // `wt carve` must fail; EWF/raw-blob carving is now a --carve flag.
    let status = wt_bin()
        .args(["carve", "--help"])
        .status()
        .expect("run wt carve --help");
    assert!(!status.success(), "wt carve subcommand must be removed");
}

#[test]
fn wt_timeline_accepts_carve_flag() {
    let path = write_evtx_with_records("timeline_carve", 2);
    let output = wt_bin()
        .args(["timeline", "--carve", path.to_str().unwrap()])
        .output()
        .expect("run wt timeline --carve");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        output.status.code(),
        Some(0),
        "--carve must be accepted on timeline; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("timeline --carve must output JSON");
    assert!(v.is_array(), "timeline --carve output must be JSON array");
}

#[test]
fn wt_verify_accepts_carve_flag() {
    let path = write_evtx_with_records("verify_carve", 2);
    let output = wt_bin()
        .args(["verify", "--carve", path.to_str().unwrap()])
        .output()
        .expect("run wt verify --carve");
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.code().is_some_and(|c| c == 0 || c == 1),
        "--carve must be accepted on verify; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn wt_frequency_accepts_carve_flag() {
    let path = write_evtx_with_records("freq_carve", 2);
    let output = wt_bin()
        .args(["frequency", "--carve", path.to_str().unwrap()])
        .output()
        .expect("run wt frequency --carve");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        output.status.code(),
        Some(0),
        "--carve must be accepted on frequency; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn wt_info_accepts_carve_flag() {
    let path = write_evtx_with_records("info_carve", 2);
    let output = wt_bin()
        .args(["info", "--carve", path.to_str().unwrap()])
        .output()
        .expect("run wt info --carve");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        output.status.code(),
        Some(0),
        "--carve must be accepted on info; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn wt_timeline_accepts_directory_path() {
    use std::fs;
    let dir = tempfile::tempdir().expect("tempdir");
    let evtx = write_evtx_with_records("dir_evtx", 2);
    fs::copy(&evtx, dir.path().join("test.evtx")).expect("copy evtx into dir");
    let _ = fs::remove_file(&evtx);

    let output = wt_bin()
        .args(["timeline", dir.path().to_str().unwrap()])
        .output()
        .expect("run wt timeline on directory");
    assert_eq!(
        output.status.code(),
        Some(0),
        "timeline must accept a directory; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("timeline dir output must be JSON");
    assert!(v.is_array(), "timeline dir output must be JSON array");
}

// ── wt reconstruct: removed — merged into wt repair ──────────────────────────

#[test]
fn wt_reconstruct_is_removed() {
    // reconstruct is no longer a valid subcommand; repair subsumes it.
    let status = wt_bin()
        .args(["reconstruct", "--help"])
        .status()
        .expect("run wt reconstruct --help");
    assert!(
        !status.success(),
        "wt reconstruct must no longer exist (exit non-zero)"
    );
}

// ── wt timeline tests ─────────────────────────────────────────────────────────

#[test]
fn wt_timeline_help_exits_success() {
    let status = wt_bin()
        .args(["timeline", "--help"])
        .status()
        .expect("run wt timeline --help");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn wt_timeline_nonexistent_exits_code_3() {
    let status = wt_bin()
        .args(["timeline", "/nonexistent/security.evtx"])
        .status()
        .expect("run wt timeline");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn wt_timeline_valid_file_outputs_json_array() {
    let path = write_evtx_with_records("timeline_valid", 3);
    let output = wt_bin()
        .args(["timeline", path.to_str().unwrap()])
        .output()
        .expect("run wt timeline");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("timeline output should be valid JSON");
    assert!(v.is_array(), "timeline should output a JSON array");
}

// ── sessions removed: wt login replaces sessions + logon-graph ───────────────

#[test]
fn wt_sessions_is_removed() {
    let status = wt_bin()
        .args(["sessions", "--help"])
        .status()
        .expect("run wt sessions --help");
    assert!(
        !status.success(),
        "wt sessions must no longer exist (use wt login)"
    );
}

#[test]
fn wt_login_help_exits_success() {
    let status = wt_bin()
        .args(["login", "--help"])
        .status()
        .expect("run wt login --help");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn wt_login_nonexistent_exits_code_3() {
    let status = wt_bin()
        .args(["login", "/nonexistent/security.evtx"])
        .status()
        .expect("run wt login nonexistent");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn wt_login_valid_file_outputs_sessions_array() {
    let path = write_evtx_with_records("login_valid", 2);
    let output = wt_bin()
        .args(["login", path.to_str().unwrap()])
        .output()
        .expect("run wt login");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0), "expected exit 0");
    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("login output should be valid JSON");
    assert!(
        v.is_array(),
        "login default output must be JSON array of sessions"
    );
}

#[test]
fn wt_login_graph_flag_outputs_graph_object() {
    let path = write_evtx_with_records("login_graph", 2);
    let output = wt_bin()
        .args(["login", "--graph", path.to_str().unwrap()])
        .output()
        .expect("run wt login --graph");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("login --graph must output JSON");
    assert!(v.get("nodes").is_some(), "login --graph must have 'nodes'");
    assert!(v.get("edges").is_some(), "login --graph must have 'edges'");
}

// ── powershell removed: wt extract --powershell replaces it ──────────────────

#[test]
fn wt_powershell_is_removed() {
    let status = wt_bin()
        .args(["powershell", "--help"])
        .status()
        .expect("run wt powershell --help");
    assert!(
        !status.success(),
        "wt powershell must no longer exist (use wt extract --powershell)"
    );
}

#[test]
fn wt_extract_powershell_nonexistent_exits_code_3() {
    let status = wt_bin()
        .args(["extract", "--powershell", "/nonexistent/ps.evtx"])
        .status()
        .expect("run wt extract --powershell nonexistent");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn wt_extract_powershell_valid_file_outputs_json_array() {
    let path = write_evtx_with_records("ps_valid", 2);
    let output = wt_bin()
        .args(["extract", "--powershell", path.to_str().unwrap()])
        .output()
        .expect("run wt extract --powershell");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0), "expected exit 0");
    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("extract --powershell must output JSON");
    assert!(
        v.is_array(),
        "extract --powershell output must be JSON array"
    );
}

// ── wt search (replaces pivot, adds --regex) ──────────────────────────────────

#[test]
fn wt_search_help_exits_success() {
    let status = wt_bin()
        .args(["search", "--help"])
        .status()
        .expect("run wt search --help");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn wt_search_nonexistent_exits_code_3() {
    let status = wt_bin()
        .args(["search", "anything", "/nonexistent/security.evtx"])
        .status()
        .expect("run wt search nonexistent");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn wt_search_regex_flag_accepted() {
    let path = write_evtx_with_records("search_regex", 2);
    let status = wt_bin()
        .args(["search", "--regex", ".*", path.to_str().unwrap()])
        .status()
        .expect("run wt search --regex");
    let _ = std::fs::remove_file(&path);
    assert!(
        status.code().is_some_and(|c| c == 0 || c == 1),
        "search --regex must exit 0 or 1"
    );
}

// ── wt frequency tests ────────────────────────────────────────────────────────

#[test]
fn wt_frequency_help_exits_success() {
    let status = wt_bin()
        .args(["frequency", "--help"])
        .status()
        .expect("run wt frequency --help");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn wt_frequency_nonexistent_exits_code_3() {
    let status = wt_bin()
        .args(["frequency", "/nonexistent/security.evtx"])
        .status()
        .expect("run wt frequency");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn wt_frequency_valid_file_outputs_json() {
    let path = write_evtx_with_records("freq_valid", 3);
    let output = wt_bin()
        .args(["frequency", path.to_str().unwrap()])
        .output()
        .expect("run wt frequency");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("frequency output should be valid JSON");
    assert!(
        v.get("total_events").is_some(),
        "frequency JSON should have 'total_events' field"
    );
}

// ── wt extract --ioc (replaces wt ioc-extract) ───────────────────────────────

#[test]
fn wt_extract_ioc_help_exits_success() {
    let status = wt_bin()
        .args(["extract", "--ioc", "--help"])
        .status()
        .expect("run wt extract --ioc --help");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn wt_extract_ioc_nonexistent_exits_code_3() {
    let status = wt_bin()
        .args(["extract", "--ioc", "/nonexistent/security.evtx"])
        .status()
        .expect("run wt extract --ioc nonexistent");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn wt_extract_ioc_valid_file_outputs_json_object() {
    let path = write_evtx_with_records("ioc_valid", 2);
    let output = wt_bin()
        .args(["extract", "--ioc", path.to_str().unwrap()])
        .output()
        .expect("run wt extract --ioc");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("extract --ioc output should be valid JSON");
    assert!(
        v.get("events_scanned").is_some(),
        "extract --ioc JSON should have 'events_scanned' field"
    );
    assert!(
        v.get("iocs").is_some(),
        "extract --ioc JSON should have 'iocs' field"
    );
}

// ── wt attack-tags: removed — use hayabusa/chainsaw for detection ─────────────

#[test]
fn wt_attack_tags_is_removed() {
    let status = wt_bin()
        .args(["attack-tags", "--help"])
        .status()
        .expect("run wt attack-tags --help");
    assert!(
        !status.success(),
        "wt attack-tags must no longer exist (detection delegated to hayabusa/chainsaw)"
    );
}

// ── wt hunt: removed — use hayabusa/chainsaw for detection ───────────────────

#[test]
fn wt_hunt_is_removed() {
    let status = wt_bin()
        .args(["hunt", "--help"])
        .status()
        .expect("run wt hunt --help");
    assert!(
        !status.success(),
        "wt hunt must no longer exist (detection delegated to hayabusa/chainsaw)"
    );
}
