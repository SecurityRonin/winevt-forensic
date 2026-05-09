//! Tests for infra commands: repair, markdown report, and parallel triage.

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

// ── wt repair ────────────────────────────────────────────────────────────────

#[test]
fn repair_valid_evtx_exits_0() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let out = tempfile::tempdir().expect("tempdir");
    let fixed = out.path().join("fixed.evtx");

    let output = Command::new(wt_bin())
        .args([
            "repair",
            evtx.to_str().unwrap(),
            "--output",
            fixed.to_str().unwrap(),
        ])
        .output()
        .expect("run wt repair");

    assert_eq!(
        output.status.code(),
        Some(0),
        "repair must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(json.get("chunks_checked").is_some(), "must report chunks_checked");
    assert!(json.get("chunks_repaired").is_some(), "must report chunks_repaired");
    assert!(fixed.exists(), "output file must be created");
}

#[test]
fn repair_is_idempotent() {
    // Pre-Security.evtx has chunks with stale header CRCs (unflushed by Windows),
    // so it is not a "zero repairs" baseline. Instead we verify idempotency:
    // a second repair pass on the already-repaired output must report 0 chunks repaired.
    let evtx = require_foxitdata!("pre-Security.evtx");
    let out = tempfile::tempdir().expect("tempdir");
    let fixed1 = out.path().join("fixed1.evtx");
    let fixed2 = out.path().join("fixed2.evtx");

    // First pass — may repair some chunks.
    Command::new(wt_bin())
        .args(["repair", evtx.to_str().unwrap(), "--output", fixed1.to_str().unwrap()])
        .output()
        .expect("run wt repair pass 1");

    // Second pass — must report 0 chunks repaired (idempotency).
    let output2 = Command::new(wt_bin())
        .args(["repair", fixed1.to_str().unwrap(), "--output", fixed2.to_str().unwrap()])
        .output()
        .expect("run wt repair pass 2");

    let json: serde_json::Value =
        serde_json::from_slice(&output2.stdout).expect("pass 2 must be JSON");
    assert_eq!(
        json["chunks_repaired"].as_u64().unwrap_or(999),
        0,
        "second repair pass must report 0 chunks repaired (idempotency)"
    );
}

#[test]
fn repair_corrupted_checksum_repairs_chunk() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let out = tempfile::tempdir().expect("tempdir");

    // Copy the EVTX and corrupt the first chunk's checksum (byte 0x78 of first chunk)
    let mut bytes = std::fs::read(&evtx).expect("read evtx");
    // File header is 4096 bytes; first chunk starts at offset 4096
    let chunk_start = 4096;
    let checksum_offset = chunk_start + 0x78; // chunk header CRC32
    if bytes.len() > checksum_offset + 4 {
        bytes[checksum_offset] ^= 0xFF; // flip bits to corrupt checksum
    }
    let corrupted = out.path().join("corrupted.evtx");
    std::fs::write(&corrupted, &bytes).expect("write corrupted");

    let fixed = out.path().join("fixed.evtx");
    let output = Command::new(wt_bin())
        .args([
            "repair",
            corrupted.to_str().unwrap(),
            "--output",
            fixed.to_str().unwrap(),
        ])
        .output()
        .expect("run wt repair corrupted");

    assert_eq!(
        output.status.code(),
        Some(0),
        "repair of corrupted file must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(
        json["chunks_repaired"].as_u64().unwrap_or(0) >= 1,
        "corrupted checksum should be repaired; got: {json}"
    );
}

// ── wt report --format md ─────────────────────────────────────────────────────

#[test]
fn report_format_md_outputs_markdown() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let out = tempfile::tempdir().expect("tempdir");

    let output = Command::new(wt_bin())
        .args([
            "report",
            evtx.to_str().unwrap(),
            "--output",
            out.path().to_str().unwrap(),
            "--format",
            "md",
        ])
        .output()
        .expect("run wt report --format md");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("# Triage Report"),
        "markdown must start with '# Triage Report'; got: {stdout}"
    );
    assert!(stdout.contains("## Input"), "markdown must have ## Input section");
    assert!(stdout.contains("## EVTX Files"), "markdown must have ## EVTX Files section");
}

#[test]
fn report_format_json_still_works() {
    let evtx = require_foxitdata!("pre-Security.evtx");
    let out = tempfile::tempdir().expect("tempdir");

    let output = Command::new(wt_bin())
        .args([
            "report",
            evtx.to_str().unwrap(),
            "--output",
            out.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("run wt report --format json");

    assert_eq!(output.status.code(), Some(0));
    let _: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("--format json must output valid JSON");
}

// ── Concurrent multi-file triage (correctness) ────────────────────────────────

#[test]
fn report_directory_returns_all_evtx_files() {
    let dir = foxitdata(".");
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

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let files = json["evtx_files"].as_array().expect("evtx_files");

    // Count .evtx files in directory manually
    let expected = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x.eq_ignore_ascii_case("evtx"))
                .unwrap_or(false)
        })
        .count();

    assert_eq!(
        files.len(),
        expected,
        "concurrent triage must not drop or duplicate files"
    );
}
