//! End-to-end integration tests with hayabusa.
//!
//! These tests require the `hayabusa` binary to be in PATH and a local
//! Sigma rule set (hayabusa rules directory).  Tests that cannot locate
//! `hayabusa` are skipped gracefully — they return `Ok(())` so CI stays
//! green on machines without the binary.
//!
//! # Running locally
//!
//! ```sh
//! # Install hayabusa (macOS/Linux)
//! # https://github.com/Yamato-Security/hayabusa/releases
//! cargo test --test hayabusa_e2e
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;
use winevt_writer::{records_to_evtx, WriteRecord};

// ── helpers ───────────────────────────────────────────────────────────────────

fn wt_bin() -> std::path::PathBuf {
    let mut bin = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bin.push("../../target/debug/ev4n6");
    bin
}

/// Returns `Some(path)` if hayabusa is in PATH, `None` otherwise.
fn hayabusa_path() -> Option<std::path::PathBuf> {
    // Try environment variable override first (useful in CI).
    if let Ok(p) = std::env::var("HAYABUSA_BIN") {
        let path = std::path::PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    // Fall back to PATH lookup.
    which_hayabusa()
}

fn which_hayabusa() -> Option<std::path::PathBuf> {
    let output = Command::new("which").arg("hayabusa").output().ok()?;
    if output.status.success() {
        let s = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !s.is_empty() {
            return Some(std::path::PathBuf::from(s));
        }
    }
    None
}

/// Build a temp EVTX file containing N records via winevt-writer.
fn write_evtx_fixture(label: &str, records: &[WriteRecord]) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "wt_hayabusa_{}_{}.evtx",
        label,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));
    std::fs::write(&path, records_to_evtx(records)).expect("write evtx fixture");
    path
}

/// Skip the test gracefully when hayabusa is absent.
///
/// The hayabusa wrapper at `/usr/local/bin/hayabusa` cds to the install
/// directory before exec, so `rules/` is always found relative to cwd.
macro_rules! require_hayabusa {
    () => {
        match hayabusa_path() {
            Some(p) => p,
            None => {
                eprintln!("SKIP: hayabusa not in PATH — set HAYABUSA_BIN or install hayabusa");
                return;
            }
        }
    };
}

// ── pipeline tests ─────────────────────────────────────────────────────────────

/// hayabusa binary is callable and exits 0 for `help`.
#[test]
fn hayabusa_help_exits_success() {
    let bin = require_hayabusa!();
    let status = Command::new(&bin)
        .arg("help")
        .status()
        .expect("run hayabusa help");
    assert!(status.success(), "hayabusa help should exit 0");
}

/// wt repair → hayabusa pipeline completes without error for a
/// synthetic EVTX fixture.
///
/// Does not assert any specific detection (that would require bundling
/// Sigma rules).  Asserts only that the pipeline runs to completion with
/// exit code 0, proving structural compatibility between winevt-writer
/// output and hayabusa's parser.
#[test]
fn hayabusa_parses_reconstructed_evtx() {
    let bin = require_hayabusa!();

    // 1. Create a synthetic EVTX via winevt-writer.
    let records: Vec<WriteRecord> = (1..=5u64)
        .map(|id| WriteRecord {
            record_id: id,
            timestamp: 132_700_000_000_000_000 + id * 10_000_000,
            payload: vec![0x0fu8, 0x01, 0x02, 0x03], // minimal BinXml
        })
        .collect();
    let input = write_evtx_fixture("pipeline_in", &records);

    // 2. Repair (CRC fixup) via wt repair — produces a structurally valid EVTX.
    let mut recon_path = std::env::temp_dir();
    recon_path.push(format!(
        "wt_hayabusa_recon_{}.evtx",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));

    let recon_status = Command::new(wt_bin())
        .args([
            "repair",
            "--output",
            recon_path.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .expect("run wt repair");
    let _ = std::fs::remove_file(&input);

    assert_eq!(recon_status.code(), Some(0), "wt repair should exit 0");

    // 3. Feed reconstructed file to hayabusa --json-timeline (or equivalent).
    //    hayabusa 2.x: `hayabusa json-timeline -f <path> -o <output>`
    //    hayabusa 3.x: same sub-command name.
    let mut haya_out = std::env::temp_dir();
    haya_out.push(format!(
        "wt_hayabusa_out_{}.jsonl",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));

    let haya_status = Command::new(&bin)
        .args([
            "json-timeline",
            "-f",
            recon_path.to_str().unwrap(),
            "-o",
            haya_out.to_str().unwrap(),
            "--no-wizard",
            "--quiet",
        ])
        .status()
        .expect("run hayabusa json-timeline");

    let _ = std::fs::remove_file(&recon_path);
    let _ = std::fs::remove_file(&haya_out);

    assert!(
        haya_status.success(),
        "hayabusa json-timeline on reconstructed EVTX should exit 0 (exit code: {:?})",
        haya_status.code()
    );
}

/// Corrupt EVTX → repair → hayabusa full pipeline.
///
/// Creates an EVTX, zeroes the middle third (simulating corruption/partial
/// encryption), runs `wt repair` on the damaged file to fix checksums, then
/// verifies hayabusa can still process the output.
#[test]
fn hayabusa_processes_corrupted_then_reconstructed_evtx() {
    let bin = require_hayabusa!();

    // 1. Build a valid EVTX with 10 records.
    let records: Vec<WriteRecord> = (1..=10u64)
        .map(|id| WriteRecord {
            record_id: id,
            timestamp: 132_700_000_000_000_000 + id * 10_000_000,
            payload: vec![0x0fu8, 0x01, 0x02, 0x03],
        })
        .collect();
    let bytes = records_to_evtx(&records);

    // 2. Corrupt the middle third.
    let mut corrupted = bytes.clone();
    let third = corrupted.len() / 3;
    for b in &mut corrupted[third..2 * third] {
        *b = 0x00;
    }

    let corrupt_path = write_evtx_fixture("corrupt", &[]);
    std::fs::write(&corrupt_path, &corrupted).expect("write corrupt evtx");

    // 3. Repair (CRC fixup).
    let mut recon_path = std::env::temp_dir();
    recon_path.push(format!(
        "wt_hayabusa_recon_corrupt_{}.evtx",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));

    let recon_status = Command::new(wt_bin())
        .args([
            "repair",
            "--output",
            recon_path.to_str().unwrap(),
            corrupt_path.to_str().unwrap(),
        ])
        .status()
        .expect("run wt repair on corrupt file");
    let _ = std::fs::remove_file(&corrupt_path);

    assert_eq!(
        recon_status.code(),
        Some(0),
        "wt repair on corrupt file should exit 0"
    );

    // 4. hayabusa on the repaired file.
    let mut haya_out = std::env::temp_dir();
    haya_out.push(format!(
        "wt_hayabusa_corrupt_out_{}.jsonl",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));

    let haya_status = Command::new(&bin)
        .args([
            "json-timeline",
            "-f",
            recon_path.to_str().unwrap(),
            "-o",
            haya_out.to_str().unwrap(),
            "--no-wizard",
            "--quiet",
        ])
        .status()
        .expect("run hayabusa on reconstructed corrupt file");

    let _ = std::fs::remove_file(&recon_path);
    let _ = std::fs::remove_file(&haya_out);

    assert!(
        haya_status.success(),
        "hayabusa on reconstructed-from-corrupt EVTX should exit 0"
    );
}
