// An integration test is its own crate, so the workspace's cfg(test)-scoped
// allow does not reach it and the attribute must be repeated here. In these
// tests the unwrap/expect IS the assertion.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Output-format vocabulary for `ev4n6 extract`.
//!
//! `--format` accepted only `json` and `csv`, so this CLI shipped **no
//! human-readable view at all** — an analyst reading EVTX records got a
//! pretty-printed JSON array or a CSV, never an aligned table. The fleet
//! standard mandates a human/machine split.
//!
//! Two things are pinned here:
//!
//! * `table` (the human view) and `jsonl` (the fleet-canonical name for
//!   newline-delimited JSON, matching the existing `--stream` behaviour) are
//!   accepted format values and are advertised in `--help`.
//! * Nothing that works today stops working: `json` and `csv` still parse, and
//!   a **piped** run with no `--format` still emits JSON, not a table. That
//!   last one is the load-bearing test — every existing
//!   `ev4n6 extract ... | jq` invocation depends on it.

use std::process::Command;
use winevt_writer::{records_to_evtx, WriteRecord};

fn ev4n6() -> Command {
    // CARGO_BIN_EXE_<name> points at the binary actually built for this run;
    // a hardcoded target/debug path breaks under cargo llvm-cov's redirected
    // target dir.
    let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_ev4n6"));
    Command::new(bin)
}

/// A valid, committed-bytes-only EVTX (synthesized via `winevt-writer`) so the
/// gate never depends on an external corpus.
fn synth_evtx(label: &str) -> std::path::PathBuf {
    let records: Vec<WriteRecord> = (1..=3u64)
        .map(|id| WriteRecord {
            record_id: id,
            timestamp: 132_700_000_000_000_000 + id * 1_000_000,
            payload: vec![0x0fu8, 0x01, 0x02],
        })
        .collect();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "ev4n6_fmt_{}_{}.evtx",
        label,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));
    std::fs::write(&path, records_to_evtx(&records)).expect("write synth evtx");
    path
}

/// Exit 2 is "argument error"; exit 3 is "path not found". Pointing a format at
/// a nonexistent path therefore separates "clap rejected the value" (2) from
/// "clap accepted the value, the file was missing" (3).
fn format_is_accepted(value: &str) -> bool {
    let status = ev4n6()
        .args([
            "extract",
            "--ioc",
            "--format",
            value,
            "/nonexistent/Security.evtx",
        ])
        .status()
        .expect("run ev4n6 extract");
    status.code() != Some(2)
}

// ── The human view this CLI never had ────────────────────────────────────────

#[test]
fn extract_accepts_format_table() {
    assert!(
        format_is_accepted("table"),
        "`ev4n6 extract --format table` must be accepted — this CLI ships no \
         human-readable view without it"
    );
}

#[test]
fn extract_help_advertises_table() {
    let out = ev4n6()
        .args(["extract", "--help"])
        .output()
        .expect("run ev4n6 extract --help");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("table"),
        "`extract --help` must advertise the `table` human view, got:\n{help}"
    );
}

// ── jsonl: the fleet-canonical name for newline-delimited JSON ───────────────

#[test]
fn extract_accepts_format_jsonl() {
    assert!(
        format_is_accepted("jsonl"),
        "`ev4n6 extract --format jsonl` must be accepted — `jsonl` is the fleet \
         name for the newline-delimited JSON that `--stream` already emits"
    );
}

#[test]
fn extract_help_advertises_jsonl() {
    let out = ev4n6()
        .args(["extract", "--help"])
        .output()
        .expect("run ev4n6 extract --help");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("jsonl"),
        "`extract --help` must advertise `jsonl`, got:\n{help}"
    );
}

// ── Nothing that works today may stop working ────────────────────────────────

#[test]
fn extract_still_accepts_legacy_json_and_csv() {
    for legacy in ["json", "csv"] {
        assert!(
            format_is_accepted(legacy),
            "`ev4n6 extract --format {legacy}` must keep working"
        );
    }
}

/// The load-bearing compatibility test. Adding a human view must not change
/// what a **pipe** receives: with no `--format`, piped stdout still gets JSON.
/// Every existing `ev4n6 extract ... | jq` invocation depends on this.
#[test]
fn extract_piped_with_no_format_still_emits_json() {
    let evtx = synth_evtx("piped");
    let out = ev4n6()
        .args(["extract", "--ioc", evtx.to_str().unwrap()])
        .output()
        .expect("run ev4n6 extract --ioc");
    let _ = std::fs::remove_file(&evtx);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim();
    assert!(
        trimmed.starts_with('[') || trimmed.starts_with('{'),
        "a piped run with no --format must still emit JSON, not a table, got:\n{stdout}"
    );
}
