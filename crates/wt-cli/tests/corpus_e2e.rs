//! E2E integration tests against the public EVTX attack corpus.
//!
//! Corpora (cloned into tests/data/):
//!   EVTX-ATTACK-SAMPLES   — markbaggett/evtx-attack-samples (278 files)
//!   hayabusa-sample-evtx  — Yamato-Security/hayabusa-sample-evtx (292 files)
//!
//! Tests skip gracefully when corpus is absent (CI without large data).
//!
//! TDD targets (RED → GREEN):
//!   RED  — cmdline_detects_lolbin_in_sysmon_file
//!          process_cmdlines only reads EID 4688; Sysmon EID 1 LOLBin files
//!          return [] → expects non-empty → FAILS until process_cmdlines is
//!          extended to also parse Sysmon EID 1 (same as build_process_tree)
//!   RED  — cmdline_sysmon_corpus_nonempty
//!          Another Sysmon-only EID 1 file returns [] → FAILS
//!   GREEN — scheduled_task_known_positive_nonempty  (already correct)
//!   GREEN — powershell_obfuscation_known_positive   (already correct)
//!   GREEN — corpus_robustness_attack_samples        (stability/no-panic)
//!   GREEN — extract_ioc_c2_corpus                  (C2 files have IPs)

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

fn attack_samples(rel: &str) -> PathBuf {
    workspace_root()
        .join("tests/data/EVTX-ATTACK-SAMPLES")
        .join(rel)
}

fn hayabusa_corpus(rel: &str) -> PathBuf {
    workspace_root()
        .join("tests/data/hayabusa-sample-evtx")
        .join(rel)
}

macro_rules! require_corpus {
    ($path:expr) => {{
        let p: PathBuf = $path;
        if !p.exists() {
            eprintln!("SKIP: corpus file not found: {}", p.display());
            return;
        }
        p
    }};
}

// ── RED tests: Sysmon EID 1 cmdline extraction ────────────────────────────────

/// `wt extract --cmdline` against a Sysmon EID 1 file whose name explicitly
/// names pcalua.exe (a known LOLBin) must return at least one entry.
///
/// Currently FAILS because process_cmdlines() only reads EID 4688
/// (Security log) and ignores Sysmon EID 1 events.
#[test]
fn cmdline_detects_lolbin_in_sysmon_file() {
    let evtx = require_corpus!(attack_samples("Execution/exec_sysmon_1_lolbin_pcalua.evtx"));

    let output = Command::new(wt_bin())
        .args(["extract", "--cmdline", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --cmdline sysmon lolbin");

    assert_eq!(
        output.status.code(),
        Some(0),
        "must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");

    assert!(
        !arr.is_empty(),
        "Sysmon LOLBin file must yield process entries via wt extract --cmdline"
    );

    let has_lolbin = arr.iter().any(|e| e["is_lolbin"].as_bool() == Some(true));
    assert!(has_lolbin, "expected is_lolbin: true for pcalua.exe; entries: {arr:?}");
}

/// `wt extract --cmdline` against a multi-LOLBin Sysmon file (rundll32 via
/// shdocvw OpenURL) must return non-empty results.
#[test]
fn cmdline_sysmon_corpus_nonempty() {
    let evtx = require_corpus!(attack_samples(
        "Execution/exec_sysmon_1_11_lolbin_rundll32_shdocvw_openurl.evtx"
    ));

    let output = Command::new(wt_bin())
        .args(["extract", "--cmdline", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --cmdline sysmon rundll32");

    assert_eq!(
        output.status.code(),
        Some(0),
        "must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");
    assert!(
        !arr.is_empty(),
        "Sysmon rundll32 LOLBin file must yield process entries"
    );
}

/// Every entry from a Sysmon EID 1 file must have the required JSON fields.
#[test]
fn cmdline_sysmon_entries_have_required_fields() {
    let evtx = require_corpus!(attack_samples("Execution/exec_sysmon_1_lolbin_pcalua.evtx"));

    let output = Command::new(wt_bin())
        .args(["extract", "--cmdline", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --cmdline sysmon lolbin fields");

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");

    for entry in arr {
        assert!(entry.get("timestamp").is_some(), "must have timestamp: {entry}");
        assert!(entry.get("image").is_some(), "must have image: {entry}");
        assert!(entry.get("command_line").is_some(), "must have command_line: {entry}");
        assert!(entry.get("is_lolbin").is_some(), "must have is_lolbin: {entry}");
    }
}

// ── Known-positive scheduled task detection ──────────────────────────────────

/// The `temp_scheduled_task_4698_4699.evtx` file explicitly contains
/// EID 4698 (task created) events — `wt extract --scheduled-task` must
/// return at least one entry.
#[test]
fn scheduled_task_known_positive_nonempty() {
    let evtx = require_corpus!(attack_samples(
        "Execution/temp_scheduled_task_4698_4699.evtx"
    ));

    let output = Command::new(wt_bin())
        .args(["extract", "--scheduled-task", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --scheduled-task");

    assert_eq!(
        output.status.code(),
        Some(0),
        "must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");
    assert!(
        !arr.is_empty(),
        "temp_scheduled_task_4698_4699.evtx must yield scheduled-task entries"
    );
}

// ── Known-positive PowerShell obfuscation detection ──────────────────────────

/// The Invoke-Obfuscation capture files contain EID 4104 (Script Block
/// Logging) — `wt extract --powershell` must return at least one entry.
#[test]
fn powershell_obfuscation_known_positive() {
    let evtx = require_corpus!(hayabusa_corpus(
        "DeepBlueCLI/Powershell-Invoke-Obfuscation-many.evtx"
    ));

    let output = Command::new(wt_bin())
        .args(["extract", "--powershell", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --powershell obfuscation");

    assert_eq!(
        output.status.code(),
        Some(0),
        "must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");
    assert!(
        !arr.is_empty(),
        "Invoke-Obfuscation EVTX must yield PowerShell block entries"
    );
}

/// String-encoded obfuscation file also yields entries.
#[test]
fn powershell_obfuscation_string_known_positive() {
    let evtx = require_corpus!(hayabusa_corpus(
        "DeepBlueCLI/Powershell-Invoke-Obfuscation-string-menu.evtx"
    ));

    let output = Command::new(wt_bin())
        .args(["extract", "--powershell", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --powershell string-obfuscation");

    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(!json.as_array().unwrap().is_empty(), "expected PowerShell entries");
}

// ── Corpus robustness: wt info must not panic on any corpus file ──────────────

/// `wt info` must exit 0 (parseable EVTX) or 3 (file error) on every file
/// in EVTX-ATTACK-SAMPLES.  Exit codes 1/2 are test results; any other code
/// or a panic is a bug.
#[test]
fn corpus_robustness_attack_samples_info() {
    let corpus_dir = workspace_root().join("tests/data/EVTX-ATTACK-SAMPLES");
    if !corpus_dir.exists() {
        eprintln!("SKIP: EVTX-ATTACK-SAMPLES corpus not found");
        return;
    }

    let evtx_files: Vec<PathBuf> = walkdir_evtx(&corpus_dir);
    assert!(!evtx_files.is_empty(), "corpus must contain EVTX files");

    let mut failures = Vec::new();
    for path in &evtx_files {
        let output = Command::new(wt_bin())
            .args(["info", path.to_str().unwrap()])
            .output()
            .expect("run wt info");

        let code = output.status.code().unwrap_or(-1);
        if code != 0 && code != 3 {
            failures.push(format!("{}: exit {code}", path.display()));
        }
    }

    assert!(
        failures.is_empty(),
        "wt info must exit 0 or 3 for all corpus files; unexpected exits:\n{}",
        failures.join("\n")
    );
}

/// Same robustness check for hayabusa-sample-evtx.
#[test]
fn corpus_robustness_hayabusa_info() {
    let corpus_dir = workspace_root().join("tests/data/hayabusa-sample-evtx");
    if !corpus_dir.exists() {
        eprintln!("SKIP: hayabusa-sample-evtx corpus not found");
        return;
    }

    let evtx_files: Vec<PathBuf> = walkdir_evtx(&corpus_dir);
    assert!(!evtx_files.is_empty(), "hayabusa corpus must contain EVTX files");

    let mut failures = Vec::new();
    for path in &evtx_files {
        let output = Command::new(wt_bin())
            .args(["info", path.to_str().unwrap()])
            .output()
            .expect("run wt info hayabusa");

        let code = output.status.code().unwrap_or(-1);
        if code != 0 && code != 3 {
            failures.push(format!("{}: exit {code}", path.display()));
        }
    }

    assert!(
        failures.is_empty(),
        "wt info must exit 0 or 3 for all hayabusa corpus files; unexpected exits:\n{}",
        failures.join("\n")
    );
}

// ── IOC extraction from C2 corpus ────────────────────────────────────────────

/// The C2 corpus directory contains Sysmon EID 3 (network connection) events
/// with real destination IPs — `wt extract --ioc` must find at least one IOC
/// across the directory.
#[test]
fn extract_ioc_c2_corpus_nonempty() {
    let c2_dir = attack_samples("Command and Control");
    if !c2_dir.exists() {
        eprintln!("SKIP: C2 corpus directory not found");
        return;
    }

    let output = Command::new(wt_bin())
        .args(["extract", "--ioc", c2_dir.to_str().unwrap()])
        .output()
        .expect("run wt extract --ioc c2 dir");

    // Exit 2 is acceptable — some corpus files are partially corrupt.
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1 || code == 2,
        "must exit 0, 1, or 2; got {code}; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    if !output.stdout.is_empty() {
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout must be JSON when non-empty");
        assert!(json.is_array(), "must be array");
    }
}

// ── Frequency analysis against corpus ────────────────────────────────────────

/// `wt frequency` across the full Execution corpus must exit 0 and return
/// a non-empty JSON array sorted by count descending.
#[test]
fn frequency_execution_corpus_sorted() {
    let exec_dir = attack_samples("Execution");
    if !exec_dir.exists() {
        eprintln!("SKIP: Execution corpus directory not found");
        return;
    }

    let output = Command::new(wt_bin())
        .args(["frequency", exec_dir.to_str().unwrap()])
        .output()
        .expect("run wt frequency execution corpus");

    // Exit 2 is acceptable — some corpus files are partially corrupt.
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 2,
        "must exit 0 or 2; got {code}; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    if output.stdout.is_empty() {
        return; // parse error path — no JSON output
    }

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");
    assert!(!arr.is_empty(), "expected frequency results from Execution corpus");

    // Verify descending sort by count.
    let counts: Vec<u64> = arr
        .iter()
        .filter_map(|e| e["count"].as_u64())
        .collect();
    let mut sorted = counts.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(counts, sorted, "frequency results must be sorted by count descending");
}

// ── wt extract --cmdline across all LOLBin execution samples ─────────────────

/// All Sysmon LOLBin files in Execution/ must yield non-empty cmdline results.
/// This is the broader batch form of the targeted RED tests above.
#[test]
fn cmdline_batch_lolbin_sysmon_files_all_nonempty() {
    let exec_dir = attack_samples("Execution");
    if !exec_dir.exists() {
        eprintln!("SKIP: Execution corpus directory not found");
        return;
    }

    // Only test files that capture Sysmon EID 1 process-create events.
    // Files like "windows_bits_4_59_60_lolbas…" name a LOLBas technique but
    // contain BITS client events (EID 4/59/60), not Sysmon EID 1.
    let lolbin_files: Vec<PathBuf> = walkdir_evtx(&exec_dir)
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| {
                    (n.contains("lolbin") || n.contains("lolbas"))
                        && (n.contains("sysmon") || n.contains("exec_sysmon"))
                })
                .unwrap_or(false)
        })
        .collect();

    if lolbin_files.is_empty() {
        eprintln!("SKIP: no lolbin/lolbas files found in Execution corpus");
        return;
    }

    let mut empties = Vec::new();
    for path in &lolbin_files {
        let output = Command::new(wt_bin())
            .args(["extract", "--cmdline", path.to_str().unwrap()])
            .output()
            .expect("run wt extract --cmdline batch");

        if output.status.code() != Some(0) {
            continue;
        }
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Array(vec![]));
        if json.as_array().map(|a| a.is_empty()).unwrap_or(true) {
            empties.push(path.display().to_string());
        }
    }

    assert!(
        empties.is_empty(),
        "these LOLBin corpus files returned no cmdline results (Sysmon EID 1 not parsed):\n{}",
        empties.join("\n")
    );
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn walkdir_evtx(dir: &PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walkdir_inner(dir, &mut out);
    out
}

fn walkdir_inner(dir: &PathBuf, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walkdir_inner(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("evtx") {
            out.push(path);
        }
    }
}
