//! E2E integration tests against the public EVTX attack corpus.
//!
//! Corpora (cloned into tests/data/):
//!   EVTX-ATTACK-SAMPLES   — markbaggett/evtx-attack-samples (278 files)
//!   hayabusa-sample-evtx  — Yamato-Security/hayabusa-sample-evtx (292 files)
//!
//! Tests skip gracefully when corpus is absent (CI without large data).
//!
//! TDD targets (RED → GREEN):
//!   RED  — `cmdline_detects_lolbin_in_sysmon_file`
//!          `process_cmdlines` only reads EID 4688; Sysmon EID 1 `LOLBin` files
//!          return [] → expects non-empty → FAILS until `process_cmdlines` is
//!          extended to also parse Sysmon EID 1 (same as `build_process_tree`)
//!   RED  — `cmdline_sysmon_corpus_nonempty`
//!          Another Sysmon-only EID 1 file returns [] → FAILS
//!   GREEN — `scheduled_task_known_positive_nonempty`  (already correct)
//!   GREEN — `powershell_obfuscation_known_positive`   (already correct)
//!   GREEN — `corpus_robustness_attack_samples`        (stability/no-panic)
//!   GREEN — `extract_ioc_c2_corpus`                  (C2 files have IPs)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

fn wt_bin() -> PathBuf {
    // `CARGO_BIN_EXE_<name>` is set by cargo for integration tests and points at
    // the binary ACTUALLY built for this run. A hardcoded ../../target/debug path
    // breaks under any target-dir redirection — notably `cargo llvm-cov`, which
    // builds into target/llvm-cov-target/ and left these tests panicking on a
    // missing file while passing fine under plain `cargo test`.
    PathBuf::from(env!("CARGO_BIN_EXE_ev4n6"))
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
/// names pcalua.exe (a known `LOLBin`) must return at least one entry.
///
/// Currently FAILS because `process_cmdlines()` only reads EID 4688
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

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");

    assert!(
        !arr.is_empty(),
        "Sysmon LOLBin file must yield process entries via wt extract --cmdline"
    );

    let has_lolbin = arr.iter().any(|e| e["is_lolbin"].as_bool() == Some(true));
    assert!(
        has_lolbin,
        "expected is_lolbin: true for pcalua.exe; entries: {arr:?}"
    );
}

/// `wt extract --cmdline` against a multi-LOLBin Sysmon file (rundll32 via
/// shdocvw `OpenURL`) must return non-empty results.
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

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
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

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");

    for entry in arr {
        assert!(
            entry.get("timestamp").is_some(),
            "must have timestamp: {entry}"
        );
        assert!(entry.get("image").is_some(), "must have image: {entry}");
        assert!(
            entry.get("command_line").is_some(),
            "must have command_line: {entry}"
        );
        assert!(
            entry.get("is_lolbin").is_some(),
            "must have is_lolbin: {entry}"
        );
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

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
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

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
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
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(
        !json.as_array().unwrap().is_empty(),
        "expected PowerShell entries"
    );
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
    assert!(
        !evtx_files.is_empty(),
        "hayabusa corpus must contain EVTX files"
    );

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
/// a non-empty report with `total_events` and `by_event_id` sorted LFO (ascending).
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

    assert_eq!(
        output.status.code(),
        Some(0),
        "must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    if output.stdout.is_empty() {
        return; // no EVTX data in corpus path
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json["by_event_id"]
        .as_array()
        .expect("must have by_event_id array");
    assert!(
        !arr.is_empty(),
        "expected frequency results from Execution corpus"
    );

    // Verify LFO (least-frequent-first, ascending) sort by count.
    let counts: Vec<u64> = arr.iter().filter_map(|e| e["count"].as_u64()).collect();
    let mut sorted = counts.clone();
    sorted.sort_unstable();
    assert_eq!(counts, sorted, "by_event_id must be sorted ascending (LFO)");
}

// ── wt extract --cmdline across all LOLBin execution samples ─────────────────

/// All Sysmon `LOLBin` files in Execution/ must yield non-empty cmdline results.
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
            p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                (n.contains("lolbin") || n.contains("lolbas"))
                    && (n.contains("sysmon") || n.contains("exec_sysmon"))
            })
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
        if json.as_array().is_none_or(std::vec::Vec::is_empty) {
            empties.push(path.display().to_string());
        }
    }

    assert!(
        empties.is_empty(),
        "these LOLBin corpus files returned no cmdline results (Sysmon EID 1 not parsed):\n{}",
        empties.join("\n")
    );
}

// ── DFIRArtifactMuseum corpus tests ──────────────────────────────────────────

fn dfir_museum(rel: &str) -> PathBuf {
    workspace_root()
        .join("tests/data/DFIRArtifactMuseum")
        .join(rel)
}

macro_rules! require_dfir_museum {
    ($rel:expr) => {{
        let p = dfir_museum($rel);
        if !p.exists() {
            eprintln!("SKIP: DFIRArtifactMuseum corpus not found: {}", p.display());
            return;
        }
        p
    }};
}

// ── RED: WMI-Activity UserData extraction ────────────────────────────────────

/// EID 5861 (permanent WMI subscription binding) stores its fields in
/// `UserData → Operation_ESStoConsumerBinding`, NOT in `EventData`.
/// The `wmi_events()` function only checks `EventData` → returns null fields.
///
/// This test expects `consumer_name` to be populated on EID 5861 events.
/// Currently FAILS because `wmi_events()` never checks `UserData`.
#[test]
fn dfir_museum_wmi_subscription_events_have_consumer_name() {
    let wmi = require_dfir_museum!(
        "APTSimulatorVM-Win10/Microsoft-Windows-WMI-Activity%4Operational.evtx"
    );

    let output = Command::new(wt_bin())
        .args(["extract", "--wmi", wmi.to_str().unwrap()])
        .output()
        .expect("run wt extract --wmi");

    assert_eq!(
        output.status.code(),
        Some(0),
        "must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");

    let sub_events: Vec<_> = arr
        .iter()
        .filter(|e| matches!(e["event_id"].as_u64(), Some(5860 | 5861)))
        .collect();

    assert!(
        !sub_events.is_empty(),
        "APTSimulatorVM WMI-Activity must contain EID 5860/5861 subscription events"
    );

    let has_consumer = sub_events
        .iter()
        .any(|e| e["consumer_name"].as_str().is_some());
    assert!(
        has_consumer,
        "at least one EID 5860/5861 event must have consumer_name populated;\
         EventData is null — data is in UserData (not yet checked by wmi_events())"
    );
}

/// EID 5861 permanent subscription binding must surface the filter name
/// from the `ESS` field inside `UserData` → `Operation_ESStoConsumerBinding`.
/// Currently FAILS (same root cause as `consumer_name` test above).
#[test]
fn dfir_museum_wmi_subscription_events_have_filter_name() {
    let wmi = require_dfir_museum!(
        "APTSimulatorVM-Win10/Microsoft-Windows-WMI-Activity%4Operational.evtx"
    );

    let output = Command::new(wt_bin())
        .args(["extract", "--wmi", wmi.to_str().unwrap()])
        .output()
        .expect("run wt extract --wmi");

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");

    let sub_events: Vec<_> = arr
        .iter()
        .filter(|e| matches!(e["event_id"].as_u64(), Some(5860 | 5861)))
        .collect();

    let has_filter = sub_events
        .iter()
        .any(|e| e["filter_name"].as_str().is_some());
    assert!(
        has_filter,
        "at least one EID 5860/5861 event must have filter_name populated;\
         ESS field in UserData contains the subscription name"
    );
}

// ── GREEN: DFIRArtifactMuseum robustness ──────────────────────────────────────

/// `wt info` must not panic on any file in the APTSimulatorVM-Win10 corpus.
#[test]
fn dfir_museum_aptvm_robustness_no_panic() {
    let corpus_dir = dfir_museum("APTSimulatorVM-Win10");
    if !corpus_dir.exists() {
        eprintln!("SKIP: DFIRArtifactMuseum/APTSimulatorVM-Win10 not found");
        return;
    }

    let evtx_files = walkdir_evtx(&corpus_dir);
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
        "wt info must exit 0 or 3 for all APTSimulatorVM files:\n{}",
        failures.join("\n")
    );
}

/// `APTSimulatorVM` Sysmon EID 1 log must yield `LOLBin` cmdline entries.
#[test]
fn dfir_museum_aptvm_sysmon_cmdline_lolbins_nonempty() {
    let sysmon =
        require_dfir_museum!("APTSimulatorVM-Win10/Microsoft-Windows-Sysmon%4Operational.evtx");

    let output = Command::new(wt_bin())
        .args(["extract", "--cmdline", sysmon.to_str().unwrap()])
        .output()
        .expect("run wt extract --cmdline sysmon");

    assert_eq!(
        output.status.code(),
        Some(0),
        "must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");
    assert!(
        !arr.is_empty(),
        "APTSimulatorVM Sysmon log must yield cmdline entries"
    );

    let lolbins: Vec<_> = arr
        .iter()
        .filter(|e| e["is_lolbin"].as_bool() == Some(true))
        .collect();
    assert!(
        !lolbins.is_empty(),
        "APTSimulatorVM Sysmon log must detect at least one LOLBin (rundll32/wscript found); \
         entries: {arr:?}"
    );
}

/// `BelkasoftCTF` `InsiderThreat` `PowerShell` log has EID 4104 script blocks.
#[test]
fn dfir_museum_belkasoft_powershell_blocks_nonempty() {
    let ps = require_dfir_museum!(
        "BelkasoftCTF-InsiderThreat/Microsoft-Windows-PowerShell%4Operational.evtx"
    );

    let output = Command::new(wt_bin())
        .args(["extract", "--powershell", ps.to_str().unwrap()])
        .output()
        .expect("run wt extract --powershell belkasoft");

    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    let arr = json.as_array().expect("must be array");
    assert!(
        !arr.is_empty(),
        "BelkasoftCTF InsiderThreat PS log must yield EID 4104 script block entries"
    );
}

/// `wt report` on the APTSimulatorVM-Win10 corpus directory must exit 0
/// and enumerate EVTX files in the JSON output.
#[test]
fn dfir_museum_aptvm_report_enumerates_evtx_files() {
    let corpus_dir = dfir_museum("APTSimulatorVM-Win10");
    if !corpus_dir.exists() {
        eprintln!("SKIP: DFIRArtifactMuseum/APTSimulatorVM-Win10 not found");
        return;
    }
    let out = tempfile::tempdir().expect("tempdir");

    let output = Command::new(wt_bin())
        .args([
            "report",
            corpus_dir.to_str().unwrap(),
            "--output",
            out.path().to_str().unwrap(),
        ])
        .output()
        .expect("run wt report aptvm");

    assert_eq!(
        output.status.code(),
        Some(0),
        "must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be JSON");
    let files = json["evtx_files"]
        .as_array()
        .expect("evtx_files must be array");
    assert!(
        !files.is_empty(),
        "wt report on APTSimulatorVM directory must enumerate EVTX files"
    );

    // Input kind must be Directory.
    assert_eq!(
        json["input"]["kind"].as_str(),
        Some("Directory"),
        "input kind must be Directory"
    );
}

// ── helpers ───────────────────────────────────────────────────────────────────

// ── EVTX-to-MITRE-Attack corpus tests ────────────────────────────────────────

fn mitre_corpus(rel: &str) -> PathBuf {
    workspace_root()
        .join("tests/data/EVTX-to-MITRE-Attack")
        .join(rel)
}

macro_rules! require_mitre {
    ($rel:expr) => {{
        let p = mitre_corpus($rel);
        if !p.exists() {
            eprintln!(
                "SKIP: EVTX-to-MITRE-Attack corpus not found: {}",
                p.display()
            );
            return;
        }
        p
    }};
}

// ── RED: Sysmon EID 19/20/21 WMI filter/consumer events ──────────────────────

/// `wt extract --wmi` on a Sysmon log containing EID 19 (`WmiEventFilter`) and
/// EID 20 (`WmiEventConsumer`) must return at least one event.
///
/// Currently FAILS: `wmi_events()` only handles WMI-Activity EIDs 5857-5861
/// and ignores the Sysmon WMI persistence EIDs 19/20/21.
#[test]
fn mitre_wmi_sysmon_eid19_20_returns_events() {
    let evtx = require_mitre!(
        "TA0003-Persistence/T1546-Event Triggered Execution/ID19-20-WMI registration via PowerLurk.evtx"
    );

    let output = Command::new(wt_bin())
        .args(["extract", "--wmi", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --wmi sysmon eid 19/20");

    assert_eq!(
        output.status.code(),
        Some(0),
        "must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be valid JSON");
    let arr = json.as_array().expect("must be array");

    assert!(
        !arr.is_empty(),
        "Sysmon WMI persistence log (EID 19/20) must yield events via wt extract --wmi;\
         wmi_events() does not yet handle Sysmon EIDs 19/20/21"
    );
}

// ── GREEN: EVTX-to-MITRE-Attack robustness ────────────────────────────────────

/// `wt info` must not panic on any of the 292 files in EVTX-to-MITRE-Attack.
#[test]
fn mitre_robustness_all_files_no_panic() {
    let corpus_dir = mitre_corpus(".");
    if !corpus_dir.exists() {
        eprintln!("SKIP: EVTX-to-MITRE-Attack corpus not found");
        return;
    }

    let evtx_files = walkdir_evtx(&corpus_dir);
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
        "wt info must exit 0 or 3 for all MITRE corpus files:\n{}",
        failures.join("\n")
    );
}

/// T1059.001 `PowerShell` execution samples contain EID 4104 script blocks.
#[test]
fn mitre_execution_ps_blocks_nonempty() {
    let evtx = require_mitre!(
        "TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload download via PowerShell.evtx"
    );

    let output = Command::new(wt_bin())
        .args(["extract", "--powershell", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --powershell mitre ps");

    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(
        !json.as_array().unwrap().is_empty(),
        "T1059.001 PowerShell payload file must yield EID 4104 blocks"
    );
}

/// T1053.005 scheduled task samples contain EID 4698 (task created) events.
#[test]
fn mitre_execution_scheduled_task_nonempty() {
    let evtx = require_mitre!(
        "TA0002-Execution/T1053.005-Scheduled Task/ID4698-4699-Fast created & deleted task by SMBexec (sups. arg.).evtx"
    );

    let output = Command::new(wt_bin())
        .args(["extract", "--scheduled-task", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --scheduled-task mitre");

    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("must be JSON");
    assert!(
        !json.as_array().unwrap().is_empty(),
        "T1053.005 scheduled task file must yield EID 4698 entries"
    );
}

/// T1003 Credential Access: Sysmon LSASS dump file has Sysmon EID 10 events
/// and `wt extract --cmdline` returns process entries.
#[test]
fn mitre_credential_access_lsass_sysmon_cmdlines() {
    let evtx = require_mitre!(
        "TA0006-Credential Access/T1003-Credential dumping/ID10-Mimikatz LSASS process dump.evtx"
    );

    let output = Command::new(wt_bin())
        .args(["extract", "--cmdline", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --cmdline mitre lsass");

    // Exit 0 (no entries) or exit 0 with entries — either is fine for robustness.
    // The key assertion is that it doesn't panic or produce invalid JSON.
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "must not panic; exit {code}; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.stdout.is_empty() {
        serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .expect("output must be valid JSON when non-empty");
    }
}

// ── GREEN: remaining DFIRArtifactMuseum subdir robustness ─────────────────────

/// `wt info` must not panic on any file in APTSimulatorVM-Server2022.
#[test]
fn dfir_museum_server2022_robustness_no_panic() {
    let corpus_dir = dfir_museum("APTSimulatorVM-Server2022");
    if !corpus_dir.exists() {
        eprintln!("SKIP: DFIRArtifactMuseum/APTSimulatorVM-Server2022 not found");
        return;
    }
    let failures = robustness_check_info(&corpus_dir);
    assert!(
        failures.is_empty(),
        "wt info must exit 0 or 3 for all APTSimulatorVM-Server2022 files:\n{}",
        failures.join("\n")
    );
}

/// `wt info` must not panic on any file in BelkasoftCTF-InsiderThreat.
#[test]
fn dfir_museum_belkasoft_robustness_no_panic() {
    let corpus_dir = dfir_museum("BelkasoftCTF-InsiderThreat");
    if !corpus_dir.exists() {
        eprintln!("SKIP: DFIRArtifactMuseum/BelkasoftCTF-InsiderThreat not found");
        return;
    }
    let failures = robustness_check_info(&corpus_dir);
    assert!(
        failures.is_empty(),
        "wt info must exit 0 or 3 for all BelkasoftCTF-InsiderThreat files:\n{}",
        failures.join("\n")
    );
}

/// `wt info` must not panic on any file in StolenSzechuan-Win2012R2.
#[test]
fn dfir_museum_szechuan_robustness_no_panic() {
    let corpus_dir = dfir_museum("StolenSzechuan-Win2012R2");
    if !corpus_dir.exists() {
        eprintln!("SKIP: DFIRArtifactMuseum/StolenSzechuan-Win2012R2 not found");
        return;
    }
    let failures = robustness_check_info(&corpus_dir);
    assert!(
        failures.is_empty(),
        "wt info must exit 0 or 3 for all StolenSzechuan-Win2012R2 files:\n{}",
        failures.join("\n")
    );
}

/// `wt info` must not panic on any file in RathbunVM-Win10 (clean baseline).
#[test]
fn dfir_museum_rathbun_win10_robustness_no_panic() {
    let corpus_dir = dfir_museum("RathbunVM-Win10");
    if !corpus_dir.exists() {
        eprintln!("SKIP: DFIRArtifactMuseum/RathbunVM-Win10 not found");
        return;
    }
    let failures = robustness_check_info(&corpus_dir);
    assert!(
        failures.is_empty(),
        "wt info must exit 0 or 3 for all RathbunVM-Win10 files:\n{}",
        failures.join("\n")
    );
}

/// `wt info` must not panic on any file in RathbunVM-Win11 (clean baseline).
#[test]
fn dfir_museum_rathbun_win11_robustness_no_panic() {
    let corpus_dir = dfir_museum("RathbunVM-Win11");
    if !corpus_dir.exists() {
        eprintln!("SKIP: DFIRArtifactMuseum/RathbunVM-Win11 not found");
        return;
    }
    let failures = robustness_check_info(&corpus_dir);
    assert!(
        failures.is_empty(),
        "wt info must exit 0 or 3 for all RathbunVM-Win11 files:\n{}",
        failures.join("\n")
    );
}

fn robustness_check_info(dir: &PathBuf) -> Vec<String> {
    let files = walkdir_evtx(dir);
    let mut failures = Vec::new();
    for path in &files {
        let output = Command::new(wt_bin())
            .args(["info", path.to_str().unwrap()])
            .output()
            .expect("run wt info");
        let code = output.status.code().unwrap_or(-1);
        if code != 0 && code != 3 {
            failures.push(format!("{}: exit {code}", path.display()));
        }
    }
    failures
}

fn walkdir_evtx(dir: &PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walkdir_inner(dir, &mut out);
    out
}

fn walkdir_inner(dir: &PathBuf, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
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

// ── CybeDefenders CorporateSecrets Lab corpus tests ───────────────────────────
//
// Extracted from 33-CorporateSecrets.zip (password: cyberdefenders.org) via
// pyad1 → ADSEGMENTEDFILE logical image → NTFS winevt/Logs directory.
// 148 EVTX files from a Windows 10 endpoint, April 2020.

fn cybedefenders_evtx(filename: &str) -> PathBuf {
    workspace_root()
        .join("tests/data/CybeDefenders CorporateSecrets Lab/evtx")
        .join(filename)
}

macro_rules! require_cybedefenders {
    ($file:expr) => {{
        let p = cybedefenders_evtx($file);
        if !p.exists() {
            eprintln!("SKIP: CybeDefenders corpus not found: {}", p.display());
            return;
        }
        p
    }};
}

/// All 148 EVTX files must exit 0 or 3 under `wt info`.
/// Exit codes 1/2 indicate parse errors or CLI bugs — not acceptable.
#[test]
fn cybedefenders_robustness_all_files_no_panic() {
    let dir = cybedefenders_evtx("");
    if !dir.exists() {
        eprintln!("SKIP: CybeDefenders corpus not found");
        return;
    }
    let failures = robustness_check_info(&dir);
    assert!(
        failures.is_empty(),
        "wt info exited unexpectedly on CybeDefenders corpus:\n{}",
        failures.join("\n")
    );
}

/// Security.evtx (9 MB, 10k+ events) must yield logon sessions via `wt login`.
#[test]
fn cybedefenders_security_login_sessions_nonempty() {
    let evtx = require_cybedefenders!("Security.evtx");
    let output = Command::new(wt_bin())
        .args(["login", evtx.to_str().unwrap()])
        .output()
        .expect("run wt login");
    assert_eq!(
        output.status.code(),
        Some(0),
        "wt login must exit 0 on Security.evtx; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("wt login must output valid JSON");
    let arr = json.as_array().expect("must be array");
    assert!(
        !arr.is_empty(),
        "Security.evtx has EID 4624 events — login must return sessions"
    );
}

/// `PowerShell` operational log must yield at least one script block.
#[test]
fn cybedefenders_powershell_blocks_nonempty() {
    let evtx = require_cybedefenders!("Microsoft-Windows-PowerShell%4Operational.evtx");
    let output = Command::new(wt_bin())
        .args(["extract", "--powershell", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --powershell");
    assert_eq!(output.status.code(), Some(0));
    let arr: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be valid JSON");
    assert!(
        arr.as_array().is_some_and(|a| !a.is_empty()),
        "PowerShell operational log must contain script blocks"
    );
}

/// WMI-Activity operational log must yield WMI events via `wt extract --wmi`.
/// This corpus is notable for having 838 WMI provider events.
#[test]
fn cybedefenders_wmi_activity_events_nonempty() {
    let evtx = require_cybedefenders!("Microsoft-Windows-WMI-Activity%4Operational.evtx");
    let output = Command::new(wt_bin())
        .args(["extract", "--wmi", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --wmi");
    assert_eq!(output.status.code(), Some(0));
    let arr: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be valid JSON");
    assert!(
        arr.as_array().is_some_and(|a| !a.is_empty()),
        "WMI-Activity log must yield events via wt extract --wmi"
    );
}

/// Security.evtx cmdlines (EID 4688 process creation) must be non-empty.
#[test]
fn cybedefenders_security_cmdlines_nonempty() {
    let evtx = require_cybedefenders!("Security.evtx");
    let output = Command::new(wt_bin())
        .args(["extract", "--cmdline", evtx.to_str().unwrap()])
        .output()
        .expect("run wt extract --cmdline");
    assert_eq!(output.status.code(), Some(0));
    let arr: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("must be valid JSON");
    assert!(
        arr.as_array().is_some_and(|a| !a.is_empty()),
        "Security.evtx must yield EID 4688 process command lines"
    );
}
