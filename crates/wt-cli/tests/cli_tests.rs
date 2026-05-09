use std::io::Write;
use std::process::Command;
use winevt_writer::{records_to_evtx, WriteRecord};

fn wt_bin() -> Command {
    let mut bin = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bin.push("../../target/debug/wt");
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
    chunk[0x78..0x7C].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

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
fn wt_carve_help_exits_success() {
    let status = wt_bin()
        .args(["carve", "--help"])
        .status()
        .expect("failed to run wt carve --help");
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
fn wt_carve_nonexistent_path_exits_nonzero() {
    let status = wt_bin()
        .args(["carve", "/tmp/does_not_exist_evtx_12345.evtx"])
        .status()
        .expect("failed to run wt carve");
    assert!(
        !status.success(),
        "wt carve on nonexistent file should fail"
    );
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

// ---- E01/EWF: wt carve-ewf subcommand ----

#[test]
fn wt_carve_ewf_nonexistent_exits_code_2() {
    let status = wt_bin()
        .args(["carve-ewf", "/nonexistent/disk.E01"])
        .status()
        .expect("run wt carve-ewf");
    assert_eq!(
        status.code(),
        Some(2),
        "wt carve-ewf on nonexistent path should exit 2"
    );
}

#[test]
fn wt_carve_ewf_help_exits_success() {
    let status = wt_bin()
        .args(["carve-ewf", "--help"])
        .status()
        .expect("run wt carve-ewf --help");
    assert!(status.success(), "wt carve-ewf --help should exit 0");
}

// ---- Feature 12: wt stats subcommand ----

#[test]
fn wt_stats_valid_file_exits_code_0() {
    let path = write_valid_evtx();
    let output = wt_bin()
        .args(["stats", path.to_str().unwrap()])
        .output()
        .expect("run wt stats");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        output.status.code(),
        Some(0),
        "wt stats should exit 0 for valid file"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Chunks:"),
        "expected 'Chunks:' in output, got: {stdout}"
    );
    assert!(
        stdout.contains("Records:"),
        "expected 'Records:' in output, got: {stdout}"
    );
    assert!(
        stdout.contains("Hash:"),
        "expected 'Hash:' in output, got: {stdout}"
    );
}

#[test]
fn wt_stats_nonexistent_exits_code_2() {
    let status = wt_bin()
        .args(["stats", "/nonexistent/path/stats_test.evtx"])
        .status()
        .expect("run wt stats");
    assert_eq!(
        status.code(),
        Some(2),
        "wt stats on nonexistent path should exit 2"
    );
}

#[test]
fn wt_stats_json_flag_outputs_valid_json() {
    let path = write_valid_evtx();
    let output = wt_bin()
        .args(["stats", "--json", path.to_str().unwrap()])
        .output()
        .expect("run wt stats --json");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let _: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("expected valid JSON from wt stats --json, got error: {e}, output: {stdout}")
    });
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

#[test]
fn wt_carve_valid_file_exits_code_0() {
    let path = write_valid_evtx();
    let status = wt_bin()
        .args(["carve", path.to_str().unwrap()])
        .status()
        .expect("run wt carve");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status.code(),
        Some(0),
        "wt carve on valid file should exit 0"
    );
}

#[test]
fn wt_carve_nonexistent_exits_code_2() {
    let status = wt_bin()
        .args(["carve", "/nonexistent/path/feature9.evtx"])
        .status()
        .expect("run wt carve");
    assert_eq!(
        status.code(),
        Some(2),
        "wt carve on nonexistent path should exit 2"
    );
}

// ── Feature 17: wt reconstruct subcommand ─────────────────────────────────────

#[test]
fn wt_reconstruct_help_exits_success() {
    let status = wt_bin()
        .args(["reconstruct", "--help"])
        .status()
        .expect("run wt reconstruct --help");
    assert!(status.success(), "wt reconstruct --help should exit 0");
}

#[test]
fn wt_reconstruct_nonexistent_input_exits_code_2() {
    let out = temp_evtx("recon_out");
    let status = wt_bin()
        .args([
            "reconstruct",
            "--output",
            out.to_str().unwrap(),
            "/nonexistent/no_such.evtx",
        ])
        .status()
        .expect("run wt reconstruct");
    let _ = std::fs::remove_file(&out);
    assert_eq!(status.code(), Some(2), "nonexistent input should exit 2");
}

#[test]
fn wt_reconstruct_valid_input_exits_code_0() {
    let input = write_evtx_with_records("recon_in", 3);
    let output = temp_evtx("recon_out");
    let status = wt_bin()
        .args([
            "reconstruct",
            "--output",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .expect("run wt reconstruct");
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    assert_eq!(
        status.code(),
        Some(0),
        "wt reconstruct on valid input should exit 0"
    );
}

#[test]
fn wt_reconstruct_output_is_valid_evtx() {
    let input = write_evtx_with_records("recon_valid_in", 3);
    let output = temp_evtx("recon_valid_out");
    let status = wt_bin()
        .args([
            "reconstruct",
            "--output",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .expect("run wt reconstruct");
    assert_eq!(status.code(), Some(0));

    // Output must start with ElfFile magic
    let bytes = std::fs::read(&output).expect("read output");
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    assert_eq!(
        &bytes[0..8],
        b"ElfFile\0",
        "output must start with ElfFile magic"
    );
}

#[test]
fn wt_reconstruct_output_preserves_record_count() {
    use winevt_carver::carve_from_bytes;

    let input = write_evtx_with_records("recon_rcount_in", 5);
    let output = temp_evtx("recon_rcount_out");
    let status = wt_bin()
        .args([
            "reconstruct",
            "--output",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .expect("run wt reconstruct");
    assert_eq!(status.code(), Some(0));

    let out_bytes = std::fs::read(&output).expect("read output");
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);

    let result = carve_from_bytes(&out_bytes);
    let recovered: usize = result.chunks.iter().map(|c| c.records.len()).sum();
    assert_eq!(recovered, 5, "reconstructed file should contain 5 records");
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

// ── wt sessions tests ─────────────────────────────────────────────────────────

#[test]
fn wt_sessions_help_exits_success() {
    let status = wt_bin()
        .args(["sessions", "--help"])
        .status()
        .expect("run wt sessions --help");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn wt_sessions_nonexistent_exits_code_3() {
    let status = wt_bin()
        .args(["sessions", "/nonexistent/security.evtx"])
        .status()
        .expect("run wt sessions");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn wt_sessions_valid_file_outputs_json_array() {
    let path = write_evtx_with_records("sessions_valid", 2);
    let output = wt_bin()
        .args(["sessions", path.to_str().unwrap()])
        .output()
        .expect("run wt sessions");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("sessions output should be valid JSON");
    assert!(v.is_array(), "sessions should output a JSON array");
}

// ── wt powershell tests ───────────────────────────────────────────────────────

#[test]
fn wt_powershell_help_exits_success() {
    let status = wt_bin()
        .args(["powershell", "--help"])
        .status()
        .expect("run wt powershell --help");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn wt_powershell_nonexistent_exits_code_3() {
    let status = wt_bin()
        .args(["powershell", "/nonexistent/ps.evtx"])
        .status()
        .expect("run wt powershell");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn wt_powershell_valid_file_outputs_json_array() {
    let path = write_evtx_with_records("powershell_valid", 2);
    let output = wt_bin()
        .args(["powershell", path.to_str().unwrap()])
        .output()
        .expect("run wt powershell");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("powershell output should be valid JSON");
    assert!(v.is_array(), "powershell should output a JSON array");
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

// ── wt ioc-extract tests ──────────────────────────────────────────────────────

#[test]
fn wt_ioc_extract_help_exits_success() {
    let status = wt_bin()
        .args(["ioc-extract", "--help"])
        .status()
        .expect("run wt ioc-extract --help");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn wt_ioc_extract_nonexistent_exits_code_3() {
    let status = wt_bin()
        .args(["ioc-extract", "/nonexistent/security.evtx"])
        .status()
        .expect("run wt ioc-extract");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn wt_ioc_extract_valid_file_outputs_json_object() {
    let path = write_evtx_with_records("ioc_valid", 2);
    let output = wt_bin()
        .args(["ioc-extract", path.to_str().unwrap()])
        .output()
        .expect("run wt ioc-extract");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("ioc-extract output should be valid JSON");
    assert!(
        v.get("events_scanned").is_some(),
        "ioc-extract JSON should have 'events_scanned' field"
    );
    assert!(
        v.get("iocs").is_some(),
        "ioc-extract JSON should have 'iocs' field"
    );
}

// ── wt attack-tags tests ──────────────────────────────────────────────────────

#[test]
fn wt_attack_tags_help_exits_success() {
    let status = wt_bin()
        .args(["attack-tags", "--help"])
        .status()
        .expect("run wt attack-tags --help");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn wt_attack_tags_nonexistent_exits_code_3() {
    let status = wt_bin()
        .args(["attack-tags", "/nonexistent/security.evtx"])
        .status()
        .expect("run wt attack-tags");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn wt_attack_tags_valid_file_outputs_json_array() {
    let path = write_evtx_with_records("attack_tags_valid", 2);
    let output = wt_bin()
        .args(["attack-tags", path.to_str().unwrap()])
        .output()
        .expect("run wt attack-tags");
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(0), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("attack-tags output should be valid JSON");
    assert!(v.is_array(), "attack-tags should output a JSON array");
}
