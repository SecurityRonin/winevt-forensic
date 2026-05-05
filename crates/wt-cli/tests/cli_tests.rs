use std::io::Write;
use std::process::Command;

fn wt_bin() -> Command {
    let mut bin = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bin.push("../../target/debug/wt");
    Command::new(bin)
}

/// Build a minimal valid EVTX file (file header + one valid chunk) in a temp file.
fn write_valid_evtx() -> std::path::PathBuf {
    // Minimal chunk with correct checksums
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
    let crc = {
        let mut h = crc32fast::Hasher::new();
        h.update(&chunk[0..0x78]);
        h.finalize()
    };
    chunk[0x78..0x7C].copy_from_slice(&crc.to_le_bytes());

    let mut path = std::env::temp_dir();
    path.push(format!(
        "wt_test_valid_{}.evtx",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));
    let mut f = std::fs::File::create(&path).expect("create temp");
    f.write_all(&chunk).expect("write chunk");
    path
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
    assert_eq!(output.status.code(), Some(0), "wt stats should exit 0 for valid file");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Chunks:"), "expected 'Chunks:' in output, got: {stdout}");
    assert!(stdout.contains("Records:"), "expected 'Records:' in output, got: {stdout}");
    assert!(stdout.contains("Hash:"), "expected 'Hash:' in output, got: {stdout}");
}

#[test]
fn wt_stats_nonexistent_exits_code_2() {
    let status = wt_bin()
        .args(["stats", "/nonexistent/path/stats_test.evtx"])
        .status()
        .expect("run wt stats");
    assert_eq!(status.code(), Some(2), "wt stats on nonexistent path should exit 2");
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
    let _: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("expected valid JSON from wt stats --json, got error: {e}, output: {stdout}"));
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
fn wt_verify_nonexistent_exits_code_2() {
    let status = wt_bin()
        .args(["verify", "/nonexistent/path/feature9.evtx"])
        .status()
        .expect("run wt verify");
    assert_eq!(
        status.code(),
        Some(2),
        "wt verify on nonexistent path should exit 2 (I/O error)"
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
