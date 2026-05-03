use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("wt-evtx").unwrap()
}

// ── 1. Help exits 0 and mentions "timeline" ──────────────────────────────────

#[test]
fn wt_evtx_help_exits_0() {
    let output = bin().arg("--help").output().unwrap();
    assert!(
        output.status.success(),
        "expected exit 0, got: {:?}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("timeline"),
        "expected 'timeline' in help output, got:\n{stdout}"
    );
}

// ── 2. timeline --help exits 0 and mentions "directory" ──────────────────────

#[test]
fn wt_evtx_timeline_help_exits_0() {
    let output = bin().args(["timeline", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("directory"),
        "expected 'directory' in timeline --help, got:\n{stdout}"
    );
}

// ── 3. sessions --help exits 0 and mentions "directory" ──────────────────────

#[test]
fn wt_evtx_sessions_help_exits_0() {
    let output = bin().args(["sessions", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("directory"),
        "expected 'directory' in sessions --help, got:\n{stdout}"
    );
}

// ── 4. processes --help exits 0 ──────────────────────────────────────────────

#[test]
fn wt_evtx_processes_help_exits_0() {
    let output = bin().args(["processes", "--help"]).output().unwrap();
    assert!(output.status.success());
}

// ── 5. frequency --help exits 0 ──────────────────────────────────────────────

#[test]
fn wt_evtx_frequency_help_exits_0() {
    let output = bin().args(["frequency", "--help"]).output().unwrap();
    assert!(output.status.success());
}

// ── 6. timeline empty dir → CSV header ───────────────────────────────────────

#[test]
fn wt_evtx_timeline_empty_dir_produces_csv_header() {
    let dir = tempfile::tempdir().unwrap();
    let output = bin()
        .args([
            "timeline",
            "--directory",
            dir.path().to_str().unwrap(),
            "--format",
            "csv",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(
        first_line.contains("timestamp") && first_line.contains("event_id") && first_line.contains("channel"),
        "expected CSV header with timestamp,event_id,channel in first line, got:\n{first_line}"
    );
}

// ── 7. sessions empty dir exits 0 ────────────────────────────────────────────

#[test]
fn wt_evtx_sessions_empty_dir_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let output = bin()
        .args(["sessions", "--directory", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── 8. processes empty dir exits 0 ───────────────────────────────────────────

#[test]
fn wt_evtx_processes_empty_dir_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let output = bin()
        .args(["processes", "--directory", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── 9. frequency empty dir exits 0 ───────────────────────────────────────────

#[test]
fn wt_evtx_frequency_empty_dir_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let output = bin()
        .args(["frequency", "--directory", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── 10. timeline missing dir fails (nonzero exit) ────────────────────────────

#[test]
fn wt_evtx_timeline_missing_dir_fails() {
    let output = bin()
        .args([
            "timeline",
            "--directory",
            "/nonexistent/path/that/does/not/exist/abc123",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "expected nonzero exit for missing directory, got success"
    );
}
