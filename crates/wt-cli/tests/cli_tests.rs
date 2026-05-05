use std::process::Command;

fn wt_bin() -> Command {
    let mut bin = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bin.push("../../target/debug/wt");
    Command::new(bin)
}

#[test]
fn wt_help_exits_success() {
    let status = wt_bin().arg("--help").status().expect("failed to run wt --help");
    assert!(status.success());
}

#[test]
fn wt_version_exits_success() {
    let status = wt_bin().arg("--version").status().expect("failed to run wt --version");
    assert!(status.success());
}

#[test]
fn wt_carve_help_exits_success() {
    let status = wt_bin().args(["carve", "--help"]).status().expect("failed to run wt carve --help");
    assert!(status.success());
}

#[test]
fn wt_verify_help_exits_success() {
    let status = wt_bin().args(["verify", "--help"]).status().expect("failed to run wt verify --help");
    assert!(status.success());
}

#[test]
fn wt_carve_nonexistent_path_exits_nonzero() {
    let status = wt_bin()
        .args(["carve", "/tmp/does_not_exist_evtx_12345.evtx"])
        .status()
        .expect("failed to run wt carve");
    assert!(!status.success(), "wt carve on nonexistent file should fail");
}

#[test]
fn wt_verify_nonexistent_path_exits_nonzero() {
    let status = wt_bin()
        .args(["verify", "/tmp/does_not_exist_evtx_12345.evtx"])
        .status()
        .expect("failed to run wt verify");
    assert!(!status.success(), "wt verify on nonexistent file should fail");
}
