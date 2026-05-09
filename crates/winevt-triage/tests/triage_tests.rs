//! Tests for winevt-triage.
//!
//! Unit tests (`parse_mbr_*`) use synthetic data and run anywhere.
//!
//! Integration tests (`extract_evtx_*`) require the MaxPowersCDrive.E01 image
//! symlinked at `tests/data/DEF CON DFIR CTF 2018/MaxPowersCDrive.E01`.
//! They skip gracefully when the file is absent.

use winevt_triage::{extract_evtx_from_e01, parse_mbr_ntfs_offset};

// ── helpers ───────────────────────────────────────────────────────────────────

fn workspace_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = crates/winevt-triage
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // workspace root
    p
}

fn maxpowers_e01() -> std::path::PathBuf {
    workspace_root()
        .join("tests/data/DEF CON DFIR CTF 2018/MaxPowersCDrive.E01")
}

macro_rules! require_maxpowers {
    () => {{
        let p = maxpowers_e01();
        if !p.exists() {
            eprintln!(
                "SKIP: {} not found — symlink from ~/src/issen/tests/data",
                p.display()
            );
            return;
        }
        p
    }};
}

// ── parse_mbr_ntfs_offset unit tests ─────────────────────────────────────────

/// Build a minimal MBR sector with one partition entry of the given type at LBA `lba`.
fn make_mbr(part_type: u8, lba: u32) -> [u8; 512] {
    let mut sector = [0u8; 512];
    // MBR signature
    sector[510] = 0x55;
    sector[511] = 0xAA;
    // First partition entry at 0x1BE
    let base = 0x1BE;
    sector[base + 4] = part_type;
    sector[base + 8..base + 12].copy_from_slice(&lba.to_le_bytes());
    sector
}

#[test]
fn parse_mbr_finds_ntfs_type_07() {
    let sector = make_mbr(0x07, 2048);
    assert_eq!(parse_mbr_ntfs_offset(&sector), Some(2048));
}

#[test]
fn parse_mbr_finds_ntfs_type_17() {
    let sector = make_mbr(0x17, 4096);
    assert_eq!(parse_mbr_ntfs_offset(&sector), Some(4096));
}

#[test]
fn parse_mbr_finds_ntfs_type_27() {
    let sector = make_mbr(0x27, 1026048);
    assert_eq!(parse_mbr_ntfs_offset(&sector), Some(1026048));
}

#[test]
fn parse_mbr_ignores_fat32_returns_none() {
    let sector = make_mbr(0x0B, 63); // FAT32 CHS
    assert_eq!(parse_mbr_ntfs_offset(&sector), None);
}

#[test]
fn parse_mbr_all_zeros_returns_none() {
    let sector = [0u8; 512];
    assert_eq!(parse_mbr_ntfs_offset(&sector), None);
}

#[test]
fn parse_mbr_skips_fat_finds_ntfs_in_second_slot() {
    let mut sector = [0u8; 512];
    sector[510] = 0x55;
    sector[511] = 0xAA;
    // First entry: FAT32 (0x0B)
    sector[0x1BE + 4] = 0x0B;
    sector[0x1BE + 8..0x1BE + 12].copy_from_slice(&63u32.to_le_bytes());
    // Second entry: NTFS (0x07) at LBA 1026048
    sector[0x1CE + 4] = 0x07;
    sector[0x1CE + 8..0x1CE + 12].copy_from_slice(&1026048u32.to_le_bytes());
    assert_eq!(parse_mbr_ntfs_offset(&sector), Some(1026048));
}

// ── extract_evtx_from_e01 integration tests ──────────────────────────────────

/// Known NTFS partition offset for MaxPowersCDrive.E01 (verified with mmls).
const MAXPOWERS_NTFS_OFFSET: u64 = 1_026_048;

#[test]
fn extract_evtx_reports_correct_ntfs_offset() {
    let e01 = require_maxpowers!();
    let out = tempfile::tempdir().expect("tempdir");
    let report = extract_evtx_from_e01(&e01, out.path())
        .expect("extract_evtx_from_e01 should succeed");
    assert_eq!(
        report.ntfs_offset_sectors, MAXPOWERS_NTFS_OFFSET,
        "expected NTFS offset {MAXPOWERS_NTFS_OFFSET}, got {}",
        report.ntfs_offset_sectors
    );
}

#[test]
fn extract_evtx_finds_security_evtx() {
    let e01 = require_maxpowers!();
    let out = tempfile::tempdir().expect("tempdir");
    let report = extract_evtx_from_e01(&e01, out.path())
        .expect("extract_evtx_from_e01 should succeed");
    assert!(
        report.evtx_files.iter().any(|f| f.name.eq_ignore_ascii_case("Security.evtx")),
        "expected Security.evtx in extracted files; got: {:?}",
        report.evtx_files.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
}

#[test]
fn extract_evtx_finds_system_evtx() {
    let e01 = require_maxpowers!();
    let out = tempfile::tempdir().expect("tempdir");
    let report = extract_evtx_from_e01(&e01, out.path())
        .expect("extract_evtx_from_e01 should succeed");
    assert!(
        report.evtx_files.iter().any(|f| f.name.eq_ignore_ascii_case("System.evtx")),
        "expected System.evtx in extracted files; got: {:?}",
        report.evtx_files.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
}

#[test]
fn extract_evtx_files_have_evtx_magic() {
    let e01 = require_maxpowers!();
    let out = tempfile::tempdir().expect("tempdir");
    let report = extract_evtx_from_e01(&e01, out.path())
        .expect("extract_evtx_from_e01 should succeed");

    // Every extracted file must start with the EVTX magic bytes.
    const EVTX_MAGIC: &[u8] = b"ElfFile\x00";
    for evtx in &report.evtx_files {
        let bytes = std::fs::read(&evtx.path).expect("read extracted evtx");
        assert!(
            bytes.starts_with(EVTX_MAGIC),
            "{} does not start with EVTX magic (ElfFile\\0)",
            evtx.name
        );
    }
}

#[test]
fn extract_evtx_nonexistent_image_returns_error() {
    let out = tempfile::tempdir().expect("tempdir");
    let result = extract_evtx_from_e01(
        std::path::Path::new("/nonexistent/no.E01"),
        out.path(),
    );
    assert!(result.is_err(), "expected error for nonexistent E01");
}
