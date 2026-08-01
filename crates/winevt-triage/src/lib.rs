//! One-click E01 → EVTX extraction + Hayabusa report pipeline.
//!
//! # Pipeline
//!
//! 1. Open the E01 via [`ewf::EwfReader`] (`Read + Seek`).
//! 2. Parse the MBR to locate the NTFS partition offset.
//! 3. Traverse NTFS with the [`ntfs`] crate to find `*.evtx` files under
//!    `Windows/System32/winevt/Logs/`.
//! 4. Stream each EVTX file out to a caller-supplied output directory.
//! 5. (CLI layer) Run Hayabusa on that directory and emit a combined JSON report.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::{Path, PathBuf};

pub use error::TriageError;

mod error;
mod extract;
mod mbr;
mod partition;

// ── Public types ─────────────────────────────────────────────────────────────

/// A single EVTX file extracted from the disk image.
#[derive(Debug, serde::Serialize)]
pub struct ExtractedEvtx {
    /// Base filename, e.g. `"Security.evtx"`.
    pub name: String,
    /// Absolute path to the extracted file in `out_dir`.
    pub path: PathBuf,
    /// File size in bytes.
    pub size: u64,
}

/// Result of the EVTX extraction phase.
#[derive(Debug, serde::Serialize)]
pub struct TriageReport {
    /// Canonical path to the source E01 image.
    pub image: PathBuf,
    /// NTFS partition start in 512-byte sectors (from MBR).
    pub ntfs_offset_sectors: u64,
    /// Extracted EVTX files.
    pub evtx_files: Vec<ExtractedEvtx>,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Parse MBR sector 0 (512 bytes) and return the LBA start of the first
/// NTFS partition (type `0x07`, `0x17`, or `0x27`).
///
/// Returns `None` when no NTFS partition entry is found.
pub fn parse_mbr_ntfs_offset(sector: &[u8; 512]) -> Option<u64> {
    mbr::parse_ntfs_offset(sector)
}

/// Extract all `*.evtx` files from an E01 forensic image into `out_dir`.
///
/// Opens the image via [`ewf::EwfReader`], locates the NTFS partition via the
/// MBR, traverses `Windows/System32/winevt/Logs/`, and writes each file to
/// `out_dir/<filename>.evtx`.
pub fn extract_evtx_from_e01(e01_path: &Path, out_dir: &Path) -> Result<TriageReport, TriageError> {
    extract::run(e01_path, out_dir)
}
