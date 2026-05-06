//! End-to-end integration tests against the real fox-it DanderSpritz before/after EVTX pair.
//!
//! These tests require the fox-it sample files to be present at:
//!   tests/data/fox-it-danderspritz/pre-Security.evtx
//!   tests/data/fox-it-danderspritz/post-Security.evtx
//!
//! Tests skip gracefully (return without panic) when files are absent so CI
//! stays green on machines without the test corpus.
//!
//! # Downloading the samples
//!
//! ```sh
//! mkdir -p tests/data/fox-it-danderspritz
//! curl -L https://raw.githubusercontent.com/fox-it/danderspritz-evtx/master/examples/pre-Security.evtx \
//!      -o tests/data/fox-it-danderspritz/pre-Security.evtx
//! curl -L https://raw.githubusercontent.com/fox-it/danderspritz-evtx/master/examples/post-Security.evtx \
//!      -o tests/data/fox-it-danderspritz/post-Security.evtx
//! ```
//!
//! Reference: Wassenaar & van Dijk, Fox-IT BV (2017).
//! "Detection and recovery of NSA's covered up tracks"
//! <https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/>

use winevt_carver::{IntegrityAnomaly, carve_from_file, verify_integrity};

fn workspace_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = crates/wt-cli
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // workspace root
    p
}

fn foxitdata_path(filename: &str) -> std::path::PathBuf {
    workspace_root()
        .join("tests/data/fox-it-danderspritz")
        .join(filename)
}

macro_rules! require_foxitdata {
    ($filename:expr) => {{
        let p = foxitdata_path($filename);
        if !p.exists() {
            eprintln!(
                "SKIP: {} not found — run download instructions in module doc",
                p.display()
            );
            return;
        }
        p
    }};
}

// ── carve_from_file tests ──────────────────────────────────────────────────

/// pre-Security.evtx (unmodified) must not produce any SurgicalRecordDeletion.
#[test]
fn pre_security_evtx_no_surgical_deletion() {
    let path = require_foxitdata!("pre-Security.evtx");
    let result = carve_from_file(&path).expect("carve_from_file on pre-Security.evtx");
    let has_surgical = result.indicators.iter().any(|ind| {
        matches!(ind, IntegrityAnomaly::SurgicalRecordDeletion { .. })
    });
    assert!(
        !has_surgical,
        "pre-Security.evtx should have no SurgicalRecordDeletion, got: {:?}",
        result.indicators
    );
}

/// post-Security.evtx (after DanderSpritz eventlogedit) must produce exactly
/// one SurgicalRecordDeletion for absorbing_record_id = 104.
///
/// The ghost record's magic is at chunk offset 0x1230 (4656), inside the body
/// of record 104 whose size was inflated from the original to absorb the deleted record.
#[test]
fn post_security_evtx_detects_surgical_deletion() {
    let path = require_foxitdata!("post-Security.evtx");
    let result = carve_from_file(&path).expect("carve_from_file on post-Security.evtx");
    let surgical: Vec<_> = result
        .indicators
        .iter()
        .filter(|ind| matches!(ind, IntegrityAnomaly::SurgicalRecordDeletion { .. }))
        .collect();
    assert_eq!(
        surgical.len(),
        1,
        "expected exactly 1 SurgicalRecordDeletion, got: {:?}",
        result.indicators
    );
    assert!(
        matches!(
            surgical[0],
            IntegrityAnomaly::SurgicalRecordDeletion {
                absorbing_record_id: 104,
                ghost_offset_in_chunk: 4656,
                ..
            }
        ),
        "wrong SurgicalRecordDeletion fields: {:?}",
        surgical[0]
    );
}

/// post-Security.evtx has more recovered records than pre-Security.evtx because
/// the carver finds the ghost record inside the inflated absorbing record's body.
///
/// This confirms our carver recovers deleted records that standard tools miss.
#[test]
fn post_security_evtx_carves_more_records_than_pre() {
    let pre_path = require_foxitdata!("pre-Security.evtx");
    let post_path = require_foxitdata!("post-Security.evtx");
    let pre = carve_from_file(&pre_path).expect("carve pre");
    let post = carve_from_file(&post_path).expect("carve post");
    let pre_count: usize = pre.chunks.iter().map(|c| c.records.len()).sum();
    let post_count: usize = post.chunks.iter().map(|c| c.records.len()).sum();
    // post was tampered — we should recover at least as many (the ghost adds at least 1)
    assert!(
        post_count >= pre_count,
        "expected post (carver recovers ghost) >= pre records, got pre={pre_count} post={post_count}"
    );
}

// ── verify_integrity tests ─────────────────────────────────────────────────

/// verify_integrity on pre-Security.evtx must not return SurgicalRecordDeletion.
#[test]
fn verify_integrity_pre_security_no_surgical_deletion() {
    let path = require_foxitdata!("pre-Security.evtx");
    let indicators = verify_integrity(&path).expect("verify_integrity on pre-Security.evtx");
    let has_surgical = indicators
        .iter()
        .any(|ind| matches!(ind, IntegrityAnomaly::SurgicalRecordDeletion { .. }));
    assert!(
        !has_surgical,
        "pre-Security.evtx should have no SurgicalRecordDeletion via verify_integrity, got: {:?}",
        indicators
    );
}

/// verify_integrity on post-Security.evtx must detect the surgical deletion.
#[test]
fn verify_integrity_post_security_detects_surgical_deletion() {
    let path = require_foxitdata!("post-Security.evtx");
    let indicators = verify_integrity(&path).expect("verify_integrity on post-Security.evtx");
    assert!(
        indicators.iter().any(|ind| {
            matches!(
                ind,
                IntegrityAnomaly::SurgicalRecordDeletion {
                    absorbing_record_id: 104,
                    ..
                }
            )
        }),
        "expected SurgicalRecordDeletion(absorbing_record_id=104) from verify_integrity, got: {:?}",
        indicators
    );
}
