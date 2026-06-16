//! Differential parity of the native decoder against the independent
//! omerbenamram `evtx` implementation on real EVTX fixtures (the Doer-Checker
//! gate). Skipped when the gitignored fixtures are absent.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use winevt_binxml::reader::decode_file;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("tests/data/fox-it-danderspritz").join(name))
        .unwrap_or_default()
}

/// omerbenamram's per-record event id, keyed by record id (the oracle).
fn oracle_event_ids(path: &Path) -> HashMap<u64, u64> {
    let mut parser = evtx::EvtxParser::from_path(path).expect("open fixture");
    let mut map = HashMap::new();
    for r in parser.records_json_value() {
        let Ok(rec) = r else { continue };
        let eid = rec
            .data
            .pointer("/Event/System/EventID")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.get("#text").and_then(serde_json::Value::as_u64))
            })
            .unwrap_or(0);
        map.insert(rec.event_record_id, eid);
    }
    map
}

#[test]
fn decoded_records_match_omerbenamram_event_ids() {
    let path = fixture("pre-Security.evtx");
    if !path.exists() {
        eprintln!("SKIP: {} not found", path.display());
        return;
    }
    let data = std::fs::read(&path).expect("read fixture");
    let theirs = oracle_event_ids(&path);
    let ours = decode_file(&data);
    assert!(!ours.is_empty(), "should decode at least some records");
    assert!(
        ours.iter()
            .any(|r| r.record.channel.as_deref() == Some("Security")),
        "expected a Security-channel record"
    );

    let mut compared = 0usize;
    for entry in &ours {
        if let Some(&their_eid) = theirs.get(&entry.record_id) {
            compared += 1;
            assert_eq!(
                u64::from(entry.record.event_id),
                their_eid,
                "event_id mismatch for record {}",
                entry.record_id
            );
        }
    }
    assert!(compared > 0, "expected to compare at least one record");
    eprintln!(
        "parity: {}/{} decoded records matched the oracle's event id",
        compared,
        ours.len()
    );
}
