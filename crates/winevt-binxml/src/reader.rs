//! Container glue: iterate an EVTX file's chunks and records and decode each
//! record's BinXml payload into a flat [`DecodedRecord`].
//!
//! Names and templates are chunk-scoped, so a fresh [`NameCache`] is used per
//! chunk and the whole 64 KiB chunk is the addressing base for every record in
//! it. A record whose payload fails to decode (e.g. it uses a substitution type
//! not yet supported) is skipped, not fatal — the rest of the file still
//! decodes.

#![allow(clippy::doc_markdown)] // "BinXml"/"EventData" appear throughout these docs

use winevt_core::binary::{
    EvtxChunkHeader, EvtxFileHeader, EvtxRecordHeader, CHUNK_RECORDS_OFFSET, CHUNK_SIZE,
};

use crate::cursor::Cursor;
use crate::deserializer::deserialize_fragment;
use crate::extract::{extract_record, DecodedRecord};
use crate::name::NameCache;

/// The EVTX file header block is 4 KiB; the first chunk starts after it.
const FILE_HEADER_BLOCK: usize = 0x1000;
/// Bytes of fixed record header before the BinXml payload.
const RECORD_HEADER_SIZE: usize = 24;

/// One decoded record with its container-level identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEntry {
    /// Event record id from the record header.
    pub record_id: u64,
    /// Record-header timestamp (Windows FILETIME, 100 ns since 1601).
    pub timestamp_filetime: u64,
    /// The decoded record content.
    pub record: DecodedRecord,
}

/// Decode every record in an in-memory EVTX file. Returns an empty vec if the
/// file header is not a valid `ElfFile`. Undecodable records are skipped.
#[must_use]
pub fn decode_file(data: &[u8]) -> Vec<RecordEntry> {
    let mut out = Vec::new();
    if EvtxFileHeader::parse(data).is_none() {
        return out;
    }
    let chunk_size = usize::try_from(CHUNK_SIZE).unwrap_or(usize::MAX);
    let mut chunk_off = FILE_HEADER_BLOCK;
    while let Some(chunk) = data.get(chunk_off..chunk_off.saturating_add(chunk_size)) {
        if let Some(header) = EvtxChunkHeader::parse(chunk) {
            decode_chunk(chunk, header.free_space_offset as usize, &mut out);
        }
        chunk_off = chunk_off.saturating_add(chunk_size);
    }
    out
}

/// Decode the records of one chunk (a fresh name cache scoped to this chunk).
fn decode_chunk(chunk: &[u8], free_space_offset: usize, out: &mut Vec<RecordEntry>) {
    let mut names = NameCache::new();
    let end = free_space_offset.min(chunk.len());
    let mut rec_off = usize::try_from(CHUNK_RECORDS_OFFSET).unwrap_or(usize::MAX);
    while rec_off.saturating_add(RECORD_HEADER_SIZE) <= end {
        let Some(header) = chunk.get(rec_off..).and_then(EvtxRecordHeader::parse) else {
            break;
        };
        let size = header.size as usize;
        let payload_end = match rec_off.checked_add(size) {
            Some(e) if size >= RECORD_HEADER_SIZE && e <= chunk.len() => e,
            _ => break,
        };
        let binxml_off = rec_off + RECORD_HEADER_SIZE;
        let mut cur = Cursor::at(chunk, binxml_off);
        if let Ok(nodes) = deserialize_fragment(&mut cur, chunk, &mut names) {
            out.push(RecordEntry {
                record_id: header.record_id,
                timestamp_filetime: header.timestamp,
                record: extract_record(&nodes),
            });
        }
        rec_off = payload_end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_evtx_input_yields_no_records() {
        assert!(decode_file(b"not an evtx file at all").is_empty());
        assert!(decode_file(&[]).is_empty());
    }

    fn fixture(name: &str) -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop(); // crates/
        p.pop(); // workspace root
        p.join("tests/data/fox-it-danderspritz").join(name)
    }

    macro_rules! require_fixture {
        ($name:expr) => {{
            let p = fixture($name);
            if !p.exists() {
                eprintln!("SKIP: {} not found", p.display());
                return;
            }
            p
        }};
    }

    /// omerbenamram's per-record event id, keyed by record id (the oracle).
    fn oracle_event_ids(path: &std::path::Path) -> std::collections::HashMap<u64, u64> {
        let mut parser = evtx::EvtxParser::from_path(path).expect("open fixture");
        let mut map = std::collections::HashMap::new();
        for r in parser.records_json_value() {
            let Ok(rec) = r else { continue };
            let eid = rec
                .data
                .pointer("/Event/System/EventID")
                .and_then(|v| v.as_u64().or_else(|| v.get("#text").and_then(serde_json::Value::as_u64)))
                .unwrap_or(0);
            map.insert(rec.event_record_id, eid);
        }
        map
    }

    #[test]
    fn decodes_real_security_evtx() {
        let path = require_fixture!("pre-Security.evtx");
        let data = std::fs::read(&path).expect("read fixture");
        let records = decode_file(&data);
        assert!(!records.is_empty(), "should decode at least some records");
        assert!(
            records.iter().any(|r| r.record.channel.as_deref() == Some("Security")),
            "expected at least one Security-channel record"
        );
    }

    #[test]
    fn decoded_records_match_omerbenamram_event_ids() {
        // Doer-Checker: for every record OUR decoder produces, the event id must
        // match the independent omerbenamram implementation on the real file.
        let path = require_fixture!("pre-Security.evtx");
        let data = std::fs::read(&path).expect("read fixture");
        let theirs = oracle_event_ids(&path);
        let ours = decode_file(&data);

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
            "parity: {}/{} of our decoded records matched the oracle's event id",
            compared,
            ours.len()
        );
    }
}

