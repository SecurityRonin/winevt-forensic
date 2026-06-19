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
    ELFFILE_MAGIC,
};

use crate::cursor::Cursor;
use crate::deserializer::deserialize_fragment;
use crate::extract::{extract_record, DecodedRecord};
use crate::name::NameCache;

/// Failure of the EVTX file-header bootstrap — the prerequisite every record
/// decode depends on. Distinct from a valid-but-empty log (`Ok(vec![])`): an
/// invalid header means the input is not an EVTX file (or its header is corrupt
/// or forged), which must be surfaced loudly, never masked as "no records".
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeFileError {
    /// The `ElfFile` magic / header block did not parse. Carries the bytes that
    /// were found where the 8-byte `ElfFile\0` magic was expected (fewer than 8
    /// when the input is shorter than the magic).
    #[error(
        "invalid EVTX file header: expected magic {expected:02x?}, found {found:02x?} at offset 0"
    )]
    InvalidHeader {
        /// The expected `ElfFile\0` magic.
        expected: [u8; 8],
        /// The bytes actually present at offset 0 (up to 8).
        found: Vec<u8>,
    },
}

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

/// Decode every record in an in-memory EVTX file, surfacing the file-header
/// bootstrap as a loud error.
///
/// Returns [`DecodeFileError::InvalidHeader`] when the `ElfFile` header does not
/// parse (the input is not an EVTX file, or its header is corrupt/forged), so
/// that condition stays distinguishable from a valid log with zero records
/// (`Ok(vec![])`). Undecodable individual records are still skipped leniently.
///
/// # Errors
/// Returns [`DecodeFileError::InvalidHeader`] if the EVTX file header is invalid.
pub fn decode_file_checked(data: &[u8]) -> Result<Vec<RecordEntry>, DecodeFileError> {
    // RED stub: always Ok, never errors — the bootstrap masker is still present.
    Ok(decode_file(data))
}

/// Decode every record in an in-memory EVTX file. Returns an empty vec if the
/// file header is not a valid `ElfFile`. Undecodable records are skipped.
///
/// This is the lenient, best-effort wrapper over [`decode_file_checked`] — use
/// it in bulk/carve loops where a non-EVTX input is expected and tolerable. When
/// the caller needs to distinguish "not an EVTX file" from "an empty EVTX log",
/// call [`decode_file_checked`] instead.
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

    /// A valid `ElfFile` header (128+ bytes, correct magic) followed by no chunk
    /// data — a legitimate, pristine empty log with zero records.
    fn valid_header_zero_records() -> Vec<u8> {
        let mut file = vec![0u8; FILE_HEADER_BLOCK];
        file[..8].copy_from_slice(b"ElfFile\0");
        file
    }

    #[test]
    fn invalid_header_errors_not_silently_empty() {
        // A garbage / forged file must be a LOUD error, never the same empty vec
        // a pristine-but-empty log returns.
        assert!(decode_file_checked(b"not an evtx file at all").is_err());
        assert!(decode_file_checked(&[]).is_err());
    }

    #[test]
    fn valid_header_zero_records_is_ok_empty() {
        // A valid header with zero records is a legitimate empty case: Ok(empty),
        // NOT an error — this must stay distinguishable from a corrupt header.
        let decoded = decode_file_checked(&valid_header_zero_records());
        assert!(decoded.is_ok());
        assert!(decoded.unwrap().is_empty());
    }

    /// A minimal single-record EVTX file: one chunk, one record whose payload is
    /// the template-free fragment `<Event/>`. (The real-fixture differential
    /// parity test lives in `tests/real_corpus_parity.rs`.)
    fn synthetic_evtx() -> Vec<u8> {
        let cs = usize::try_from(CHUNK_SIZE).unwrap();
        let mut chunk = vec![0u8; cs];
        chunk[..8].copy_from_slice(b"ElfChnk\0");
        let rec_off = usize::try_from(CHUNK_RECORDS_OFFSET).unwrap();
        let mut p = rec_off;
        chunk[p..p + 4].copy_from_slice(&[0x2a, 0x2a, 0x00, 0x00]); // record magic
        p += 4;
        let size_at = p;
        p += 4; // size (patched)
        chunk[p..p + 8].copy_from_slice(&7u64.to_le_bytes()); // record_id
        p += 8;
        chunk[p..p + 8].copy_from_slice(&0u64.to_le_bytes()); // timestamp
        p += 8;
        // BinXml `<Event/>` (direct fragment); p is now rec_off + 24.
        chunk[p..p + 4].copy_from_slice(&[0x0f, 0x01, 0x01, 0x00]); // fragment header
        p += 4;
        chunk[p] = 0x01; // open start element, no attrs / dep id
        p += 1;
        chunk[p..p + 4].copy_from_slice(&0u32.to_le_bytes()); // element data_size
        p += 4;
        let name_off = u32::try_from(p + 4).unwrap(); // inline: struct follows the u32
        chunk[p..p + 4].copy_from_slice(&name_off.to_le_bytes());
        p += 4;
        chunk[p..p + 4].copy_from_slice(&0u32.to_le_bytes()); // next_string
        p += 4;
        chunk[p..p + 2].copy_from_slice(&0u16.to_le_bytes()); // hash
        p += 2;
        let chars: Vec<u16> = "Event".encode_utf16().collect();
        chunk[p..p + 2].copy_from_slice(&u16::try_from(chars.len()).unwrap().to_le_bytes());
        p += 2;
        for c in &chars {
            chunk[p..p + 2].copy_from_slice(&c.to_le_bytes());
            p += 2;
        }
        chunk[p..p + 2].copy_from_slice(&0u16.to_le_bytes()); // NUL terminator
        p += 2;
        chunk[p] = 0x03; // close empty element
        p += 1;
        chunk[p] = 0x00; // end of stream
        p += 1;
        chunk[p..p + 4].copy_from_slice(&0u32.to_le_bytes()); // size copy
        p += 4;
        let rec_size = u32::try_from(p - rec_off).unwrap();
        chunk[size_at..size_at + 4].copy_from_slice(&rec_size.to_le_bytes());
        chunk[48..52].copy_from_slice(&u32::try_from(p).unwrap().to_le_bytes()); // free_space_offset
        chunk[44..48].copy_from_slice(&u32::try_from(rec_off).unwrap().to_le_bytes());
        let mut file = vec![0u8; FILE_HEADER_BLOCK];
        file[..8].copy_from_slice(b"ElfFile\0");
        file.extend_from_slice(&chunk);
        file
    }

    #[test]
    fn decodes_a_synthetic_record() {
        let records = decode_file(&synthetic_evtx());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_id, 7);
        assert_eq!(records[0].record.event_id, 0); // <Event/> has no System
    }

    #[test]
    fn bad_record_magic_stops_the_chunk() {
        let mut data = synthetic_evtx();
        let rec = FILE_HEADER_BLOCK + usize::try_from(CHUNK_RECORDS_OFFSET).unwrap();
        data[rec] = 0xFF; // corrupt the record magic
        assert!(decode_file(&data).is_empty());
    }

    #[test]
    fn absurd_record_size_stops_the_chunk() {
        let mut data = synthetic_evtx();
        let size_at = FILE_HEADER_BLOCK + usize::try_from(CHUNK_RECORDS_OFFSET).unwrap() + 4;
        data[size_at..size_at + 4].copy_from_slice(&10u32.to_le_bytes()); // size < header
        assert!(decode_file(&data).is_empty());
    }

    #[test]
    fn record_extending_past_chunk_stops_the_chunk() {
        // A valid-looking size (>=24, <=CHUNK_SIZE) that nonetheless runs past the
        // end of the chunk must stop iteration, not read out of bounds.
        let mut data = synthetic_evtx();
        let size_at = FILE_HEADER_BLOCK + usize::try_from(CHUNK_RECORDS_OFFSET).unwrap() + 4;
        data[size_at..size_at + 4].copy_from_slice(&0xFF00u32.to_le_bytes());
        let fso = FILE_HEADER_BLOCK + 48; // free_space_offset → admit the header read
        data[fso..fso + 4].copy_from_slice(&u32::try_from(CHUNK_SIZE).unwrap().to_le_bytes());
        assert!(decode_file(&data).is_empty());
    }
}
