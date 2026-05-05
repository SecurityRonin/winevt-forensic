//! `winevt-writer` — reconstruct well-formed EVTX bytes from carved records.
//!
//! # Layered design (for debuggability)
//!
//! ```text
//! records_to_evtx(records)
//!   ├─ build_file_header(chunk_count, next_record_id) → [u8; 4096]
//!   └─ for each chunk: build_chunk(records, chunk_number) → [u8; 65536]
//!         └─ for each record: build_record_bytes(record) → Vec<u8>
//! ```
//!
//! Each layer is independently testable, making regressions easy to localise.

// ── EVTX binary layout constants ─────────────────────────────────────────────

/// Total size of the ElfFile header block (4 KiB).
pub const FILE_HEADER_SIZE: usize = 0x1000;
/// Total size of one ElfChnk chunk (64 KiB).
pub const CHUNK_SIZE: usize = 0x1_0000;
/// Byte offset where records start within a chunk.
pub const RECORDS_OFFSET: usize = 0x200;
/// Maximum bytes available for record data in one chunk.
pub const MAX_RECORDS_AREA: usize = CHUNK_SIZE - RECORDS_OFFSET;

// File-header field offsets (all little-endian).
pub const FH_MAGIC: usize = 0x00;
pub const FH_FIRST_CHUNK: usize = 0x08;
pub const FH_LAST_CHUNK: usize = 0x10;
pub const FH_NEXT_RECORD_ID: usize = 0x18;
pub const FH_HEADER_SIZE: usize = 0x20;
pub const FH_MINOR_VERSION: usize = 0x24;
pub const FH_MAJOR_VERSION: usize = 0x26;
pub const FH_HEADER_CHUNK_COUNT: usize = 0x28;
pub const FH_CHUNK_COUNT: usize = 0x2A;
pub const FH_FLAGS: usize = 0x78;
pub const FH_CHECKSUM: usize = 0x7C;

// Chunk-header field offsets.
pub const CH_MAGIC: usize = 0x00;
pub const CH_FIRST_REC_NUM: usize = 0x08;
pub const CH_LAST_REC_NUM: usize = 0x10;
pub const CH_FIRST_REC_ID: usize = 0x18;
pub const CH_LAST_REC_ID: usize = 0x20;
pub const CH_HEADER_SIZE: usize = 0x28;
pub const CH_LAST_REC_DATA_OFF: usize = 0x2C;
pub const CH_FREE_SPACE_OFF: usize = 0x30;
pub const CH_RECORDS_CHECKSUM: usize = 0x34;
pub const CH_HEADER_CHECKSUM: usize = 0x78;

// Record field offsets (relative to record start).
pub const REC_MAGIC: usize = 0x00;
pub const REC_SIZE: usize = 0x04;
pub const REC_ID: usize = 0x08;
pub const REC_TIMESTAMP: usize = 0x10;
pub const REC_PAYLOAD: usize = 0x18;

// ── Input type ────────────────────────────────────────────────────────────────

/// Minimal record representation accepted by the writer.
///
/// Callers convert from [`winevt_carver::RecoveredRecord`] or construct
/// directly for testing. Keeping this type in `winevt-writer` (not
/// `winevt-carver`) avoids a circular dependency.
#[derive(Debug, Clone)]
pub struct WriteRecord {
    pub record_id: u64,
    pub timestamp: u64,
    /// Raw BinXml payload bytes (everything between the 24-byte header
    /// and the trailing size field).
    pub payload: Vec<u8>,
}

impl WriteRecord {
    /// Total on-disk size of this record in bytes.
    ///
    /// Layout: 4 (magic) + 4 (size) + 8 (id) + 8 (ts) + payload + 4 (trailing size).
    #[inline]
    pub fn on_disk_size(&self) -> usize {
        4 + 4 + 8 + 8 + self.payload.len() + 4
    }
}

// ── Layer 1: record serialisation ────────────────────────────────────────────

/// Serialise one `WriteRecord` to raw EVTX bytes.
pub fn build_record_bytes(_record: &WriteRecord) -> Vec<u8> {
    todo!("not yet implemented")
}

// ── Layer 2: chunk construction ───────────────────────────────────────────────

/// Pack `records` into a 65536-byte `ElfChnk` block.
pub fn build_chunk(_records: &[WriteRecord], _chunk_number: u64) -> [u8; CHUNK_SIZE] {
    todo!("not yet implemented")
}

// ── Layer 3: file header construction ─────────────────────────────────────────

/// Build the 4096-byte ElfFile header block.
pub fn build_file_header(_chunk_count: u16, _next_record_id: u64) -> [u8; FILE_HEADER_SIZE] {
    todo!("not yet implemented")
}

// ── Layer 4: top-level API ─────────────────────────────────────────────────────

/// Split a flat record list into chunk-sized batches.
pub fn split_into_chunks(_records: &[WriteRecord]) -> Vec<Vec<WriteRecord>> {
    todo!("not yet implemented")
}

/// Reconstruct a well-formed EVTX byte stream from a slice of [`WriteRecord`]s.
pub fn records_to_evtx(_records: &[WriteRecord]) -> Vec<u8> {
    todo!("not yet implemented")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(id: u64, ts: u64, payload: &[u8]) -> WriteRecord {
        WriteRecord {
            record_id: id,
            timestamp: ts,
            payload: payload.to_vec(),
        }
    }

    // ── WriteRecord helpers ───────────────────────────────────────────────────

    #[test]
    fn on_disk_size_is_header_plus_payload_plus_trailing() {
        let r = make_record(1, 0, &[0xAA, 0xBB]);
        // 4 + 4 + 8 + 8 + 2 + 4 = 30
        assert_eq!(r.on_disk_size(), 30);
    }

    #[test]
    fn on_disk_size_empty_payload_is_28() {
        // 4 (magic) + 4 (size) + 8 (id) + 8 (ts) + 0 (payload) + 4 (trailing size) = 28
        let r = make_record(1, 0, &[]);
        assert_eq!(r.on_disk_size(), 28);
    }

    // ── build_record_bytes ────────────────────────────────────────────────────

    #[test]
    fn build_record_bytes_starts_with_record_magic() {
        let r = make_record(42, 1_000, b"hello");
        let bytes = build_record_bytes(&r);
        assert_eq!(&bytes[0..4], &[0x2A, 0x2A, 0x00, 0x00]);
    }

    #[test]
    fn build_record_bytes_size_field_matches_total_length() {
        let r = make_record(1, 0, b"payload");
        let bytes = build_record_bytes(&r);
        let size_field = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        assert_eq!(size_field, bytes.len());
    }

    #[test]
    fn build_record_bytes_trailing_size_matches_leading_size() {
        let r = make_record(5, 0, b"data");
        let bytes = build_record_bytes(&r);
        let leading = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let trailing =
            u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
        assert_eq!(leading, trailing);
    }

    #[test]
    fn build_record_bytes_record_id_is_encoded_at_offset_8() {
        let r = make_record(0xDEAD_BEEF_CAFE_1234, 0, &[]);
        let bytes = build_record_bytes(&r);
        let id = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        assert_eq!(id, 0xDEAD_BEEF_CAFE_1234);
    }

    #[test]
    fn build_record_bytes_timestamp_is_encoded_at_offset_16() {
        let r = make_record(1, 0x0102_0304_0506_0708, &[]);
        let bytes = build_record_bytes(&r);
        let ts = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        assert_eq!(ts, 0x0102_0304_0506_0708);
    }

    #[test]
    fn build_record_bytes_payload_follows_header() {
        let payload = b"\xAB\xCD\xEF";
        let r = make_record(1, 0, payload);
        let bytes = build_record_bytes(&r);
        assert_eq!(&bytes[0x18..0x18 + 3], payload);
    }

    // ── build_file_header ─────────────────────────────────────────────────────

    #[test]
    fn file_header_starts_with_elffile_magic() {
        let hdr = build_file_header(2, 100);
        assert_eq!(&hdr[0..8], b"ElfFile\0");
    }

    #[test]
    fn file_header_size_is_4096() {
        let hdr = build_file_header(0, 1);
        assert_eq!(hdr.len(), FILE_HEADER_SIZE);
    }

    #[test]
    fn file_header_chunk_count_field_is_correct() {
        let hdr = build_file_header(7, 1);
        let count = u16::from_le_bytes(hdr[FH_CHUNK_COUNT..FH_CHUNK_COUNT + 2].try_into().unwrap());
        assert_eq!(count, 7);
    }

    #[test]
    fn file_header_next_record_id_field_is_correct() {
        let hdr = build_file_header(1, 42);
        let nrid = u64::from_le_bytes(
            hdr[FH_NEXT_RECORD_ID..FH_NEXT_RECORD_ID + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(nrid, 42);
    }

    #[test]
    fn file_header_checksum_is_valid() {
        let hdr = build_file_header(3, 99);
        let stored = u32::from_le_bytes(hdr[FH_CHECKSUM..FH_CHECKSUM + 4].try_into().unwrap());
        let computed = crc32fast::hash(&hdr[0x00..0x78]);
        assert_eq!(stored, computed, "file header CRC32 mismatch");
    }

    #[test]
    fn file_header_version_is_3_1() {
        let hdr = build_file_header(0, 1);
        let minor = u16::from_le_bytes(hdr[FH_MINOR_VERSION..FH_MINOR_VERSION + 2].try_into().unwrap());
        let major = u16::from_le_bytes(hdr[FH_MAJOR_VERSION..FH_MAJOR_VERSION + 2].try_into().unwrap());
        assert_eq!(minor, 1);
        assert_eq!(major, 3);
    }

    // ── build_chunk ───────────────────────────────────────────────────────────

    #[test]
    fn chunk_size_is_65536() {
        let chunk = build_chunk(&[], 0);
        assert_eq!(chunk.len(), CHUNK_SIZE);
    }

    #[test]
    fn chunk_starts_with_elfchnk_magic() {
        let r = make_record(1, 0, b"data");
        let chunk = build_chunk(&[r], 0);
        assert_eq!(&chunk[0..8], b"ElfChnk\0");
    }

    #[test]
    fn chunk_header_checksum_is_valid() {
        let r = make_record(1, 0, b"payload_data");
        let chunk = build_chunk(&[r], 0);
        let stored =
            u32::from_le_bytes(chunk[CH_HEADER_CHECKSUM..CH_HEADER_CHECKSUM + 4].try_into().unwrap());
        let computed = crc32fast::hash(&chunk[0x00..0x78]);
        assert_eq!(stored, computed, "chunk header CRC32 mismatch");
    }

    #[test]
    fn chunk_records_area_checksum_is_valid() {
        let r = make_record(2, 500, b"abc");
        let chunk = build_chunk(&[r], 0);
        let free_off = u32::from_le_bytes(
            chunk[CH_FREE_SPACE_OFF..CH_FREE_SPACE_OFF + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let stored = u32::from_le_bytes(
            chunk[CH_RECORDS_CHECKSUM..CH_RECORDS_CHECKSUM + 4]
                .try_into()
                .unwrap(),
        );
        let computed = crc32fast::hash(&chunk[RECORDS_OFFSET..free_off]);
        assert_eq!(stored, computed, "records area CRC32 mismatch");
    }

    #[test]
    fn chunk_first_last_record_ids_match_input() {
        let records = vec![
            make_record(10, 100, b"a"),
            make_record(11, 200, b"b"),
            make_record(12, 300, b"c"),
        ];
        let chunk = build_chunk(&records, 0);
        let first_id =
            u64::from_le_bytes(chunk[CH_FIRST_REC_ID..CH_FIRST_REC_ID + 8].try_into().unwrap());
        let last_id =
            u64::from_le_bytes(chunk[CH_LAST_REC_ID..CH_LAST_REC_ID + 8].try_into().unwrap());
        assert_eq!(first_id, 10);
        assert_eq!(last_id, 12);
    }

    #[test]
    fn chunk_record_magic_is_present_at_records_offset() {
        let r = make_record(1, 0, b"x");
        let chunk = build_chunk(&[r], 0);
        assert_eq!(
            &chunk[RECORDS_OFFSET..RECORDS_OFFSET + 4],
            &[0x2A, 0x2A, 0x00, 0x00]
        );
    }

    // ── split_into_chunks ─────────────────────────────────────────────────────

    #[test]
    fn split_empty_input_returns_empty() {
        assert!(split_into_chunks(&[]).is_empty());
    }

    #[test]
    fn split_small_records_fit_in_one_chunk() {
        let records: Vec<WriteRecord> =
            (0..10).map(|i| make_record(i, i * 100, b"tiny")).collect();
        let batches = split_into_chunks(&records);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 10);
    }

    #[test]
    fn split_large_payloads_span_multiple_chunks() {
        // Each record has a 32 KiB payload — two × 32776 bytes = 65552 > MAX_RECORDS_AREA (65024)
        let big = vec![0xABu8; 32 * 1024];
        let records: Vec<WriteRecord> = (0..3)
            .map(|i| make_record(i, 0, &big))
            .collect();
        let batches = split_into_chunks(&records);
        assert!(batches.len() >= 2);
    }

    // ── records_to_evtx (round-trip) ─────────────────────────────────────────

    #[test]
    fn records_to_evtx_empty_input_returns_file_header_only() {
        let bytes = records_to_evtx(&[]);
        assert_eq!(bytes.len(), FILE_HEADER_SIZE);
        assert_eq!(&bytes[0..8], b"ElfFile\0");
    }

    #[test]
    fn records_to_evtx_single_record_has_correct_total_size() {
        let r = make_record(1, 0, b"data");
        let bytes = records_to_evtx(&[r]);
        assert_eq!(bytes.len(), FILE_HEADER_SIZE + CHUNK_SIZE);
    }

    #[test]
    fn records_to_evtx_file_header_checksum_valid() {
        let r = make_record(1, 0, b"abc");
        let bytes = records_to_evtx(&[r]);
        let stored =
            u32::from_le_bytes(bytes[FH_CHECKSUM..FH_CHECKSUM + 4].try_into().unwrap());
        let computed = crc32fast::hash(&bytes[0x00..0x78]);
        assert_eq!(stored, computed);
    }

    #[test]
    fn records_to_evtx_chunk_appears_after_file_header() {
        let r = make_record(1, 0, b"chunk_test");
        let bytes = records_to_evtx(&[r]);
        assert_eq!(&bytes[FILE_HEADER_SIZE..FILE_HEADER_SIZE + 8], b"ElfChnk\0");
    }

    #[test]
    fn records_to_evtx_roundtrip_via_carve_from_bytes() {
        use winevt_carver::carve_from_bytes;

        let records = vec![
            make_record(1, 132_700_000_000_000_000, b"\x0f\xfe\x00"),
            make_record(2, 132_700_000_100_000_000, b"\x0f\xfe\x01"),
            make_record(3, 132_700_000_200_000_000, b"\x0f\xfe\x02"),
        ];
        let bytes = records_to_evtx(&records);
        let result = carve_from_bytes(&bytes);

        let recovered: Vec<_> = result.chunks.iter().flat_map(|c| c.records.iter()).collect();
        assert_eq!(recovered.len(), 3, "expected 3 records in round-trip");

        let ids: Vec<u64> = recovered.iter().map(|r| r.header.record_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);

        let timestamps: Vec<u64> = recovered.iter().map(|r| r.header.timestamp).collect();
        assert_eq!(
            timestamps,
            vec![
                132_700_000_000_000_000,
                132_700_000_100_000_000,
                132_700_000_200_000_000,
            ]
        );
    }

    #[test]
    fn records_to_evtx_roundtrip_preserves_payload() {
        use winevt_carver::carve_from_bytes;

        let payload = b"\x0f\xAA\xBB\xCC\xDD";
        let r = make_record(7, 132_700_000_000_000_000, payload);
        let bytes = records_to_evtx(&[r]);
        let result = carve_from_bytes(&bytes);

        let recovered = result
            .chunks
            .iter()
            .flat_map(|c| c.records.iter())
            .next()
            .expect("no records recovered");

        assert_eq!(recovered.bxml_payload, payload);
    }

    #[test]
    fn records_to_evtx_next_record_id_in_header() {
        let r = make_record(99, 0, b"x");
        let bytes = records_to_evtx(&[r]);
        let nrid = u64::from_le_bytes(
            bytes[FH_NEXT_RECORD_ID..FH_NEXT_RECORD_ID + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(nrid, 100, "next_record_id should be max_id + 1");
    }
}
