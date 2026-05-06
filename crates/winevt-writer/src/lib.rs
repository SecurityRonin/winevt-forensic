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

/// Total size of the `ElfFile` header block (4 KiB).
pub const FILE_HEADER_SIZE: usize = 0x1000;
/// Total size of one `ElfChnk` chunk (64 KiB).
pub const CHUNK_SIZE: usize = 0x1_0000;
/// Byte offset where records start within a chunk.
pub const RECORDS_OFFSET: usize = 0x200;
/// Maximum bytes available for record data in one chunk.
pub const MAX_RECORDS_AREA: usize = CHUNK_SIZE - RECORDS_OFFSET;

// File-header field offsets (all little-endian).
const FH_MAGIC: usize = 0x00; // b"ElfFile\0"    8 bytes
const FH_FIRST_CHUNK: usize = 0x08; //              8 bytes (u64)
const FH_LAST_CHUNK: usize = 0x10; //              8 bytes (u64)
const FH_NEXT_RECORD_ID: usize = 0x18; //              8 bytes (u64)
const FH_HEADER_SIZE: usize = 0x20; //              4 bytes (u32) = 0x80
const FH_MINOR_VERSION: usize = 0x24; //              2 bytes (u16) = 1
const FH_MAJOR_VERSION: usize = 0x26; //              2 bytes (u16) = 3
const FH_HEADER_CHUNK_COUNT: usize = 0x28; //              2 bytes (u16) = 1
const FH_CHUNK_COUNT: usize = 0x2A; //              2 bytes (u16)
const FH_FLAGS: usize = 0x78; //              4 bytes (u32) = 0
const FH_CHECKSUM: usize = 0x7C; //              4 bytes (u32) CRC32[0x00..0x78]

// Chunk-header field offsets.
const CH_MAGIC: usize = 0x00; // b"ElfChnk\0"   8 bytes
const CH_FIRST_REC_NUM: usize = 0x08; //              8 bytes (u64)
const CH_LAST_REC_NUM: usize = 0x10; //              8 bytes (u64)
const CH_FIRST_REC_ID: usize = 0x18; //              8 bytes (u64)
const CH_LAST_REC_ID: usize = 0x20; //              8 bytes (u64)
const CH_HEADER_SIZE: usize = 0x28; //              4 bytes (u32) = 0x80
const CH_LAST_REC_DATA_OFF: usize = 0x2C; //              4 bytes (u32)
const CH_FREE_SPACE_OFF: usize = 0x30; //              4 bytes (u32)
const CH_RECORDS_CHECKSUM: usize = 0x34; //              4 bytes (u32) CRC32 of records area
const CH_HEADER_CHECKSUM: usize = 0x78; //              4 bytes (u32) CRC32[0x00..0x78]

// Record field offsets (relative to record start).
const REC_MAGIC: usize = 0x00; // 0x2A 0x2A 0x00 0x00   4 bytes
const REC_SIZE: usize = 0x04; //                         4 bytes (u32)
const REC_ID: usize = 0x08; //                         8 bytes (u64)
const REC_TIMESTAMP: usize = 0x10; //                         8 bytes (u64)
const REC_PAYLOAD: usize = 0x18; //                         variable

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
    /// Raw `BinXml` payload bytes (everything between the 24-byte header
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
///
/// Layout: magic(4) + size(4) + id(8) + timestamp(8) + payload(N) + size(4).
///
/// # Panics
/// Never panics; payload length is bounded by `usize`.
pub fn build_record_bytes(record: &WriteRecord) -> Vec<u8> {
    let total = record.on_disk_size();
    let mut buf = vec![0u8; total];

    // Magic
    buf[REC_MAGIC..REC_MAGIC + 4].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
    // Size (u32 LE)
    // total is bounded by MAX_RECORDS_AREA (< u32::MAX); cast is safe.
    #[allow(clippy::cast_possible_truncation)]
    let total_u32 = total as u32;
    buf[REC_SIZE..REC_SIZE + 4].copy_from_slice(&total_u32.to_le_bytes());
    // Record ID (u64 LE)
    buf[REC_ID..REC_ID + 8].copy_from_slice(&record.record_id.to_le_bytes());
    // Timestamp (u64 LE)
    buf[REC_TIMESTAMP..REC_TIMESTAMP + 8].copy_from_slice(&record.timestamp.to_le_bytes());
    // Payload
    buf[REC_PAYLOAD..REC_PAYLOAD + record.payload.len()].copy_from_slice(&record.payload);
    // Trailing size copy
    let tail = total - 4;
    buf[tail..].copy_from_slice(&total_u32.to_le_bytes());

    buf
}

// ── Layer 2: chunk construction ───────────────────────────────────────────────

/// Pack `records` into a 65536-byte `ElfChnk` block.
///
/// `chunk_number` is the 0-based index of this chunk in the file (used for
/// the `first_event_record_number` / `last_event_record_number` fields which
/// are sequence numbers within the log).
///
/// Records are written sequentially; any record that would overflow the
/// records area is silently dropped (callers must split batches beforehand
/// via [`split_into_chunks`]).
pub fn build_chunk(records: &[WriteRecord], chunk_number: u64) -> [u8; CHUNK_SIZE] {
    // 64 KiB is intentional for EVTX chunk size; suppress large_stack_arrays.
    #[allow(clippy::large_stack_arrays)]
    let mut buf = [0u8; CHUNK_SIZE];

    // --- write records into the records area first ---
    let mut write_pos = RECORDS_OFFSET;
    let mut first_id = 0u64;
    let mut last_id = 0u64;
    let mut first_num = 0u64;
    let mut last_num = 0u64;
    let mut last_data_end = RECORDS_OFFSET; // offset just past the last record written

    for (i, record) in records.iter().enumerate() {
        let bytes = build_record_bytes(record);
        if write_pos + bytes.len() > CHUNK_SIZE {
            break; // overflow — caller should have split
        }
        buf[write_pos..write_pos + bytes.len()].copy_from_slice(&bytes);

        if i == 0 {
            first_id = record.record_id;
            first_num = chunk_number * records.len() as u64 + 1;
        }
        last_id = record.record_id;
        last_num = chunk_number * records.len() as u64 + i as u64 + 1;
        last_data_end = write_pos + bytes.len();
        write_pos += bytes.len();
    }

    // write_pos is bounded by CHUNK_SIZE (65536 < u32::MAX); cast is safe.
    #[allow(clippy::cast_possible_truncation)]
    let free_space_offset = write_pos as u32;

    // --- chunk header ---
    buf[CH_MAGIC..CH_MAGIC + 8].copy_from_slice(b"ElfChnk\0");

    // Record numbers (sequence numbers within the log, 1-based)
    buf[CH_FIRST_REC_NUM..CH_FIRST_REC_NUM + 8].copy_from_slice(&first_num.to_le_bytes());
    buf[CH_LAST_REC_NUM..CH_LAST_REC_NUM + 8].copy_from_slice(&last_num.to_le_bytes());

    // Record IDs (globally unique, from the record headers)
    buf[CH_FIRST_REC_ID..CH_FIRST_REC_ID + 8].copy_from_slice(&first_id.to_le_bytes());
    buf[CH_LAST_REC_ID..CH_LAST_REC_ID + 8].copy_from_slice(&last_id.to_le_bytes());

    // Header size = 0x80
    buf[CH_HEADER_SIZE..CH_HEADER_SIZE + 4].copy_from_slice(&0x80u32.to_le_bytes());

    // Last event record data offset = byte offset from chunk start to last record start
    let last_data_offset = if last_data_end > RECORDS_OFFSET {
        // offset of last record start = last_data_end - last_record_size
        // We need the offset of the LAST record's start, not its end.
        // Recompute by walking records.
        let mut off = RECORDS_OFFSET;
        for r in records.iter().take(records.len().saturating_sub(1)) {
            let sz = r.on_disk_size();
            if off + sz >= CHUNK_SIZE {
                break;
            }
            off += sz;
        }
        // off is bounded by CHUNK_SIZE; cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        {
            off as u32
        }
    } else {
        u32::try_from(RECORDS_OFFSET).expect("RECORDS_OFFSET fits u32")
    };
    buf[CH_LAST_REC_DATA_OFF..CH_LAST_REC_DATA_OFF + 4]
        .copy_from_slice(&last_data_offset.to_le_bytes());

    // Free space offset
    buf[CH_FREE_SPACE_OFF..CH_FREE_SPACE_OFF + 4].copy_from_slice(&free_space_offset.to_le_bytes());

    // Records area CRC32 (0x200..free_space_offset)
    let records_area = &buf[RECORDS_OFFSET..write_pos];
    let records_crc = crc32fast::hash(records_area);
    buf[CH_RECORDS_CHECKSUM..CH_RECORDS_CHECKSUM + 4].copy_from_slice(&records_crc.to_le_bytes());

    // Header CRC32 (0x00..0x78)
    let header_crc = crc32fast::hash(&buf[0x00..0x78]);
    buf[CH_HEADER_CHECKSUM..CH_HEADER_CHECKSUM + 4].copy_from_slice(&header_crc.to_le_bytes());

    buf
}

// ── Layer 3: file header construction ─────────────────────────────────────────

/// Build the 4096-byte `ElfFile` header block.
///
/// `chunk_count` — number of `ElfChnk` blocks that follow.
/// `next_record_id` — the ID that the next new record would receive
///   (= highest existing `record_id` + 1, or 1 if no records).
pub fn build_file_header(chunk_count: u16, next_record_id: u64) -> [u8; FILE_HEADER_SIZE] {
    let mut buf = [0u8; FILE_HEADER_SIZE];

    buf[FH_MAGIC..FH_MAGIC + 8].copy_from_slice(b"ElfFile\0");

    // first_chunk_number = 0, last_chunk_number = chunk_count - 1
    let last_chunk = if chunk_count > 0 {
        u64::from(chunk_count - 1)
    } else {
        0
    };
    buf[FH_FIRST_CHUNK..FH_FIRST_CHUNK + 8].copy_from_slice(&0u64.to_le_bytes());
    buf[FH_LAST_CHUNK..FH_LAST_CHUNK + 8].copy_from_slice(&last_chunk.to_le_bytes());
    buf[FH_NEXT_RECORD_ID..FH_NEXT_RECORD_ID + 8].copy_from_slice(&next_record_id.to_le_bytes());

    // header_size = 0x80 (128)
    buf[FH_HEADER_SIZE..FH_HEADER_SIZE + 4].copy_from_slice(&0x80u32.to_le_bytes());
    // minor version = 1, major version = 3
    buf[FH_MINOR_VERSION..FH_MINOR_VERSION + 2].copy_from_slice(&1u16.to_le_bytes());
    buf[FH_MAJOR_VERSION..FH_MAJOR_VERSION + 2].copy_from_slice(&3u16.to_le_bytes());
    // header chunk count = 1
    buf[FH_HEADER_CHUNK_COUNT..FH_HEADER_CHUNK_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
    // chunk count
    buf[FH_CHUNK_COUNT..FH_CHUNK_COUNT + 2].copy_from_slice(&chunk_count.to_le_bytes());

    // flags = 0 (clean shutdown)
    buf[FH_FLAGS..FH_FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());

    // checksum = CRC32(buf[0x00..0x78])
    let checksum = crc32fast::hash(&buf[0x00..0x78]);
    buf[FH_CHECKSUM..FH_CHECKSUM + 4].copy_from_slice(&checksum.to_le_bytes());

    buf
}

// ── Layer 4: top-level API ─────────────────────────────────────────────────────

/// Split a flat record list into chunk-sized batches.
///
/// Each batch fits within [`MAX_RECORDS_AREA`] bytes.  Empty record slices
/// are never emitted; an empty input returns an empty `Vec`.
pub fn split_into_chunks(records: &[WriteRecord]) -> Vec<Vec<WriteRecord>> {
    let mut chunks: Vec<Vec<WriteRecord>> = Vec::new();
    let mut current: Vec<WriteRecord> = Vec::new();
    let mut current_size = 0usize;

    for record in records {
        let sz = record.on_disk_size();
        if current_size + sz > MAX_RECORDS_AREA && !current.is_empty() {
            chunks.push(current);
            current = Vec::new();
            current_size = 0;
        }
        current_size += sz;
        current.push(record.clone());
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Reconstruct a well-formed EVTX byte stream from a slice of [`WriteRecord`]s.
///
/// Returns a `Vec<u8>` whose layout is:
/// - 4096-byte `ElfFile` header
/// - N × 65536-byte `ElfChnk` blocks (one per chunk batch)
///
/// The result can be written to a `.evtx` file and parsed by any conforming
/// reader (`hayabusa`, `evtx`, `EvtxECmd`, …).
pub fn records_to_evtx(records: &[WriteRecord]) -> Vec<u8> {
    let batches = split_into_chunks(records);
    // A valid EVTX file has at most 65535 chunks; truncation is not a
    // realistic concern but we document the invariant explicitly.
    #[allow(clippy::cast_possible_truncation)]
    let chunk_count = batches.len() as u16;

    let next_record_id = records
        .iter()
        .map(|r| r.record_id)
        .max()
        .map_or(1, |id| id + 1);

    let file_header = build_file_header(chunk_count, next_record_id);

    let total_size = FILE_HEADER_SIZE + chunk_count as usize * CHUNK_SIZE;
    let mut out = Vec::with_capacity(total_size);
    out.extend_from_slice(&file_header);

    for (i, batch) in batches.iter().enumerate() {
        let chunk = build_chunk(batch, i as u64);
        out.extend_from_slice(&chunk);
    }

    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid `WriteRecord` for testing.
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
        let trailing = u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
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
        let minor = u16::from_le_bytes(
            hdr[FH_MINOR_VERSION..FH_MINOR_VERSION + 2]
                .try_into()
                .unwrap(),
        );
        let major = u16::from_le_bytes(
            hdr[FH_MAJOR_VERSION..FH_MAJOR_VERSION + 2]
                .try_into()
                .unwrap(),
        );
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
        let stored = u32::from_le_bytes(
            chunk[CH_HEADER_CHECKSUM..CH_HEADER_CHECKSUM + 4]
                .try_into()
                .unwrap(),
        );
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
        let first_id = u64::from_le_bytes(
            chunk[CH_FIRST_REC_ID..CH_FIRST_REC_ID + 8]
                .try_into()
                .unwrap(),
        );
        let last_id = u64::from_le_bytes(
            chunk[CH_LAST_REC_ID..CH_LAST_REC_ID + 8]
                .try_into()
                .unwrap(),
        );
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
        let records: Vec<WriteRecord> = (0..10).map(|i| make_record(i, i * 100, b"tiny")).collect();
        let batches = split_into_chunks(&records);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 10);
    }

    #[test]
    fn split_large_payloads_span_multiple_chunks() {
        // Each record has a 32 KiB payload — two fit, three do not
        let big = vec![0xABu8; 32 * 1024];
        let records: Vec<WriteRecord> = (0..3).map(|i| make_record(i, 0, &big)).collect();
        let batches = split_into_chunks(&records);
        // First batch: record 0 + record 1 = 2 × 32776 ≈ 65552 > MAX_RECORDS_AREA (65024)?
        // Actually 32776 * 2 = 65552 > 65024, so each record gets its own chunk.
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
        let stored = u32::from_le_bytes(bytes[FH_CHECKSUM..FH_CHECKSUM + 4].try_into().unwrap());
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

        // All three records recovered
        let recovered: Vec<_> = result
            .chunks
            .iter()
            .flat_map(|c| c.records.iter())
            .collect();
        assert_eq!(recovered.len(), 3, "expected 3 records in round-trip");

        // Record IDs preserved
        let ids: Vec<u64> = recovered.iter().map(|r| r.header.record_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);

        // Timestamps preserved
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
