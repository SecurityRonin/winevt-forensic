use winevt_core::binary::{IntegrityAnomaly, Severity};

/// Unified EVTX integrity analyser.
///
/// Runs all available detection algorithms in one pass and returns a
/// deduplicated, severity-sorted list of anomalies.
pub struct WinevtIntegrity;

impl WinevtIntegrity {
    /// Analyse `data` (raw EVTX bytes) and return all detected anomalies,
    /// sorted from highest severity to lowest.
    pub fn analyse(_data: &[u8]) -> Vec<IntegrityAnomaly> {
        unimplemented!("WinevtIntegrity::analyse not yet implemented")
    }

    /// Same as `analyse` but also accepts a severity floor — only anomalies
    /// at or above `min_severity` are returned.
    pub fn analyse_min_severity(data: &[u8], min_severity: Severity) -> Vec<IntegrityAnomaly> {
        Self::analyse(data)
            .into_iter()
            .filter(|a| a.severity() >= min_severity)
            .collect()
    }
}

pub mod provider_heuristics;
pub use provider_heuristics::{check_provider_consistency, ProviderAnomaly};

/// Given (first_record_number, last_record_number) per chunk in order,
/// detect gaps between adjacent chunks.
pub fn detect_record_id_gaps(chunks: &[(u64, u64)]) -> Vec<IntegrityAnomaly> {
    let mut out = Vec::new();
    for window in chunks.windows(2) {
        let (_, prev_last) = window[0];
        let (next_first, _) = window[1];
        let expected = prev_last + 1;
        if next_first != expected {
            out.push(IntegrityAnomaly::RecordIdGap {
                chunk_offset: 0, // caller fills in real offset
                expected,
                found: next_first,
            });
        }
    }
    out
}

/// Verify the chunk header CRC32 (bytes 0x00..0x78) against stored value at 0x78.
/// `buf` must be at least 0x7C bytes. `chunk_offset` is for the indicator.
pub fn verify_chunk_header_checksum(buf: &[u8], chunk_offset: u64) -> Vec<IntegrityAnomaly> {
    if buf.len() < 0x7C {
        return vec![];
    }
    let stored = u32::from_le_bytes(buf[0x78..0x7C].try_into().unwrap_or([0; 4]));
    let computed = crc32fast::hash(&buf[0..0x78]);
    if stored != computed {
        vec![IntegrityAnomaly::ChunkChecksumMismatch {
            chunk_offset,
            computed,
            stored,
        }]
    } else {
        vec![]
    }
}

/// Check that (record_id, timestamp) pairs are monotonically non-decreasing in timestamp.
pub fn check_timestamp_monotonicity(
    records: &[(u64, u64)],
    chunk_offset: u64,
) -> Vec<IntegrityAnomaly> {
    let mut out = Vec::new();
    let mut prev_ts = 0u64;
    for &(record_id, ts) in records {
        if ts < prev_ts {
            out.push(IntegrityAnomaly::TimestampAnomaly {
                chunk_offset,
                record_id,
                prev_ts,
                this_ts: ts,
            });
        }
        prev_ts = ts;
    }
    out
}

/// Verify the file header CRC32 (bytes 0x00..0x78) against stored value at 0x7C.
/// `buf` must be at least 0x80 bytes (128 bytes).
pub fn verify_file_header_checksum(buf: &[u8]) -> Vec<IntegrityAnomaly> {
    if buf.len() < 0x80 {
        return vec![];
    }
    let stored = u32::from_le_bytes(buf[0x7C..0x80].try_into().unwrap_or([0; 4]));
    let computed = crc32fast::hash(&buf[0..0x78]);
    if stored != computed {
        vec![IntegrityAnomaly::FileHeaderChecksumMismatch { computed, stored }]
    } else {
        vec![]
    }
}

/// Check file flags for dirty/full anomalies.
/// Bit 0x1 = not cleanly shut down; bit 0x2 = file full.
pub fn check_file_flags(flags: u32) -> Vec<IntegrityAnomaly> {
    let mut out = Vec::new();
    if flags & 0x1 != 0 {
        out.push(IntegrityAnomaly::FileNotCleanlyShutdown);
    }
    if flags & 0x2 != 0 {
        out.push(IntegrityAnomaly::FileFull);
    }
    out
}

/// Check that the chunk count in the file header matches the number of chunks found.
pub fn check_chunk_count(header_count: u16, actual_count: usize) -> Vec<IntegrityAnomaly> {
    if header_count as usize != actual_count {
        vec![IntegrityAnomaly::ChunkCountMismatch {
            header_count,
            actual_count,
        }]
    } else {
        vec![]
    }
}

/// Verify the event records area CRC32 for a chunk.
/// Records area = bytes `0x200..free_space_offset` (from chunk header field at bytes 48..52).
/// CRC32 compared with `event_records_checksum` at bytes 52..56.
pub fn verify_records_area_checksum(chunk_data: &[u8], chunk_offset: u64) -> Vec<IntegrityAnomaly> {
    if chunk_data.len() < 0x38 {
        return vec![];
    }
    let free_space_offset =
        u32::from_le_bytes(chunk_data[48..52].try_into().unwrap_or([0; 4])) as usize;
    let stored = u32::from_le_bytes(chunk_data[52..56].try_into().unwrap_or([0; 4]));
    let records_start = 0x200usize;
    if free_space_offset < records_start || chunk_data.len() < free_space_offset {
        return vec![];
    }
    let computed = crc32fast::hash(&chunk_data[records_start..free_space_offset]);
    if stored != computed {
        vec![IntegrityAnomaly::RecordChecksumMismatch {
            chunk_offset,
            computed,
            stored,
        }]
    } else {
        vec![]
    }
}

/// Check file header consistency: next_record_id should be > actual_highest_record_id.
pub fn check_file_header_consistency(
    header_next: u64,
    actual_highest: u64,
) -> Vec<IntegrityAnomaly> {
    if header_next <= actual_highest {
        vec![IntegrityAnomaly::NextRecordIdInconsistency {
            header_next,
            actual_highest,
        }]
    } else {
        vec![]
    }
}

/// Validate that a chunk's data-length field is within the legal EVTX range [512, 65536].
///
/// Chunk data lengths outside this range indicate a structurally corrupt or hand-crafted chunk.
pub fn check_chunk_data_length(length: u32) -> Vec<IntegrityAnomaly> {
    if length < 512 || length > 65536 {
        vec![IntegrityAnomaly::InvalidChunkDataLength(length)]
    } else {
        vec![]
    }
}

/// Check that the `log_file_guid` is identical across all chunks.
///
/// `guids` is a slice of 16-byte GUIDs, one per chunk in file order.  A mismatch at any index
/// implies the chunk was transplanted from a different log file, which is an anti-forensic
/// indicator.  Returns one `LogFileGuidMismatch` per mismatching chunk (compared to chunk 0).
pub fn check_log_file_guid_consistency(guids: &[[u8; 16]]) -> Vec<IntegrityAnomaly> {
    if guids.len() <= 1 {
        return vec![];
    }
    let first = guids[0];
    guids.iter().enumerate().skip(1)
        .filter(|(_, g)| **g != first)
        .map(|(i, g)| IntegrityAnomaly::LogFileGuidMismatch {
            chunk_index: i,
            expected: u128::from_le_bytes(first),
            actual: u128::from_le_bytes(*g),
        })
        .collect()
}

/// A suspicious gap in the record ID sequence that may indicate phantom record injection.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PhantomAlert {
    /// First record ID in the gap (inclusive).
    pub gap_start_id: u64,
    /// Last record ID in the gap (inclusive).
    pub gap_end_id: u64,
    /// Timestamp (nanoseconds) of the record immediately before the gap.
    pub prev_timestamp_ns: i64,
    /// Timestamp (nanoseconds) of the record immediately after the gap.
    pub next_timestamp_ns: i64,
    /// True when the timestamp gap does not proportionally explain the record ID gap,
    /// suggesting records were injected without advancing the clock.
    pub suspicious: bool,
}

/// Detect phantom record injection by correlating record-ID gaps with timestamp gaps.
///
/// `records` is a slice of `(record_id, timestamp_ns)` pairs sorted by `record_id`.
///
/// A record-ID gap where the elapsed nanoseconds per missing record is less than 1 ms
/// (1_000_000 ns) is flagged as suspicious — real log activity cannot normally produce
/// millions of events per second.  A large timestamp jump alongside the gap (≥ 1 ms per
/// missing ID) is treated as a normal cleared-log or ring-buffer rollover period.
pub fn detect_phantom_records(records: &[(u64, i64)]) -> Vec<PhantomAlert> {
    // 1 ms per missing record: below this rate the gap is suspicious.
    const MIN_NS_PER_MISSING_RECORD: i64 = 1_000_000;

    let mut out = Vec::new();
    for window in records.windows(2) {
        let (prev_id, prev_ts) = window[0];
        let (next_id, next_ts) = window[1];
        if next_id != prev_id + 1 {
            let gap_count = (next_id - prev_id - 1) as i64;
            let ts_gap = next_ts - prev_ts;
            let suspicious = ts_gap <= 0 || ts_gap / gap_count < MIN_NS_PER_MISSING_RECORD;
            out.push(PhantomAlert {
                gap_start_id: prev_id + 1,
                gap_end_id: next_id - 1,
                prev_timestamp_ns: prev_ts,
                next_timestamp_ns: next_ts,
                suspicious,
            });
        }
    }
    out
}

/// Detect the wevtutil / Event Viewer export timestamp corruption described by Fox-IT.
///
/// When `wevtutil epl` or "Save As…" exports an EVTX, each record's header timestamp is
/// replaced with the **previous** record's BinXml timestamp.  The first record in the export
/// therefore receives no predecessor and gets timestamp = 0.
///
/// This function returns one [`IntegrityAnomaly::ExportTimestampCorruption`] for every
/// record whose header timestamp is 0.
///
/// `records` is a slice of `(record_id, chunk_offset, header_timestamp)` tuples.
///
/// Reference: Wassenaar, Fox-IT BV (2019).
/// "Export corrupts Windows Event Log files"
/// <https://blog.fox-it.com/2019/06/04/export-corrupts-windows-event-log-files/>
pub fn detect_export_timestamp_corruption(records: &[(u64, u64, u64)]) -> Vec<IntegrityAnomaly> {
    records
        .iter()
        .filter(|&&(_, _, ts)| ts == 0)
        .map(
            |&(record_id, chunk_offset, _)| IntegrityAnomaly::ExportTimestampCorruption {
                record_id,
                chunk_offset,
            },
        )
        .collect()
}

/// Detect surgical record deletion consistent with the NSA DanderSpritz `eventlogedit` tool.
///
/// The tool absorbs a deleted record into the preceding record's size field: the absorbing
/// record's `size` is inflated to span the bytes of the deleted record, whose magic bytes
/// (`0x2A 0x2A 0x00 0x00`) remain visible inside the inflated body.  No EID 1102 is emitted.
///
/// This function walks the records area (`0x200..free_space_offset`) of `chunk_data` and
/// emits one [`IntegrityAnomaly::SurgicalRecordDeletion`] for each record whose stated
/// body contains the record-magic pattern.
///
/// `chunk_offset` is the byte offset of the chunk within the source file (used in indicators).
///
/// Reference: Wassenaar & van Dijk, Fox-IT BV (2017).
/// "Detection and recovery of NSA's covered up tracks"
/// <https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/>
///
/// Reference implementation (Python, MIT License): fox-it/danderspritz-evtx
/// <https://github.com/fox-it/danderspritz-evtx>
/// Algorithm independently re-implemented in Rust.
pub fn detect_danderspritz_deletion(chunk_data: &[u8], chunk_offset: u64) -> Vec<IntegrityAnomaly> {
    const RECORD_MAGIC: [u8; 4] = [0x2A, 0x2A, 0x00, 0x00];
    const RECORDS_START: usize = 0x200;
    const FREE_SPACE_OFF_FIELD: usize = 0x30; // bytes 48..52 in chunk header

    if chunk_data.len() < FREE_SPACE_OFF_FIELD + 4 {
        return vec![];
    }
    let free_space_offset = u32::from_le_bytes(
        chunk_data[FREE_SPACE_OFF_FIELD..FREE_SPACE_OFF_FIELD + 4]
            .try_into()
            .unwrap_or([0; 4]),
    ) as usize;

    if free_space_offset <= RECORDS_START || chunk_data.len() < free_space_offset {
        return vec![];
    }

    let mut indicators = Vec::new();
    let mut pos = RECORDS_START;

    while pos + 24 <= free_space_offset {
        // Every valid record starts with magic.
        if chunk_data[pos..pos + 4] != RECORD_MAGIC {
            break;
        }

        let stated_size =
            u32::from_le_bytes(chunk_data[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;

        // Minimum well-formed record: 4 magic + 4 size + 8 id + 8 ts + 0 payload + 4 tail = 28
        if stated_size < 28 || pos + stated_size > free_space_offset {
            break;
        }

        let record_id =
            u64::from_le_bytes(chunk_data[pos + 8..pos + 16].try_into().unwrap_or([0; 8]));

        // Body = bytes after the 24-byte header, before the 4-byte trailing size field.
        let body_start = pos + 24;
        let body_end = pos + stated_size - 4;

        // Search the body for a nested record-magic pattern.
        if body_end > body_start {
            let body = &chunk_data[body_start..body_end];
            if let Some(rel) = body.windows(4).position(|w| w == RECORD_MAGIC) {
                let ghost_offset_in_chunk = (body_start + rel) as u64;
                indicators.push(IntegrityAnomaly::SurgicalRecordDeletion {
                    chunk_offset,
                    absorbing_record_id: record_id,
                    stated_size: stated_size as u32,
                    ghost_offset_in_chunk,
                });
            }
        }

        pos += stated_size;
    }

    indicators
}

#[cfg(test)]
mod tests {
    use super::*;
    use winevt_core::binary::{IntegrityAnomaly, Severity};

    // ── WinevtIntegrity unified entry point ──────────────────────────────────

    #[test]
    fn analyse_empty_bytes_returns_empty() {
        let result = WinevtIntegrity::analyse(&[]);
        // Must not panic; empty or minimal result is acceptable
        let _ = result;
    }

    #[test]
    fn analyse_random_bytes_does_not_panic() {
        let data = vec![0xAAu8; 65536];
        let _ = WinevtIntegrity::analyse(&data);
    }

    #[test]
    fn analyse_sorted_by_severity_desc() {
        let data = vec![0xAAu8; 65536];
        let result = WinevtIntegrity::analyse(&data);
        if result.len() >= 2 {
            let last = result.len() - 1;
            assert!(
                result[0].severity() >= result[last].severity(),
                "first anomaly severity {:?} must be >= last {:?}",
                result[0].severity(),
                result[last].severity()
            );
        }
    }

    #[test]
    fn analyse_min_severity_filters() {
        let data = vec![0xAAu8; 65536];
        let result = WinevtIntegrity::analyse_min_severity(&data, Severity::Error);
        for anomaly in &result {
            assert!(
                anomaly.severity() >= Severity::Error,
                "expected severity >= Error, got {:?}",
                anomaly.severity()
            );
        }
    }

    #[test]
    fn no_gaps_for_contiguous_chunks() {
        // first_record_number, last_record_number per chunk
        let chunks = vec![(1u64, 10u64), (11, 20), (21, 30)];
        let gaps = detect_record_id_gaps(&chunks);
        assert!(gaps.is_empty());
    }

    #[test]
    fn gap_detected_between_chunks() {
        let chunks = vec![(1u64, 10u64), (15, 20)]; // gap: 11-14 missing
        let gaps = detect_record_id_gaps(&chunks);
        assert_eq!(gaps.len(), 1);
        match &gaps[0] {
            IntegrityAnomaly::RecordIdGap {
                expected, found, ..
            } => {
                assert_eq!(*expected, 11);
                assert_eq!(*found, 15);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn checksum_ok_for_correct_data() {
        // Build a minimal "chunk" with correct CRC32 at offset 0x78
        let mut buf = [0u8; 0x7C + 4];
        buf[0..8].copy_from_slice(b"ElfChnk\0");
        // compute CRC32 of first 0x78 bytes
        let crc = crc32fast::hash(&buf[0..0x78]);
        buf[0x78..0x7C].copy_from_slice(&crc.to_le_bytes());
        let indicators = verify_chunk_header_checksum(&buf, 0);
        assert!(
            indicators.is_empty(),
            "expected no indicators, got {:?}",
            indicators
        );
    }

    #[test]
    fn checksum_mismatch_detected() {
        let mut buf = [0u8; 0x7C + 4];
        buf[0..8].copy_from_slice(b"ElfChnk\0");
        // wrong checksum at 0x78 — just leave as zero
        let indicators = verify_chunk_header_checksum(&buf, 0x10000);
        assert_eq!(indicators.len(), 1);
        match &indicators[0] {
            IntegrityAnomaly::ChunkChecksumMismatch { chunk_offset, .. } => {
                assert_eq!(*chunk_offset, 0x10000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn timestamp_anomaly_detected() {
        // timestamps: 100, 200, 150 (out of order)
        let records = vec![(1u64, 100u64), (2, 200), (3, 150)];
        let anomalies = check_timestamp_monotonicity(&records, 0);
        assert_eq!(anomalies.len(), 1);
        match &anomalies[0] {
            IntegrityAnomaly::TimestampAnomaly { record_id, .. } => {
                assert_eq!(*record_id, 3);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn no_anomaly_for_monotonic_timestamps() {
        let records = vec![(1u64, 100u64), (2, 200), (3, 300)];
        let anomalies = check_timestamp_monotonicity(&records, 0);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn file_header_consistency_next_record_id_too_low() {
        // header says next is 50, but actual highest record id is 100
        let indicators = check_file_header_consistency(50, 100);
        assert_eq!(indicators.len(), 1);
        match &indicators[0] {
            IntegrityAnomaly::NextRecordIdInconsistency {
                header_next,
                actual_highest,
            } => {
                assert_eq!(*header_next, 50);
                assert_eq!(*actual_highest, 100);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn file_header_consistency_correct() {
        // header says next is 101, actual highest is 100
        let indicators = check_file_header_consistency(101, 100);
        assert!(indicators.is_empty());
    }

    // ---- Feature 2: File header checksum verification ----

    fn make_valid_file_header_128() -> Vec<u8> {
        let mut buf = vec![0u8; 0x80];
        buf[0..8].copy_from_slice(b"ElfFile\0");
        let crc = crc32fast::hash(&buf[0..0x78]);
        buf[0x7C..0x80].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    #[test]
    fn verify_file_header_checksum_valid_returns_empty() {
        let buf = make_valid_file_header_128();
        let indicators = verify_file_header_checksum(&buf);
        assert!(
            indicators.is_empty(),
            "expected no indicators for valid file header, got: {:?}",
            indicators
        );
    }

    #[test]
    fn verify_file_header_checksum_corrupt_returns_indicator() {
        let mut buf = make_valid_file_header_128();
        // Corrupt the checksum
        buf[0x7C..0x80].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let indicators = verify_file_header_checksum(&buf);
        assert_eq!(indicators.len(), 1);
        assert!(
            matches!(
                &indicators[0],
                IntegrityAnomaly::FileHeaderChecksumMismatch { stored, .. }
                    if *stored == 0xDEADBEEF
            ),
            "expected FileHeaderChecksumMismatch, got: {:?}",
            indicators
        );
    }

    #[test]
    fn verify_file_header_checksum_too_short_returns_empty() {
        let buf = vec![0u8; 10];
        let indicators = verify_file_header_checksum(&buf);
        assert!(indicators.is_empty());
    }

    // ---- Feature 3: File flags ----

    #[test]
    fn check_file_flags_zero_returns_empty() {
        let indicators = check_file_flags(0x0);
        assert!(indicators.is_empty());
    }

    #[test]
    fn check_file_flags_bit0_returns_not_cleanly_shutdown() {
        let indicators = check_file_flags(0x1);
        assert_eq!(indicators.len(), 1);
        assert!(
            matches!(&indicators[0], IntegrityAnomaly::FileNotCleanlyShutdown),
            "expected FileNotCleanlyShutdown, got: {:?}",
            indicators
        );
    }

    #[test]
    fn check_file_flags_bit1_returns_file_full() {
        let indicators = check_file_flags(0x2);
        assert_eq!(indicators.len(), 1);
        assert!(
            matches!(&indicators[0], IntegrityAnomaly::FileFull),
            "expected FileFull, got: {:?}",
            indicators
        );
    }

    #[test]
    fn check_file_flags_both_bits_returns_two_indicators() {
        let indicators = check_file_flags(0x3);
        assert_eq!(indicators.len(), 2);
        let has_shutdown = indicators
            .iter()
            .any(|i| matches!(i, IntegrityAnomaly::FileNotCleanlyShutdown));
        let has_full = indicators
            .iter()
            .any(|i| matches!(i, IntegrityAnomaly::FileFull));
        assert!(has_shutdown && has_full);
    }

    // ---- Feature 4: Chunk count consistency ----

    #[test]
    fn check_chunk_count_match_returns_empty() {
        let indicators = check_chunk_count(5, 5);
        assert!(indicators.is_empty());
    }

    #[test]
    fn check_chunk_count_actual_greater_returns_mismatch() {
        let indicators = check_chunk_count(3, 5);
        assert_eq!(indicators.len(), 1);
        assert!(
            matches!(
                &indicators[0],
                IntegrityAnomaly::ChunkCountMismatch {
                    header_count: 3,
                    actual_count: 5
                }
            ),
            "expected ChunkCountMismatch, got: {:?}",
            indicators
        );
    }

    #[test]
    fn check_chunk_count_actual_less_returns_mismatch() {
        let indicators = check_chunk_count(10, 3);
        assert_eq!(indicators.len(), 1);
        assert!(matches!(
            &indicators[0],
            IntegrityAnomaly::ChunkCountMismatch {
                header_count: 10,
                actual_count: 3
            }
        ));
    }

    // ---- Feature 5: Records area checksum ----

    fn make_valid_chunk_with_free_space_200() -> Vec<u8> {
        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[8..16].copy_from_slice(&1u64.to_le_bytes());
        chunk[16..24].copy_from_slice(&1u64.to_le_bytes());
        chunk[24..32].copy_from_slice(&1u64.to_le_bytes());
        chunk[32..40].copy_from_slice(&1u64.to_le_bytes());
        chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes());
        chunk[44..48].copy_from_slice(&0x200u32.to_le_bytes());
        // free_space_offset = 0x200 (empty records area)
        chunk[48..52].copy_from_slice(&0x200u32.to_le_bytes());
        // CRC32 of empty slice (0x200..0x200) = 0x00000000
        chunk[52..56].copy_from_slice(&0u32.to_le_bytes());
        let crc = crc32fast::hash(&chunk[0..0x78]);
        chunk[0x78..0x7C].copy_from_slice(&crc.to_le_bytes());
        chunk
    }

    #[test]
    fn verify_records_area_checksum_valid_returns_empty() {
        let chunk = make_valid_chunk_with_free_space_200();
        let indicators = verify_records_area_checksum(&chunk, 0);
        assert!(
            indicators.is_empty(),
            "expected empty for valid records area, got: {:?}",
            indicators
        );
    }

    #[test]
    fn verify_records_area_checksum_tampered_returns_mismatch() {
        let mut chunk = make_valid_chunk_with_free_space_200();
        // Set free_space_offset to 0x210 so records area is 0x200..0x210
        chunk[48..52].copy_from_slice(&0x210u32.to_le_bytes());
        // Store wrong checksum at bytes 52..56
        chunk[52..56].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        // Recompute header checksum so it's valid
        let crc = crc32fast::hash(&chunk[0..0x78]);
        chunk[0x78..0x7C].copy_from_slice(&crc.to_le_bytes());
        let indicators = verify_records_area_checksum(&chunk, 0x10000);
        assert_eq!(indicators.len(), 1);
        assert!(
            matches!(
                &indicators[0],
                IntegrityAnomaly::RecordChecksumMismatch {
                    chunk_offset: 0x10000,
                    ..
                }
            ),
            "expected RecordChecksumMismatch, got: {:?}",
            indicators
        );
    }

    // ── detect_export_timestamp_corruption ───────────────────────────────────
    //
    // Reference: Wassenaar, Fox-IT BV (2019).
    // "Export corrupts Windows Event Log files"
    // https://blog.fox-it.com/2019/06/04/export-corrupts-windows-event-log-files/

    #[test]
    fn export_corruption_empty_records_returns_empty() {
        let indicators = detect_export_timestamp_corruption(&[]);
        assert!(indicators.is_empty());
    }

    #[test]
    fn export_corruption_all_nonzero_timestamps_returns_empty() {
        let records = vec![(1u64, 0u64, 100u64), (2, 0, 200), (3, 0, 300)];
        assert!(detect_export_timestamp_corruption(&records).is_empty());
    }

    #[test]
    fn export_corruption_first_record_zero_ts_detected() {
        let records = vec![
            (1u64, 0x10000u64, 0u64),
            (2, 0x10000, 200),
            (3, 0x10000, 300),
        ];
        let indicators = detect_export_timestamp_corruption(&records);
        assert_eq!(indicators.len(), 1);
        assert!(
            matches!(
                &indicators[0],
                IntegrityAnomaly::ExportTimestampCorruption {
                    record_id: 1,
                    chunk_offset: 0x10000,
                }
            ),
            "got: {:?}",
            indicators
        );
    }

    #[test]
    fn export_corruption_single_zero_ts_detected() {
        let records = vec![(42u64, 0u64, 0u64)];
        let indicators = detect_export_timestamp_corruption(&records);
        assert_eq!(indicators.len(), 1);
        assert!(matches!(
            &indicators[0],
            IntegrityAnomaly::ExportTimestampCorruption { record_id: 42, .. }
        ));
    }

    #[test]
    fn export_corruption_all_zero_ts_emits_one_per_record() {
        let records = vec![(1u64, 0u64, 0u64), (2, 0, 0), (3, 0, 0)];
        assert_eq!(detect_export_timestamp_corruption(&records).len(), 3);
    }

    #[test]
    fn export_corruption_two_leading_zeros_flagged() {
        let records = vec![(1u64, 0u64, 0u64), (2, 0, 0), (3, 0, 999)];
        assert_eq!(detect_export_timestamp_corruption(&records).len(), 2);
    }

    // ── detect_danderspritz_deletion ─────────────────────────────────────────
    //
    // Reference: Wassenaar & van Dijk, Fox-IT BV (2017).
    // "Detection and recovery of NSA's covered up tracks"
    // https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/
    //
    // Reference implementation (Python, MIT License):
    // fox-it/danderspritz-evtx — https://github.com/fox-it/danderspritz-evtx
    // Algorithm independently re-implemented in Rust.

    fn write_record_at(
        buf: &mut Vec<u8>,
        offset: usize,
        record_id: u64,
        ts: u64,
        payload: &[u8],
    ) -> u32 {
        let size = (4 + 4 + 8 + 8 + payload.len() + 4) as u32;
        let end = offset + size as usize;
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[offset..offset + 4].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        buf[offset + 4..offset + 8].copy_from_slice(&size.to_le_bytes());
        buf[offset + 8..offset + 16].copy_from_slice(&record_id.to_le_bytes());
        buf[offset + 16..offset + 24].copy_from_slice(&ts.to_le_bytes());
        buf[offset + 24..offset + 24 + payload.len()].copy_from_slice(payload);
        let tail = offset + size as usize - 4;
        buf[tail..tail + 4].copy_from_slice(&size.to_le_bytes());
        size
    }

    fn empty_chunk_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 0x10000];
        buf[0..8].copy_from_slice(b"ElfChnk\0");
        buf[0x30..0x34].copy_from_slice(&0x200u32.to_le_bytes()); // free_space_offset
        buf
    }

    #[test]
    fn danderspritz_empty_chunk_returns_empty() {
        assert!(detect_danderspritz_deletion(&empty_chunk_buf(), 0).is_empty());
    }

    #[test]
    fn danderspritz_single_valid_record_returns_empty() {
        let mut chunk = empty_chunk_buf();
        let sz = write_record_at(&mut chunk, 0x200, 1, 100, b"payload");
        chunk[0x30..0x34].copy_from_slice(&(0x200u32 + sz).to_le_bytes());
        assert!(detect_danderspritz_deletion(&chunk, 0).is_empty());
    }

    #[test]
    fn danderspritz_two_valid_records_returns_empty() {
        let mut chunk = empty_chunk_buf();
        let sz1 = write_record_at(&mut chunk, 0x200, 1, 100, b"rec1");
        let sz2 = write_record_at(&mut chunk, 0x200 + sz1 as usize, 2, 200, b"rec2");
        chunk[0x30..0x34].copy_from_slice(&(0x200u32 + sz1 + sz2).to_le_bytes());
        assert!(detect_danderspritz_deletion(&chunk, 0).is_empty());
    }

    #[test]
    fn danderspritz_inflated_size_absorbing_deleted_record_detected() {
        let mut chunk = empty_chunk_buf();
        let sz1 = write_record_at(&mut chunk, 0x200, 1, 100, b"absorber");
        let sz2 = write_record_at(&mut chunk, 0x200 + sz1 as usize, 2, 200, b"ghost");
        chunk[0x30..0x34].copy_from_slice(&(0x200u32 + sz1 + sz2).to_le_bytes());
        // Inflate record1 to absorb record2 (eventlogedit pattern)
        let inflated = sz1 + sz2;
        chunk[0x204..0x208].copy_from_slice(&inflated.to_le_bytes());
        let trail = 0x200 + inflated as usize - 4;
        chunk[trail..trail + 4].copy_from_slice(&inflated.to_le_bytes());

        let indicators = detect_danderspritz_deletion(&chunk, 0);
        assert_eq!(indicators.len(), 1, "got: {:?}", indicators);
        assert!(matches!(
            &indicators[0],
            IntegrityAnomaly::SurgicalRecordDeletion {
                absorbing_record_id: 1,
                ..
            }
        ));
    }

    // ── §2 extra: check_chunk_data_length ────────────────────────────────────

    #[test]
    fn chunk_data_length_valid_returns_empty() {
        assert!(check_chunk_data_length(4096).is_empty());
        assert!(check_chunk_data_length(512).is_empty());
        assert!(check_chunk_data_length(65536).is_empty());
    }

    #[test]
    fn chunk_data_length_too_small_returns_indicator() {
        let v = check_chunk_data_length(256);
        assert_eq!(v.len(), 1, "length 256 is below minimum 512");
        assert!(matches!(&v[0], IntegrityAnomaly::InvalidChunkDataLength(256)));
    }

    #[test]
    fn chunk_data_length_too_large_returns_indicator() {
        let v = check_chunk_data_length(65537);
        assert_eq!(v.len(), 1, "length 65537 is above maximum 65536");
        assert!(matches!(&v[0], IntegrityAnomaly::InvalidChunkDataLength(65537)));
    }

    #[test]
    fn chunk_data_length_zero_returns_indicator() {
        let v = check_chunk_data_length(0);
        assert_eq!(v.len(), 1);
    }

    // ── §2 extra: check_log_file_guid_consistency ─────────────────────────────

    #[test]
    fn guid_consistency_all_same_returns_empty() {
        let guid = [0xABu8; 16];
        let guids = vec![guid, guid, guid];
        assert!(check_log_file_guid_consistency(&guids).is_empty());
    }

    #[test]
    fn guid_consistency_empty_returns_empty() {
        assert!(check_log_file_guid_consistency(&[]).is_empty());
    }

    #[test]
    fn guid_consistency_single_returns_empty() {
        assert!(check_log_file_guid_consistency(&[[0u8; 16]]).is_empty());
    }

    #[test]
    fn guid_consistency_mismatch_returns_indicator() {
        let g1 = [0xAAu8; 16];
        let g2 = [0xBBu8; 16];
        let guids = vec![g1, g1, g2];
        let v = check_log_file_guid_consistency(&guids);
        assert_eq!(v.len(), 1, "one mismatch expected; got {:?}", v);
        assert!(
            matches!(&v[0], IntegrityAnomaly::LogFileGuidMismatch { chunk_index: 2, .. }),
            "mismatch should be at chunk_index 2; got {:?}", v
        );
    }

    #[test]
    fn guid_consistency_multiple_mismatches_all_reported() {
        let g1 = [0x01u8; 16];
        let g2 = [0x02u8; 16];
        let g3 = [0x03u8; 16];
        let guids = vec![g1, g2, g3];
        let v = check_log_file_guid_consistency(&guids);
        assert_eq!(v.len(), 2, "chunks 1 and 2 differ from chunk 0; got {:?}", v);
    }

    // ── §3: detect_phantom_records ────────────────────────────────────────────

    #[test]
    fn phantom_contiguous_records_returns_empty() {
        // record_id, timestamp_ns (must be nanoseconds as i64)
        let records: &[(u64, i64)] = &[(1, 100), (2, 200), (3, 300)];
        assert!(detect_phantom_records(records).is_empty());
    }

    #[test]
    fn phantom_empty_returns_empty() {
        assert!(detect_phantom_records(&[]).is_empty());
    }

    #[test]
    fn phantom_single_record_returns_empty() {
        assert!(detect_phantom_records(&[(5, 1_000_000)]).is_empty());
    }

    #[test]
    fn phantom_gap_with_no_time_gap_is_suspicious() {
        // record_ids 1, 2, 10 — gap of 8 between 2 and 10, timestamps contiguous
        let records: &[(u64, i64)] = &[(1, 1_000_000), (2, 2_000_000), (10, 3_000_000)];
        let alerts = detect_phantom_records(records);
        assert_eq!(alerts.len(), 1, "one gap expected; got {:?}", alerts);
        assert!(alerts[0].suspicious, "timestamp doesn't explain the gap → suspicious");
        assert_eq!(alerts[0].gap_start_id, 3, "gap starts at 3 (next after 2)");
        assert_eq!(alerts[0].gap_end_id, 9, "gap ends at 9 (just before 10)");
    }

    #[test]
    fn phantom_gap_with_proportional_time_gap_is_not_suspicious() {
        // record_ids 1..10..20 — gap of 10, but large time jump
        let records: &[(u64, i64)] = &[
            (1, 1_000_000_000),
            (10, 1_000_000_000),   // same ts as record 1
            (20, 100_000_000_000), // large ts jump
        ];
        let alerts = detect_phantom_records(records);
        // Two gaps: 2..9 (no time gap → suspicious) and 11..19 (large time gap → not suspicious)
        let suspicious_count = alerts.iter().filter(|a| a.suspicious).count();
        let not_suspicious_count = alerts.iter().filter(|a| !a.suspicious).count();
        assert!(suspicious_count >= 1, "gap 2..9 has no time gap → suspicious");
        assert!(not_suspicious_count >= 1, "gap 11..19 has large time gap → not suspicious");
    }

    #[test]
    fn phantom_no_alerts_on_contiguous_records_with_time_gaps() {
        let records: &[(u64, i64)] = &[
            (1, 0),
            (2, 60_000_000_000),   // 60s gap
            (3, 120_000_000_000),  // 60s gap
        ];
        assert!(detect_phantom_records(records).is_empty());
    }

    #[test]
    fn danderspritz_ghost_offset_matches_deleted_record_position() {
        let mut chunk = empty_chunk_buf();
        let sz1 = write_record_at(&mut chunk, 0x200, 5, 500, b"absorber");
        let sz2 = write_record_at(&mut chunk, 0x200 + sz1 as usize, 6, 600, b"ghost");
        chunk[0x30..0x34].copy_from_slice(&(0x200u32 + sz1 + sz2).to_le_bytes());
        let inflated = sz1 + sz2;
        chunk[0x204..0x208].copy_from_slice(&inflated.to_le_bytes());
        let trail = 0x200 + inflated as usize - 4;
        chunk[trail..trail + 4].copy_from_slice(&inflated.to_le_bytes());

        let indicators = detect_danderspritz_deletion(&chunk, 0x20000);
        assert_eq!(indicators.len(), 1);
        if let IntegrityAnomaly::SurgicalRecordDeletion {
            chunk_offset,
            ghost_offset_in_chunk,
            ..
        } = &indicators[0]
        {
            assert_eq!(*chunk_offset, 0x20000);
            assert_eq!(*ghost_offset_in_chunk, 0x200 + sz1 as u64);
        } else {
            panic!("wrong variant: {:?}", indicators[0]);
        }
    }
}
