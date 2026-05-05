use winevt_core::binary::IntegrityIndicator;

/// Given (first_record_number, last_record_number) per chunk in order,
/// detect gaps between adjacent chunks.
pub fn detect_record_id_gaps(chunks: &[(u64, u64)]) -> Vec<IntegrityIndicator> {
    let mut out = Vec::new();
    for window in chunks.windows(2) {
        let (_, prev_last) = window[0];
        let (next_first, _) = window[1];
        let expected = prev_last + 1;
        if next_first != expected {
            out.push(IntegrityIndicator::RecordIdGap {
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
pub fn verify_chunk_header_checksum(buf: &[u8], chunk_offset: u64) -> Vec<IntegrityIndicator> {
    if buf.len() < 0x7C {
        return vec![];
    }
    let stored = u32::from_le_bytes(buf[0x78..0x7C].try_into().unwrap_or([0; 4]));
    let computed = crc32fast::hash(&buf[0..0x78]);
    if stored != computed {
        vec![IntegrityIndicator::ChunkChecksumMismatch {
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
) -> Vec<IntegrityIndicator> {
    let mut out = Vec::new();
    let mut prev_ts = 0u64;
    for &(record_id, ts) in records {
        if ts < prev_ts {
            out.push(IntegrityIndicator::TimestampAnomaly {
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
pub fn verify_file_header_checksum(buf: &[u8]) -> Vec<IntegrityIndicator> {
    if buf.len() < 0x80 {
        return vec![];
    }
    let stored = u32::from_le_bytes(buf[0x7C..0x80].try_into().unwrap_or([0; 4]));
    let computed = crc32fast::hash(&buf[0..0x78]);
    if stored != computed {
        vec![IntegrityIndicator::FileHeaderChecksumMismatch { computed, stored }]
    } else {
        vec![]
    }
}

/// Check file flags for dirty/full anomalies.
/// Bit 0x1 = not cleanly shut down; bit 0x2 = file full.
pub fn check_file_flags(flags: u32) -> Vec<IntegrityIndicator> {
    let mut out = Vec::new();
    if flags & 0x1 != 0 {
        out.push(IntegrityIndicator::FileNotCleanlyShutdown);
    }
    if flags & 0x2 != 0 {
        out.push(IntegrityIndicator::FileFull);
    }
    out
}

/// Check that the chunk count in the file header matches the number of chunks found.
pub fn check_chunk_count(header_count: u16, actual_count: usize) -> Vec<IntegrityIndicator> {
    if header_count as usize != actual_count {
        vec![IntegrityIndicator::ChunkCountMismatch {
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
pub fn verify_records_area_checksum(
    chunk_data: &[u8],
    chunk_offset: u64,
) -> Vec<IntegrityIndicator> {
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
        vec![IntegrityIndicator::RecordChecksumMismatch {
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
) -> Vec<IntegrityIndicator> {
    if header_next <= actual_highest {
        vec![IntegrityIndicator::NextRecordIdInconsistency {
            header_next,
            actual_highest,
        }]
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winevt_core::binary::IntegrityIndicator;

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
            IntegrityIndicator::RecordIdGap {
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
            IntegrityIndicator::ChunkChecksumMismatch { chunk_offset, .. } => {
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
            IntegrityIndicator::TimestampAnomaly { record_id, .. } => {
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
            IntegrityIndicator::NextRecordIdInconsistency {
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
                IntegrityIndicator::FileHeaderChecksumMismatch { stored, .. }
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
            matches!(&indicators[0], IntegrityIndicator::FileNotCleanlyShutdown),
            "expected FileNotCleanlyShutdown, got: {:?}",
            indicators
        );
    }

    #[test]
    fn check_file_flags_bit1_returns_file_full() {
        let indicators = check_file_flags(0x2);
        assert_eq!(indicators.len(), 1);
        assert!(
            matches!(&indicators[0], IntegrityIndicator::FileFull),
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
            .any(|i| matches!(i, IntegrityIndicator::FileNotCleanlyShutdown));
        let has_full = indicators
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::FileFull));
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
                IntegrityIndicator::ChunkCountMismatch {
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
            IntegrityIndicator::ChunkCountMismatch {
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
                IntegrityIndicator::RecordChecksumMismatch { chunk_offset: 0x10000, .. }
            ),
            "expected RecordChecksumMismatch, got: {:?}",
            indicators
        );
    }
}
