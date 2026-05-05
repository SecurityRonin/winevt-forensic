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
}
