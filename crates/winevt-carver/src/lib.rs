pub use winevt_core::binary::{
    EvtxChunkHeader, EvtxFileHeader, EvtxRecordHeader, IntegrityIndicator, CHUNK_RECORDS_OFFSET,
    CHUNK_SIZE, ELFCHNK_MAGIC, ELFFILE_MAGIC, RECORD_MAGIC,
};
use winevt_integrity::{
    check_file_header_consistency, detect_record_id_gaps, verify_chunk_header_checksum,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    Valid,
    HeaderCorrupt,
    RecordCorrupt,
    SizeMismatch,
    Carved,
    Truncated,
}

#[derive(Debug, Clone)]
pub struct RecoveredRecord {
    pub offset: u64,
    pub header: EvtxRecordHeader,
    pub integrity: Integrity,
    pub bxml_payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CarvedChunk {
    pub offset: u64,
    pub header: EvtxChunkHeader,
    pub integrity: Integrity,
    pub records: Vec<RecoveredRecord>,
    pub anti_forensic: Vec<IntegrityIndicator>,
}

#[derive(Debug, Default)]
pub struct CarveStats {
    pub bytes_scanned: u64,
    pub chunks_found: usize,
    pub chunks_valid: usize,
    pub chunks_corrupt: usize,
    pub records_recovered: usize,
    pub records_corrupt: usize,
}

#[derive(Debug)]
pub struct CarveResult {
    pub file_header: Option<EvtxFileHeader>,
    pub chunks: Vec<CarvedChunk>,
    pub anti_forensic: Vec<IntegrityIndicator>,
    pub stats: CarveStats,
}

pub fn carve_from_bytes(data: &[u8]) -> CarveResult {
    let mut result = CarveResult {
        file_header: None,
        chunks: Vec::new(),
        anti_forensic: Vec::new(),
        stats: CarveStats {
            bytes_scanned: data.len() as u64,
            ..Default::default()
        },
    };

    // Look for file header at start
    if data.len() >= 128 {
        result.file_header = EvtxFileHeader::parse(&data[0..128]);
    }

    // Scan for ElfChnk magic at 8-byte granularity
    let mut i = 0usize;
    while i + 8 <= data.len() {
        if data[i..i + 8] == ELFCHNK_MAGIC {
            let chunk_end = i + CHUNK_SIZE as usize;
            if chunk_end > data.len() {
                // Truncated chunk
                if let Some(header) = EvtxChunkHeader::parse(&data[i..]) {
                    let records = recover_records_from_slice(&data[i..], i as u64, true);
                    let rec_count = records.len();
                    result.chunks.push(CarvedChunk {
                        offset: i as u64,
                        header,
                        integrity: Integrity::Truncated,
                        records,
                        anti_forensic: vec![],
                    });
                    result.stats.chunks_found += 1;
                    result.stats.records_recovered += rec_count;
                }
                i += 8;
                continue;
            }

            let chunk_data = &data[i..chunk_end];
            let header = match EvtxChunkHeader::parse(chunk_data) {
                Some(h) => h,
                None => {
                    i += 8;
                    continue;
                }
            };

            let checksum_indicators = verify_chunk_header_checksum(chunk_data, i as u64);
            let integrity = if checksum_indicators.is_empty() {
                Integrity::Valid
            } else {
                Integrity::HeaderCorrupt
            };

            let records = recover_records_from_slice(chunk_data, i as u64, false);
            let rec_count = records.len();

            result.chunks.push(CarvedChunk {
                offset: i as u64,
                header,
                integrity,
                records,
                anti_forensic: checksum_indicators,
            });
            result.stats.chunks_found += 1;
            if integrity == Integrity::Valid {
                result.stats.chunks_valid += 1;
            } else {
                result.stats.chunks_corrupt += 1;
            }
            result.stats.records_recovered += rec_count;

            // Skip to end of chunk
            i += CHUNK_SIZE as usize;
            continue;
        }
        i += 8;
    }

    // Post-carve: detect record ID gaps across all chunks
    let chunk_ranges: Vec<(u64, u64)> = result
        .chunks
        .iter()
        .map(|c| {
            (
                c.header.first_event_record_number,
                c.header.last_event_record_number,
            )
        })
        .collect();
    result
        .anti_forensic
        .extend(detect_record_id_gaps(&chunk_ranges));

    // Post-carve: check file header consistency if we have a file header
    if let Some(ref fh) = result.file_header {
        let actual_highest = result
            .chunks
            .iter()
            .map(|c| c.header.last_event_record_id)
            .max()
            .unwrap_or(0);
        result.anti_forensic.extend(check_file_header_consistency(
            fh.next_record_id,
            actual_highest,
        ));
    }

    result
}

fn recover_records_from_slice(
    chunk_data: &[u8],
    _chunk_offset: u64,
    truncated: bool,
) -> Vec<RecoveredRecord> {
    let mut records = Vec::new();
    let start = CHUNK_RECORDS_OFFSET as usize;
    let end = if truncated {
        chunk_data.len()
    } else {
        CHUNK_SIZE as usize
    };
    if chunk_data.len() < start {
        return records;
    }
    let records_area = &chunk_data[start..chunk_data.len().min(end)];

    let mut pos = 0usize;
    while pos + 24 <= records_area.len() {
        if records_area[pos..pos + 4] == RECORD_MAGIC {
            if pos + 8 > records_area.len() {
                break;
            }
            let size =
                u32::from_le_bytes(records_area[pos + 4..pos + 8].try_into().unwrap_or([0; 4]))
                    as usize;
            if size < 24 || pos + size > records_area.len() {
                pos += 8;
                continue;
            }
            let Some(header) = EvtxRecordHeader::parse(&records_area[pos..]) else {
                pos += 8;
                continue;
            };
            // Check copy-of-size at record_end - 4
            let copy_size = u32::from_le_bytes(
                records_area[pos + size - 4..pos + size]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;
            let integrity = if copy_size == size {
                Integrity::Valid
            } else {
                Integrity::SizeMismatch
            };
            let payload_start = 24usize;
            let payload_end = if size > 4 { size - 4 } else { size };
            let bxml_payload = if payload_end > payload_start {
                records_area[pos + payload_start..pos + payload_end].to_vec()
            } else {
                vec![]
            };
            records.push(RecoveredRecord {
                offset: (start + pos) as u64,
                header,
                integrity,
                bxml_payload,
            });
            pos += size;
        } else {
            pos += 8;
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_chunk() -> Vec<u8> {
        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[8..16].copy_from_slice(&1u64.to_le_bytes()); // first record number
        chunk[16..24].copy_from_slice(&1u64.to_le_bytes()); // last record number
        chunk[24..32].copy_from_slice(&1u64.to_le_bytes()); // first record id
        chunk[32..40].copy_from_slice(&1u64.to_le_bytes()); // last record id
        chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes()); // header_size
        chunk[44..48].copy_from_slice(&0x200u32.to_le_bytes()); // last_event_record_data_offset
        chunk[48..52].copy_from_slice(&0x200u32.to_le_bytes()); // free_space_offset
        chunk[52..56].copy_from_slice(&0u32.to_le_bytes()); // event_records_checksum
                                                            // compute header checksum
        let crc = crc32fast::hash(&chunk[0..0x78]);
        chunk[0x78..0x7C].copy_from_slice(&crc.to_le_bytes());
        chunk
    }

    fn make_chunk_with_one_record() -> Vec<u8> {
        let mut chunk = make_minimal_chunk();
        // Write one record at offset 0x200
        let record_size: u32 = 28; // 24 header + 4 copy-of-size
        chunk[0x200..0x204].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]); // magic
        chunk[0x204..0x208].copy_from_slice(&record_size.to_le_bytes()); // size
        chunk[0x208..0x210].copy_from_slice(&42u64.to_le_bytes()); // record_id
        chunk[0x210..0x218].copy_from_slice(&133_297_085_160_000_000u64.to_le_bytes()); // timestamp
                                                                                        // bxml payload area (0 bytes here — size 28 = 24 header + 4 trailer)
        let end = 0x200 + record_size as usize;
        chunk[end - 4..end].copy_from_slice(&record_size.to_le_bytes()); // copy-of-size
        chunk
    }

    #[test]
    fn carve_empty_slice_returns_empty_result() {
        let result = carve_from_bytes(&[]);
        assert!(result.chunks.is_empty());
        assert_eq!(result.stats.chunks_found, 0);
    }

    #[test]
    fn carve_no_magic_returns_empty() {
        let data = vec![0u8; 0x20000];
        let result = carve_from_bytes(&data);
        assert!(result.chunks.is_empty());
    }

    #[test]
    fn carve_finds_single_valid_chunk() {
        let data = make_minimal_chunk();
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].integrity, Integrity::Valid);
        assert_eq!(result.chunks[0].offset, 0);
        assert_eq!(result.stats.chunks_found, 1);
        assert_eq!(result.stats.chunks_valid, 1);
    }

    #[test]
    fn carve_finds_two_back_to_back_chunks() {
        let mut data = make_minimal_chunk();
        data.extend(make_minimal_chunk());
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 2);
        assert_eq!(result.chunks[0].offset, 0);
        assert_eq!(result.chunks[1].offset, 0x10000);
    }

    #[test]
    fn truncated_chunk_at_end_marked_truncated() {
        // Provide only half a chunk
        let data: Vec<u8> = make_minimal_chunk()[..0x8000].to_vec();
        let result = carve_from_bytes(&data);
        // The magic is at offset 0, but we only have 0x8000 bytes, not a full 0x10000
        // So it should be found as truncated OR not found — we require it's found but Truncated
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].integrity, Integrity::Truncated);
    }

    #[test]
    fn corrupt_header_checksum_marked_header_corrupt() {
        let mut data = make_minimal_chunk();
        // Corrupt the header checksum
        data[0x78..0x7C].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].integrity, Integrity::HeaderCorrupt);
    }

    #[test]
    fn chunk_with_record_recovers_one_record() {
        let data = make_chunk_with_one_record();
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].records.len(), 1);
        assert_eq!(result.chunks[0].records[0].header.record_id, 42);
        assert_eq!(result.chunks[0].records[0].integrity, Integrity::Valid);
        assert_eq!(result.stats.records_recovered, 1);
    }

    #[test]
    fn file_header_found_when_elffile_magic_present() {
        let mut data = vec![0u8; 0x1000 + 0x10000]; // 4KiB file header + one chunk
        data[0..8].copy_from_slice(b"ElfFile\0");
        // chunk at 0x1000
        let chunk = make_minimal_chunk();
        data[0x1000..0x1000 + 0x10000].copy_from_slice(&chunk);
        let result = carve_from_bytes(&data);
        assert!(result.file_header.is_some());
    }

    // ---- US-01: anti-forensic integration tests ----

    /// Build a minimal chunk with explicit first/last record numbers and IDs, with correct checksum.
    fn make_chunk_with_record_range(
        first_record_number: u64,
        last_record_number: u64,
        first_record_id: u64,
        last_record_id: u64,
    ) -> Vec<u8> {
        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[8..16].copy_from_slice(&first_record_number.to_le_bytes());
        chunk[16..24].copy_from_slice(&last_record_number.to_le_bytes());
        chunk[24..32].copy_from_slice(&first_record_id.to_le_bytes());
        chunk[32..40].copy_from_slice(&last_record_id.to_le_bytes());
        chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes());
        chunk[44..48].copy_from_slice(&0x200u32.to_le_bytes());
        chunk[48..52].copy_from_slice(&0x200u32.to_le_bytes());
        chunk[52..56].copy_from_slice(&0u32.to_le_bytes());
        let crc = crc32fast::hash(&chunk[0..0x78]);
        chunk[0x78..0x7C].copy_from_slice(&crc.to_le_bytes());
        chunk
    }

    /// Build a valid file header (128 bytes at offset 0) with given next_record_id.
    fn make_file_header(next_record_id: u64) -> Vec<u8> {
        let mut hdr = vec![0u8; 0x1000];
        hdr[0..8].copy_from_slice(b"ElfFile\0");
        hdr[8..16].copy_from_slice(&0u64.to_le_bytes()); // first_chunk_number
        hdr[16..24].copy_from_slice(&0u64.to_le_bytes()); // last_chunk_number
        hdr[24..32].copy_from_slice(&next_record_id.to_le_bytes()); // next_record_id
        hdr[36..38].copy_from_slice(&1u16.to_le_bytes()); // minor_version
        hdr[38..40].copy_from_slice(&3u16.to_le_bytes()); // major_version
        hdr[40..42].copy_from_slice(&0u16.to_le_bytes()); // HeaderBlockSize padding
        hdr[42..44].copy_from_slice(&1u16.to_le_bytes()); // chunk_count
        hdr
    }

    #[test]
    fn record_id_gap_between_chunks_populates_anti_forensic() {
        // chunk 1: records 1..10, chunk 2: records 15..20 — gap at 11-14
        let mut data = make_chunk_with_record_range(1, 10, 1, 10);
        data.extend(make_chunk_with_record_range(15, 20, 15, 20));
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 2, "expected two chunks");
        let has_gap = result.anti_forensic.iter().any(|ind| {
            matches!(ind, IntegrityIndicator::RecordIdGap { expected, found, .. }
                if *expected == 11 && *found == 15)
        });
        assert!(
            has_gap,
            "expected RecordIdGap(expected=11, found=15) in result.anti_forensic, got: {:?}",
            result.anti_forensic
        );
    }

    #[test]
    fn corrupt_chunk_checksum_populates_chunk_anti_forensic() {
        let mut data = make_minimal_chunk();
        // Corrupt the checksum so it no longer matches
        data[0x78..0x7C].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 1);
        let has_mismatch = result.chunks[0]
            .anti_forensic
            .iter()
            .any(|ind| matches!(ind, IntegrityIndicator::ChunkChecksumMismatch { .. }));
        assert!(
            has_mismatch,
            "expected ChunkChecksumMismatch in chunk.anti_forensic"
        );
    }

    #[test]
    fn file_header_inconsistency_populates_result_anti_forensic() {
        // File header says next_record_id = 5, but chunk has records up to 100
        let mut data = make_file_header(5);
        data.extend(make_chunk_with_record_range(1, 100, 1, 100));
        let result = carve_from_bytes(&data);
        let has_inconsistency = result.anti_forensic.iter().any(|ind| {
            matches!(ind, IntegrityIndicator::NextRecordIdInconsistency { header_next, actual_highest }
                if *header_next == 5 && *actual_highest == 100)
        });
        assert!(
            has_inconsistency,
            "expected NextRecordIdInconsistency in result.anti_forensic, got: {:?}",
            result.anti_forensic
        );
    }

    #[test]
    fn clean_data_returns_empty_anti_forensic() {
        // Two contiguous chunks with no gaps and valid checksums
        let mut data = make_chunk_with_record_range(1, 10, 1, 10);
        data.extend(make_chunk_with_record_range(11, 20, 11, 20));
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 2);
        assert!(
            result.anti_forensic.is_empty(),
            "expected empty result.anti_forensic for clean data, got: {:?}",
            result.anti_forensic
        );
        for chunk in &result.chunks {
            assert!(
                chunk.anti_forensic.is_empty(),
                "expected empty chunk.anti_forensic for valid chunk, got: {:?}",
                chunk.anti_forensic
            );
        }
    }
}
