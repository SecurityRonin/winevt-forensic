pub use winevt_core::binary::{
    AntiForensicIndicator, EvtxChunkHeader, EvtxFileHeader, EvtxRecordHeader,
    ELFCHNK_MAGIC, ELFFILE_MAGIC, RECORD_MAGIC, CHUNK_SIZE, CHUNK_RECORDS_OFFSET,
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
    pub anti_forensic: Vec<AntiForensicIndicator>,
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
    pub anti_forensic: Vec<AntiForensicIndicator>,
    pub stats: CarveStats,
}

pub fn carve_from_bytes(_data: &[u8]) -> CarveResult {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_chunk() -> Vec<u8> {
        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[8..16].copy_from_slice(&1u64.to_le_bytes());  // first record number
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
}
