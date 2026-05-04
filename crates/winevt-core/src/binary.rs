use crc32fast::Hasher;

pub const ELFFILE_MAGIC: [u8; 8] = *b"ElfFile\0";
pub const ELFCHNK_MAGIC: [u8; 8] = *b"ElfChnk\0";
pub const RECORD_MAGIC: [u8; 4] = [0x2A, 0x2A, 0x00, 0x00];
pub const CHUNK_SIZE: u64 = 0x1_0000;
pub const CHUNK_RECORDS_OFFSET: u64 = 0x200;

#[derive(Debug, Clone)]
pub struct EvtxFileHeader {
    pub first_chunk_number: u64,
    pub last_chunk_number: u64,
    pub next_record_id: u64,
    pub minor_version: u16,
    pub major_version: u16,
    pub chunk_count: u16,
    pub file_flags: u32,
    pub checksum: u32,
}

impl EvtxFileHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 128 {
            return None;
        }
        if buf[0..8] != ELFFILE_MAGIC {
            return None;
        }
        Some(Self {
            first_chunk_number: u64::from_le_bytes(buf[8..16].try_into().ok()?),
            last_chunk_number: u64::from_le_bytes(buf[16..24].try_into().ok()?),
            next_record_id: u64::from_le_bytes(buf[24..32].try_into().ok()?),
            minor_version: u16::from_le_bytes(buf[36..38].try_into().ok()?),
            major_version: u16::from_le_bytes(buf[38..40].try_into().ok()?),
            chunk_count: u16::from_le_bytes(buf[42..44].try_into().ok()?),
            file_flags: u32::from_le_bytes(buf[0x78..0x7C].try_into().ok()?),
            checksum: u32::from_le_bytes(buf[0x7C..0x80].try_into().ok()?),
        })
    }
}

#[derive(Debug, Clone)]
pub struct EvtxChunkHeader {
    pub first_event_record_number: u64,
    pub last_event_record_number: u64,
    pub first_event_record_id: u64,
    pub last_event_record_id: u64,
    pub header_size: u32,
    pub last_event_record_data_offset: u32,
    pub free_space_offset: u32,
    pub event_records_checksum: u32,
    pub header_checksum: u32,
}

impl EvtxChunkHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 0x7C {
            return None;
        }
        if buf[0..8] != ELFCHNK_MAGIC {
            return None;
        }
        Some(Self {
            first_event_record_number: u64::from_le_bytes(buf[8..16].try_into().ok()?),
            last_event_record_number: u64::from_le_bytes(buf[16..24].try_into().ok()?),
            first_event_record_id: u64::from_le_bytes(buf[24..32].try_into().ok()?),
            last_event_record_id: u64::from_le_bytes(buf[32..40].try_into().ok()?),
            header_size: u32::from_le_bytes(buf[40..44].try_into().ok()?),
            last_event_record_data_offset: u32::from_le_bytes(buf[44..48].try_into().ok()?),
            free_space_offset: u32::from_le_bytes(buf[48..52].try_into().ok()?),
            event_records_checksum: u32::from_le_bytes(buf[52..56].try_into().ok()?),
            header_checksum: u32::from_le_bytes(buf[0x78..0x7C].try_into().ok()?),
        })
    }
}

#[derive(Debug, Clone)]
pub struct EvtxRecordHeader {
    pub size: u32,
    pub record_id: u64,
    pub timestamp: u64,
}

impl EvtxRecordHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 24 {
            return None;
        }
        if buf[0..4] != RECORD_MAGIC {
            return None;
        }
        Some(Self {
            size: u32::from_le_bytes(buf[4..8].try_into().ok()?),
            record_id: u64::from_le_bytes(buf[8..16].try_into().ok()?),
            timestamp: u64::from_le_bytes(buf[16..24].try_into().ok()?),
        })
    }
}

/// CRC32 (ISO 3309) — the variant used throughout EVTX format.
pub fn compute_checksum(data: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize()
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum IntegrityIndicator {
    LogCleared {
        channel: String,
        timestamp: u64,
        user_sid: Option<String>,
    },
    RecordIdGap {
        chunk_offset: u64,
        expected: u64,
        found: u64,
    },
    ChunkChecksumMismatch {
        chunk_offset: u64,
        computed: u32,
        stored: u32,
    },
    RecordChecksumMismatch {
        chunk_offset: u64,
        computed: u32,
        stored: u32,
    },
    NextRecordIdInconsistency {
        header_next: u64,
        actual_highest: u64,
    },
    TimestampAnomaly {
        chunk_offset: u64,
        record_id: u64,
        prev_ts: u64,
        this_ts: u64,
    },
}
