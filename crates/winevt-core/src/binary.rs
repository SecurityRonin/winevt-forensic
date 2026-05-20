use crc32fast::Hasher;

pub use forensicnomicon::evtx::{
    CHUNK_RECORDS_OFFSET, CHUNK_SIZE, ELFCHNK_MAGIC, ELFFILE_MAGIC, RECORD_MAGIC,
};

#[derive(Debug, Clone, serde::Serialize)]
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

#[derive(Debug, Clone, serde::Serialize)]
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

#[derive(Debug, Clone, serde::Serialize)]
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

/// Severity level of an [`IntegrityAnomaly`].
///
/// Variants are ordered from least to most severe so that `<` / `>` comparisons
/// work naturally (e.g. `Severity::Warning < Severity::Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Severity {
    /// Consistent with legitimate operation; worth noting.
    Info,
    /// Suspicious; plausible legitimate explanation exists.
    Warning,
    /// Strong indicator of tampering or structural corruption.
    Error,
    /// File cannot be reliably decoded.
    Critical,
}

/// Structural integrity anomalies detected in an EVTX file.
///
/// These variants represent low-level binary format facts only.
/// Intent inference (e.g. anti-forensic classification) belongs in the
/// caller — for example, the `RapidTriage` correlation engine.
#[derive(Debug, Clone, serde::Serialize)]
pub enum IntegrityAnomaly {
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
    /// Generic checksum mismatch (caller should prefer the specific variants below).
    ChecksumMismatch,
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
    FileHeaderChecksumMismatch {
        computed: u32,
        stored: u32,
    },
    FileNotCleanlyShutdown,
    FileFull,
    ChunkCountMismatch {
        header_count: u16,
        actual_count: usize,
    },
    /// A record has a zeroed header timestamp consistent with the wevtutil /
    /// Event Viewer export bug: when exporting with `wevtutil epl` or
    /// "Save As…", each record's header timestamp is replaced with the
    /// *previous* record's `BinXml` timestamp; the first record in the export
    /// therefore has no predecessor and receives timestamp 0.
    ///
    /// Reference: Wassenaar, Fox-IT BV (2019).
    /// "Export corrupts Windows Event Log files"
    /// <https://blog.fox-it.com/2019/06/04/export-corrupts-windows-event-log-files/>
    ExportTimestampCorruption {
        /// Record ID of the affected record (header timestamp is 0).
        record_id: u64,
        /// Byte offset of the chunk that contains this record.
        chunk_offset: u64,
    },
    /// A record's stated size spans the magic bytes of a subsequent record,
    /// consistent with surgical deletion by the NSA `DanderSpritz`
    /// `eventlogedit` tool.  The tool absorbs the deleted record into the
    /// preceding record's size field without emitting EID 1102.
    ///
    /// Reference: Wassenaar & van Dijk, Fox-IT BV (2017).
    /// "Detection and recovery of NSA's covered up tracks"
    /// <https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/>
    ///
    /// Reference implementation (Python):
    /// Wassenaar, Fox-IT BV — fox-it/danderspritz-evtx
    /// <https://github.com/fox-it/danderspritz-evtx>
    /// (MIT License; algorithm independently re-implemented in Rust)
    SurgicalRecordDeletion {
        /// Byte offset of the chunk containing the anomaly.
        chunk_offset: u64,
        /// Record ID of the absorbing record (its size was inflated).
        absorbing_record_id: u64,
        /// The inflated size value read from the absorbing record.
        stated_size: u32,
        /// Byte offset within the chunk where the ghost record's magic
        /// bytes (`0x2A 0x2A 0x00 0x00`) were found inside the absorbing
        /// record's body.
        ghost_offset_in_chunk: u64,
    },
    /// Chunk data length field falls outside the valid EVTX range [512, 65536].
    InvalidChunkDataLength(u32),
    /// The `log_file_guid` field in a chunk header differs from the first chunk's GUID,
    /// indicating the chunk was transplanted from a different log file.
    LogFileGuidMismatch {
        chunk_index: usize,
        expected: u128,
        actual: u128,
    },
    /// Unexpected bytes follow the last valid chunk in the file.
    TrailingData {
        /// Byte offset where unexpected data begins after the last valid chunk.
        offset: u64,
        /// Number of unexpected bytes.
        len: usize,
    },
    /// The file ends before all chunks declared in the file header are present.
    TruncatedFile {
        /// Chunk count declared in the file header.
        declared_chunks: u16,
        /// Chunks actually found in the file.
        found_chunks: usize,
    },
    /// Two chunk byte-ranges overlap, indicating structural corruption.
    OverlappingChunks {
        /// Byte offset of the first (earlier) chunk.
        chunk_a_offset: u64,
        /// Byte offset of the second (later) chunk whose range overlaps chunk_a.
        chunk_b_offset: u64,
    },
}

impl IntegrityAnomaly {
    /// Returns the [`Severity`] of this anomaly.
    pub fn severity(&self) -> Severity {
        match self {
            IntegrityAnomaly::SurgicalRecordDeletion { .. } => Severity::Critical,

            IntegrityAnomaly::ChunkChecksumMismatch { .. }
            | IntegrityAnomaly::RecordChecksumMismatch { .. }
            | IntegrityAnomaly::FileHeaderChecksumMismatch { .. }
            | IntegrityAnomaly::LogFileGuidMismatch { .. }
            | IntegrityAnomaly::NextRecordIdInconsistency { .. }
            | IntegrityAnomaly::RecordIdGap { .. }
            | IntegrityAnomaly::ChunkCountMismatch { .. }
            | IntegrityAnomaly::InvalidChunkDataLength(_)
            | IntegrityAnomaly::TrailingData { .. }
            | IntegrityAnomaly::TruncatedFile { .. }
            | IntegrityAnomaly::OverlappingChunks { .. } => Severity::Error,

            IntegrityAnomaly::TimestampAnomaly { .. }
            | IntegrityAnomaly::ExportTimestampCorruption { .. }
            | IntegrityAnomaly::LogCleared { .. }
            | IntegrityAnomaly::FileNotCleanlyShutdown
            | IntegrityAnomaly::FileFull
            | IntegrityAnomaly::ChecksumMismatch => Severity::Warning,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_anomaly_has_checksum_variant() {
        let a = IntegrityAnomaly::ChecksumMismatch;
        let s = format!("{a:?}");
        assert!(s.contains("ChecksumMismatch"));
    }

    #[test]
    fn constants_match_forensicnomicon() {
        assert_eq!(ELFFILE_MAGIC,        forensicnomicon::evtx::ELFFILE_MAGIC);
        assert_eq!(ELFCHNK_MAGIC,        forensicnomicon::evtx::ELFCHNK_MAGIC);
        assert_eq!(RECORD_MAGIC,         forensicnomicon::evtx::RECORD_MAGIC);
        assert_eq!(CHUNK_SIZE,           forensicnomicon::evtx::CHUNK_SIZE);
        assert_eq!(CHUNK_RECORDS_OFFSET, forensicnomicon::evtx::CHUNK_RECORDS_OFFSET);
    }

    // ── Severity ordering ────────────────────────────────────────────────────

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    // ── severity() mapping for every existing variant ────────────────────────

    #[test]
    fn severity_surgical_record_deletion_is_critical() {
        let a = IntegrityAnomaly::SurgicalRecordDeletion {
            chunk_offset: 0,
            absorbing_record_id: 1,
            stated_size: 100,
            ghost_offset_in_chunk: 50,
        };
        assert_eq!(a.severity(), Severity::Critical);
    }

    #[test]
    fn severity_chunk_checksum_mismatch_is_error() {
        let a = IntegrityAnomaly::ChunkChecksumMismatch {
            chunk_offset: 0,
            computed: 1,
            stored: 2,
        };
        assert_eq!(a.severity(), Severity::Error);
    }

    #[test]
    fn severity_record_checksum_mismatch_is_error() {
        let a = IntegrityAnomaly::RecordChecksumMismatch {
            chunk_offset: 0,
            computed: 1,
            stored: 2,
        };
        assert_eq!(a.severity(), Severity::Error);
    }

    #[test]
    fn severity_file_header_checksum_mismatch_is_error() {
        let a = IntegrityAnomaly::FileHeaderChecksumMismatch {
            computed: 1,
            stored: 2,
        };
        assert_eq!(a.severity(), Severity::Error);
    }

    #[test]
    fn severity_log_file_guid_mismatch_is_error() {
        let a = IntegrityAnomaly::LogFileGuidMismatch {
            chunk_index: 1,
            expected: 0,
            actual: 1,
        };
        assert_eq!(a.severity(), Severity::Error);
    }

    #[test]
    fn severity_next_record_id_inconsistency_is_error() {
        let a = IntegrityAnomaly::NextRecordIdInconsistency {
            header_next: 5,
            actual_highest: 3,
        };
        assert_eq!(a.severity(), Severity::Error);
    }

    #[test]
    fn severity_record_id_gap_is_error() {
        let a = IntegrityAnomaly::RecordIdGap {
            chunk_offset: 0,
            expected: 5,
            found: 10,
        };
        assert_eq!(a.severity(), Severity::Error);
    }

    #[test]
    fn severity_chunk_count_mismatch_is_error() {
        let a = IntegrityAnomaly::ChunkCountMismatch {
            header_count: 5,
            actual_count: 3,
        };
        assert_eq!(a.severity(), Severity::Error);
    }

    #[test]
    fn severity_invalid_chunk_data_length_is_error() {
        let a = IntegrityAnomaly::InvalidChunkDataLength(999);
        assert_eq!(a.severity(), Severity::Error);
    }

    #[test]
    fn severity_timestamp_anomaly_is_warning() {
        let a = IntegrityAnomaly::TimestampAnomaly {
            chunk_offset: 0,
            record_id: 1,
            prev_ts: 100,
            this_ts: 50,
        };
        assert_eq!(a.severity(), Severity::Warning);
    }

    #[test]
    fn severity_export_timestamp_corruption_is_warning() {
        let a = IntegrityAnomaly::ExportTimestampCorruption {
            record_id: 1,
            chunk_offset: 0,
        };
        assert_eq!(a.severity(), Severity::Warning);
    }

    #[test]
    fn severity_log_cleared_is_warning() {
        let a = IntegrityAnomaly::LogCleared {
            channel: "Security".to_string(),
            timestamp: 0,
            user_sid: None,
        };
        assert_eq!(a.severity(), Severity::Warning);
    }

    #[test]
    fn severity_file_not_cleanly_shutdown_is_warning() {
        assert_eq!(IntegrityAnomaly::FileNotCleanlyShutdown.severity(), Severity::Warning);
    }

    #[test]
    fn severity_file_full_is_warning() {
        assert_eq!(IntegrityAnomaly::FileFull.severity(), Severity::Warning);
    }

    #[test]
    fn severity_checksum_mismatch_is_warning() {
        assert_eq!(IntegrityAnomaly::ChecksumMismatch.severity(), Severity::Warning);
    }

    // ── New variants: existence + Debug serialisation + severity ─────────────

    #[test]
    fn trailing_data_exists_and_debug() {
        let a = IntegrityAnomaly::TrailingData { offset: 65536, len: 128 };
        let s = format!("{a:?}");
        assert!(s.contains("TrailingData"));
    }

    #[test]
    fn trailing_data_severity_is_error() {
        let a = IntegrityAnomaly::TrailingData { offset: 0, len: 1 };
        assert_eq!(a.severity(), Severity::Error);
    }

    #[test]
    fn truncated_file_exists_and_debug() {
        let a = IntegrityAnomaly::TruncatedFile { declared_chunks: 10, found_chunks: 7 };
        let s = format!("{a:?}");
        assert!(s.contains("TruncatedFile"));
    }

    #[test]
    fn truncated_file_severity_is_error() {
        let a = IntegrityAnomaly::TruncatedFile { declared_chunks: 10, found_chunks: 7 };
        assert_eq!(a.severity(), Severity::Error);
    }

    #[test]
    fn overlapping_chunks_exists_and_debug() {
        let a = IntegrityAnomaly::OverlappingChunks { chunk_a_offset: 512, chunk_b_offset: 1024 };
        let s = format!("{a:?}");
        assert!(s.contains("OverlappingChunks"));
    }

    #[test]
    fn overlapping_chunks_severity_is_error() {
        let a = IntegrityAnomaly::OverlappingChunks { chunk_a_offset: 0, chunk_b_offset: 512 };
        assert_eq!(a.severity(), Severity::Error);
    }
}
