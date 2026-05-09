// winevt-memory: types and analysis functions for EVTX/ETW data recovered from memory dumps.
// No dependency on memory readers — provides types that memf-windows populates.

pub use winevt_core::binary::{EvtxChunkHeader, IntegrityAnomaly};

/// An ETW event recovered from a session buffer in kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecoveredEtwEvent {
    pub timestamp: u64,
    pub provider_id: String,
    pub event_id: u16,
    pub payload: Vec<u8>,
}

/// A chunk recovered from process memory (Event Log service VAD scan).
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryRecoveredChunk {
    pub vaddr: u64,
    pub header: EvtxChunkHeader,
    pub record_count: u32,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
    pub channel: String,
    pub source_process: Option<String>,
    pub source_pid: Option<u32>,
    pub anti_forensic: Vec<IntegrityAnomaly>,
}

/// An ETW session recovered from kernel memory (`_WMI_LOGGER_CONTEXT` walk).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecoveredEtwSession {
    pub logger_id: u32,
    pub name: String,
    pub is_running: bool,
    pub buffer_count: u32,
    pub buffer_size: u32,
    pub events_lost: u32,
    pub log_mode: u32,
    pub buffer_events: Vec<RecoveredEtwEvent>,
}

/// ETW-level tampering indicators.
#[derive(Debug, Clone, serde::Serialize)]
pub enum EtwTamperingIndicator {
    /// Session has abnormally high `events_lost` count.
    HighEventsLost {
        session_name: String,
        events_lost: u32,
        threshold: u32,
    },
    /// Expected Event Log session missing (e.g., "EventLog-Security" not found).
    MissingEventLogSession { expected_name: String },
    /// Session exists but is not running (stopped ETW session = blind spot).
    SessionStopped { session_name: String },
    /// Buffer count is zero for a running session (buffers deallocated).
    ZeroBuffers { session_name: String },
    /// Session has `log_mode = 0` (no output configured).
    SuspiciousLogMode { session_name: String, log_mode: u32 },
}

/// Events-lost threshold above which a session is flagged.
const HIGH_EVENTS_LOST_THRESHOLD: u32 = 1000;

/// Filter sessions whose name starts with `"EventLog-"`.
pub fn identify_eventlog_sessions(sessions: &[RecoveredEtwSession]) -> Vec<&RecoveredEtwSession> {
    sessions
        .iter()
        .filter(|s| s.name.starts_with("EventLog-"))
        .collect()
}

/// Required `EventLog` session names that must be present.
const REQUIRED_EVENTLOG_SESSIONS: &[&str] = &[
    "EventLog-Security",
    "EventLog-System",
    "EventLog-Application",
];

/// Detect ETW-level tampering indicators across the given sessions.
pub fn detect_etw_tampering(sessions: &[RecoveredEtwSession]) -> Vec<EtwTamperingIndicator> {
    let mut indicators = Vec::new();

    // Feature 7: check required sessions are present
    for required in REQUIRED_EVENTLOG_SESSIONS {
        if !sessions.iter().any(|s| s.name == *required) {
            indicators.push(EtwTamperingIndicator::MissingEventLogSession {
                expected_name: (*required).to_string(),
            });
        }
    }

    for session in sessions {
        if session.events_lost > HIGH_EVENTS_LOST_THRESHOLD {
            indicators.push(EtwTamperingIndicator::HighEventsLost {
                session_name: session.name.clone(),
                events_lost: session.events_lost,
                threshold: HIGH_EVENTS_LOST_THRESHOLD,
            });
        }
        if session.log_mode == 0 {
            indicators.push(EtwTamperingIndicator::SuspiciousLogMode {
                session_name: session.name.clone(),
                log_mode: 0,
            });
        }
        // Feature 7: stopped session
        if session.name.starts_with("EventLog-") && !session.is_running {
            indicators.push(EtwTamperingIndicator::SessionStopped {
                session_name: session.name.clone(),
            });
        }
        // Feature 7: zero buffers on running session
        if session.is_running && session.buffer_count == 0 {
            indicators.push(EtwTamperingIndicator::ZeroBuffers {
                session_name: session.name.clone(),
            });
        }
    }
    indicators
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_chunk_header() -> winevt_core::binary::EvtxChunkHeader {
        let mut buf = vec![0u8; 0x10000];
        buf[0..8].copy_from_slice(b"ElfChnk\0");
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..24].copy_from_slice(&10u64.to_le_bytes());
        buf[24..32].copy_from_slice(&1u64.to_le_bytes());
        buf[32..40].copy_from_slice(&10u64.to_le_bytes());
        buf[40..44].copy_from_slice(&0x80u32.to_le_bytes());
        buf[44..48].copy_from_slice(&0x200u32.to_le_bytes());
        buf[48..52].copy_from_slice(&0x200u32.to_le_bytes());
        buf[52..56].copy_from_slice(&0u32.to_le_bytes());
        let crc = crc32fast::hash(&buf[0..0x78]);
        buf[0x78..0x7C].copy_from_slice(&crc.to_le_bytes());
        winevt_core::binary::EvtxChunkHeader::parse(&buf).unwrap()
    }

    #[test]
    fn memory_recovered_chunk_can_be_constructed() {
        let header = make_chunk_header();
        let chunk = MemoryRecoveredChunk {
            vaddr: 0xFFFF_C000_0000_0000,
            header,
            record_count: 10,
            first_timestamp: 100,
            last_timestamp: 200,
            channel: "Security".to_string(),
            source_process: Some("EventLog".to_string()),
            source_pid: Some(1234),
            anti_forensic: vec![],
        };
        assert_eq!(chunk.vaddr, 0xFFFF_C000_0000_0000);
        assert_eq!(chunk.record_count, 10);
        assert_eq!(chunk.channel, "Security");
    }

    #[test]
    fn recovered_etw_session_can_be_constructed() {
        let session = RecoveredEtwSession {
            logger_id: 7,
            name: "EventLog-Security".to_string(),
            is_running: true,
            buffer_count: 4,
            buffer_size: 64,
            events_lost: 0,
            log_mode: 0x00000101,
            buffer_events: vec![],
        };
        assert_eq!(session.logger_id, 7);
        assert_eq!(session.name, "EventLog-Security");
        assert!(session.is_running);
    }

    #[test]
    fn identify_eventlog_sessions_returns_only_prefixed() {
        let sessions = vec![
            RecoveredEtwSession {
                logger_id: 1,
                name: "EventLog-Security".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 0,
                log_mode: 0,
                buffer_events: vec![],
            },
            RecoveredEtwSession {
                logger_id: 2,
                name: "NT Kernel Logger".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 0,
                log_mode: 0,
                buffer_events: vec![],
            },
            RecoveredEtwSession {
                logger_id: 3,
                name: "EventLog-System".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 0,
                log_mode: 0,
                buffer_events: vec![],
            },
        ];
        let found = identify_eventlog_sessions(&sessions);
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|s| s.name == "EventLog-Security"));
        assert!(found.iter().any(|s| s.name == "EventLog-System"));
    }

    #[test]
    fn identify_eventlog_sessions_returns_empty_when_none_match() {
        let sessions = vec![RecoveredEtwSession {
            logger_id: 1,
            name: "NT Kernel Logger".to_string(),
            is_running: true,
            buffer_count: 4,
            buffer_size: 64,
            events_lost: 0,
            log_mode: 0,
            buffer_events: vec![],
        }];
        let found = identify_eventlog_sessions(&sessions);
        assert!(found.is_empty());
    }

    #[test]
    fn detect_etw_tampering_flags_high_events_lost() {
        let sessions = vec![RecoveredEtwSession {
            logger_id: 1,
            name: "EventLog-Security".to_string(),
            is_running: true,
            buffer_count: 4,
            buffer_size: 64,
            events_lost: 1001,
            log_mode: 0x00000101,
            buffer_events: vec![],
        }];
        let indicators = detect_etw_tampering(&sessions);
        let has_high_lost = indicators.iter().any(|ind| {
            matches!(ind, EtwTamperingIndicator::HighEventsLost { session_name, events_lost, .. }
                if session_name == "EventLog-Security" && *events_lost == 1001)
        });
        assert!(
            has_high_lost,
            "expected HighEventsLost indicator, got: {:?}",
            indicators
        );
    }

    #[test]
    fn detect_etw_tampering_returns_empty_for_low_events_lost() {
        // Must include all three required sessions to avoid MissingEventLogSession indicators
        let sessions = vec![
            RecoveredEtwSession {
                logger_id: 1,
                name: "EventLog-Security".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 100,
                log_mode: 0x00000101,
                buffer_events: vec![],
            },
            RecoveredEtwSession {
                logger_id: 2,
                name: "EventLog-System".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 0,
                log_mode: 0x00000101,
                buffer_events: vec![],
            },
            RecoveredEtwSession {
                logger_id: 3,
                name: "EventLog-Application".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 0,
                log_mode: 0x00000101,
                buffer_events: vec![],
            },
        ];
        let indicators = detect_etw_tampering(&sessions);
        assert!(
            indicators.is_empty(),
            "expected empty indicators for low events_lost (all sessions present), got: {:?}",
            indicators
        );
    }

    // ---- US-05: extended ETW tampering detection ----

    #[test]
    fn detect_etw_tampering_flags_suspicious_log_mode_zero() {
        let sessions = vec![RecoveredEtwSession {
            logger_id: 1,
            name: "EventLog-Security".to_string(),
            is_running: true,
            buffer_count: 4,
            buffer_size: 64,
            events_lost: 0,
            log_mode: 0, // no output configured — suspicious
            buffer_events: vec![],
        }];
        let indicators = detect_etw_tampering(&sessions);
        let has_suspicious = indicators.iter().any(|ind| {
            matches!(ind, EtwTamperingIndicator::SuspiciousLogMode { session_name, .. }
                if session_name == "EventLog-Security")
        });
        assert!(
            has_suspicious,
            "expected SuspiciousLogMode indicator for log_mode=0, got: {:?}",
            indicators
        );
    }

    #[test]
    fn detect_etw_tampering_returns_empty_for_normal_active_session() {
        // Must include all three required sessions
        let sessions = vec![
            RecoveredEtwSession {
                logger_id: 1,
                name: "EventLog-Security".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 5,
                log_mode: 0x00000101,
                buffer_events: vec![],
            },
            RecoveredEtwSession {
                logger_id: 2,
                name: "EventLog-System".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 0,
                log_mode: 0x00000101,
                buffer_events: vec![],
            },
            RecoveredEtwSession {
                logger_id: 3,
                name: "EventLog-Application".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 0,
                log_mode: 0x00000101,
                buffer_events: vec![],
            },
        ];
        let indicators = detect_etw_tampering(&sessions);
        assert!(
            indicators.is_empty(),
            "expected empty indicators for normal session (all required present), got: {:?}",
            indicators
        );
    }

    #[test]
    fn identify_eventlog_sessions_finds_security_system_application() {
        let sessions = vec![
            RecoveredEtwSession {
                logger_id: 1,
                name: "EventLog-Security".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 0,
                log_mode: 0,
                buffer_events: vec![],
            },
            RecoveredEtwSession {
                logger_id: 2,
                name: "EventLog-System".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 0,
                log_mode: 0,
                buffer_events: vec![],
            },
            RecoveredEtwSession {
                logger_id: 3,
                name: "EventLog-Application".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 0,
                log_mode: 0,
                buffer_events: vec![],
            },
            RecoveredEtwSession {
                logger_id: 4,
                name: "NT Kernel Logger".to_string(),
                is_running: true,
                buffer_count: 4,
                buffer_size: 64,
                events_lost: 0,
                log_mode: 0,
                buffer_events: vec![],
            },
        ];
        let found = identify_eventlog_sessions(&sessions);
        assert_eq!(found.len(), 3);
        let names: Vec<&str> = found.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"EventLog-Security"));
        assert!(names.contains(&"EventLog-System"));
        assert!(names.contains(&"EventLog-Application"));
    }

    #[test]
    fn memory_recovered_chunk_implements_serialize() {
        let header = make_chunk_header();
        let chunk = MemoryRecoveredChunk {
            vaddr: 0x1000,
            header,
            record_count: 1,
            first_timestamp: 0,
            last_timestamp: 0,
            channel: "Security".to_string(),
            source_process: None,
            source_pid: None,
            anti_forensic: vec![],
        };
        let json = serde_json::to_string(&chunk).expect("serialize MemoryRecoveredChunk");
        assert!(json.contains("Security"));
    }

    #[test]
    fn recovered_etw_session_implements_serialize() {
        let session = RecoveredEtwSession {
            logger_id: 1,
            name: "EventLog-Security".to_string(),
            is_running: true,
            buffer_count: 4,
            buffer_size: 64,
            events_lost: 0,
            log_mode: 0,
            buffer_events: vec![],
        };
        let json = serde_json::to_string(&session).expect("serialize RecoveredEtwSession");
        assert!(json.contains("EventLog-Security"));
    }

    // ---- Feature 7: Missing/stopped ETW sessions + zero buffers ----

    fn make_session(
        name: &str,
        is_running: bool,
        buffer_count: u32,
        log_mode: u32,
    ) -> RecoveredEtwSession {
        RecoveredEtwSession {
            logger_id: 1,
            name: name.to_string(),
            is_running,
            buffer_count,
            buffer_size: 64,
            events_lost: 0,
            log_mode,
            buffer_events: vec![],
        }
    }

    #[test]
    fn detect_etw_tampering_all_expected_present_no_new_indicators() {
        let sessions = vec![
            make_session("EventLog-Security", true, 4, 0x101),
            make_session("EventLog-System", true, 4, 0x101),
            make_session("EventLog-Application", true, 4, 0x101),
        ];
        let indicators = detect_etw_tampering(&sessions);
        let has_missing = indicators
            .iter()
            .any(|i| matches!(i, EtwTamperingIndicator::MissingEventLogSession { .. }));
        let has_stopped = indicators
            .iter()
            .any(|i| matches!(i, EtwTamperingIndicator::SessionStopped { .. }));
        let has_zero = indicators
            .iter()
            .any(|i| matches!(i, EtwTamperingIndicator::ZeroBuffers { .. }));
        assert!(
            !has_missing && !has_stopped && !has_zero,
            "expected no missing/stopped/zero indicators, got: {:?}",
            indicators
        );
    }

    #[test]
    fn detect_etw_tampering_missing_security_emits_missing_indicator() {
        let sessions = vec![
            make_session("EventLog-System", true, 4, 0x101),
            make_session("EventLog-Application", true, 4, 0x101),
        ];
        let indicators = detect_etw_tampering(&sessions);
        let has_missing = indicators.iter().any(|i| {
            matches!(i, EtwTamperingIndicator::MissingEventLogSession { expected_name }
                if expected_name == "EventLog-Security")
        });
        assert!(
            has_missing,
            "expected MissingEventLogSession for EventLog-Security, got: {:?}",
            indicators
        );
    }

    #[test]
    fn detect_etw_tampering_stopped_session_emits_stopped_indicator() {
        let sessions = vec![
            make_session("EventLog-Security", false, 4, 0x101),
            make_session("EventLog-System", true, 4, 0x101),
            make_session("EventLog-Application", true, 4, 0x101),
        ];
        let indicators = detect_etw_tampering(&sessions);
        let has_stopped = indicators.iter().any(|i| {
            matches!(i, EtwTamperingIndicator::SessionStopped { session_name }
                if session_name == "EventLog-Security")
        });
        assert!(
            has_stopped,
            "expected SessionStopped for EventLog-Security, got: {:?}",
            indicators
        );
    }

    #[test]
    fn detect_etw_tampering_zero_buffers_running_emits_zero_indicator() {
        let sessions = vec![
            make_session("EventLog-Security", true, 0, 0x101),
            make_session("EventLog-System", true, 4, 0x101),
            make_session("EventLog-Application", true, 4, 0x101),
        ];
        let indicators = detect_etw_tampering(&sessions);
        let has_zero = indicators.iter().any(|i| {
            matches!(i, EtwTamperingIndicator::ZeroBuffers { session_name }
                if session_name == "EventLog-Security")
        });
        assert!(
            has_zero,
            "expected ZeroBuffers for EventLog-Security (running, 0 buffers), got: {:?}",
            indicators
        );
    }

    #[test]
    fn detect_etw_tampering_all_three_missing_when_no_sessions() {
        let sessions: Vec<RecoveredEtwSession> = vec![];
        let indicators = detect_etw_tampering(&sessions);
        let missing_names: Vec<&str> = indicators
            .iter()
            .filter_map(|i| {
                if let EtwTamperingIndicator::MissingEventLogSession { expected_name } = i {
                    Some(expected_name.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(missing_names.contains(&"EventLog-Security"));
        assert!(missing_names.contains(&"EventLog-System"));
        assert!(missing_names.contains(&"EventLog-Application"));
    }

    // ── §8: scan_memory_buffer ────────────────────────────────────────────────

    fn make_raw_record(record_id: u64, ts: u64, payload: &[u8]) -> Vec<u8> {
        let size = (4 + 4 + 8 + 8 + payload.len() + 4) as u32;
        let mut rec = vec![0u8; size as usize];
        rec[0..4].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        rec[4..8].copy_from_slice(&size.to_le_bytes());
        rec[8..16].copy_from_slice(&record_id.to_le_bytes());
        rec[16..24].copy_from_slice(&ts.to_le_bytes());
        rec[24..24 + payload.len()].copy_from_slice(payload);
        let tail = size as usize - 4;
        rec[tail..].copy_from_slice(&size.to_le_bytes());
        rec
    }

    fn valid_binxml_payload() -> Vec<u8> {
        // Minimal BinXML fragment header: 0x0F 0x01 ...
        vec![0x0Fu8, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
    }

    #[test]
    fn scan_empty_buffer_returns_empty() {
        let records = scan_memory_buffer(&[]);
        assert!(records.is_empty(), "empty buffer must return empty");
    }

    #[test]
    fn scan_buffer_with_no_magic_returns_empty() {
        let buf = vec![0xFFu8; 256];
        let records = scan_memory_buffer(&buf);
        assert!(records.is_empty(), "buffer with no record magic must return empty");
    }

    #[test]
    fn scan_buffer_with_injected_record_finds_it() {
        let payload = valid_binxml_payload();
        let rec = make_raw_record(42, 100_000, &payload);
        let mut buf = vec![0u8; 64];
        buf.extend_from_slice(&rec);
        buf.extend_from_slice(&[0u8; 64]);
        let records = scan_memory_buffer(&buf);
        assert_eq!(records.len(), 1, "should find exactly one record; got {}", records.len());
        assert_eq!(records[0].offset, 64, "record should be at offset 64");
    }

    #[test]
    fn scan_ignores_random_bytes_matching_magic_only() {
        // Magic bytes with invalid record_length (0 bytes)
        let mut buf = vec![0u8; 128];
        buf[10] = 0x2A;
        buf[11] = 0x2A;
        buf[12] = 0x00;
        buf[13] = 0x00;
        // size field at [14..18] = 0 (invalid — below minimum 28)
        let records = scan_memory_buffer(&buf);
        assert!(
            records.is_empty(),
            "magic with invalid size must be ignored; got {} records", records.len()
        );
    }

    #[test]
    fn scan_multi_record_buffer_finds_all() {
        let payload = valid_binxml_payload();
        let rec1 = make_raw_record(1, 100, &payload);
        let rec2 = make_raw_record(2, 200, &payload);
        let rec3 = make_raw_record(3, 300, &payload);
        let mut buf = vec![0u8; 32];
        buf.extend_from_slice(&rec1);
        buf.extend_from_slice(&rec2);
        buf.extend_from_slice(&rec3);
        let records = scan_memory_buffer(&buf);
        assert_eq!(records.len(), 3, "should find 3 records; got {}", records.len());
        assert_eq!(records[0].offset, 32);
        assert!(records[1].offset > records[0].offset);
        assert!(records[2].offset > records[1].offset);
    }

    #[test]
    fn scan_record_beyond_buffer_end_is_ignored() {
        // Record whose size field claims more bytes than available
        let mut buf = vec![0x2A, 0x2A, 0x00, 0x00];
        buf.extend_from_slice(&65000u32.to_le_bytes()); // very large size
        buf.extend_from_slice(&[0u8; 20]);
        let records = scan_memory_buffer(&buf);
        assert!(
            records.is_empty(),
            "record extending beyond buffer must be ignored"
        );
    }
}
