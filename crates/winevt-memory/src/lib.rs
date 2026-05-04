// winevt-memory: types and analysis functions for EVTX/ETW data recovered from memory dumps.
// No dependency on memory readers — provides types that memf-windows populates.

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
        let sessions = vec![RecoveredEtwSession {
            logger_id: 1,
            name: "EventLog-Security".to_string(),
            is_running: true,
            buffer_count: 4,
            buffer_size: 64,
            events_lost: 100,
            log_mode: 0x00000101,
            buffer_events: vec![],
        }];
        let indicators = detect_etw_tampering(&sessions);
        assert!(
            indicators.is_empty(),
            "expected empty indicators for low events_lost, got: {:?}",
            indicators
        );
    }
}
