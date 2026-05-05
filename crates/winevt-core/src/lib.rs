//! Core types and lookup tables for Windows Event Log forensic analysis.

pub mod binary;

use std::collections::HashMap;

/// Core event type — parsed from EVTX.
#[derive(Debug, Clone)]
pub struct EvtxEvent {
    pub event_id: u32,
    pub channel: String,
    pub timestamp_ns: i64,
    pub computer: String,
    pub user_sid: Option<String>,
    pub logon_id: Option<u64>,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub data: HashMap<String, String>,
}

/// Session correlation output.
#[derive(Debug, Clone)]
pub struct LogonSession {
    pub logon_id: u64,
    pub logon_type: u8,
    pub username: String,
    pub domain: String,
    pub src_ip: Option<String>,
    pub logon_time_ns: i64,
    pub logoff_time_ns: Option<i64>,
    pub duration_secs: Option<u64>,
    pub processes: Vec<u32>,
    pub is_orphaned: bool,
}

/// Process creation event (from 4688).
#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub timestamp_ns: i64,
    pub process_id: u32,
    pub parent_pid: Option<u32>,
    pub image_path: String,
    pub command_line: Option<String>,
    pub logon_id: Option<u64>,
    pub user: Option<String>,
}

/// Service event (from 7045).
#[derive(Debug, Clone)]
pub struct ServiceEvent {
    pub timestamp_ns: i64,
    pub service_name: String,
    pub image_path: Option<String>,
    pub start_type: Option<String>,
    pub account: Option<String>,
}

/// Return the human-readable name of a Windows logon type code.
pub fn logon_type_name(t: u8) -> &'static str {
    match t {
        0 => "System",
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        10 => "RemoteInteractive",
        11 => "CachedInteractive",
        12 => "CachedRemoteInteractive",
        13 => "CachedUnlock",
        _ => "Unknown",
    }
}

/// Return the description for a 4625 failure sub-status hex code.
///
/// Codes are matched case-insensitively with or without the `0x` prefix.
pub fn substatus_description(code: &str) -> Option<&'static str> {
    // Normalise: upper-case, strip 0x prefix
    let upper = code.to_ascii_uppercase();
    let hex = upper.strip_prefix("0X").unwrap_or(&upper);
    match hex {
        "C000005E" => Some("No logon servers available"),
        "C0000064" => Some("User name does not exist"),
        "C000006A" => Some("Wrong password"),
        "C000006D" => Some("Bad username or authentication info"),
        "C000006E" => Some("Account restriction"),
        "C000006F" => Some("Logon outside authorized hours"),
        "C0000070" => Some("Unauthorized workstation"),
        "C0000071" => Some("Password expired"),
        "C0000072" => Some("Account disabled"),
        "C00000DC" => Some("SAM server in wrong state"),
        "C0000133" => Some("Clocks out of sync"),
        "C000015B" => Some("User not granted logon type"),
        "C000018C" => Some("Trust relationship failure"),
        "C0000192" => Some("Netlogon service not started"),
        "C0000193" => Some("Account expired"),
        "C0000224" => Some("Password must change at next logon"),
        "C0000225" => Some("Windows bug — not a risk"),
        "C0000234" => Some("Account locked out"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn evtx_event_data_access_by_key() {
        let mut data = HashMap::new();
        data.insert("TargetUserName".to_string(), "admin".to_string());
        data.insert("LogonType".to_string(), "10".to_string());
        let event = EvtxEvent {
            event_id: 4624,
            channel: "Security".into(),
            timestamp_ns: 1_700_000_000_000_000_000,
            computer: "DC01".into(),
            user_sid: Some("S-1-5-21-1234".into()),
            logon_id: Some(0x456789),
            process_id: Some(500),
            thread_id: Some(504),
            data,
        };
        assert_eq!(event.data.get("TargetUserName").unwrap(), "admin");
        assert_eq!(event.data.get("LogonType").unwrap(), "10");
        assert!(event.data.get("NonExistent").is_none());
    }

    #[test]
    fn logon_session_duration_none_when_no_logoff() {
        let session = LogonSession {
            logon_id: 0x123456,
            logon_type: 10,
            username: "analyst".into(),
            domain: "CORP".into(),
            src_ip: Some("10.0.0.5".into()),
            logon_time_ns: 1_700_000_000_000_000_000,
            logoff_time_ns: None,
            duration_secs: None,
            processes: vec![],
            is_orphaned: true,
        };
        assert!(session.duration_secs.is_none());
        assert!(session.logoff_time_ns.is_none());
        assert!(session.is_orphaned);
    }

    #[test]
    fn logon_type_2_is_interactive() {
        assert_eq!(logon_type_name(2), "Interactive");
    }

    #[test]
    fn logon_type_10_is_remote_interactive() {
        assert_eq!(logon_type_name(10), "RemoteInteractive");
    }

    #[test]
    fn substatus_wrong_password_code() {
        assert_eq!(substatus_description("0xC000006A"), Some("Wrong password"));
    }

    #[test]
    fn process_event_has_logon_id() {
        let pe = ProcessEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            process_id: 1234,
            parent_pid: Some(456),
            image_path: r"C:\Windows\System32\cmd.exe".into(),
            command_line: Some("cmd.exe /c whoami".into()),
            logon_id: Some(0xABCDEF),
            user: Some("CORP\\analyst".into()),
        };
        assert_eq!(pe.logon_id, Some(0xABCDEF));
        assert_eq!(pe.process_id, 1234);
    }

    // --- binary format tests ---
    use crate::binary::*;

    #[test]
    fn elffile_magic_constant_is_correct() {
        assert_eq!(ELFFILE_MAGIC, *b"ElfFile\0");
    }

    #[test]
    fn elfchnk_magic_constant_is_correct() {
        assert_eq!(ELFCHNK_MAGIC, *b"ElfChnk\0");
    }

    #[test]
    fn record_magic_constant_is_correct() {
        assert_eq!(RECORD_MAGIC, [0x2A, 0x2A, 0x00, 0x00]);
    }

    #[test]
    fn file_header_parse_returns_none_for_wrong_magic() {
        let buf = [0u8; 128];
        assert!(EvtxFileHeader::parse(&buf).is_none());
    }

    #[test]
    fn file_header_parse_returns_fields_for_known_good() {
        let mut buf = [0u8; 128];
        buf[0..8].copy_from_slice(b"ElfFile\0");
        // first_chunk_number = 0
        buf[8..16].copy_from_slice(&0u64.to_le_bytes());
        // last_chunk_number = 5
        buf[16..24].copy_from_slice(&5u64.to_le_bytes());
        // next_record_id = 1000
        buf[24..32].copy_from_slice(&1000u64.to_le_bytes());
        // header_size at 0x20 = 0x80
        buf[32..36].copy_from_slice(&0x80u32.to_le_bytes());
        // minor_version = 1
        buf[36..38].copy_from_slice(&1u16.to_le_bytes());
        // major_version = 3
        buf[38..40].copy_from_slice(&3u16.to_le_bytes());
        // header_block_size = 0x1000
        buf[40..42].copy_from_slice(&0x1000u16.to_le_bytes());
        // chunk_count = 6
        buf[42..44].copy_from_slice(&6u16.to_le_bytes());
        // file_flags at 0x78 = 0
        buf[0x78..0x7C].copy_from_slice(&0u32.to_le_bytes());
        // checksum at 0x7C (leave as 0 for this test)
        let h = EvtxFileHeader::parse(&buf).expect("should parse");
        assert_eq!(h.first_chunk_number, 0);
        assert_eq!(h.last_chunk_number, 5);
        assert_eq!(h.next_record_id, 1000);
        assert_eq!(h.chunk_count, 6);
        assert_eq!(h.major_version, 3);
    }

    #[test]
    fn chunk_header_parse_returns_none_for_wrong_magic() {
        let buf = [0u8; 512];
        assert!(EvtxChunkHeader::parse(&buf).is_none());
    }

    #[test]
    fn chunk_header_parse_returns_fields_for_known_good() {
        let mut buf = [0u8; 512];
        buf[0..8].copy_from_slice(b"ElfChnk\0");
        buf[8..16].copy_from_slice(&10u64.to_le_bytes()); // first record number
        buf[16..24].copy_from_slice(&19u64.to_le_bytes()); // last record number
        buf[24..32].copy_from_slice(&100u64.to_le_bytes()); // first record id
        buf[32..40].copy_from_slice(&109u64.to_le_bytes()); // last record id
        buf[40..44].copy_from_slice(&0x80u32.to_le_bytes()); // header_size
        buf[44..48].copy_from_slice(&0x500u32.to_le_bytes()); // last_event_record_data_offset
        buf[48..52].copy_from_slice(&0x800u32.to_le_bytes()); // free_space_offset
        buf[52..56].copy_from_slice(&0xDEADBEEFu32.to_le_bytes()); // event_records_checksum
        buf[0x78..0x7C].copy_from_slice(&0xCAFEBABEu32.to_le_bytes()); // header_checksum
        let h = EvtxChunkHeader::parse(&buf).expect("should parse");
        assert_eq!(h.first_event_record_number, 10);
        assert_eq!(h.last_event_record_number, 19);
        assert_eq!(h.header_size, 0x80);
        assert_eq!(h.event_records_checksum, 0xDEADBEEF);
        assert_eq!(h.header_checksum, 0xCAFEBABE);
    }

    #[test]
    fn record_header_parse_returns_none_for_wrong_magic() {
        let buf = [0u8; 32];
        assert!(EvtxRecordHeader::parse(&buf).is_none());
    }

    #[test]
    fn record_header_parse_returns_fields_for_known_good() {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]); // magic
        buf[4..8].copy_from_slice(&100u32.to_le_bytes()); // size
        buf[8..16].copy_from_slice(&42u64.to_le_bytes()); // record_id
        buf[16..24].copy_from_slice(&133_297_085_160_000_000u64.to_le_bytes()); // timestamp (FILETIME)
        let r = EvtxRecordHeader::parse(&buf).expect("should parse");
        assert_eq!(r.size, 100);
        assert_eq!(r.record_id, 42);
        assert_eq!(r.timestamp, 133_297_085_160_000_000);
    }

    #[test]
    fn compute_chunk_header_checksum_matches_expected() {
        use crate::binary::compute_checksum;
        // CRC32 of 120 zero bytes
        let data = [0u8; 0x78];
        let crc = compute_checksum(&data);
        // Verify it's deterministic
        assert_eq!(crc, compute_checksum(&data));
        // Not zero (CRC32 of all-zeros is not zero)
        assert_ne!(crc, 0);
    }
}
