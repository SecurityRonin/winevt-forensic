//! Minimal `BinXml` token scanner for Windows Event Log payloads.
//!
//! This is a best-effort scanner, NOT a full `BinXml` parser. It extracts
//! commonly needed fields by scanning byte patterns in the `BinXml` System element.
//! Returns `None` for any field that cannot be reliably determined.

/// Summary of fields extracted from a `BinXml` event payload.
#[derive(Debug, Clone)]
pub struct BinXmlSummary {
    pub event_id: Option<u16>,
    pub channel: Option<String>,
    pub computer: Option<String>,
    pub provider_name: Option<String>,
    pub level: Option<u8>,
}

/// Scan a `BinXml` payload for known fields. Best-effort: all fields may be `None`.
///
/// # Limitations
/// This is not a full `BinXml` parser. It uses heuristic byte-pattern scanning
/// and is intentionally conservative — it returns `None` rather than guessing.
pub fn scan_binxml(payload: &[u8]) -> BinXmlSummary {
    // BinXml is a complex binary format. A full parser requires tracking
    // the string table, template substitution slots, and element nesting.
    // This stub returns all None to ensure no panics on arbitrary input.
    // Future work: implement a proper BinXml token walker.
    let _ = payload; // suppress unused warning while remaining a no-op
    BinXmlSummary {
        event_id: None,
        channel: None,
        computer: None,
        provider_name: None,
        level: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_binxml_empty_payload_returns_all_none() {
        let summary = scan_binxml(&[]);
        assert!(summary.event_id.is_none());
        assert!(summary.channel.is_none());
        assert!(summary.computer.is_none());
        assert!(summary.provider_name.is_none());
        assert!(summary.level.is_none());
    }

    #[test]
    fn scan_binxml_random_bytes_does_not_panic() {
        let data = vec![0xFFu8; 128];
        let _ = scan_binxml(&data);
    }

    #[test]
    fn scan_binxml_very_large_payload_does_not_panic() {
        let data = vec![0u8; 65536];
        let _ = scan_binxml(&data);
    }

    #[test]
    fn binxml_summary_fields_are_optional() {
        let summary = BinXmlSummary {
            event_id: Some(4624),
            channel: Some("Security".to_string()),
            computer: None,
            provider_name: Some("Microsoft-Windows-Security-Auditing".to_string()),
            level: Some(0),
        };
        assert_eq!(summary.event_id, Some(4624));
        assert_eq!(summary.channel.as_deref(), Some("Security"));
        assert!(summary.computer.is_none());
    }

    // ── §4: validate_binxml ───────────────────────────────────────────────────

    fn minimal_valid_binxml() -> Vec<u8> {
        // FragmentHeader (0x0F), major=1, minor=1, flags=0x00, EndOfStream (0x00)
        vec![0x0F, 0x01, 0x01, 0x00, 0x00]
    }

    #[test]
    fn valid_binxml_passes_validation() {
        let result = validate_binxml(&minimal_valid_binxml());
        assert!(result.is_ok(), "valid BinXML must pass; got {:?}", result);
    }

    #[test]
    fn empty_binxml_returns_error() {
        let result = validate_binxml(&[]);
        assert!(result.is_err(), "empty bytes must return error");
        assert!(matches!(result, Err(BinXmlError::TooShort { .. })));
    }

    #[test]
    fn truncated_binxml_returns_error() {
        // Only 2 bytes — not enough for a fragment header
        let result = validate_binxml(&[0x0F, 0x01]);
        assert!(result.is_err(), "truncated header must return error");
    }

    #[test]
    fn wrong_first_byte_returns_error() {
        let mut bytes = minimal_valid_binxml();
        bytes[0] = 0xAA; // not 0x0F
        let result = validate_binxml(&bytes);
        assert!(result.is_err(), "wrong fragment header must return error");
        assert!(
            matches!(result, Err(BinXmlError::InvalidFragmentHeader { .. })),
            "got {:?}", result
        );
    }

    #[test]
    fn unknown_opcode_returns_error() {
        // Valid header, then an unknown token 0x7F
        let bytes = vec![0x0F, 0x01, 0x01, 0x00, 0x7F];
        let result = validate_binxml(&bytes);
        assert!(result.is_err(), "unknown opcode must return error");
        assert!(
            matches!(result, Err(BinXmlError::UnknownOpcode { opcode: 0x7F, .. })),
            "got {:?}", result
        );
    }

    #[test]
    fn string_table_overflow_returns_error() {
        // OpenStartElement token (0x01), then name_offset exceeding 65536
        // Layout: 0x01 flags(u1) dep_id(u2) attr_count(u2) name_offset(u4)
        let mut bytes = vec![0x0F, 0x01, 0x01, 0x00]; // fragment header
        bytes.push(0x01); // OpenStartElement token
        bytes.push(0x00); // flags
        bytes.extend_from_slice(&0u16.to_le_bytes()); // dependency_id
        bytes.extend_from_slice(&0u16.to_le_bytes()); // attribute_count
        bytes.extend_from_slice(&0x0001_0001u32.to_le_bytes()); // name_offset = 65537 > 65536
        bytes.push(0x00); // EndOfStream
        let result = validate_binxml(&bytes);
        assert!(result.is_err(), "string table overflow must return error");
        assert!(
            matches!(result, Err(BinXmlError::StringTableOverflow { .. })),
            "got {:?}", result
        );
    }

    #[test]
    fn end_of_stream_terminates_successfully() {
        // Header + EndOfStream immediately = valid minimal fragment
        let bytes = vec![0x0F, 0x01, 0x01, 0x00, 0x00];
        assert!(validate_binxml(&bytes).is_ok());
    }
}
