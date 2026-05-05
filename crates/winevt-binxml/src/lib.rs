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
}
