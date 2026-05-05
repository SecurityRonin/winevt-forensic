// Tests only — implementation comes in GREEN commit

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
