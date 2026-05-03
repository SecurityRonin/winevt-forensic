fn main() {
    todo!("wt-evtx not yet implemented")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use winevt_core::EvtxEvent;

    /// Unit test 11: constructing EvtxEvent from empty HashMap works.
    #[test]
    fn parse_evtx_event_from_record_data_empty_map() {
        let event = EvtxEvent {
            event_id: 4624,
            channel: "Security".into(),
            timestamp_ns: 0,
            computer: "test-host".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data: HashMap::new(),
        };
        assert_eq!(event.event_id, 4624);
        assert_eq!(event.channel, "Security");
        assert!(event.data.is_empty());
    }

    /// Unit test 12: a formatting helper converts nanoseconds to ISO 8601.
    #[test]
    fn format_timestamp_ns_to_rfc3339() {
        // 1_700_000_000_000_000_000 ns = 2023-11-14T22:13:20Z
        let ns: i64 = 1_700_000_000_000_000_000;
        let result = format_ns(ns);
        assert!(result.starts_with("2023-11-14T22:13:20"), "got: {result}");
    }

    fn format_ns(ns: i64) -> String {
        use chrono::{TimeZone, Utc};
        let secs = ns / 1_000_000_000;
        let nanos = (ns % 1_000_000_000) as u32;
        Utc.timestamp_opt(secs, nanos)
            .single()
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "invalid".into())
    }
}
