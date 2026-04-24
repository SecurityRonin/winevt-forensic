//! Frequency analysis and aggregation for Windows Event Log forensics.

use std::collections::HashMap;
use winevt_core::{EvtxEvent, LogonSession};

/// Key to group events by for frequency analysis.
#[derive(Debug, Clone, Copy)]
pub enum FrequencyKey {
    /// Group by `data["CommandLine"]`.
    CommandLine,
    /// Group by `data["NewProcessName"]`.
    ProcessImage,
    /// Group by `data["TargetUserName"]`.
    Username,
}

/// A frequency anomaly: a value that appeared at most `cap` times.
#[derive(Debug, Clone)]
pub struct FrequencyAnomaly {
    pub key: String,
    pub count: usize,
    pub events: Vec<i64>,
}

/// Frequency analysis: events whose group-by key appears at most `cap` times
/// are returned as anomalies. Port of Events Ripper posh600.pl cap=5 logic.
pub fn frequency_analysis(
    events: &[EvtxEvent],
    group_by: FrequencyKey,
    cap: usize,
) -> Vec<FrequencyAnomaly> {
    let data_key = match group_by {
        FrequencyKey::CommandLine => "CommandLine",
        FrequencyKey::ProcessImage => "NewProcessName",
        FrequencyKey::Username => "TargetUserName",
    };

    // Count occurrences and collect timestamps per key value
    let mut groups: HashMap<String, Vec<i64>> = HashMap::new();
    for ev in events {
        if let Some(val) = ev.data.get(data_key) {
            if !val.is_empty() {
                groups
                    .entry(val.clone())
                    .or_default()
                    .push(ev.timestamp_ns);
            }
        }
    }

    groups
        .into_iter()
        .filter(|(_, ts)| ts.len() <= cap)
        .map(|(key, events)| FrequencyAnomaly {
            count: events.len(),
            key,
            events,
        })
        .collect()
}

/// Pivot table: group sessions by source IP for lateral movement analysis.
pub fn pivot_sessions_by_src_ip<'a>(
    sessions: &'a [LogonSession],
) -> HashMap<String, Vec<&'a LogonSession>> {
    let mut result: HashMap<String, Vec<&'a LogonSession>> = HashMap::new();
    for s in sessions {
        let ip = s
            .src_ip
            .as_deref()
            .unwrap_or("(unknown)")
            .to_string();
        result.entry(ip).or_default().push(s);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;

    fn make_event_with_data(event_id: u32, data: Vec<(&str, &str)>, ts: i64) -> EvtxEvent {
        let data: Map<String, String> = data
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        EvtxEvent {
            event_id,
            channel: "Security".into(),
            timestamp_ns: ts,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        }
    }

    #[test]
    fn frequency_rare_command_flagged() {
        let events = vec![
            make_event_with_data(4688, vec![("CommandLine", "whoami")], 100),
            make_event_with_data(4688, vec![("CommandLine", "dir")], 200),
            make_event_with_data(4688, vec![("CommandLine", "dir")], 300),
            make_event_with_data(4688, vec![("CommandLine", "dir")], 400),
        ];
        let anomalies = frequency_analysis(&events, FrequencyKey::CommandLine, 2);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].key, "whoami");
        assert_eq!(anomalies[0].count, 1);
    }

    #[test]
    fn frequency_common_command_not_flagged() {
        let events = vec![
            make_event_with_data(4688, vec![("CommandLine", "svchost.exe")], 100),
            make_event_with_data(4688, vec![("CommandLine", "svchost.exe")], 200),
            make_event_with_data(4688, vec![("CommandLine", "svchost.exe")], 300),
        ];
        // cap=2 means only items appearing <= 2 times are anomalies
        // svchost.exe appears 3 times, so no anomalies
        let anomalies = frequency_analysis(&events, FrequencyKey::CommandLine, 2);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn frequency_empty_events_returns_empty() {
        let anomalies = frequency_analysis(&[], FrequencyKey::ProcessImage, 5);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn pivot_sessions_groups_by_src_ip() {
        let sessions = vec![
            LogonSession {
                logon_id: 1,
                logon_type: 3,
                username: "a".into(),
                domain: "D".into(),
                src_ip: Some("10.0.0.1".into()),
                logon_time_ns: 100,
                logoff_time_ns: None,
                duration_secs: None,
                processes: vec![],
                is_orphaned: true,
            },
            LogonSession {
                logon_id: 2,
                logon_type: 3,
                username: "b".into(),
                domain: "D".into(),
                src_ip: Some("10.0.0.1".into()),
                logon_time_ns: 200,
                logoff_time_ns: None,
                duration_secs: None,
                processes: vec![],
                is_orphaned: true,
            },
            LogonSession {
                logon_id: 3,
                logon_type: 10,
                username: "c".into(),
                domain: "D".into(),
                src_ip: Some("192.168.1.5".into()),
                logon_time_ns: 300,
                logoff_time_ns: None,
                duration_secs: None,
                processes: vec![],
                is_orphaned: true,
            },
        ];
        let pivot = pivot_sessions_by_src_ip(&sessions);
        assert_eq!(pivot.len(), 2);
        assert_eq!(pivot["10.0.0.1"].len(), 2);
        assert_eq!(pivot["192.168.1.5"].len(), 1);
    }

    #[test]
    fn pivot_sessions_no_ip_uses_unknown() {
        let sessions = vec![LogonSession {
            logon_id: 1,
            logon_type: 2,
            username: "local".into(),
            domain: "D".into(),
            src_ip: None,
            logon_time_ns: 100,
            logoff_time_ns: None,
            duration_secs: None,
            processes: vec![],
            is_orphaned: true,
        }];
        let pivot = pivot_sessions_by_src_ip(&sessions);
        assert_eq!(pivot.len(), 1);
        assert!(pivot.contains_key("(unknown)"));
    }
}
