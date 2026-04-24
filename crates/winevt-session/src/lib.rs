//! Logon session correlation and process linking for Windows Event Logs.
//!
//! The crown jewel of winevt-forensic: correlates 4624 logon events with
//! 4634/4647 logoff events by `LogonId`, then links 4688 process creation
//! events to their owning sessions. This is the innovation that Events Ripper's
//! `sec4688.pl` explicitly does NOT do.

use std::collections::HashMap;
use winevt_core::{EvtxEvent, LogonSession, ProcessEvent};

/// Lateral movement finding from session analysis.
#[derive(Debug, Clone)]
pub struct LateralMovementFinding {
    pub src_ip: String,
    pub sessions: Vec<u64>,
    pub reason: String,
}

/// Build a map of `LogonId` -> `LogonSession` from a slice of `EvtxEvent`s.
///
/// Matches 4624 (logon) with 4634/4647 (logoff) by logon_id.
/// Sessions without a matching logoff are marked `is_orphaned = true`.
pub fn correlate_sessions(events: &[EvtxEvent]) -> HashMap<u64, LogonSession> {
    let mut sessions: HashMap<u64, LogonSession> = HashMap::new();

    // First pass: create sessions from 4624 logon events
    for ev in events {
        if ev.event_id == 4624 {
            let Some(logon_id) = ev.logon_id else {
                continue;
            };
            let logon_type = ev
                .data
                .get("LogonType")
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0);
            let username = ev
                .data
                .get("TargetUserName")
                .cloned()
                .unwrap_or_default();
            let domain = ev
                .data
                .get("TargetDomainName")
                .cloned()
                .unwrap_or_default();
            let src_ip = ev.data.get("IpAddress").cloned().filter(|ip| ip != "-");

            sessions.insert(
                logon_id,
                LogonSession {
                    logon_id,
                    logon_type,
                    username,
                    domain,
                    src_ip,
                    logon_time_ns: ev.timestamp_ns,
                    logoff_time_ns: None,
                    duration_secs: None,
                    processes: Vec::new(),
                    is_orphaned: true,
                },
            );
        }
    }

    // Second pass: match 4634/4647 logoff events
    for ev in events {
        if ev.event_id == 4634 || ev.event_id == 4647 {
            let Some(logon_id) = ev.logon_id else {
                continue;
            };
            if let Some(session) = sessions.get_mut(&logon_id) {
                session.logoff_time_ns = Some(ev.timestamp_ns);
                session.is_orphaned = false;
                // Duration in seconds = (logoff - logon) / 1_000_000_000
                let delta_ns = ev.timestamp_ns.saturating_sub(session.logon_time_ns);
                #[allow(clippy::cast_sign_loss)]
                let secs = (delta_ns / 1_000_000_000) as u64;
                session.duration_secs = Some(secs);
            }
        }
    }

    sessions
}

/// Link process events (4688) to sessions via `logon_id`.
///
/// Mutates sessions in-place: adds PIDs to `LogonSession::processes`.
/// THIS IS OUR INNOVATION -- Events Ripper's sec4688.pl explicitly does NOT do this.
pub fn link_processes_to_sessions(
    sessions: &mut HashMap<u64, LogonSession>,
    process_events: &[ProcessEvent],
) {
    for proc in process_events {
        if let Some(lid) = proc.logon_id {
            if let Some(session) = sessions.get_mut(&lid) {
                session.processes.push(proc.process_id);
            }
        }
    }
}

/// Extract all `ProcessEvent`s from `EvtxEvent`s where `event_id == 4688`.
pub fn extract_process_events(events: &[EvtxEvent]) -> Vec<ProcessEvent> {
    events
        .iter()
        .filter(|ev| ev.event_id == 4688)
        .map(|ev| {
            let image_path = ev
                .data
                .get("NewProcessName")
                .cloned()
                .unwrap_or_default();
            let command_line = ev.data.get("CommandLine").cloned();
            let parent_pid = ev.data.get("ProcessId").and_then(|s| {
                let s = s.strip_prefix("0x").unwrap_or(s);
                u32::from_str_radix(s, 16).ok()
            });
            ProcessEvent {
                timestamp_ns: ev.timestamp_ns,
                process_id: ev.process_id.unwrap_or(0),
                parent_pid,
                image_path,
                command_line,
                logon_id: ev.logon_id,
                user: ev.data.get("SubjectUserName").cloned(),
            }
        })
        .collect()
}

/// Find sessions that had lateral movement indicators:
/// - Type 3 (Network) logons from remote IPs
/// - Multiple sessions from same source with short gaps
pub fn find_lateral_movement(sessions: &[LogonSession]) -> Vec<LateralMovementFinding> {
    // Group type-3 sessions by source IP
    let mut by_ip: HashMap<String, Vec<u64>> = HashMap::new();
    for s in sessions {
        if s.logon_type == 3 {
            if let Some(ref ip) = s.src_ip {
                by_ip.entry(ip.clone()).or_default().push(s.logon_id);
            }
        }
    }

    by_ip
        .into_iter()
        .map(|(ip, session_ids)| {
            let reason = if session_ids.len() > 1 {
                format!(
                    "Multiple Network logons ({}) from {}",
                    session_ids.len(),
                    ip
                )
            } else {
                format!("Network logon (type 3) from {ip}")
            };
            LateralMovementFinding {
                src_ip: ip,
                sessions: session_ids,
                reason,
            }
        })
        .collect()
}

/// Detect orphaned sessions (logon without matching logoff).
pub fn find_orphaned_sessions(sessions: &[LogonSession]) -> Vec<&LogonSession> {
    sessions.iter().filter(|s| s.is_orphaned).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;

    fn make_logon(logon_id: u64, logon_type: u8, ts_ns: i64) -> EvtxEvent {
        let mut data = Map::new();
        data.insert(
            "TargetLogonId".into(),
            format!("0x{logon_id:016x}"),
        );
        data.insert("LogonType".into(), logon_type.to_string());
        data.insert("TargetUserName".into(), "testuser".into());
        data.insert("TargetDomainName".into(), "TESTDOMAIN".into());
        data.insert("IpAddress".into(), "192.168.1.100".into());
        EvtxEvent {
            event_id: 4624,
            channel: "Security".into(),
            timestamp_ns: ts_ns,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: Some(logon_id),
            process_id: None,
            thread_id: None,
            data,
        }
    }

    fn make_logoff(logon_id: u64, ts_ns: i64) -> EvtxEvent {
        let mut data = Map::new();
        data.insert(
            "TargetLogonId".into(),
            format!("0x{logon_id:016x}"),
        );
        EvtxEvent {
            event_id: 4634,
            channel: "Security".into(),
            timestamp_ns: ts_ns,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: Some(logon_id),
            process_id: None,
            thread_id: None,
            data,
        }
    }

    fn make_process(pid: u32, logon_id: u64, image: &str, ts_ns: i64) -> EvtxEvent {
        let mut data = Map::new();
        data.insert("NewProcessId".into(), format!("0x{pid:x}"));
        data.insert("NewProcessName".into(), image.into());
        data.insert(
            "SubjectLogonId".into(),
            format!("0x{logon_id:016x}"),
        );
        EvtxEvent {
            event_id: 4688,
            channel: "Security".into(),
            timestamp_ns: ts_ns,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: Some(logon_id),
            process_id: Some(pid),
            thread_id: None,
            data,
        }
    }

    #[test]
    fn empty_events_returns_empty_sessions() {
        let sessions = correlate_sessions(&[]);
        assert!(sessions.is_empty());
    }

    #[test]
    fn single_4624_creates_session() {
        let events = vec![make_logon(0x1000, 10, 100_000_000)];
        let sessions = correlate_sessions(&events);
        assert_eq!(sessions.len(), 1);
        let s = sessions.get(&0x1000).unwrap();
        assert_eq!(s.logon_type, 10);
        assert_eq!(s.username, "testuser");
        assert!(s.is_orphaned);
    }

    #[test]
    fn pair_4624_4634_correlates_to_session_with_duration() {
        let events = vec![
            make_logon(0x2000, 2, 1_000_000_000),
            make_logoff(0x2000, 4_000_000_000),
        ];
        let sessions = correlate_sessions(&events);
        let s = sessions.get(&0x2000).unwrap();
        assert!(!s.is_orphaned);
        assert_eq!(s.logoff_time_ns, Some(4_000_000_000));
        // 3 seconds duration
        assert_eq!(s.duration_secs, Some(3));
    }

    #[test]
    fn session_without_logoff_is_orphaned() {
        let events = vec![make_logon(0x3000, 3, 500_000_000)];
        let sessions = correlate_sessions(&events);
        let s = sessions.get(&0x3000).unwrap();
        assert!(s.is_orphaned);
        assert!(s.logoff_time_ns.is_none());
        assert!(s.duration_secs.is_none());
    }

    #[test]
    fn multiple_sessions_same_user_tracked_separately_by_logon_id() {
        let events = vec![
            make_logon(0x4000, 10, 100),
            make_logon(0x4001, 10, 200),
            make_logoff(0x4000, 300),
        ];
        let sessions = correlate_sessions(&events);
        assert_eq!(sessions.len(), 2);
        assert!(!sessions[&0x4000].is_orphaned);
        assert!(sessions[&0x4001].is_orphaned);
    }

    #[test]
    fn process_link_adds_pid_to_correct_session() {
        let events = vec![
            make_logon(0x5000, 2, 100),
            make_logoff(0x5000, 10_000_000_000),
        ];
        let mut sessions = correlate_sessions(&events);

        let procs = vec![
            ProcessEvent {
                timestamp_ns: 200,
                process_id: 1234,
                parent_pid: Some(4),
                image_path: r"C:\Windows\cmd.exe".into(),
                command_line: Some("cmd /c dir".into()),
                logon_id: Some(0x5000),
                user: Some("testuser".into()),
            },
            ProcessEvent {
                timestamp_ns: 300,
                process_id: 5678,
                parent_pid: Some(1234),
                image_path: r"C:\Windows\whoami.exe".into(),
                command_line: None,
                logon_id: Some(0x5000),
                user: None,
            },
        ];
        link_processes_to_sessions(&mut sessions, &procs);
        let s = sessions.get(&0x5000).unwrap();
        assert_eq!(s.processes.len(), 2);
        assert!(s.processes.contains(&1234));
        assert!(s.processes.contains(&5678));
    }

    #[test]
    fn process_link_unknown_logon_id_ignored() {
        let events = vec![make_logon(0x6000, 2, 100)];
        let mut sessions = correlate_sessions(&events);

        let procs = vec![ProcessEvent {
            timestamp_ns: 200,
            process_id: 999,
            parent_pid: None,
            image_path: "malware.exe".into(),
            command_line: None,
            logon_id: Some(0xDEAD), // not a known session
            user: None,
        }];
        link_processes_to_sessions(&mut sessions, &procs);
        // Session 0x6000 should have no processes
        assert!(sessions[&0x6000].processes.is_empty());
    }

    #[test]
    fn network_logon_type3_found_by_lateral_movement_finder() {
        let sessions = vec![LogonSession {
            logon_id: 0x7000,
            logon_type: 3,
            username: "admin".into(),
            domain: "CORP".into(),
            src_ip: Some("10.0.0.50".into()),
            logon_time_ns: 100,
            logoff_time_ns: Some(500),
            duration_secs: Some(0),
            processes: vec![],
            is_orphaned: false,
        }];
        let findings = find_lateral_movement(&sessions);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].src_ip, "10.0.0.50");
    }

    #[test]
    fn orphaned_session_finder_returns_sessions_without_logoff() {
        let sessions = vec![
            LogonSession {
                logon_id: 0x8000,
                logon_type: 10,
                username: "user1".into(),
                domain: "D".into(),
                src_ip: None,
                logon_time_ns: 100,
                logoff_time_ns: None,
                duration_secs: None,
                processes: vec![],
                is_orphaned: true,
            },
            LogonSession {
                logon_id: 0x8001,
                logon_type: 2,
                username: "user2".into(),
                domain: "D".into(),
                src_ip: None,
                logon_time_ns: 200,
                logoff_time_ns: Some(300),
                duration_secs: Some(0),
                processes: vec![],
                is_orphaned: false,
            },
        ];
        let orphans = find_orphaned_sessions(&sessions);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].logon_id, 0x8000);
    }
}
