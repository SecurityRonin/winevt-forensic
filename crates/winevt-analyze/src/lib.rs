//! Structured field analysis of Windows Event Log records.
//!
//! Builds on the `evtx` crate (full BinXml parser) to extract per-event
//! fields — event ID, logon session LUIDs, PowerShell script block text,
//! event frequency distributions — from intact or reconstructed EVTX files.
//!
//! For corrupt or cleared EVTX files, first reconstruct with
//! `winevt_carver::carve_from_file` + `winevt_writer::records_to_evtx`,
//! then pass the reconstructed path here.

use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;


// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum AnalyzeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("EVTX parse error: {0}")]
    Parse(String),
}

// ── Public types ──────────────────────────────────────────────────────────────

/// A single timeline entry: one event extracted from an EVTX file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelineEntry {
    /// Record sequence number from the EVTX chunk header.
    pub record_id: u64,
    /// ISO-8601 UTC timestamp, e.g. `"2017-12-08T12:34:56.000000Z"`.
    pub timestamp: String,
    /// Windows Event ID (the numeric code in `<System><EventID>`).
    pub event_id: u32,
    /// Severity level (0 = LogAlways, 1 = Critical, 2 = Error, 3 = Warning,
    /// 4 = Information, 5 = Verbose). `None` when the field cannot be parsed.
    pub level: Option<u8>,
    /// Log channel name, e.g. `"Security"`.
    pub channel: Option<String>,
    /// Hostname that generated the event.
    pub computer: Option<String>,
    /// ETW provider GUID or friendly name.
    pub provider: Option<String>,
}

/// A reconstructed Windows logon session, assembled from EID 4624 (logon)
/// and EID 4634/4647 (logoff) events.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LogonSession {
    /// Target logon ID (LUID) as a hex string, e.g. `"0x3e7"`.
    pub logon_id: String,
    /// Target username.
    pub username: String,
    /// Target domain.
    pub domain: String,
    /// Logon type (2=Interactive, 3=Network, 10=RemoteInteractive, …).
    pub logon_type: u32,
    /// Source IP address, if present (network logons).
    pub ip_address: Option<String>,
    /// Logon timestamp (ISO-8601).
    pub logon_time: Option<String>,
    /// Logoff timestamp (ISO-8601). `None` if session was still open at log end.
    pub logoff_time: Option<String>,
    /// Session duration in seconds, if both logon and logoff are known.
    pub duration_secs: Option<i64>,
}

/// A reassembled PowerShell script block, reconstructed from one or more
/// EID 4104 (Script Block Logging) events sharing a `ScriptBlockId`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScriptBlock {
    /// GUID that groups all parts of this script block, e.g.
    /// `"12345678-abcd-ef01-2345-6789abcdef01"`.
    pub script_block_id: String,
    /// Fully reassembled script text (parts joined in MessageNumber order).
    pub text: String,
    /// `<Path>` field from the event, when a script file path is logged.
    pub path: Option<String>,
    /// Number of EID 4104 fragments consumed to assemble this block.
    pub parts: u32,
}

/// Event ID frequency entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EventFrequency {
    /// Windows Event ID.
    pub event_id: u32,
    /// How many times this event ID appeared.
    pub count: usize,
}

/// Frequency distribution of events in an EVTX file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FrequencyReport {
    /// Total number of events parsed.
    pub total_events: usize,
    /// Per-event-ID counts, sorted by count descending.
    pub by_event_id: Vec<EventFrequency>,
}

// ── Helper: extract EventID from evtx JSON value ──────────────────────────────

/// Extract the integer EventID from the `Event.System.EventID` field.
///
/// The `evtx` crate may represent this as:
/// - `4624` (bare integer)
/// - `{"#text": 4624, "#attributes": {"Qualifiers": 0}}` (with Qualifiers)
fn event_id_from_system(system: &serde_json::Value) -> Option<u32> {
    let raw = system.get("EventID")?;
    if let Some(n) = raw.as_u64() {
        return Some(n as u32);
    }
    // Object form: { "#text": N, ... }
    raw.get("#text").and_then(serde_json::Value::as_u64).map(|n| n as u32)
}

/// Extract a string field from `EventData` by name.
fn event_data_str<'a>(event_data: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    event_data.get("Data")?.as_array()?.iter().find_map(|item| {
        if item.get("@Name")?.as_str()? == key {
            item.get("#text").and_then(|v| v.as_str())
        } else {
            None
        }
    })
}

// ── Public functions ──────────────────────────────────────────────────────────

/// Parse an EVTX file and return all events sorted by timestamp.
///
/// Records with unparseable timestamps are included with an empty string
/// timestamp and sorted to the end.
pub fn timeline(path: &Path) -> Result<Vec<TimelineEntry>, AnalyzeError> {
    // Verify path is readable before handing to the evtx crate (gives a
    // friendlier error via our AnalyzeError::Io variant).
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;

    let mut parser = evtx::EvtxParser::from_path(path)
        .map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut entries: Vec<TimelineEntry> = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue, // skip unparseable records
        };
        let system = record
            .data
            .get("Event")
            .and_then(|e| e.get("System"));

        let event_id = system
            .and_then(event_id_from_system)
            .unwrap_or(0);

        let level = system
            .and_then(|s| s.get("Level"))
            .and_then(serde_json::Value::as_u64)
            .map(|n| n as u8);

        let channel = system
            .and_then(|s| s.get("Channel"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);

        let computer = system
            .and_then(|s| s.get("Computer"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);

        let provider = system
            .and_then(|s| s.get("Provider"))
            .and_then(|p| {
                // Provider can be {"@Name": "...", "@Guid": "..."}
                p.get("@Name").or_else(|| p.get("@Guid"))
            })
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);

        entries.push(TimelineEntry {
            record_id: record.event_record_id,
            timestamp: record.timestamp.to_string(),
            event_id,
            level,
            channel,
            computer,
            provider,
        });
    }

    // Sort by timestamp string (ISO-8601 sorts lexicographically)
    entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(entries)
}

/// Reconstruct logon sessions from EID 4624 / 4634 / 4647 events.
///
/// Sessions are keyed on the `TargetLogonId` LUID field.  Logoff events
/// (EID 4634 and 4647) are matched to the most recent logon with the
/// same `TargetLogonId`.  Sessions with no matching logoff have
/// `logoff_time = None`.
pub fn sessions(path: &Path) -> Result<Vec<LogonSession>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;

    let mut parser = evtx::EvtxParser::from_path(path)
        .map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    // logon_id → LogonSession (open sessions)
    let mut open: HashMap<String, LogonSession> = HashMap::new();
    // Completed sessions (logoff matched)
    let mut closed: Vec<LogonSession> = Vec::new();
    // Preserve insertion order for open sessions
    let mut insertion_order: Vec<String> = Vec::new();

    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let event = &record.data;
        let system = match event.get("Event").and_then(|e| e.get("System")) {
            Some(s) => s,
            None => continue,
        };
        let event_id = match event_id_from_system(system) {
            Some(id) => id,
            None => continue,
        };
        let ts = record.timestamp.to_string();
        let event_data = event.get("Event").and_then(|e| e.get("EventData"));

        match event_id {
            // EID 4624 — An account was successfully logged on
            4624 => {
                let ed = match event_data {
                    Some(d) => d,
                    None => continue,
                };
                let logon_id = event_data_str(ed, "TargetLogonId")
                    .unwrap_or("-")
                    .to_owned();
                let username = event_data_str(ed, "TargetUserName")
                    .unwrap_or("-")
                    .to_owned();
                let domain = event_data_str(ed, "TargetDomainName")
                    .unwrap_or("-")
                    .to_owned();
                let logon_type = event_data_str(ed, "LogonType")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let ip_raw = event_data_str(ed, "IpAddress").map(str::to_owned);
                let ip_address = ip_raw.filter(|ip| ip != "-" && !ip.is_empty());

                let session = LogonSession {
                    logon_id: logon_id.clone(),
                    username,
                    domain,
                    logon_type,
                    ip_address,
                    logon_time: Some(ts),
                    logoff_time: None,
                    duration_secs: None,
                };
                if !open.contains_key(&logon_id) {
                    insertion_order.push(logon_id.clone());
                }
                open.insert(logon_id, session);
            }
            // EID 4634 — An account was logged off
            // EID 4647 — User initiated logoff
            4634 | 4647 => {
                let ed = match event_data {
                    Some(d) => d,
                    None => continue,
                };
                let logon_id = match event_data_str(ed, "TargetLogonId") {
                    Some(id) => id.to_owned(),
                    None => continue,
                };
                if let Some(mut session) = open.remove(&logon_id) {
                    session.logoff_time = Some(ts.clone());
                    // Compute duration using jiff::Timestamp arithmetic
                    if let (Some(logon), Some(logoff)) =
                        (session.logon_time.as_deref(), session.logoff_time.as_deref())
                    {
                        if let (Ok(t0), Ok(t1)) = (
                            logon.parse::<jiff::Timestamp>(),
                            logoff.parse::<jiff::Timestamp>(),
                        ) {
                            let d = t1.duration_since(t0).as_secs();
                            session.duration_secs = Some(d);
                        }
                    }
                    closed.push(session);
                    insertion_order.retain(|id| id != &logon_id);
                }
            }
            _ => {}
        }
    }

    // Append still-open sessions in insertion order
    let mut result = closed;
    for id in &insertion_order {
        if let Some(s) = open.remove(id) {
            result.push(s);
        }
    }
    Ok(result)
}

/// Reassemble PowerShell script blocks from EID 4104 events.
///
/// Groups events by `ScriptBlockId`, sorts fragments by `MessageNumber`,
/// and concatenates `ScriptBlockText` values.  Returns one `ScriptBlock`
/// per unique GUID, in the order the first fragment was observed.
pub fn powershell_blocks(path: &Path) -> Result<Vec<ScriptBlock>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;

    let mut parser = evtx::EvtxParser::from_path(path)
        .map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    // script_block_id → (path, Vec<(message_number, text)>)
    let mut blocks: HashMap<String, (Option<String>, Vec<(u32, String)>)> = HashMap::new();
    let mut insertion_order: Vec<String> = Vec::new();

    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let event = &record.data;
        let system = match event.get("Event").and_then(|e| e.get("System")) {
            Some(s) => s,
            None => continue,
        };
        if event_id_from_system(system) != Some(4104) {
            continue;
        }
        let event_data = match event.get("Event").and_then(|e| e.get("EventData")) {
            Some(d) => d,
            None => continue,
        };

        let script_id = match event_data_str(event_data, "ScriptBlockId") {
            Some(id) => id.to_owned(),
            None => continue,
        };
        let text = event_data_str(event_data, "ScriptBlockText")
            .unwrap_or("")
            .to_owned();
        let msg_num: u32 = event_data_str(event_data, "MessageNumber")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let script_path = event_data_str(event_data, "Path")
            .filter(|p| !p.is_empty())
            .map(str::to_owned);

        let entry = blocks.entry(script_id.clone()).or_insert_with(|| {
            insertion_order.push(script_id.clone());
            (script_path, Vec::new())
        });
        entry.1.push((msg_num, text));
    }

    let mut result = Vec::with_capacity(blocks.len());
    for id in insertion_order {
        if let Some((path_val, mut parts)) = blocks.remove(&id) {
            parts.sort_by_key(|(n, _)| *n);
            let count = parts.len() as u32;
            let text = parts.into_iter().map(|(_, t)| t).collect::<Vec<_>>().join("");
            result.push(ScriptBlock {
                script_block_id: id,
                text,
                path: path_val,
                parts: count,
            });
        }
    }
    Ok(result)
}

/// Compute a frequency distribution of event IDs.
///
/// Useful for spotting bursts of a single event ID that may indicate
/// brute-force attacks, log flooding, or other anomalies.
pub fn frequency(path: &Path) -> Result<FrequencyReport, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;

    let mut parser = evtx::EvtxParser::from_path(path)
        .map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut counts: HashMap<u32, usize> = HashMap::new();
    let mut total = 0usize;

    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        total += 1;
        let event_id = record
            .data
            .get("Event")
            .and_then(|e| e.get("System"))
            .and_then(event_id_from_system)
            .unwrap_or(0);
        *counts.entry(event_id).or_insert(0) += 1;
    }

    let mut by_event_id: Vec<EventFrequency> = counts
        .into_iter()
        .map(|(event_id, count)| EventFrequency { event_id, count })
        .collect();
    by_event_id.sort_by(|a, b| b.count.cmp(&a.count).then(a.event_id.cmp(&b.event_id)));

    Ok(FrequencyReport { total_events: total, by_event_id })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Error paths ───────────────────────────────────────────────────────────

    #[test]
    fn timeline_nonexistent_path_returns_error() {
        let result = timeline(Path::new("/nonexistent/security.evtx"));
        assert!(result.is_err(), "expected error for nonexistent path");
    }

    #[test]
    fn sessions_nonexistent_path_returns_error() {
        let result = sessions(Path::new("/nonexistent/security.evtx"));
        assert!(result.is_err(), "expected error for nonexistent path");
    }

    #[test]
    fn powershell_blocks_nonexistent_path_returns_error() {
        let result = powershell_blocks(Path::new("/nonexistent/powershell.evtx"));
        assert!(result.is_err(), "expected error for nonexistent path");
    }

    #[test]
    fn frequency_nonexistent_path_returns_error() {
        let result = frequency(Path::new("/nonexistent/security.evtx"));
        assert!(result.is_err(), "expected error for nonexistent path");
    }

    // ── Type shape tests ──────────────────────────────────────────────────────

    #[test]
    fn timeline_entry_fields_are_accessible() {
        let e = TimelineEntry {
            record_id: 42,
            timestamp: "2017-12-08T12:00:00.000000Z".to_string(),
            event_id: 4624,
            level: Some(0),
            channel: Some("Security".to_string()),
            computer: Some("WORKSTATION".to_string()),
            provider: Some("Microsoft-Windows-Security-Auditing".to_string()),
        };
        assert_eq!(e.record_id, 42);
        assert_eq!(e.event_id, 4624);
        assert_eq!(e.level, Some(0));
    }

    #[test]
    fn logon_session_fields_are_accessible() {
        let s = LogonSession {
            logon_id: "0x3e7".to_string(),
            username: "SYSTEM".to_string(),
            domain: "NT AUTHORITY".to_string(),
            logon_type: 0,
            ip_address: None,
            logon_time: None,
            logoff_time: None,
            duration_secs: None,
        };
        assert_eq!(s.logon_id, "0x3e7");
        assert_eq!(s.logon_type, 0);
        assert!(s.ip_address.is_none());
        assert!(s.duration_secs.is_none());
    }

    #[test]
    fn script_block_fields_are_accessible() {
        let b = ScriptBlock {
            script_block_id: "00000000-0000-0000-0000-000000000000".to_string(),
            text: "Write-Host 'hello'".to_string(),
            path: None,
            parts: 1,
        };
        assert_eq!(b.parts, 1);
        assert!(b.path.is_none());
    }

    #[test]
    fn frequency_report_fields_are_accessible() {
        let r = FrequencyReport {
            total_events: 100,
            by_event_id: vec![EventFrequency { event_id: 4624, count: 50 }],
        };
        assert_eq!(r.total_events, 100);
        assert_eq!(r.by_event_id[0].event_id, 4624);
        assert_eq!(r.by_event_id[0].count, 50);
    }

    // ── Serde ─────────────────────────────────────────────────────────────────

    #[test]
    fn timeline_entry_serializes_to_json() {
        let e = TimelineEntry {
            record_id: 1,
            timestamp: "2017-12-08T12:00:00.000000Z".to_string(),
            event_id: 4624,
            level: Some(0),
            channel: Some("Security".to_string()),
            computer: None,
            provider: None,
        };
        let json = serde_json::to_string(&e).expect("serialize TimelineEntry");
        assert!(json.contains("4624"));
        assert!(json.contains("Security"));
    }

    #[test]
    fn logon_session_serializes_to_json() {
        let s = LogonSession {
            logon_id: "0x3e7".to_string(),
            username: "Administrator".to_string(),
            domain: "WORKGROUP".to_string(),
            logon_type: 3,
            ip_address: Some("192.168.1.1".to_string()),
            logon_time: Some("2017-12-08T12:00:00Z".to_string()),
            logoff_time: None,
            duration_secs: None,
        };
        let json = serde_json::to_string(&s).expect("serialize LogonSession");
        assert!(json.contains("0x3e7"));
        assert!(json.contains("192.168.1.1"));
    }

    // ── Fox-it integration (skip when absent) ─────────────────────────────────

    fn foxitdata_path(filename: &str) -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop(); // crates/
        p.pop(); // workspace root
        p.join("tests/data/fox-it-danderspritz").join(filename)
    }

    macro_rules! require_foxitdata {
        ($filename:expr) => {{
            let p = foxitdata_path($filename);
            if !p.exists() {
                eprintln!(
                    "SKIP: {} not found — run download instructions",
                    p.display()
                );
                return;
            }
            p
        }};
    }

    #[test]
    fn pre_security_timeline_returns_entries() {
        let path = require_foxitdata!("pre-Security.evtx");
        let entries = timeline(&path).expect("timeline on pre-Security.evtx");
        assert!(!entries.is_empty(), "expected some timeline entries");
    }

    #[test]
    fn pre_security_timeline_sorted_by_timestamp() {
        let path = require_foxitdata!("pre-Security.evtx");
        let entries = timeline(&path).expect("timeline on pre-Security.evtx");
        for i in 1..entries.len() {
            assert!(
                entries[i].timestamp >= entries[i - 1].timestamp,
                "timeline not sorted at index {i}: {} < {}",
                entries[i].timestamp,
                entries[i - 1].timestamp
            );
        }
    }

    #[test]
    fn pre_security_timeline_has_event_ids() {
        let path = require_foxitdata!("pre-Security.evtx");
        let entries = timeline(&path).expect("timeline on pre-Security.evtx");
        assert!(
            entries.iter().any(|e| e.event_id > 0),
            "expected non-zero event IDs in timeline"
        );
    }

    #[test]
    fn pre_security_frequency_total_matches_timeline_count() {
        let path = require_foxitdata!("pre-Security.evtx");
        let entries = timeline(&path).expect("timeline");
        let report = frequency(&path).expect("frequency");
        assert_eq!(
            report.total_events,
            entries.len(),
            "frequency total_events should equal timeline entry count"
        );
    }

    #[test]
    fn pre_security_sessions_returns_sessions() {
        let path = require_foxitdata!("pre-Security.evtx");
        let result = sessions(&path).expect("sessions on pre-Security.evtx");
        // Security.evtx should have at least one logon session
        assert!(!result.is_empty(), "expected at least one logon session");
    }

    #[test]
    fn pre_security_sessions_have_logon_ids() {
        let path = require_foxitdata!("pre-Security.evtx");
        let result = sessions(&path).expect("sessions on pre-Security.evtx");
        for s in &result {
            assert!(!s.logon_id.is_empty(), "logon_id should not be empty");
        }
    }
}
