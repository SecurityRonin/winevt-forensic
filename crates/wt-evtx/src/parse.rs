//! EVTX file parsing: walk a directory for *.evtx files and convert records
//! to `winevt_core::EvtxEvent`.

use anyhow::{Context, Result};
use evtx::{EvtxParser, ParserSettings};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use winevt_core::EvtxEvent;

/// Walk `directory` recursively and collect every `*.evtx` file path.
pub fn collect_evtx_paths(directory: &Path) -> Result<Vec<PathBuf>> {
    if !directory.exists() {
        anyhow::bail!("directory does not exist: {}", directory.display());
    }
    if !directory.is_dir() {
        anyhow::bail!("path is not a directory: {}", directory.display());
    }

    let paths: Vec<PathBuf> = WalkDir::new(directory)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
        })
        .map(|entry| entry.path().to_path_buf())
        .collect();

    Ok(paths)
}

/// Parse a single EVTX file into a `Vec<EvtxEvent>`.
/// Records that cannot be parsed are silently skipped (logged to stderr).
pub fn parse_evtx_file(path: &Path) -> Result<Vec<EvtxEvent>> {
    let settings = ParserSettings::default()
        .separate_json_attributes(true)
        .indent(false);

    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| anyhow::anyhow!("failed to open {}: {e}", path.display()))?
        .with_configuration(settings);

    let mut events: Vec<EvtxEvent> = Vec::new();

    for record in parser.records_json_value() {
        match record {
            Err(e) => {
                eprintln!("warn: skipping record in {}: {e}", path.display());
            }
            Ok(rec) => {
                if let Some(ev) = evtx_record_to_event(rec.timestamp, &rec.data) {
                    events.push(ev);
                }
            }
        }
    }

    Ok(events)
}

/// Parse all EVTX files in `directory` into a flat, timestamp-sorted `Vec<EvtxEvent>`.
pub fn parse_directory(directory: &Path) -> Result<Vec<EvtxEvent>> {
    let paths = collect_evtx_paths(directory)?;

    let mut all_events: Vec<EvtxEvent> = Vec::new();
    for path in paths {
        let events = parse_evtx_file(&path)
            .with_context(|| format!("parsing {}", path.display()))?;
        all_events.extend(events);
    }

    all_events.sort_by_key(|e| e.timestamp_ns);
    Ok(all_events)
}

/// Convert a `serde_json::Value` (the deserialized EVTX record body) to an `EvtxEvent`.
///
/// Returns `None` if the record cannot be interpreted as an event.
#[allow(clippy::too_many_lines)]
fn evtx_record_to_event(
    timestamp: chrono::DateTime<chrono::Utc>,
    value: &Value,
) -> Option<EvtxEvent> {
    let event = value.get("Event")?;
    let system = event.get("System")?;

    // EventID — may be a plain number or {"#text": N, "#attributes": {...}}
    let event_id: u32 = {
        let raw = system.get("EventID")?;
        if let Some(n) = raw.as_u64() {
            u32::try_from(n).ok()?
        } else if let Some(text) = raw.get("#text").and_then(Value::as_u64) {
            u32::try_from(text).ok()?
        } else if let Some(s) = raw.as_str() {
            s.parse().ok()?
        } else {
            return None;
        }
    };

    let channel = system
        .get("Channel")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let computer = system
        .get("Computer")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // timestamp_ns from the record header (already parsed by evtx crate)
    let timestamp_ns = timestamp.timestamp_nanos_opt().unwrap_or(0);

    // user_sid from System.Security.UserID
    let user_sid = system
        .get("Security")
        .and_then(|s| s.get("UserID"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from);

    // process_id and thread_id from System.Execution
    let process_id = system
        .get("Execution")
        .and_then(|e| e.get("ProcessID"))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());

    let thread_id = system
        .get("Execution")
        .and_then(|e| e.get("ThreadID"))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());

    // EventData key-value pairs
    let mut data: HashMap<String, String> = HashMap::new();
    let mut logon_id: Option<u64> = None;

    if let Some(event_data) = event.get("EventData") {
        collect_kv(event_data, &mut data);
    }
    if let Some(user_data) = event.get("UserData") {
        collect_kv(user_data, &mut data);
    }

    // Try to extract LogonID from common fields
    for key in &["TargetLogonId", "SubjectLogonId", "LogonId"] {
        if let Some(val) = data.get(*key) {
            logon_id = parse_logon_id(val);
            if logon_id.is_some() {
                break;
            }
        }
    }

    Some(EvtxEvent {
        event_id,
        channel,
        timestamp_ns,
        computer,
        user_sid,
        logon_id,
        process_id,
        thread_id,
        data,
    })
}

/// Flatten a JSON object (or array of {Name,#text} pairs) into key-value strings.
fn collect_kv(value: &Value, out: &mut HashMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if k.starts_with('#') {
                    // skip metadata keys like #attributes
                    continue;
                }
                let str_val = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => String::new(),
                    Value::Object(_) | Value::Array(_) => {
                        // recurse one level for nested objects
                        collect_kv(v, out);
                        continue;
                    }
                };
                out.insert(k.clone(), str_val);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_kv(item, out);
            }
        }
        _ => {}
    }
}

/// Parse a logon ID string like `"0x00000000000f6d8b"` or `"1010059"` to u64.
fn parse_logon_id(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() || s == "-" || s == "0x0000000000000000" {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}
