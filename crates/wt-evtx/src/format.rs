//! Output formatting for wt-evtx subcommands.

use chrono::{TimeZone, Utc};
use winevt_core::{EvtxEvent, LogonSession, ProcessEvent, logon_type_name};

/// Convert nanoseconds-since-Unix-epoch to a UTC RFC 3339 string.
pub fn format_timestamp_ns(ns: i64) -> String {
    let secs = ns / 1_000_000_000;
    let nanos = u32::try_from(ns % 1_000_000_000).unwrap_or(0);
    Utc.timestamp_opt(secs, nanos)
        .single()
        .map_or_else(|| "invalid".into(), |dt| dt.to_rfc3339())
}

// ── Timeline formatting ───────────────────────────────────────────────────────

/// CSV header for timeline output.
pub const TIMELINE_CSV_HEADER: &str = "timestamp,event_id,channel,computer,description";

/// Format a single event as a CSV row.
pub fn event_to_csv_row(ev: &EvtxEvent) -> String {
    let ts = format_timestamp_ns(ev.timestamp_ns);
    let desc = build_description(ev);
    format!(
        "{},{},{},{},{}",
        ts,
        ev.event_id,
        csv_escape(&ev.channel),
        csv_escape(&ev.computer),
        csv_escape(&desc),
    )
}

/// Format a single event as a compact JSONL object.
pub fn event_to_jsonl(ev: &EvtxEvent) -> String {
    let ts = format_timestamp_ns(ev.timestamp_ns);
    let desc = build_description(ev);
    let obj = serde_json::json!({
        "timestamp": ts,
        "event_id": ev.event_id,
        "channel": ev.channel,
        "computer": ev.computer,
        "description": desc,
    });
    obj.to_string()
}

/// Format a single event as a human-readable text line.
pub fn event_to_text(ev: &EvtxEvent) -> String {
    let ts = format_timestamp_ns(ev.timestamp_ns);
    let desc = build_description(ev);
    format!(
        "[{}] EID:{} {} ({}) \u{2014} {}",
        ts, ev.event_id, ev.channel, ev.computer, desc
    )
}

/// Build a short human-readable description for an event.
fn build_description(ev: &EvtxEvent) -> String {
    match ev.event_id {
        4624 => {
            let user = ev.data.get("TargetUserName").map_or("-", String::as_str);
            let domain = ev.data.get("TargetDomainName").map_or("-", String::as_str);
            let lt = ev
                .data
                .get("LogonType")
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0);
            format!("Logon: {}\\{} ({})", domain, user, logon_type_name(lt))
        }
        4625 => {
            let user = ev.data.get("TargetUserName").map_or("-", String::as_str);
            format!("Failed logon: {user}")
        }
        4634 | 4647 => {
            let user = ev.data.get("TargetUserName").map_or("-", String::as_str);
            format!("Logoff: {user}")
        }
        4688 => {
            let process = ev.data.get("NewProcessName").map_or("-", String::as_str);
            format!("Process created: {process}")
        }
        7045 => {
            let svc = ev.data.get("ServiceName").map_or("-", String::as_str);
            format!("Service installed: {svc}")
        }
        4720 => {
            let user = ev.data.get("SamAccountName").map_or("-", String::as_str);
            format!("Account created: {user}")
        }
        4732 => {
            let group = ev.data.get("GroupName").map_or("-", String::as_str);
            format!("Member added to group: {group}")
        }
        1102 => "Audit log cleared".to_string(),
        _ => format!("EID {}", ev.event_id),
    }
}

/// Escape a string for CSV (quotes if it contains comma, quote, or newline).
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ── Session formatting ────────────────────────────────────────────────────────

pub const SESSIONS_CSV_HEADER: &str =
    "logon_id,logon_type,username,domain,src_ip,logon_time,duration_secs,orphaned";

pub fn session_to_csv_row(s: &LogonSession) -> String {
    let logon_time = format_timestamp_ns(s.logon_time_ns);
    let duration = s.duration_secs.map_or_else(String::new, |d| d.to_string());
    let ip = s.src_ip.as_deref().unwrap_or("-");
    format!(
        "0x{:x},{},{},{},{},{},{},{}",
        s.logon_id,
        logon_type_name(s.logon_type),
        csv_escape(&s.username),
        csv_escape(&s.domain),
        csv_escape(ip),
        logon_time,
        duration,
        s.is_orphaned,
    )
}

pub fn session_to_text(s: &LogonSession) -> String {
    let logon_time = format_timestamp_ns(s.logon_time_ns);
    let ip = s.src_ip.as_deref().unwrap_or("-");
    let dur = s
        .duration_secs
        .map_or_else(|| "open".into(), |d| format!("{d}s"));
    format!(
        "LogonID=0x{:x} | {}\\{} | {} | {} | src={} | {} | orphaned={}",
        s.logon_id,
        s.domain,
        s.username,
        logon_type_name(s.logon_type),
        logon_time,
        ip,
        dur,
        s.is_orphaned,
    )
}

// ── Process formatting ────────────────────────────────────────────────────────

pub const PROCESSES_CSV_HEADER: &str =
    "timestamp,pid,parent_pid,image,command_line,logon_id,user";

pub fn process_to_csv_row(p: &ProcessEvent) -> String {
    let ts = format_timestamp_ns(p.timestamp_ns);
    let parent = p.parent_pid.map_or_else(String::new, |n| n.to_string());
    let cmd = p.command_line.as_deref().unwrap_or("");
    let lid = p.logon_id.map_or_else(String::new, |n| format!("0x{n:x}"));
    let user = p.user.as_deref().unwrap_or("");
    format!(
        "{},{},{},{},{},{},{}",
        ts,
        p.process_id,
        parent,
        csv_escape(&p.image_path),
        csv_escape(cmd),
        lid,
        csv_escape(user),
    )
}

pub fn process_to_text(p: &ProcessEvent) -> String {
    let ts = format_timestamp_ns(p.timestamp_ns);
    let cmd = p.command_line.as_deref().unwrap_or("<no cmdline>");
    format!(
        "[{}] PID={} {} | {}",
        ts, p.process_id, p.image_path, cmd
    )
}

// ── Frequency formatting ──────────────────────────────────────────────────────

pub const FREQUENCY_CSV_HEADER: &str = "count,key";

pub fn anomaly_to_csv_row(count: usize, key: &str) -> String {
    format!("{},{}", count, csv_escape(key))
}

pub fn anomaly_to_text(count: usize, key: &str) -> String {
    format!("count={count:>5}  {key}")
}
