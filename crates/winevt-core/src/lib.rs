//! Core types and lookup tables for Windows Event Log forensic analysis.

use std::collections::HashMap;

/// Core event type — parsed from EVTX.
#[derive(Debug, Clone)]
pub struct EvtxEvent {
    pub event_id: u32,
    pub channel: String,
    pub timestamp_ns: i64,
    pub computer: String,
    pub user_sid: Option<String>,
    pub logon_id: Option<u64>,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub data: HashMap<String, String>,
}

/// Session correlation output.
#[derive(Debug, Clone)]
pub struct LogonSession {
    pub logon_id: u64,
    pub logon_type: u8,
    pub username: String,
    pub domain: String,
    pub src_ip: Option<String>,
    pub logon_time_ns: i64,
    pub logoff_time_ns: Option<i64>,
    pub duration_secs: Option<u64>,
    pub processes: Vec<u32>,
    pub is_orphaned: bool,
}

/// Process creation event (from 4688).
#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub timestamp_ns: i64,
    pub process_id: u32,
    pub parent_pid: Option<u32>,
    pub image_path: String,
    pub command_line: Option<String>,
    pub logon_id: Option<u64>,
    pub user: Option<String>,
}

/// Service event (from 7045).
#[derive(Debug, Clone)]
pub struct ServiceEvent {
    pub timestamp_ns: i64,
    pub service_name: String,
    pub image_path: Option<String>,
    pub start_type: Option<String>,
    pub account: Option<String>,
}
