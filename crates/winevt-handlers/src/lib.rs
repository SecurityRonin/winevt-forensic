//! Event handler modules for Windows Event Log forensic analysis.
//!
//! Each handler knows which event IDs it handles, can produce a human-readable
//! summary, and can extract structured key-value fields from an event.

use winevt_core::EvtxEvent;

/// Trait implemented by all event handlers.
pub trait EventHandler: Send + Sync {
    /// Returns true if this handler should process this event.
    fn handles(&self, event_id: u32, channel: &str) -> bool;

    /// Extract a human-readable summary from the event.
    fn summarize(&self, event: &EvtxEvent) -> Option<String>;

    /// Extract structured fields relevant to this handler.
    fn extract_fields(&self, event: &EvtxEvent) -> Vec<(String, String)>;
}

// --- Handler structs (stubs) ---

pub struct LogonHandler;
pub struct ProcessHandler;
pub struct ServiceHandler;
pub struct SchedTaskHandler;
pub struct PowershellHandler;
pub struct RdpClientHandler;
pub struct RdpServerHandler;
pub struct WlanHandler;
pub struct LogClearedHandler;
pub struct BitsHandler;
pub struct AuditChangeHandler;
pub struct DefenderHandler;

// All trait impls are todo!() for the RED phase.

impl EventHandler for LogonHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

impl EventHandler for ProcessHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

impl EventHandler for ServiceHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

impl EventHandler for SchedTaskHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

impl EventHandler for PowershellHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

impl EventHandler for RdpClientHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

impl EventHandler for RdpServerHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

impl EventHandler for WlanHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

impl EventHandler for LogClearedHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

impl EventHandler for BitsHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

impl EventHandler for AuditChangeHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

impl EventHandler for DefenderHandler {
    fn handles(&self, _event_id: u32, _channel: &str) -> bool {
        todo!()
    }
    fn summarize(&self, _event: &EvtxEvent) -> Option<String> {
        todo!()
    }
    fn extract_fields(&self, _event: &EvtxEvent) -> Vec<(String, String)> {
        todo!()
    }
}

/// Return all built-in handlers.
pub fn all_handlers() -> Vec<Box<dyn EventHandler>> {
    vec![
        Box::new(LogonHandler),
        Box::new(ProcessHandler),
        Box::new(ServiceHandler),
        Box::new(SchedTaskHandler),
        Box::new(PowershellHandler),
        Box::new(RdpClientHandler),
        Box::new(RdpServerHandler),
        Box::new(WlanHandler),
        Box::new(LogClearedHandler),
        Box::new(BitsHandler),
        Box::new(AuditChangeHandler),
        Box::new(DefenderHandler),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_event(event_id: u32, channel: &str) -> EvtxEvent {
        EvtxEvent {
            event_id,
            channel: channel.into(),
            timestamp_ns: 1_700_000_000_000_000_000,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data: HashMap::new(),
        }
    }

    fn make_logon_event() -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("TargetUserName".into(), "admin".into());
        data.insert("TargetDomainName".into(), "CORP".into());
        data.insert("LogonType".into(), "2".into());
        data.insert("IpAddress".into(), "10.0.0.1".into());
        EvtxEvent {
            event_id: 4624,
            channel: "Security".into(),
            timestamp_ns: 1_700_000_000_000_000_000,
            computer: "DC01".into(),
            user_sid: None,
            logon_id: Some(0x12345),
            process_id: None,
            thread_id: None,
            data,
        }
    }

    #[test]
    fn logon_handler_handles_4624() {
        let h = LogonHandler;
        assert!(h.handles(4624, "Security"));
        assert!(h.handles(4625, "Security"));
        assert!(h.handles(4634, "Security"));
        assert!(h.handles(4648, "Security"));
        assert!(h.handles(4647, "Security"));
        assert!(!h.handles(7045, "System"));
    }

    #[test]
    fn logon_handler_summarizes_interactive_logon() {
        let h = LogonHandler;
        let ev = make_logon_event();
        let summary = h.summarize(&ev).expect("should produce summary");
        assert!(summary.contains("admin"), "summary should mention user");
        assert!(summary.contains("CORP"), "summary should mention domain");
    }

    #[test]
    fn process_handler_handles_4688() {
        let h = ProcessHandler;
        assert!(h.handles(4688, "Security"));
        assert!(h.handles(4689, "Security"));
        assert!(!h.handles(4624, "Security"));
    }

    #[test]
    fn service_handler_handles_7045() {
        let h = ServiceHandler;
        assert!(h.handles(7045, "System"));
        assert!(h.handles(7034, "System"));
        assert!(h.handles(7036, "System"));
        assert!(!h.handles(4624, "Security"));
    }

    #[test]
    fn sched_task_handler_handles_4698() {
        let h = SchedTaskHandler;
        assert!(h.handles(4698, "Security"));
        assert!(h.handles(4702, "Security"));
        assert!(!h.handles(7045, "System"));
    }

    #[test]
    fn powershell_handler_handles_4104() {
        let h = PowershellHandler;
        assert!(h.handles(4104, "Microsoft-Windows-PowerShell/Operational"));
        assert!(h.handles(4103, "Microsoft-Windows-PowerShell/Operational"));
        assert!(h.handles(400, "Windows PowerShell"));
        assert!(h.handles(600, "Windows PowerShell"));
    }

    #[test]
    fn rdp_client_handler_handles_1024() {
        let h = RdpClientHandler;
        assert!(h.handles(1024, "Microsoft-Windows-TerminalServices-RDPClient/Operational"));
        assert!(h.handles(1102, "Microsoft-Windows-TerminalServices-RDPClient/Operational"));
    }

    #[test]
    fn rdp_server_handler_handles_4778() {
        let h = RdpServerHandler;
        assert!(h.handles(4778, "Security"));
        assert!(h.handles(4779, "Security"));
        assert!(!h.handles(4624, "Security"));
    }

    #[test]
    fn wlan_handler_handles_11000() {
        let h = WlanHandler;
        assert!(h.handles(11000, "Microsoft-Windows-WLAN-AutoConfig/Operational"));
        assert!(h.handles(11001, "Microsoft-Windows-WLAN-AutoConfig/Operational"));
        assert!(h.handles(11010, "Microsoft-Windows-WLAN-AutoConfig/Operational"));
    }

    #[test]
    fn log_cleared_handler_handles_1102() {
        let h = LogClearedHandler;
        assert!(h.handles(1102, "Security"));
        assert!(h.handles(104, "System"));
        assert!(!h.handles(4624, "Security"));
    }

    #[test]
    fn bits_handler_handles_59() {
        let h = BitsHandler;
        assert!(h.handles(59, "Microsoft-Windows-Bits-Client/Operational"));
        assert!(h.handles(60, "Microsoft-Windows-Bits-Client/Operational"));
        assert!(h.handles(61, "Microsoft-Windows-Bits-Client/Operational"));
    }

    #[test]
    fn audit_change_handler_handles_4719() {
        let h = AuditChangeHandler;
        assert!(h.handles(4719, "Security"));
        assert!(!h.handles(4624, "Security"));
    }
}
