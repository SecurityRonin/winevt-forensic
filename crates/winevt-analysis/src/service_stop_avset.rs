//! Detect ransomware service-stop cluster targeting AV/backup services (T1489).

use forensicnomicon::heuristics::{
    evtx::{EID_PROCESS_CREATE, EID_SYSMON_PROCESS_CREATE, SYSMON_CHANNEL},
    ransomware::{
        RANSOMWARE_KILL_WINDOW_NS, RANSOMWARE_SERVICE_STOP_CLUSTER_THRESHOLD,
        RANSOMWARE_STOP_SERVICES,
    },
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect a cluster of `net stop <svc>` or `sc.exe stop <svc>` executions
/// where ≥3 targets are in the canonical AV/backup service list within 60s.
///
/// Single service stops have medium FP risk.  A cluster of ≥3 canonical
/// services stopped within `RANSOMWARE_KILL_WINDOW_NS` is near-zero-FP
/// (T1489 — Service Stop; T1562.001 — Impair Defenses).
pub fn detect_service_stop_avset(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!()
}

fn is_process_event(ev: &EvtxEvent) -> bool {
    (ev.event_id == EID_PROCESS_CREATE && ev.channel == "Security")
        || (ev.event_id == EID_SYSMON_PROCESS_CREATE && ev.channel == SYSMON_CHANNEL)
}

fn basename(path: &str) -> &str {
    path.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(path)
}

fn stopped_canonical_service<'a>(ev: &EvtxEvent) -> Option<&'a str> {
    let img = ev
        .data
        .get("Image")
        .or_else(|| ev.data.get("NewProcessName"))
        .map(String::as_str)
        .unwrap_or("");
    let base = basename(img).to_lowercase();
    if base != "net.exe" && base != "net1.exe" && base != "sc.exe" {
        return None;
    }
    let cl = ev.data.get("CommandLine").map(String::as_str).unwrap_or("");
    let cl_lower = cl.to_lowercase();
    if !cl_lower.contains("stop") {
        return None;
    }
    RANSOMWARE_STOP_SERVICES
        .iter()
        .find(|&&svc| cl_lower.contains(svc))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn stop_event(svc: &str, ts: i64) -> EvtxEvent {
        let mut ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\net.exe"),
                ("CommandLine", &format!("net stop {svc}")),
            ],
        );
        ev.timestamp_ns = ts;
        ev
    }

    const BASE_TS: i64 = 1_700_000_000_000_000_000;
    const SEC: i64 = 1_000_000_000;

    #[test]
    fn cluster_of_three_detected() {
        let svcs = ["veeambackupsvc", "gxvss", "sqlserveragent"];
        let events: Vec<_> = svcs
            .iter()
            .enumerate()
            .map(|(i, s)| stop_event(s, BASE_TS + (i as i64) * 5 * SEC))
            .collect();
        let hits = detect_service_stop_avset(&events);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::ServiceStopAvSet);
        assert_eq!(hits[0].mitre_technique_id, "T1489");
    }

    #[test]
    fn cluster_of_two_not_detected() {
        let svcs = ["veeambackupsvc", "gxvss"];
        let events: Vec<_> = svcs
            .iter()
            .enumerate()
            .map(|(i, s)| stop_event(s, BASE_TS + (i as i64) * SEC))
            .collect();
        assert!(detect_service_stop_avset(&events).is_empty());
    }

    #[test]
    fn three_stops_outside_window_not_detected() {
        let svcs = ["veeambackupsvc", "gxvss", "sqlserveragent"];
        // 25s apart → total span 50s — wait, threshold is 60s and 25*2=50s, so still in window
        // Use 35s apart → total span 70s > 60s window
        let events: Vec<_> = svcs
            .iter()
            .enumerate()
            .map(|(i, s)| stop_event(s, BASE_TS + (i as i64) * 35 * SEC))
            .collect();
        assert!(detect_service_stop_avset(&events).is_empty());
    }

    #[test]
    fn non_canonical_service_not_counted() {
        let svcs = ["myservice1", "myservice2", "myservice3"];
        let events: Vec<_> = svcs
            .iter()
            .enumerate()
            .map(|(i, s)| stop_event(s, BASE_TS + (i as i64) * SEC))
            .collect();
        assert!(detect_service_stop_avset(&events).is_empty());
    }

    #[test]
    fn sc_exe_stop_detected() {
        let mut events = Vec::new();
        for (i, svc) in ["veeambackupsvc", "gxvss", "mssqlserver"]
            .iter()
            .enumerate()
        {
            let mut ev = make_event(
                EID_SYSMON_PROCESS_CREATE,
                SYSMON_CHANNEL,
                &[
                    ("Image", "C:\\Windows\\System32\\sc.exe"),
                    ("CommandLine", &format!("sc.exe stop {svc}")),
                ],
            );
            ev.timestamp_ns = BASE_TS + (i as i64) * 5 * SEC;
            events.push(ev);
        }
        assert!(!detect_service_stop_avset(&events).is_empty());
    }

    #[test]
    fn evidence_contains_service_names() {
        let svcs = ["veeambackupsvc", "gxvss", "sqlserveragent"];
        let events: Vec<_> = svcs
            .iter()
            .enumerate()
            .map(|(i, s)| stop_event(s, BASE_TS + (i as i64) * SEC))
            .collect();
        let hits = detect_service_stop_avset(&events);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("veeam") || combined.contains("gxvss") || combined.contains("sql"));
    }
}
