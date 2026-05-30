//! Detect ransomware AV/DB process-kill cluster (T1562.001 / T1489).

use forensicnomicon::heuristics::{
    evtx::{EID_PROCESS_CREATE, EID_SYSMON_PROCESS_CREATE, SYSMON_CHANNEL},
    ransomware::{
        RANSOMWARE_KILL_CLUSTER_THRESHOLD, RANSOMWARE_KILL_PROCESSES, RANSOMWARE_KILL_WINDOW_NS,
    },
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect a cluster of `taskkill /IM <process>` executions where ≥5 targets
/// are in the canonical AV/SQL/backup kill list within a 60-second window.
///
/// Single kills have medium FP risk; a cluster of ≥`RANSOMWARE_KILL_CLUSTER_THRESHOLD`
/// canonical targets within `RANSOMWARE_KILL_WINDOW_NS` is near-zero-FP for
/// ransomware staging (T1562.001 — Impair Defenses: Disable/Modify Tools,
/// T1489 — Service Stop).
pub fn detect_taskkill_av_cluster(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!()
}

fn is_process_event(ev: &EvtxEvent) -> bool {
    (ev.event_id == EID_PROCESS_CREATE && ev.channel == "Security")
        || (ev.event_id == EID_SYSMON_PROCESS_CREATE && ev.channel == SYSMON_CHANNEL)
}

fn basename(path: &str) -> &str {
    path.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(path)
}

fn cmdline(ev: &EvtxEvent) -> &str {
    ev.data.get("CommandLine").map(String::as_str).unwrap_or("")
}

fn image(ev: &EvtxEvent) -> &str {
    ev.data
        .get("Image")
        .or_else(|| ev.data.get("NewProcessName"))
        .map(String::as_str)
        .unwrap_or("")
}

fn killed_canonical_process<'a>(ev: &EvtxEvent) -> Option<&'a str> {
    let cl = cmdline(ev).to_lowercase();
    if !cl.contains("/im") {
        return None;
    }
    RANSOMWARE_KILL_PROCESSES
        .iter()
        .find(|&&proc| cl.contains(proc))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn kill_event(target: &str, ts: i64) -> EvtxEvent {
        let mut ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\taskkill.exe"),
                (
                    "CommandLine",
                    &format!("taskkill /F /IM {target}"),
                ),
            ],
        );
        ev.timestamp_ns = ts;
        ev
    }

    const BASE_TS: i64 = 1_700_000_000_000_000_000;
    const SEC: i64 = 1_000_000_000;

    #[test]
    fn cluster_of_five_detected() {
        let targets = [
            "sqlservr.exe",
            "veeam.exe",
            "msmpeng.exe",
            "sophos.exe",
            "mbam.exe",
        ];
        let events: Vec<_> = targets
            .iter()
            .enumerate()
            .map(|(i, t)| kill_event(t, BASE_TS + (i as i64) * 2 * SEC))
            .collect();
        let hits = detect_taskkill_av_cluster(&events);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::TaskkillAvCluster);
        assert_eq!(hits[0].mitre_technique_id, "T1562.001");
    }

    #[test]
    fn cluster_of_four_not_detected() {
        let targets = ["sqlservr.exe", "veeam.exe", "msmpeng.exe", "sophos.exe"];
        let events: Vec<_> = targets
            .iter()
            .enumerate()
            .map(|(i, t)| kill_event(t, BASE_TS + (i as i64) * SEC))
            .collect();
        assert!(detect_taskkill_av_cluster(&events).is_empty());
    }

    #[test]
    fn five_kills_outside_window_not_detected() {
        let targets = [
            "sqlservr.exe",
            "veeam.exe",
            "msmpeng.exe",
            "sophos.exe",
            "mbam.exe",
        ];
        // Space them 20 seconds apart — total span 80s > 60s window
        let events: Vec<_> = targets
            .iter()
            .enumerate()
            .map(|(i, t)| kill_event(t, BASE_TS + (i as i64) * 20 * SEC))
            .collect();
        assert!(detect_taskkill_av_cluster(&events).is_empty());
    }

    #[test]
    fn non_canonical_process_not_counted() {
        let mut events: Vec<_> = (0..5)
            .map(|i| kill_event("notepadxx.exe", BASE_TS + i * SEC))
            .collect();
        // notepadxx.exe is not in the canonical list
        let _ = events; // suppress warning
        let benign: Vec<_> = (0..5)
            .map(|i| {
                let mut ev = make_event(
                    EID_SYSMON_PROCESS_CREATE,
                    SYSMON_CHANNEL,
                    &[
                        ("Image", "C:\\Windows\\System32\\taskkill.exe"),
                        ("CommandLine", "taskkill /F /IM notepadxx.exe"),
                    ],
                );
                ev.timestamp_ns = BASE_TS + i * SEC;
                ev
            })
            .collect();
        assert!(detect_taskkill_av_cluster(&benign).is_empty());
    }

    #[test]
    fn evidence_contains_process_names() {
        let targets = [
            "sqlservr.exe", "veeam.exe", "msmpeng.exe", "sophos.exe", "mbam.exe",
        ];
        let events: Vec<_> = targets
            .iter()
            .enumerate()
            .map(|(i, t)| kill_event(t, BASE_TS + (i as i64) * SEC))
            .collect();
        let hits = detect_taskkill_av_cluster(&events);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("sqlservr.exe") || combined.contains("sql"));
    }
}
