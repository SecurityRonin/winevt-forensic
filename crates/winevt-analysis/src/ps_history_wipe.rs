//! Detect PowerShell history file deletion via Sysmon EID 23/26 (T1070.003).

use forensicnomicon::heuristics::evtx::{
    EID_SYSMON_FILE_DELETE, EID_SYSMON_FILE_DELETE_DETECTED, PS_HISTORY_PATH_FRAGMENT,
    SYSMON_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect deletion of `ConsoleHost_history.txt` — the PowerShell PSReadLine
/// command history file.
///
/// QWCrypt/RedCurl's cleanup batch script deletes PowerShell history across all
/// user profiles (T1070.003).  Sysmon EID 23 (FileDelete, requires archiving)
/// or EID 26 (FileDeleteDetected, v13+) fires when `TargetFilename` matches the
/// path fragment `ConsoleHost_history.txt`.  A single deletion may be a user
/// action; deletions across multiple user profiles within seconds indicate
/// automated ransomware cleanup.
pub fn detect_ps_history_wipe(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| {
            (ev.event_id == EID_SYSMON_FILE_DELETE
                || ev.event_id == EID_SYSMON_FILE_DELETE_DETECTED)
                && ev.channel == SYSMON_CHANNEL
        })
        .filter_map(|ev| {
            let path = ev.data.get("TargetFilename")?;
            if !path.contains(PS_HISTORY_PATH_FRAGMENT) {
                return None;
            }
            Some(EvtxDetection {
                kind: EvtxDetectionKind::PsHistoryWipe,
                mitre_technique_id: "T1070.003",
                tactic: "Defense Evasion",
                description: format!("PowerShell history file deleted: '{path}'"),
                evidence: vec![format!("TargetFilename={path}")],
                timestamp_ns: ev.timestamp_ns,
                event_id: ev.event_id,
                channel: ev.channel.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn history_delete(eid: u32, path: &str) -> EvtxEvent {
        make_event(eid, SYSMON_CHANNEL, &[("TargetFilename", path)])
    }

    const HISTORY_PATH: &str =
        "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";

    #[test]
    fn eid23_history_wipe_detected() {
        let ev = history_delete(EID_SYSMON_FILE_DELETE, HISTORY_PATH);
        let hits = detect_ps_history_wipe(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::PsHistoryWipe);
        assert_eq!(hits[0].mitre_technique_id, "T1070.003");
    }

    #[test]
    fn eid26_history_wipe_detected() {
        let ev = history_delete(EID_SYSMON_FILE_DELETE_DETECTED, HISTORY_PATH);
        let hits = detect_ps_history_wipe(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::PsHistoryWipe);
    }

    #[test]
    fn benign_file_delete_not_detected() {
        let ev = history_delete(
            EID_SYSMON_FILE_DELETE,
            "C:\\Users\\victim\\Desktop\\report.docx",
        );
        assert!(detect_ps_history_wipe(&[ev]).is_empty());
    }

    #[test]
    fn wrong_channel_not_detected() {
        let ev = make_event(
            EID_SYSMON_FILE_DELETE,
            "Security",
            &[("TargetFilename", HISTORY_PATH)],
        );
        assert!(detect_ps_history_wipe(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(11, SYSMON_CHANNEL, &[("TargetFilename", HISTORY_PATH)]);
        assert!(detect_ps_history_wipe(&[ev]).is_empty());
    }

    #[test]
    fn multiple_user_wipes_produce_multiple_detections() {
        let events = vec![
            history_delete(
                EID_SYSMON_FILE_DELETE,
                "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
            ),
            history_delete(
                EID_SYSMON_FILE_DELETE,
                "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
            ),
        ];
        assert_eq!(detect_ps_history_wipe(&events).len(), 2);
    }

    #[test]
    fn evidence_contains_file_path() {
        let ev = history_delete(EID_SYSMON_FILE_DELETE, HISTORY_PATH);
        let hits = detect_ps_history_wipe(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("ConsoleHost_history.txt"));
    }
}
