//! Detect scheduled tasks with browser-update names but wrong action paths (T1053.005).

use forensicnomicon::heuristics::evtx::{
    BROWSER_UPDATE_TASK_PATTERNS, EID_TASK_REGISTERED, EID_TASK_UPDATED, TASKSCHEDULER_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect scheduled tasks that mimic browser auto-update tasks for persistence.
///
/// QWCrypt/RedCurl registers scheduled tasks with names like `GoogleUpdateTask*`
/// or `MicrosoftEdgeUpdate*` but sets the action path to a user-writable
/// directory (`C:\ProgramData\`, `%APPDATA%\`, etc.) rather than the real
/// browser installation location (T1053.005).
///
/// Fires on TaskScheduler EID 106 (task registered) or EID 140 (task updated)
/// when `TaskName` matches any `BROWSER_UPDATE_TASK_PATTERNS` substring AND
/// `TaskName` exists (basic name-based check — action path is rarely available
/// in EventData without parsing the task XML).
pub fn detect_fake_browser_task(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn task_event(eid: u32, task_name: &str) -> EvtxEvent {
        make_event(
            eid,
            TASKSCHEDULER_CHANNEL,
            &[("TaskName", task_name), ("SubjectUserName", "SYSTEM")],
        )
    }

    #[test]
    fn google_update_task_detected() {
        let ev = task_event(EID_TASK_REGISTERED, "\\GoogleUpdateTaskMachineUA{abc123}");
        let hits = detect_fake_browser_task(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::FakeBrowserTask);
        assert_eq!(hits[0].mitre_technique_id, "T1053.005");
    }

    #[test]
    fn edge_update_task_detected() {
        let ev = task_event(EID_TASK_REGISTERED, "\\MicrosoftEdgeUpdateTaskMachineCore");
        assert!(!detect_fake_browser_task(&[ev]).is_empty());
    }

    #[test]
    fn mozilla_maintenance_task_detected() {
        let ev = task_event(EID_TASK_UPDATED, "\\MozillaMaintenance {12345678-abcd-ef00-1234-567890abcdef}");
        assert!(!detect_fake_browser_task(&[ev]).is_empty());
    }

    #[test]
    fn brave_update_task_detected() {
        let ev = task_event(EID_TASK_REGISTERED, "\\BraveSoftwareUpdateTaskMachineUA");
        assert!(!detect_fake_browser_task(&[ev]).is_empty());
    }

    #[test]
    fn legitimate_schtask_not_detected() {
        let ev = task_event(EID_TASK_REGISTERED, "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start");
        assert!(detect_fake_browser_task(&[ev]).is_empty());
    }

    #[test]
    fn wrong_channel_not_detected() {
        let ev = make_event(
            EID_TASK_REGISTERED,
            "Security",
            &[("TaskName", "\\GoogleUpdateTaskMachineUA")],
        );
        assert!(detect_fake_browser_task(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(
            200,
            TASKSCHEDULER_CHANNEL,
            &[("TaskName", "\\GoogleUpdateTaskMachineUA")],
        );
        assert!(detect_fake_browser_task(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_task_name() {
        let ev = task_event(EID_TASK_REGISTERED, "\\GoogleUpdateTaskMachineUA{abc}");
        let hits = detect_fake_browser_task(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("GoogleUpdateTask"));
    }
}
