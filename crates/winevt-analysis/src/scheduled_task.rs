//! Detect scheduled task creation events (T1053.005).

use forensicnomicon::heuristics::evtx::EID_SECURITY_TASK_CREATED;
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// TaskScheduler/Operational EID 106 — task registered.
const EID_TASKSCHEDULER_TASK_REGISTERED: u32 = 106;

/// Detect scheduled task creation.
///
/// Fires on Security EID 4698 (task created, from Object Access audit) and
/// TaskScheduler/Operational EID 106 (task registered).  QWCrypt/RedCurl
/// installs a scheduled task for persistence after the initial DLL sideload
/// (T1053.005).
///
/// Returns one detection per matching event.
pub fn detect_scheduled_task_creation(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!("implement scheduled_task detector")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    #[test]
    fn security_4698_task_created_detected() {
        let ev = make_event(
            EID_SECURITY_TASK_CREATED,
            "Security",
            &[("TaskName", "\\Microsoft\\Windows\\EvilTask")],
        );
        let hits = detect_scheduled_task_creation(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::ScheduledTaskCreation);
        assert_eq!(hits[0].mitre_technique_id, "T1053.005");
    }

    #[test]
    fn taskscheduler_106_detected() {
        let ev = make_event(
            EID_TASKSCHEDULER_TASK_REGISTERED,
            "Microsoft-Windows-TaskScheduler/Operational",
            &[("TaskName", "\\MyTask")],
        );
        assert!(!detect_scheduled_task_creation(&[ev]).is_empty());
    }

    #[test]
    fn unrelated_event_not_detected() {
        let ev = make_event(4624, "Security", &[("TaskName", "\\SomeTask")]);
        assert!(detect_scheduled_task_creation(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_task_name() {
        let ev = make_event(
            EID_SECURITY_TASK_CREATED,
            "Security",
            &[("TaskName", "\\RedCurlPersist")],
        );
        let hits = detect_scheduled_task_creation(&[ev]);
        assert!(!hits.is_empty());
        let combined = [hits[0].description.as_str(), &hits[0].evidence.join(" ")].join(" ");
        assert!(combined.contains("RedCurlPersist"));
    }
}
