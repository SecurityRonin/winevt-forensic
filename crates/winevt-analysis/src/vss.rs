//! Detect shadow copy / VSS deletion events (T1490).

use forensicnomicon::heuristics::evtx::{EID_VSS_ERROR, EID_VSS_SNAPSHOT_DELETED};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect VSS shadow copy deletion events.
///
/// Fires on Application channel EID 8193 (VSS service error — fired when
/// `vssadmin delete shadows` or `wmic shadowcopy delete` runs) and EID 524
/// (snapshot deleted).  QWCrypt deletes shadow copies to prevent recovery
/// of encrypted Hyper-V VHD/VHDX files (T1490).
///
/// Returns one detection per matching event.
pub fn detect_vss_deletion(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!("implement vss detector")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    #[test]
    fn eid_8193_vss_error_detected() {
        let ev = make_event(EID_VSS_ERROR, "Application", &[("Source", "VSS")]);
        let hits = detect_vss_deletion(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::VssDeletion);
        assert_eq!(hits[0].mitre_technique_id, "T1490");
    }

    #[test]
    fn eid_524_snapshot_deleted_detected() {
        let ev = make_event(EID_VSS_SNAPSHOT_DELETED, "Application", &[]);
        assert!(!detect_vss_deletion(&[ev]).is_empty());
    }

    #[test]
    fn unrelated_application_event_not_detected() {
        let ev = make_event(1000, "Application", &[]);
        assert!(detect_vss_deletion(&[ev]).is_empty());
    }

    #[test]
    fn security_8193_wrong_channel_not_detected() {
        // EID 8193 in Security channel is unrelated
        let ev = make_event(EID_VSS_ERROR, "Security", &[]);
        assert!(
            detect_vss_deletion(&[ev]).is_empty(),
            "EID 8193 in Security channel is not a VSS event"
        );
    }

    #[test]
    fn multiple_vss_events_produce_multiple_detections() {
        let events = vec![
            make_event(EID_VSS_ERROR, "Application", &[]),
            make_event(EID_VSS_SNAPSHOT_DELETED, "Application", &[]),
        ];
        assert_eq!(detect_vss_deletion(&events).len(), 2);
    }
}
