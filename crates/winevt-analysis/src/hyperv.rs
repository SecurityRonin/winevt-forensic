//! Detect Hyper-V VM shutdown events indicating pre-encryption staging (T1486).

use forensicnomicon::heuristics::evtx::{
    EID_HYPERV_VM_STATE_CHANGE, EID_HYPERV_VM_STOPPED, HYPERV_VMMS_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect Hyper-V VM shutdown events in the VMMS Admin channel.
///
/// QWCrypt/RedCurl shuts down all Hyper-V VMs before encrypting the VHD/VHDX
/// files on disk — the guest OS must be stopped for the host to get exclusive
/// write access.  EID 13002 (state change initiated) and EID 13003 (VM
/// stopped) in the `Microsoft-Windows-Hyper-V-VMMS/Admin` channel indicate
/// this pre-encryption staging step (T1486).
///
/// Returns one detection per matching event.
pub fn detect_hyperv_vm_shutdown(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| {
            ev.channel == HYPERV_VMMS_CHANNEL
                && (ev.event_id == EID_HYPERV_VM_STATE_CHANGE
                    || ev.event_id == EID_HYPERV_VM_STOPPED)
        })
        .map(|ev| {
            let vm_name = ev
                .data
                .get("VmName")
                .map(String::as_str)
                .unwrap_or("<unknown>");
            EvtxDetection {
                kind: EvtxDetectionKind::HypervVmShutdown,
                mitre_technique_id: "T1486",
                tactic: "Impact",
                description: format!(
                    "Hyper-V VM shut down (EID {}): '{vm_name}' — pre-encryption staging",
                    ev.event_id
                ),
                evidence: vec![
                    format!("VmName={vm_name}"),
                    format!("event_id={}", ev.event_id),
                ],
                timestamp_ns: ev.timestamp_ns,
                event_id: ev.event_id,
                channel: ev.channel.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn hyperv_event(eid: u32) -> winevt_core::EvtxEvent {
        make_event(eid, HYPERV_VMMS_CHANNEL, &[("VmName", "test-vm-01")])
    }

    #[test]
    fn eid_13002_vm_state_change_detected() {
        let ev = hyperv_event(EID_HYPERV_VM_STATE_CHANGE);
        let hits = detect_hyperv_vm_shutdown(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::HypervVmShutdown);
        assert_eq!(hits[0].mitre_technique_id, "T1486");
    }

    #[test]
    fn eid_13003_vm_stopped_detected() {
        let ev = hyperv_event(EID_HYPERV_VM_STOPPED);
        assert!(!detect_hyperv_vm_shutdown(&[ev]).is_empty());
    }

    #[test]
    fn wrong_channel_not_detected() {
        // Same EID in a different channel is not a Hyper-V event
        let ev = make_event(EID_HYPERV_VM_STATE_CHANGE, "System", &[]);
        assert!(detect_hyperv_vm_shutdown(&[ev]).is_empty());
    }

    #[test]
    fn unrelated_hyperv_event_not_detected() {
        let ev = make_event(9999, HYPERV_VMMS_CHANNEL, &[]);
        assert!(detect_hyperv_vm_shutdown(&[ev]).is_empty());
    }

    #[test]
    fn evidence_mentions_vm_name() {
        let ev = hyperv_event(EID_HYPERV_VM_STOPPED);
        let hits = detect_hyperv_vm_shutdown(&[ev]);
        assert!(!hits.is_empty());
        assert!(
            hits[0].evidence.iter().any(|e| e.contains("test-vm-01"))
                || hits[0].description.contains("test-vm-01")
        );
    }

    #[test]
    fn cluster_of_shutdowns_produces_multiple_detections() {
        let events: Vec<_> = (0..3)
            .map(|i| {
                make_event(
                    EID_HYPERV_VM_STOPPED,
                    HYPERV_VMMS_CHANNEL,
                    &[("VmName", &format!("vm-{i:02}"))],
                )
            })
            .collect();
        assert_eq!(detect_hyperv_vm_shutdown(&events).len(), 3);
    }
}
