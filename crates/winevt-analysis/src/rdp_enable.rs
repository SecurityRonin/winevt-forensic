//! Detect RDP enable via fDenyTSConnections registry write (T1021.001 / T1112).

use forensicnomicon::heuristics::evtx::{
    EID_SYSMON_REGISTRY_MODIFY, RDP_FDENYTSC_KEY_FRAGMENT, SYSMON_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect RDP being enabled by setting `fDenyTSConnections` to 0 via registry.
///
/// `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`
/// controls whether Terminal Services (RDP) accepts inbound connections.
/// Setting it to 0 enables RDP; ransomware actors do this before lateral movement
/// and as a persistent backdoor (T1021.001 / T1112 — Modify Registry).
///
/// Fires on Sysmon EID 13 (RegistryEvent — Value Set) when `TargetObject`
/// contains `fDenyTSConnections` and `Details` indicates a 0 value.
pub fn detect_rdp_enable(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn rdp_registry_event(target_object: &str, details: &str) -> EvtxEvent {
        make_event(
            EID_SYSMON_REGISTRY_MODIFY,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\reg.exe"),
                ("TargetObject", target_object),
                ("Details", details),
            ],
        )
    }

    #[test]
    fn fdenytsconnections_set_to_0_detected() {
        let ev = rdp_registry_event(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections",
            "DWORD (0x00000000)",
        );
        let hits = detect_rdp_enable(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::RdpEnabled);
        assert_eq!(hits[0].mitre_technique_id, "T1021.001");
    }

    #[test]
    fn fdenytsconnections_set_to_1_not_detected() {
        let ev = rdp_registry_event(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections",
            "DWORD (0x00000001)",
        );
        assert!(detect_rdp_enable(&[ev]).is_empty());
    }

    #[test]
    fn unrelated_registry_key_not_detected() {
        let ev = rdp_registry_event(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\myapp",
            "DWORD (0x00000000)",
        );
        assert!(detect_rdp_enable(&[ev]).is_empty());
    }

    #[test]
    fn wrong_sysmon_eid_not_detected() {
        let ev = make_event(
            12, // RegistryAdd (object create), not 13 (value set)
            SYSMON_CHANNEL,
            &[
                (
                    "TargetObject",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections",
                ),
                ("Details", "DWORD (0x00000000)"),
            ],
        );
        assert!(detect_rdp_enable(&[ev]).is_empty());
    }

    #[test]
    fn plain_zero_details_detected() {
        let ev = rdp_registry_event(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections",
            "0",
        );
        assert!(!detect_rdp_enable(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_key_name() {
        let ev = rdp_registry_event(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections",
            "DWORD (0x00000000)",
        );
        let hits = detect_rdp_enable(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("fDenyTSConnections") || combined.contains("Terminal Server"));
    }
}
