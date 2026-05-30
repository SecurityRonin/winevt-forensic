//! Detect Sysinternals AD Explorer first-run registry tombstone (T1087).

use forensicnomicon::heuristics::evtx::{
    ADEXPLORER_EULAACCEPTED_KEY_FRAGMENT, EID_SYSMON_REGISTRY_ADD, EID_SYSMON_REGISTRY_MODIFY,
    SYSMON_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect Sysinternals AD Explorer domain recon via its EulaAccepted registry key.
///
/// AD Explorer (ADExplorer.exe / ADExplorer64.exe) writes
/// `HKCU\Software\Sysinternals\Active Directory Explorer\EulaAccepted=1` on
/// first run.  This key persists even after the binary is deleted, making it a
/// durable forensic tombstone (T1087).  Sysmon EID 12 (RegistryEvent object
/// create) or EID 13 (RegistryEvent value set) with `TargetObject` containing
/// the key path fragment fires on first run.
pub fn detect_adexplorer_recon(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn adexplorer_reg_create() -> EvtxEvent {
        make_event(
            EID_SYSMON_REGISTRY_ADD,
            SYSMON_CHANNEL,
            &[(
                "TargetObject",
                "HKCU\\Software\\Sysinternals\\Active Directory Explorer\\EulaAccepted",
            )],
        )
    }

    #[test]
    fn adexplorer_registry_create_detected() {
        let ev = adexplorer_reg_create();
        let hits = detect_adexplorer_recon(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::AdExplorerRecon);
        assert_eq!(hits[0].mitre_technique_id, "T1087");
    }

    #[test]
    fn adexplorer_registry_modify_detected() {
        let ev = make_event(
            EID_SYSMON_REGISTRY_MODIFY,
            SYSMON_CHANNEL,
            &[(
                "TargetObject",
                "HKCU\\Software\\Sysinternals\\Active Directory Explorer\\EulaAccepted",
            )],
        );
        assert!(!detect_adexplorer_recon(&[ev]).is_empty());
    }

    #[test]
    fn unrelated_registry_key_not_detected() {
        let ev = make_event(
            EID_SYSMON_REGISTRY_ADD,
            SYSMON_CHANNEL,
            &[("TargetObject", "HKCU\\Software\\Microsoft\\Office\\16.0\\Common")],
        );
        assert!(detect_adexplorer_recon(&[ev]).is_empty());
    }

    #[test]
    fn wrong_channel_not_detected() {
        let ev = make_event(
            EID_SYSMON_REGISTRY_ADD,
            "Security",
            &[(
                "TargetObject",
                "HKCU\\Software\\Sysinternals\\Active Directory Explorer\\EulaAccepted",
            )],
        );
        assert!(detect_adexplorer_recon(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_registry_key() {
        let ev = adexplorer_reg_create();
        let hits = detect_adexplorer_recon(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("Active Directory Explorer"));
    }

    #[test]
    fn tactic_is_discovery() {
        let ev = adexplorer_reg_create();
        let hits = detect_adexplorer_recon(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].tactic, "Discovery");
    }
}
