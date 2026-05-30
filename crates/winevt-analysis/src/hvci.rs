//! Detect HVCI / Vulnerable Driver Blocklist registry tampering (T1562.001).

use forensicnomicon::heuristics::evtx::{
    EID_REGISTRY_VALUE_SET, HVCI_REGISTRY_KEY_PATHS, HVCI_REGISTRY_VALUE_NAMES,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect modification of HVCI and Vulnerable Driver Blocklist registry values.
///
/// Matches Security EID 4657 (registry value modified) where `ObjectName`
/// contains an [`HVCI_REGISTRY_KEY_PATHS`] fragment AND `ObjectValueName`
/// is in [`HVCI_REGISTRY_VALUE_NAMES`].
///
/// QWCrypt/RedCurl disables `VulnerableDriverBlocklistEnable` and
/// `HypervisorEnforcedCodeIntegrity` before installing the Zemana BYOVD
/// driver, allowing it to bypass Driver Signature Enforcement (T1562.001).
pub fn detect_hvci_registry_tamper(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!("implement hvci detector")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn hvci_event(key: &str, value: &str) -> winevt_core::EvtxEvent {
        make_event(
            EID_REGISTRY_VALUE_SET,
            "Security",
            &[("ObjectName", key), ("ObjectValueName", value)],
        )
    }

    #[test]
    fn vulnerable_driver_blocklist_disable_detected() {
        let ev = hvci_event(
            "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
            "VulnerableDriverBlocklistEnable",
        );
        let hits = detect_hvci_registry_tamper(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::HvciRegistryTamper);
        assert_eq!(hits[0].mitre_technique_id, "T1562.001");
    }

    #[test]
    fn hvci_device_guard_key_detected() {
        let ev = hvci_event(
            "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            "EnableVirtualizationBasedSecurity",
        );
        assert!(!detect_hvci_registry_tamper(&[ev]).is_empty());
    }

    #[test]
    fn unrelated_registry_change_not_detected() {
        let ev = make_event(
            EID_REGISTRY_VALUE_SET,
            "Security",
            &[
                ("ObjectName", "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\Run"),
                ("ObjectValueName", "SomeApp"),
            ],
        );
        assert!(detect_hvci_registry_tamper(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(
            4624,
            "Security",
            &[
                ("ObjectName", "\\Control\\CI\\Config"),
                ("ObjectValueName", "VulnerableDriverBlocklistEnable"),
            ],
        );
        assert!(detect_hvci_registry_tamper(&[ev]).is_empty());
    }

    #[test]
    fn hvci_key_wrong_value_not_detected() {
        // Correct key, but value name not in HVCI_REGISTRY_VALUE_NAMES
        let ev = hvci_event("\\Control\\CI\\Config", "SomeOtherValue");
        assert!(detect_hvci_registry_tamper(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_key_and_value() {
        let ev = hvci_event("\\Control\\CI\\Config", "VulnerableDriverBlocklistEnable");
        let hits = detect_hvci_registry_tamper(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("VulnerableDriverBlocklistEnable"));
    }
}
