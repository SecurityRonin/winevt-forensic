//! Detect BYOVD (Bring Your Own Vulnerable Driver) service installation (T1068).

use forensicnomicon::heuristics::evtx::BYOVD_DRIVER_NAMES;
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect installation of a known-vulnerable driver service.
///
/// Matches Security EID 4697 and System EID 7045 (service installed) where
/// `ServiceName` is in [`BYOVD_DRIVER_NAMES`].  QWCrypt uses the Zemana
/// AntiMalware driver (`zamguard64`) to terminate EDR/AV at kernel level
/// before deploying the encryptor (T1068).
pub fn detect_byovd_driver_install(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!("implement byovd detector")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    #[test]
    fn zamguard64_service_install_detected() {
        let ev = make_event(7045, "System", &[("ServiceName", "zamguard64")]);
        let hits = detect_byovd_driver_install(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::ByovdDriverInstall);
        assert_eq!(hits[0].mitre_technique_id, "T1068");
    }

    #[test]
    fn zam_variant_detected() {
        let ev = make_event(7045, "System", &[("ServiceName", "ZAM")]);
        assert!(!detect_byovd_driver_install(&[ev]).is_empty());
    }

    #[test]
    fn security_4697_also_detected() {
        let ev = make_event(4697, "Security", &[("ServiceName", "ZemanaAntiMalware")]);
        assert!(!detect_byovd_driver_install(&[ev]).is_empty());
    }

    #[test]
    fn other_driver_names_detected() {
        // RTCore64 is another commonly abused BYOVD driver
        let ev = make_event(7045, "System", &[("ServiceName", "RTCore64")]);
        assert!(!detect_byovd_driver_install(&[ev]).is_empty());
    }

    #[test]
    fn benign_service_not_detected() {
        let ev = make_event(7045, "System", &[("ServiceName", "Spooler")]);
        assert!(detect_byovd_driver_install(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(4624, "Security", &[("ServiceName", "zamguard64")]);
        assert!(detect_byovd_driver_install(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_service_name() {
        let ev = make_event(7045, "System", &[("ServiceName", "zamguard64")]);
        let hits = detect_byovd_driver_install(&[ev]);
        assert!(!hits.is_empty());
        assert!(hits[0].evidence.iter().any(|e| e.contains("zamguard64")));
    }
}
