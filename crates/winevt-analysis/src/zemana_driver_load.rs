//! Detect Zemana BYOVD driver load via Sysmon EID 6 (T1068).

use forensicnomicon::heuristics::evtx::{
    EID_SYSMON_DRIVER_LOAD, SYSMON_CHANNEL, ZEMANA_SIGNER_THUMBPRINT,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect Zemana Anti-Malware driver loaded from a non-standard path.
///
/// Sysmon EID 6 (Driver Load) fires when a kernel driver is loaded.  The
/// Terminator BYOVD tool loads the Zemana driver (ZAM64.sys / zamguard64.sys)
/// signed by thumbprint `96A7749D...` from an attacker-controlled path.
/// Legitimate Zemana installs from `C:\Program Files\Zemana\*`.  Any load of a
/// Zemana-signed driver from outside that path is a BYOVD indicator (T1068).
pub fn detect_zemana_driver_load(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| ev.event_id == EID_SYSMON_DRIVER_LOAD && ev.channel == SYSMON_CHANNEL)
        .filter_map(|ev| {
            if !is_zemana_signed(ev) {
                return None;
            }
            let path = ev.data.get("ImageLoaded")?;
            if is_standard_zemana_path(path) {
                return None;
            }
            Some(EvtxDetection {
                kind: EvtxDetectionKind::ZemanaDriverLoad,
                mitre_technique_id: "T1068",
                tactic: "Privilege Escalation",
                description: format!(
                    "Zemana-signed driver loaded from non-standard path: '{path}' — BYOVD EDR killer"
                ),
                evidence: vec![
                    format!("ImageLoaded={path}"),
                    format!("Thumbprint={ZEMANA_SIGNER_THUMBPRINT}"),
                ],
                timestamp_ns: ev.timestamp_ns,
                event_id: ev.event_id,
                channel: ev.channel.clone(),
            })
        })
        .collect()
}

fn is_zemana_signed(ev: &winevt_core::EvtxEvent) -> bool {
    ev.data
        .get("SignatureStatus")
        .is_some_and(|s| s.eq_ignore_ascii_case("Valid"))
        && ev.data.get("Hashes").is_some_and(|h| {
            h.to_uppercase()
                .contains(&ZEMANA_SIGNER_THUMBPRINT.to_uppercase())
        })
}

fn is_standard_zemana_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("\\program files\\zemana\\") || lower.contains("\\program files (x86)\\zemana\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn byovd_driver_load() -> EvtxEvent {
        make_event(
            EID_SYSMON_DRIVER_LOAD,
            SYSMON_CHANNEL,
            &[
                ("ImageLoaded", "C:\\Windows\\Temp\\zamguard64.sys"),
                ("Signed", "true"),
                ("SignatureStatus", "Valid"),
                (
                    "Hashes",
                    "SHA256=AAAA,THUMBPRINT=96A7749D856CB49DE32005BCDD8621F38E2B4C05",
                ),
            ],
        )
    }

    #[test]
    fn zemana_byovd_driver_detected() {
        let ev = byovd_driver_load();
        let hits = detect_zemana_driver_load(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::ZemanaDriverLoad);
        assert_eq!(hits[0].mitre_technique_id, "T1068");
    }

    #[test]
    fn zemana_from_program_files_not_detected() {
        let ev = make_event(
            EID_SYSMON_DRIVER_LOAD,
            SYSMON_CHANNEL,
            &[
                (
                    "ImageLoaded",
                    "C:\\Program Files\\Zemana\\AntiMalware\\zamguard64.sys",
                ),
                ("Signed", "true"),
                ("SignatureStatus", "Valid"),
                (
                    "Hashes",
                    "SHA256=AAAA,THUMBPRINT=96A7749D856CB49DE32005BCDD8621F38E2B4C05",
                ),
            ],
        );
        assert!(detect_zemana_driver_load(&[ev]).is_empty());
    }

    #[test]
    fn unsigned_driver_not_detected() {
        let ev = make_event(
            EID_SYSMON_DRIVER_LOAD,
            SYSMON_CHANNEL,
            &[
                ("ImageLoaded", "C:\\Temp\\evil.sys"),
                ("Signed", "false"),
                ("SignatureStatus", "Unsigned"),
                ("Hashes", "SHA256=BBBB"),
            ],
        );
        assert!(detect_zemana_driver_load(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(
            7045,
            SYSMON_CHANNEL,
            &[
                ("ImageLoaded", "C:\\Temp\\zamguard64.sys"),
                ("Signed", "true"),
                ("SignatureStatus", "Valid"),
                (
                    "Hashes",
                    "THUMBPRINT=96A7749D856CB49DE32005BCDD8621F38E2B4C05",
                ),
            ],
        );
        assert!(detect_zemana_driver_load(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_driver_path() {
        let ev = byovd_driver_load();
        let hits = detect_zemana_driver_load(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("zamguard64.sys"));
    }
}
