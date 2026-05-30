//! Detect WMI lateral movement: permanent event consumer (EID 5861) and
//! Impacket wmiexec output-redirect pattern (T1047).

use forensicnomicon::heuristics::evtx::{
    EID_PROCESS_CREATE, EID_SYSMON_PROCESS_CREATE, EID_WMI_FILTER_TRIGGERED, SYSMON_CHANNEL,
    WMI_ACTIVITY_CHANNEL, WMI_IMPACKET_INDICATORS,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect WMI-based lateral movement.
///
/// Two signals under this kind:
/// 1. **WMI-Activity EID 5861** (Permanent Event Consumer registration) —
///    rare in clean environments; malware registers consumers to persist or
///    execute on arbitrary triggers.
/// 2. **Impacket wmiexec output-redirect** — `CommandLine` containing
///    `\\127.0.0.1\ADMIN$\__<timestamp>` (the temp output file path used by
///    Impacket's wmiexec.py), visible in EID 4688 or Sysmon EID 1.
pub fn detect_wmi_lateral_movement(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!()
}

fn is_process_event(ev: &winevt_core::EvtxEvent) -> bool {
    (ev.event_id == EID_PROCESS_CREATE && ev.channel == "Security")
        || (ev.event_id == EID_SYSMON_PROCESS_CREATE && ev.channel == SYSMON_CHANNEL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    #[test]
    fn wmi_permanent_consumer_detected() {
        let ev = make_event(
            EID_WMI_FILTER_TRIGGERED,
            WMI_ACTIVITY_CHANNEL,
            &[
                ("User", "DOMAIN\\attacker"),
                ("PossibleCause", "Permanent"),
            ],
        );
        let hits = detect_wmi_lateral_movement(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::WmiLateralMovement);
        assert_eq!(hits[0].mitre_technique_id, "T1047");
    }

    #[test]
    fn impacket_wmiexec_output_redirect_detected() {
        let ev = make_event(
            EID_PROCESS_CREATE,
            "Security",
            &[
                ("NewProcessName", "C:\\Windows\\System32\\cmd.exe"),
                (
                    "CommandLine",
                    "cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1234567890.123 2>&1",
                ),
            ],
        );
        let hits = detect_wmi_lateral_movement(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::WmiLateralMovement);
    }

    #[test]
    fn sysmon_eid1_impacket_pattern_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\cmd.exe"),
                (
                    "CommandLine",
                    "cmd.exe /Q /c ipconfig 1> \\\\127.0.0.1\\ADMIN$\\__9876543210.456 2>&1",
                ),
            ],
        );
        assert!(!detect_wmi_lateral_movement(&[ev]).is_empty());
    }

    #[test]
    fn benign_cmd_not_detected() {
        let ev = make_event(
            EID_PROCESS_CREATE,
            "Security",
            &[
                ("NewProcessName", "C:\\Windows\\System32\\cmd.exe"),
                ("CommandLine", "cmd.exe /c dir C:\\"),
            ],
        );
        assert!(detect_wmi_lateral_movement(&[ev]).is_empty());
    }

    #[test]
    fn wrong_wmi_channel_not_detected() {
        let ev = make_event(
            EID_WMI_FILTER_TRIGGERED,
            "Application",
            &[("User", "DOMAIN\\attacker")],
        );
        assert!(detect_wmi_lateral_movement(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_wmi_detail() {
        let ev = make_event(
            EID_WMI_FILTER_TRIGGERED,
            WMI_ACTIVITY_CHANNEL,
            &[("User", "DOMAIN\\attacker"), ("PossibleCause", "Permanent")],
        );
        let hits = detect_wmi_lateral_movement(&[ev]);
        assert!(!hits.is_empty());
        assert!(!hits[0].evidence.is_empty());
    }
}
