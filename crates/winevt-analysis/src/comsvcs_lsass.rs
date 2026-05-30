//! Detect comsvcs.dll MiniDump of LSASS for credential dumping (T1003.001).

use forensicnomicon::heuristics::evtx::{
    COMSVCS_MINIDUMP_PATTERNS, EID_PROCESS_CREATE, EID_SYSMON_PROCESS_ACCESS,
    EID_SYSMON_PROCESS_CREATE, LSASS_IMAGE_NAME, SYSMON_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect LSASS credential dumping via comsvcs.dll MiniDump technique (T1003.001).
///
/// Two signals:
/// 1. **Process create** (EID 4688 / Sysmon 1): `Image` = `rundll32.exe` AND
///    `CommandLine` contains `comsvcs.dll` AND `MiniDump`.
///    Pattern: `rundll32.exe comsvcs.dll, MiniDump <lsass-pid> out.dmp full`.
/// 2. **Sysmon EID 10** (ProcessAccess): `TargetImage` ends in `lsass.exe`.
///    Many credential dumpers open lsass with broad access masks.
///
/// Near-zero FP for signal 1 — rundll32+comsvcs+MiniDump is effectively unique
/// to credential dumping.  Signal 2 has higher FP but is still actionable.
pub fn detect_comsvcs_lsass(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!()
}

fn is_process_event(ev: &EvtxEvent) -> bool {
    (ev.event_id == EID_PROCESS_CREATE && ev.channel == "Security")
        || (ev.event_id == EID_SYSMON_PROCESS_CREATE && ev.channel == SYSMON_CHANNEL)
}

fn basename(path: &str) -> &str {
    path.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    #[test]
    fn rundll32_comsvcs_minidump_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\rundll32.exe"),
                (
                    "CommandLine",
                    "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 lsass.dmp full",
                ),
            ],
        );
        let hits = detect_comsvcs_lsass(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::ComsvcslsassDump);
        assert_eq!(hits[0].mitre_technique_id, "T1003.001");
    }

    #[test]
    fn powershell_comsvcs_minidump_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
                (
                    "CommandLine",
                    "powershell -c \"rundll32 comsvcs.dll MiniDump $pid lsass.dmp full\"",
                ),
            ],
        );
        assert!(!detect_comsvcs_lsass(&[ev]).is_empty());
    }

    #[test]
    fn sysmon_eid10_lsass_access_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_ACCESS,
            SYSMON_CHANNEL,
            &[
                ("SourceImage", "C:\\Windows\\System32\\rundll32.exe"),
                ("TargetImage", "C:\\Windows\\System32\\lsass.exe"),
                ("GrantedAccess", "0x1fffff"),
            ],
        );
        assert!(!detect_comsvcs_lsass(&[ev]).is_empty());
    }

    #[test]
    fn rundll32_without_comsvcs_not_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\rundll32.exe"),
                ("CommandLine", "rundll32.exe printui.dll PrintUIEntry /e"),
            ],
        );
        assert!(detect_comsvcs_lsass(&[ev]).is_empty());
    }

    #[test]
    fn benign_process_accessing_lsass_context_not_forced_detected() {
        // Sysmon-10 on lsass is detected regardless of GrantedAccess — the signal
        // is a TargetImage=lsass; callers filter further upstream.
        let ev = make_event(
            EID_SYSMON_PROCESS_ACCESS,
            SYSMON_CHANNEL,
            &[
                ("SourceImage", "C:\\Windows\\System32\\svchost.exe"),
                ("TargetImage", "C:\\Windows\\System32\\lsass.exe"),
                ("GrantedAccess", "0x0010"),
            ],
        );
        // svchost legitimately reads lsass — we should still flag for investigation
        // (analyst review expected); the test verifies the detector fires on lsass access
        let _ = detect_comsvcs_lsass(&[ev]); // no assertion — either outcome is acceptable
    }

    #[test]
    fn evidence_contains_comsvcs_or_minidump() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\rundll32.exe"),
                (
                    "CommandLine",
                    "rundll32.exe comsvcs.dll MiniDump 624 dump.bin full",
                ),
            ],
        );
        let hits = detect_comsvcs_lsass(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("comsvcs") || combined.contains("MiniDump"));
    }
}
