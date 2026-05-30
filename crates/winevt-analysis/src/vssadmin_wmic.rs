//! Detect VSS shadow copy deletion via vssadmin.exe or wmic.exe (T1490).

use forensicnomicon::heuristics::evtx::{
    EID_PROCESS_CREATE, EID_SYSMON_PROCESS_CREATE, SYSMON_CHANNEL,
    VSSADMIN_SHADOW_DELETE_PATTERNS, WMIC_SHADOW_DELETE_PATTERNS,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect shadow copy deletion via `vssadmin.exe delete shadows` or
/// `wmic shadowcopy delete` (T1490 — Inhibit System Recovery).
///
/// Both commands destroy VSS snapshots in preparation for ransomware deployment.
/// ~60 of the 76 families in `RANSOM_NOTE_FILENAMES` issue one or both commands.
/// Fires on Security EID 4688 (Process Creation) or Sysmon EID 1.
pub fn detect_vssadmin_wmic(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
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

    fn proc_event(image: &str, cmdline: &str) -> EvtxEvent {
        make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[("Image", image), ("CommandLine", cmdline)],
        )
    }

    #[test]
    fn vssadmin_delete_shadows_detected() {
        let ev = proc_event(
            "C:\\Windows\\System32\\vssadmin.exe",
            "vssadmin.exe delete shadows /all /quiet",
        );
        let hits = detect_vssadmin_wmic(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::VssAdminWmicDelete);
        assert_eq!(hits[0].mitre_technique_id, "T1490");
    }

    #[test]
    fn wmic_shadowcopy_delete_detected() {
        let ev = proc_event(
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic shadowcopy delete",
        );
        assert!(!detect_vssadmin_wmic(&[ev]).is_empty());
    }

    #[test]
    fn vssadmin_list_not_detected() {
        let ev = proc_event(
            "C:\\Windows\\System32\\vssadmin.exe",
            "vssadmin.exe list shadows",
        );
        assert!(detect_vssadmin_wmic(&[ev]).is_empty());
    }

    #[test]
    fn benign_wmic_not_detected() {
        let ev = proc_event(
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic process list",
        );
        assert!(detect_vssadmin_wmic(&[ev]).is_empty());
    }

    #[test]
    fn non_process_event_not_detected() {
        let ev = make_event(
            9999,
            "Application",
            &[("CommandLine", "vssadmin.exe delete shadows /all")],
        );
        assert!(detect_vssadmin_wmic(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_cmdline() {
        let ev = proc_event(
            "C:\\Windows\\System32\\vssadmin.exe",
            "vssadmin delete shadows /all /quiet",
        );
        let hits = detect_vssadmin_wmic(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("delete shadow"));
    }

    #[test]
    fn security_eid_4688_detected() {
        let ev = make_event(
            EID_PROCESS_CREATE,
            "Security",
            &[
                ("NewProcessName", "C:\\Windows\\System32\\vssadmin.exe"),
                ("CommandLine", "vssadmin delete shadows /all"),
            ],
        );
        assert!(!detect_vssadmin_wmic(&[ev]).is_empty());
    }
}
