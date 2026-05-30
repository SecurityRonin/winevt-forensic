//! Detect execution of known QWCrypt/RedCurl binaries (T1486).

use forensicnomicon::heuristics::evtx::QWCRYPT_IOC_FILENAMES;
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Security EID 4688 — a new process was created.
const EID_PROCESS_CREATED: u32 = 4688;
/// Sysmon EID 1 — process created (same information as 4688, richer fields).
const EID_SYSMON_PROCESS_CREATE: u32 = 1;

/// Detect execution of QWCrypt/RedCurl-specific binaries.
///
/// Fires on process-creation events (Security EID 4688, Sysmon EID 1) where
/// `NewProcessName` or `Image` contains a filename from [`QWCRYPT_IOC_FILENAMES`]
/// (`rbcw.exe`, `ADNotificationManager.exe`).
///
/// Returns one detection per matching event.
pub fn detect_qwcrypt_process(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| {
            (ev.event_id == EID_PROCESS_CREATED && ev.channel == "Security")
                || (ev.event_id == EID_SYSMON_PROCESS_CREATE
                    && ev.channel.contains("Sysmon"))
        })
        .filter_map(|ev| {
            let path = ev
                .data
                .get("NewProcessName")
                .or_else(|| ev.data.get("Image"))?;
            let base = basename(path);
            QWCRYPT_IOC_FILENAMES
                .iter()
                .find(|&&ioc| base.eq_ignore_ascii_case(ioc))
                .map(|&ioc| EvtxDetection {
                    kind: EvtxDetectionKind::QwcryptProcessExecution,
                    mitre_technique_id: "T1486",
                    tactic: "Impact",
                    description: format!(
                        "QWCrypt/RedCurl binary executed: '{base}'"
                    ),
                    evidence: vec![
                        format!("process={path}"),
                        format!("matched_ioc={ioc}"),
                    ],
                    timestamp_ns: ev.timestamp_ns,
                    event_id: ev.event_id,
                    channel: ev.channel.clone(),
                })
        })
        .collect()
}

fn basename(path: &str) -> &str {
    path.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    #[test]
    fn rbcw_exe_process_creation_detected() {
        let ev = make_event(
            EID_PROCESS_CREATED,
            "Security",
            &[("NewProcessName", "C:\\Users\\victim\\AppData\\Local\\Temp\\rbcw.exe")],
        );
        let hits = detect_qwcrypt_process(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::QwcryptProcessExecution);
        assert_eq!(hits[0].mitre_technique_id, "T1486");
    }

    #[test]
    fn adnotification_manager_detected() {
        let ev = make_event(
            EID_PROCESS_CREATED,
            "Security",
            &[("NewProcessName", "C:\\Windows\\Temp\\ADNotificationManager.exe")],
        );
        assert!(!detect_qwcrypt_process(&[ev]).is_empty());
    }

    #[test]
    fn sysmon_eid1_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            "Microsoft-Windows-Sysmon/Operational",
            &[("Image", "C:\\Temp\\rbcw.exe")],
        );
        assert!(!detect_qwcrypt_process(&[ev]).is_empty());
    }

    #[test]
    fn benign_process_not_detected() {
        let ev = make_event(
            EID_PROCESS_CREATED,
            "Security",
            &[("NewProcessName", "C:\\Windows\\System32\\notepad.exe")],
        );
        assert!(detect_qwcrypt_process(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_process_name() {
        let ev = make_event(
            EID_PROCESS_CREATED,
            "Security",
            &[("NewProcessName", "C:\\Temp\\rbcw.exe")],
        );
        let hits = detect_qwcrypt_process(&[ev]);
        assert!(!hits.is_empty());
        assert!(hits[0].evidence.iter().any(|e| e.contains("rbcw.exe")));
    }
}
