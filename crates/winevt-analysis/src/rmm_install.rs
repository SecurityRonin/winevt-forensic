//! Detect RMM tool installation outside standard paths (T1219).

use forensicnomicon::heuristics::evtx::{
    EID_SYSMON_FILE_CREATE, RMM_BINARY_NAMES, RMM_SAFE_INSTALL_PATHS, SYSMON_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect installation of a remote-monitoring/management (RMM) tool outside
/// `C:\Program Files\` or `C:\Program Files (x86)\` (T1219 — Remote Access Software).
///
/// Threat actors drop AnyDesk, ScreenConnect, TeamViewer, Atera, etc. into
/// `%TEMP%`, `%APPDATA%`, or `C:\ProgramData\` to maintain interactive access
/// while evading policy-based RMM blocklists. ~25/76 families use RMM tools for
/// lateral movement or persistent interactive C2 alongside their encryptor.
///
/// Fires on Sysmon EID 11 (File Create) when `TargetFilename` basename is in
/// `RMM_BINARY_NAMES` and the full path does NOT start with a safe install prefix.
pub fn detect_rmm_install(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| ev.event_id == EID_SYSMON_FILE_CREATE && ev.channel == SYSMON_CHANNEL)
        .filter_map(|ev| {
            let target = ev.data.get("TargetFilename").map(String::as_str)?;
            let base = basename(target).to_lowercase();
            let matched = RMM_BINARY_NAMES
                .iter()
                .find(|&&name| name.to_lowercase() == base)?;
            if is_safe_path(target) {
                return None;
            }
            Some(EvtxDetection {
                kind: EvtxDetectionKind::RmmToolInstall,
                mitre_technique_id: "T1219",
                tactic: "Command and Control",
                description: format!(
                    "RMM tool '{matched}' dropped outside standard install paths: '{target}'"
                ),
                evidence: vec![
                    format!("TargetFilename={target}"),
                    format!("matched_binary={matched}"),
                ],
                timestamp_ns: ev.timestamp_ns,
                event_id: ev.event_id,
                channel: ev.channel.clone(),
            })
        })
        .collect()
}

fn basename(path: &str) -> &str {
    path.rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(path)
}

fn is_safe_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    RMM_SAFE_INSTALL_PATHS
        .iter()
        .any(|safe| lower.starts_with(&safe.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn file_create_event(path: &str) -> EvtxEvent {
        make_event(
            EID_SYSMON_FILE_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\msiexec.exe"),
                ("TargetFilename", path),
            ],
        )
    }

    #[test]
    fn anydesk_in_temp_detected() {
        let ev = file_create_event("C:\\Users\\victim\\AppData\\Local\\Temp\\anydesk.exe");
        let hits = detect_rmm_install(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::RmmToolInstall);
        assert_eq!(hits[0].mitre_technique_id, "T1219");
    }

    #[test]
    fn teamviewer_in_programdata_detected() {
        let ev = file_create_event("C:\\ProgramData\\tools\\teamviewer.exe");
        assert!(!detect_rmm_install(&[ev]).is_empty());
    }

    #[test]
    fn screenconnect_in_programfiles_not_detected() {
        let ev =
            file_create_event("C:\\Program Files\\ScreenConnect\\ScreenConnect.WindowsClient.exe");
        assert!(detect_rmm_install(&[ev]).is_empty());
    }

    #[test]
    fn anydesk_in_program_files_x86_not_detected() {
        let ev = file_create_event("C:\\Program Files (x86)\\AnyDesk\\anydesk.exe");
        assert!(detect_rmm_install(&[ev]).is_empty());
    }

    #[test]
    fn benign_exe_in_temp_not_detected() {
        let ev = file_create_event("C:\\Users\\victim\\AppData\\Local\\Temp\\setup.exe");
        assert!(detect_rmm_install(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(
            1,
            SYSMON_CHANNEL,
            &[("TargetFilename", "C:\\Temp\\anydesk.exe")],
        );
        assert!(detect_rmm_install(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_filename() {
        let ev = file_create_event("C:\\Users\\victim\\AppData\\Roaming\\anydesk.exe");
        let hits = detect_rmm_install(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("anydesk"));
    }
}
