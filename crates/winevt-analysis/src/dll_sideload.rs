//! Detect srvcli.dll / netutils.dll sideloading via Sysmon EID 7 (T1574.002).

use forensicnomicon::heuristics::evtx::{
    EID_SYSMON_IMAGE_LOAD, SIDELOAD_HIJACK_DLLS, SYSMON_CHANNEL, SYSTEM_DLL_SAFE_PATH_PREFIXES,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect DLL sideloading of srvcli.dll or netutils.dll from a non-system path.
///
/// Sysmon EID 7 (ImageLoad) fires when a process loads a DLL.  `ImageLoaded`
/// gives the full path of the loaded DLL.  Both `srvcli.dll` and `netutils.dll`
/// are legitimate Windows DLLs (loaded by 29+ applications) but are confirmed
/// as sideloading targets in QWCrypt/RedCurl intrusions — loaded by a renamed
/// copy of ADNotificationManager.exe from `%APPDATA%`, `%LOCALAPPDATA%\Temp\`,
/// or `C:\ProgramData\<random>\` (T1574.002).
pub fn detect_dll_sideload(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!()
}

fn basename(path: &str) -> &str {
    path.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(path)
}

fn is_safe_system_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    SYSTEM_DLL_SAFE_PATH_PREFIXES
        .iter()
        .any(|safe| path_lower.starts_with(&safe.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn sideload_event(dll_path: &str) -> EvtxEvent {
        make_event(
            EID_SYSMON_IMAGE_LOAD,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Users\\victim\\AppData\\Local\\Temp\\ADNotificationManager.exe"),
                ("ImageLoaded", dll_path),
                ("Signed", "false"),
            ],
        )
    }

    #[test]
    fn srvcli_from_temp_detected() {
        let ev = sideload_event("C:\\Users\\victim\\AppData\\Local\\Temp\\srvcli.dll");
        let hits = detect_dll_sideload(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::DllSideloadHijack);
        assert_eq!(hits[0].mitre_technique_id, "T1574.002");
    }

    #[test]
    fn netutils_from_programdata_detected() {
        let ev = sideload_event("C:\\ProgramData\\redcurl\\netutils.dll");
        assert!(!detect_dll_sideload(&[ev]).is_empty());
    }

    #[test]
    fn srvcli_from_system32_not_detected() {
        let ev = sideload_event("C:\\Windows\\System32\\srvcli.dll");
        assert!(detect_dll_sideload(&[ev]).is_empty());
    }

    #[test]
    fn netutils_from_syswow64_not_detected() {
        let ev = sideload_event("C:\\Windows\\SysWOW64\\netutils.dll");
        assert!(detect_dll_sideload(&[ev]).is_empty());
    }

    #[test]
    fn benign_dll_from_temp_not_detected() {
        let ev = make_event(
            EID_SYSMON_IMAGE_LOAD,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Users\\victim\\AppData\\Local\\Temp\\app.exe"),
                ("ImageLoaded", "C:\\Users\\victim\\AppData\\Local\\Temp\\myhelper.dll"),
                ("Signed", "false"),
            ],
        );
        assert!(detect_dll_sideload(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(
            1,
            SYSMON_CHANNEL,
            &[("ImageLoaded", "C:\\Temp\\srvcli.dll")],
        );
        assert!(detect_dll_sideload(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_dll_path() {
        let ev = sideload_event("C:\\Users\\victim\\AppData\\Local\\Temp\\srvcli.dll");
        let hits = detect_dll_sideload(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("srvcli.dll"));
    }
}
