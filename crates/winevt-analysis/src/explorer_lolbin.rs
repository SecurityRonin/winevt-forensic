//! Detect LOLBin processes spawned directly by the Windows shell (T1204.002).

use forensicnomicon::heuristics::evtx::{
    EID_PROCESS_CREATE, EID_SYSMON_PROCESS_CREATE, SHELL_PARENT_PROCESS_NAMES, SYSMON_CHANNEL,
    WEBDAV_LOL_PROCESSES,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect a LOLBin process spawned directly by `explorer.exe` (T1204.002).
///
/// When a user double-clicks a malicious LNK, shortcut, or script file, Windows
/// Explorer becomes the immediate parent of the launched process. Legitimate
/// software installers run through `msiexec.exe` or their own launcher, never
/// spawning `rundll32.exe`, `mshta.exe`, or `wscript.exe` as direct children of
/// `explorer.exe` without user intent.
///
/// This is the earliest EVTX-visible signal of T1204.002 — it fires at the
/// process-create event, before any network connection is attempted, filling the
/// gap left by `detect_webdav_lolbin` which fires only after the LOLBin connects.
///
/// Sources: Sysmon EID 1 (`ParentImage` field) and Security EID 4688
/// (`ParentProcessName` field, requires Windows 8.1+ audit policy).
pub fn detect_explorer_lolbin(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| is_process_event(ev))
        .filter_map(|ev| {
            let parent_base = basename(parent_image(ev)).to_lowercase();
            if !SHELL_PARENT_PROCESS_NAMES
                .iter()
                .any(|p| p.eq_ignore_ascii_case(&parent_base))
            {
                return None;
            }
            let img = image(ev);
            let img_base = basename(img).to_lowercase();
            let matched = WEBDAV_LOL_PROCESSES
                .iter()
                .find(|&&lol| lol.eq_ignore_ascii_case(&img_base))?;
            let parent = parent_image(ev);
            let cmdline = ev.data.get("CommandLine").map(String::as_str).unwrap_or("");
            Some(EvtxDetection {
                kind: EvtxDetectionKind::ExplorerLolbinExecution,
                mitre_technique_id: "T1204.002",
                tactic: "Execution",
                description: format!(
                    "LOLBin '{matched}' spawned by shell '{}'  — likely user-executed LNK/script",
                    basename(parent)
                ),
                evidence: vec![
                    format!("Image={img}"),
                    format!("ParentImage={parent}"),
                    format!("CommandLine={cmdline}"),
                ],
                timestamp_ns: ev.timestamp_ns,
                event_id: ev.event_id,
                channel: ev.channel.clone(),
            })
        })
        .collect()
}

fn is_process_event(ev: &EvtxEvent) -> bool {
    (ev.event_id == EID_PROCESS_CREATE && ev.channel == "Security")
        || (ev.event_id == EID_SYSMON_PROCESS_CREATE && ev.channel == SYSMON_CHANNEL)
}

fn basename(path: &str) -> &str {
    path.rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(path)
}

fn image(ev: &EvtxEvent) -> &str {
    ev.data
        .get("Image")
        .or_else(|| ev.data.get("NewProcessName"))
        .map(String::as_str)
        .unwrap_or("")
}

fn parent_image(ev: &EvtxEvent) -> &str {
    // Sysmon EID 1: "ParentImage"; Security EID 4688: "ParentProcessName"
    ev.data
        .get("ParentImage")
        .or_else(|| ev.data.get("ParentProcessName"))
        .map(String::as_str)
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn lolbin_from_parent(lolbin: &str, parent: &str) -> EvtxEvent {
        make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", &format!("C:\\Windows\\System32\\{lolbin}")),
                ("ParentImage", &format!("C:\\Windows\\{parent}")),
                (
                    "CommandLine",
                    &format!("{lolbin} /s DavWWWRoot\\payload.dll"),
                ),
            ],
        )
    }

    #[test]
    fn rundll32_from_explorer_detected() {
        let ev = lolbin_from_parent("rundll32.exe", "explorer.exe");
        let hits = detect_explorer_lolbin(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::ExplorerLolbinExecution);
        assert_eq!(hits[0].mitre_technique_id, "T1204.002");
    }

    #[test]
    fn mshta_from_explorer_detected() {
        let ev = lolbin_from_parent("mshta.exe", "explorer.exe");
        assert!(!detect_explorer_lolbin(&[ev]).is_empty());
    }

    #[test]
    fn wscript_from_explorer_detected() {
        let ev = lolbin_from_parent("wscript.exe", "explorer.exe");
        assert!(!detect_explorer_lolbin(&[ev]).is_empty());
    }

    #[test]
    fn certutil_from_explorer_detected() {
        let ev = lolbin_from_parent("certutil.exe", "explorer.exe");
        assert!(!detect_explorer_lolbin(&[ev]).is_empty());
    }

    #[test]
    fn benign_process_from_explorer_not_detected() {
        // notepad.exe is not a LOLBin
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\notepad.exe"),
                ("ParentImage", "C:\\Windows\\explorer.exe"),
                ("CommandLine", "notepad.exe"),
            ],
        );
        assert!(detect_explorer_lolbin(&[ev]).is_empty());
    }

    #[test]
    fn lolbin_from_non_shell_parent_not_detected() {
        // rundll32 spawned from svchost is normal/expected
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\rundll32.exe"),
                ("ParentImage", "C:\\Windows\\System32\\svchost.exe"),
                (
                    "CommandLine",
                    "rundll32.exe shell32.dll,SHCreateLocalServerRunDll",
                ),
            ],
        );
        assert!(detect_explorer_lolbin(&[ev]).is_empty());
    }

    #[test]
    fn security_eid_4688_parent_process_name_detected() {
        // Security channel uses ParentProcessName instead of ParentImage
        let ev = make_event(
            EID_PROCESS_CREATE,
            "Security",
            &[
                ("NewProcessName", "C:\\Windows\\System32\\rundll32.exe"),
                ("ParentProcessName", "C:\\Windows\\explorer.exe"),
                ("CommandLine", "rundll32.exe DavWWWRoot\\x.dll"),
            ],
        );
        let hits = detect_explorer_lolbin(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::ExplorerLolbinExecution);
    }

    #[test]
    fn wrong_channel_not_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            "Application",
            &[
                ("Image", "C:\\Windows\\System32\\rundll32.exe"),
                ("ParentImage", "C:\\Windows\\explorer.exe"),
            ],
        );
        assert!(detect_explorer_lolbin(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_parent_and_image() {
        let ev = lolbin_from_parent("rundll32.exe", "explorer.exe");
        let hits = detect_explorer_lolbin(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("explorer") || combined.contains("ParentImage"));
        assert!(combined.contains("rundll32") || combined.contains("Image"));
    }
}
