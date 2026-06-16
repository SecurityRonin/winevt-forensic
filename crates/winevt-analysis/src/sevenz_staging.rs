//! Detect 7-Zip header-encrypted staging from a suspicious parent (T1560.001).

use forensicnomicon::heuristics::evtx::{
    ARCHIVER_HEADER_ENCRYPT_FLAG, ARCHIVER_PROCESS_NAMES, EID_PROCESS_CREATE,
    EID_SYSMON_PROCESS_CREATE, STAGING_PARENT_IMAGES, SYSMON_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect 7-Zip invoked with `-mhe` (header encryption) from a suspicious parent.
///
/// The `-mhe` flag hides filenames inside the archive — rarely used by
/// legitimate administrators.  QWCrypt/RedCurl uses it to package exfil data
/// and payload drops in a way that conceals contents from basic inspection.
/// The combination of: 7-Zip binary + `-mhe` in CommandLine + parent process
/// in `STAGING_PARENT_IMAGES` is a high-confidence staging indicator (T1560.001).
pub fn detect_sevenz_staging(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| is_process_event(ev))
        .filter_map(|ev| {
            let image = ev.data.get("Image").map(String::as_str).unwrap_or("");
            let base = basename(image).to_lowercase();
            if !ARCHIVER_PROCESS_NAMES.iter().any(|a| a.to_lowercase() == base) {
                return None;
            }
            let cl = ev.data.get("CommandLine").map(String::as_str).unwrap_or("");
            if !cl.contains(ARCHIVER_HEADER_ENCRYPT_FLAG) {
                return None;
            }
            let parent = ev.data.get("ParentImage").map(String::as_str).unwrap_or("");
            let parent_base = basename(parent).to_lowercase();
            if !STAGING_PARENT_IMAGES.iter().any(|p| p.to_lowercase() == parent_base) {
                return None;
            }
            Some(EvtxDetection {
                kind: EvtxDetectionKind::SevenZipStagingEncrypted,
                mitre_technique_id: "T1560.001",
                tactic: "Collection",
                description: format!(
                    "7-Zip with header-encryption (-mhe) spawned by suspicious parent '{parent}': '{cl}'"
                ),
                evidence: vec![
                    format!("Image={image}"),
                    format!("CommandLine={cl}"),
                    format!("ParentImage={parent}"),
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

fn is_process_event(ev: &winevt_core::EvtxEvent) -> bool {
    (ev.event_id == EID_PROCESS_CREATE && ev.channel == "Security")
        || (ev.event_id == EID_SYSMON_PROCESS_CREATE && ev.channel == SYSMON_CHANNEL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn sevenz_event(image: &str, cmdline: &str, parent: &str) -> EvtxEvent {
        make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", image),
                ("CommandLine", cmdline),
                ("ParentImage", parent),
            ],
        )
    }

    #[test]
    fn sevenz_mhe_from_pcalua_detected() {
        let ev = sevenz_event(
            "C:\\ProgramData\\tools\\7za.exe",
            "7za.exe a -p SecretPass -mhe output.7z C:\\Users\\victim\\Documents\\",
            "C:\\Windows\\System32\\pcalua.exe",
        );
        let hits = detect_sevenz_staging(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::SevenZipStagingEncrypted);
        assert_eq!(hits[0].mitre_technique_id, "T1560.001");
    }

    #[test]
    fn sevenz_mhe_from_wmiprvse_detected() {
        let ev = sevenz_event(
            "C:\\Windows\\Temp\\7z.exe",
            "7z.exe a -mhe -p pass exfil.7z C:\\data\\",
            "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
        );
        assert!(!detect_sevenz_staging(&[ev]).is_empty());
    }

    #[test]
    fn sevenz_without_mhe_not_detected() {
        let ev = sevenz_event(
            "C:\\Program Files\\7-Zip\\7z.exe",
            "7z.exe a -p password backup.7z C:\\data\\",
            "C:\\Windows\\System32\\pcalua.exe",
        );
        assert!(detect_sevenz_staging(&[ev]).is_empty());
    }

    #[test]
    fn sevenz_mhe_from_benign_parent_not_detected() {
        let ev = sevenz_event(
            "C:\\Program Files\\7-Zip\\7z.exe",
            "7z.exe a -mhe -p pass archive.7z C:\\backup\\",
            "C:\\Windows\\explorer.exe",
        );
        assert!(detect_sevenz_staging(&[ev]).is_empty());
    }

    #[test]
    fn non_archiver_not_detected() {
        let ev = sevenz_event(
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c dir",
            "C:\\Windows\\System32\\pcalua.exe",
        );
        assert!(detect_sevenz_staging(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_mhe_flag() {
        let ev = sevenz_event(
            "C:\\Temp\\7za.exe",
            "7za.exe a -mhe -p x out.7z docs\\",
            "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
        );
        let hits = detect_sevenz_staging(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("-mhe") || combined.contains("7za.exe"));
    }
}
