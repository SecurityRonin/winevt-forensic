//! Detect ransom note file creation via Sysmon EID 11 (T1486).

use forensicnomicon::heuristics::evtx::{EID_SYSMON_FILE_CREATE, SYSMON_CHANNEL};
use forensicnomicon::heuristics::ransomware::RANSOM_NOTE_FILENAMES;
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect ransom note file creation in Sysmon EID 11 events.
///
/// Fires on Sysmon/Operational EID 11 (FileCreate) where the basename of
/// `TargetFilename` matches any entry in [`RANSOM_NOTE_FILENAMES`] (case-
/// insensitive).  Covers 50+ ransomware families including STOP/DJVU,
/// LockBit, BlackCat/ALPHV, Hive, Akira, and QWCrypt/RedCurl (T1486).
///
/// Returns one detection per matching event.
pub fn detect_ransom_note_creation(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| ev.event_id == EID_SYSMON_FILE_CREATE && ev.channel == SYSMON_CHANNEL)
        .filter_map(|ev| {
            let path = ev.data.get("TargetFilename")?;
            let base = basename(path);
            let base_lower = base.to_lowercase();
            RANSOM_NOTE_FILENAMES
                .iter()
                .find(|&&note| note.to_lowercase() == base_lower)
                .map(|&matched| EvtxDetection {
                    kind: EvtxDetectionKind::RansomNoteCreated,
                    mitre_technique_id: "T1486",
                    tactic: "Impact",
                    description: format!("Ransom note created: '{path}' (matched '{matched}')"),
                    evidence: vec![
                        format!("TargetFilename={path}"),
                        format!("matched_note={matched}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn file_create(target: &str) -> winevt_core::EvtxEvent {
        make_event(
            EID_SYSMON_FILE_CREATE,
            SYSMON_CHANNEL,
            &[("TargetFilename", target)],
        )
    }

    #[test]
    fn stop_djvu_readme_detected() {
        let ev = file_create("C:\\Users\\victim\\Documents\\_readme.txt");
        let hits = detect_ransom_note_creation(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::RansomNoteCreated);
        assert_eq!(hits[0].mitre_technique_id, "T1486");
    }

    #[test]
    fn lockbit_readme_detected() {
        let ev = file_create("C:\\Windows\\Temp\\LockBit_README.txt");
        assert!(!detect_ransom_note_creation(&[ev]).is_empty());
    }

    #[test]
    fn hive_note_detected() {
        let ev = file_create("D:\\Shares\\Finance\\HOW_TO_DECRYPT.txt");
        assert!(!detect_ransom_note_creation(&[ev]).is_empty());
    }

    #[test]
    fn wannacry_note_detected() {
        let ev = file_create("C:\\Users\\Public\\@Please_Read_Me@.txt");
        assert!(!detect_ransom_note_creation(&[ev]).is_empty());
    }

    #[test]
    fn akira_note_detected() {
        let ev = file_create("E:\\Backups\\akira_readme.txt");
        assert!(!detect_ransom_note_creation(&[ev]).is_empty());
    }

    #[test]
    fn qwcrypt_note_detected() {
        let ev = file_create("C:\\Hyper-V\\Virtual Machines\\FILES_ENCRYPTED.txt");
        assert!(!detect_ransom_note_creation(&[ev]).is_empty());
    }

    #[test]
    fn benign_file_not_detected() {
        let ev = file_create("C:\\Users\\alice\\Documents\\report.docx");
        assert!(detect_ransom_note_creation(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(
            4688,
            SYSMON_CHANNEL,
            &[("TargetFilename", "C:\\Temp\\_readme.txt")],
        );
        assert!(detect_ransom_note_creation(&[ev]).is_empty());
    }

    #[test]
    fn wrong_channel_not_detected() {
        let ev = make_event(
            EID_SYSMON_FILE_CREATE,
            "Security",
            &[("TargetFilename", "C:\\Temp\\_readme.txt")],
        );
        assert!(detect_ransom_note_creation(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_full_path() {
        let ev = file_create("C:\\Users\\victim\\Desktop\\_readme.txt");
        let hits = detect_ransom_note_creation(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("_readme.txt"));
    }

    #[test]
    fn multiple_notes_produce_multiple_detections() {
        let events = vec![
            file_create("C:\\Users\\alice\\_readme.txt"),
            file_create("C:\\Users\\bob\\_readme.txt"),
            file_create("C:\\Temp\\HOW_TO_DECRYPT.txt"),
        ];
        assert_eq!(detect_ransom_note_creation(&events).len(), 3);
    }
}
