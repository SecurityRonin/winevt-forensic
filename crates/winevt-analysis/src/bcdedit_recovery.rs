//! Detect bcdedit recovery/boot tamper (T1490 / T1562.009).

use forensicnomicon::heuristics::evtx::{
    BCDEDIT_RECOVERY_DISABLE_PATTERNS, EID_PROCESS_CREATE, EID_SYSMON_PROCESS_CREATE,
    SYSMON_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect `bcdedit.exe` invocations that disable Windows boot recovery.
///
/// The three canonical ransomware bcdedit calls:
/// - `bcdedit /set {default} recoveryenabled no` — disables WinRE recovery.
/// - `bcdedit /set {default} bootstatuspolicy ignoreallfailures` — suppresses
///   the "Windows failed to start" repair screen after an encryption crash.
/// - `bcdedit /set {default} safeboot network` — reboots into Safe Mode to
///   bypass endpoint protection (AvosLocker/REvil/BlackBasta family pattern).
///
/// Near-zero FP — bcdedit is almost never used interactively outside IT imaging.
pub fn detect_bcdedit_recovery(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| is_process_event(ev))
        .filter_map(|ev| {
            let image = ev
                .data
                .get("Image")
                .or_else(|| ev.data.get("NewProcessName"))
                .map(String::as_str)
                .unwrap_or("");
            if basename(image).to_lowercase() != "bcdedit.exe" {
                return None;
            }
            let cl = ev.data.get("CommandLine").map(String::as_str).unwrap_or("");
            let cl_lower = cl.to_lowercase();
            let matched = BCDEDIT_RECOVERY_DISABLE_PATTERNS
                .iter()
                .find(|&&p| cl_lower.contains(p))?;
            Some(EvtxDetection {
                kind: EvtxDetectionKind::BcdeditRecoveryTamper,
                mitre_technique_id: "T1490",
                tactic: "Impact",
                description: format!(
                    "bcdedit.exe recovery tamper '{matched}' in command line: '{cl}'"
                ),
                evidence: vec![
                    format!("Image={image}"),
                    format!("CommandLine={cl}"),
                    format!("matched_pattern={matched}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn bcdedit_event(cmdline: &str) -> EvtxEvent {
        make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\bcdedit.exe"),
                ("CommandLine", cmdline),
            ],
        )
    }

    #[test]
    fn recoveryenabled_no_detected() {
        let ev = bcdedit_event("bcdedit /set {default} recoveryenabled no");
        let hits = detect_bcdedit_recovery(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::BcdeditRecoveryTamper);
        assert_eq!(hits[0].mitre_technique_id, "T1490");
    }

    #[test]
    fn bootstatuspolicy_ignoreallfailures_detected() {
        let ev = bcdedit_event("bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures");
        assert!(!detect_bcdedit_recovery(&[ev]).is_empty());
    }

    #[test]
    fn safeboot_network_detected() {
        let ev = bcdedit_event("bcdedit /set {default} safeboot network");
        assert!(!detect_bcdedit_recovery(&[ev]).is_empty());
    }

    #[test]
    fn bcdedit_enum_not_detected() {
        let ev = bcdedit_event("bcdedit /enum all");
        assert!(detect_bcdedit_recovery(&[ev]).is_empty());
    }

    #[test]
    fn non_bcdedit_not_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\cmd.exe"),
                ("CommandLine", "cmd.exe /c bcdedit /set recoveryenabled no"),
            ],
        );
        // cmd.exe is not bcdedit — should not match
        assert!(detect_bcdedit_recovery(&[ev]).is_empty());
    }

    #[test]
    fn security_eid_4688_bcdedit_detected() {
        let ev = make_event(
            EID_PROCESS_CREATE,
            "Security",
            &[
                ("NewProcessName", "C:\\Windows\\System32\\bcdedit.exe"),
                ("CommandLine", "bcdedit /set recoveryenabled no"),
            ],
        );
        assert!(!detect_bcdedit_recovery(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_tamper_pattern() {
        let ev = bcdedit_event("bcdedit /set {default} recoveryenabled no");
        let hits = detect_bcdedit_recovery(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("recoveryenabled") || combined.contains("bcdedit"));
    }
}
