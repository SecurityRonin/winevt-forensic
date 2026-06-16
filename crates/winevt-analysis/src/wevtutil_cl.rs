//! Detect event log clearing via wevtutil.exe or PowerShell Clear-EventLog (T1070.001).

use forensicnomicon::heuristics::evtx::{
    EID_PROCESS_CREATE, EID_PS_SCRIPT_BLOCK, EID_SYSMON_PROCESS_CREATE,
    POWERSHELL_OPERATIONAL_CHANNEL, PS_CLEAR_EVENTLOG_PATTERNS, SYSMON_CHANNEL,
    WEVTUTIL_CLEAR_SUBSTRINGS,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect event log clearing by `wevtutil.exe cl` or PowerShell `Clear-EventLog`.
///
/// Two signal sources:
/// 1. **Process create** (EID 4688 / Sysmon 1) with `Image` ending in
///    `wevtutil.exe` and `CommandLine` containing ` cl ` or `clear-log`.
/// 2. **PowerShell script block** (EID 4104) with `ScriptBlockText` containing
///    `Clear-EventLog`, `Remove-EventLog`, or `wevtutil cl`.
///
/// ~30/76 ransomware families clear logs post-encryption (T1070.001).
pub fn detect_wevtutil_cl(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter_map(|ev| {
            // Signal 1: wevtutil process create
            if is_process_event(ev) {
                let image = ev
                    .data
                    .get("Image")
                    .or_else(|| ev.data.get("NewProcessName"))
                    .map(String::as_str)
                    .unwrap_or("");
                if basename(image).to_lowercase() == "wevtutil.exe" {
                    let cl = ev.data.get("CommandLine").map(String::as_str).unwrap_or("");
                    let cl_lower = cl.to_lowercase();
                    if let Some(&pat) = WEVTUTIL_CLEAR_SUBSTRINGS
                        .iter()
                        .find(|&&p| cl_lower.contains(p))
                    {
                        return Some(EvtxDetection {
                            kind: EvtxDetectionKind::WevtutilLogClear,
                            mitre_technique_id: "T1070.001",
                            tactic: "Defense Evasion",
                            description: format!(
                                "wevtutil log-clear pattern '{pat}' in command line: '{cl}'"
                            ),
                            evidence: vec![format!("Image={image}"), format!("CommandLine={cl}")],
                            timestamp_ns: ev.timestamp_ns,
                            event_id: ev.event_id,
                            channel: ev.channel.clone(),
                        });
                    }
                }
            }
            // Signal 2: PowerShell script block containing log-clear patterns
            if ev.event_id == EID_PS_SCRIPT_BLOCK && ev.channel == POWERSHELL_OPERATIONAL_CHANNEL {
                let script = ev
                    .data
                    .get("ScriptBlockText")
                    .map(String::as_str)
                    .unwrap_or("");
                if let Some(&pat) = PS_CLEAR_EVENTLOG_PATTERNS
                    .iter()
                    .find(|&&p| script.contains(p))
                {
                    return Some(EvtxDetection {
                        kind: EvtxDetectionKind::WevtutilLogClear,
                        mitre_technique_id: "T1070.001",
                        tactic: "Defense Evasion",
                        description: format!(
                            "PowerShell log-clear pattern '{pat}' in script block"
                        ),
                        evidence: vec![
                            format!(
                                "ScriptBlockText snippet: ...{}...",
                                &script[..script.len().min(120)]
                            ),
                            format!("matched_pattern={pat}"),
                        ],
                        timestamp_ns: ev.timestamp_ns,
                        event_id: ev.event_id,
                        channel: ev.channel.clone(),
                    });
                }
            }
            None
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

    #[test]
    fn wevtutil_cl_security_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\wevtutil.exe"),
                ("CommandLine", "wevtutil.exe cl Security"),
            ],
        );
        let hits = detect_wevtutil_cl(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::WevtutilLogClear);
        assert_eq!(hits[0].mitre_technique_id, "T1070.001");
    }

    #[test]
    fn wevtutil_enum_not_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\wevtutil.exe"),
                ("CommandLine", "wevtutil.exe el"),
            ],
        );
        assert!(detect_wevtutil_cl(&[ev]).is_empty());
    }

    #[test]
    fn powershell_clear_eventlog_detected() {
        let ev = make_event(
            EID_PS_SCRIPT_BLOCK,
            POWERSHELL_OPERATIONAL_CHANNEL,
            &[(
                "ScriptBlockText",
                "Clear-EventLog -LogName Security,System,Application",
            )],
        );
        assert!(!detect_wevtutil_cl(&[ev]).is_empty());
    }

    #[test]
    fn powershell_wevtutil_cl_in_scriptblock_detected() {
        let ev = make_event(
            EID_PS_SCRIPT_BLOCK,
            POWERSHELL_OPERATIONAL_CHANNEL,
            &[(
                "ScriptBlockText",
                "& wevtutil cl Security; wevtutil cl System",
            )],
        );
        assert!(!detect_wevtutil_cl(&[ev]).is_empty());
    }

    #[test]
    fn benign_powershell_not_detected() {
        let ev = make_event(
            EID_PS_SCRIPT_BLOCK,
            POWERSHELL_OPERATIONAL_CHANNEL,
            &[(
                "ScriptBlockText",
                "Get-EventLog -LogName Security -Newest 10",
            )],
        );
        assert!(detect_wevtutil_cl(&[ev]).is_empty());
    }

    #[test]
    fn non_wevtutil_process_not_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\cmd.exe"),
                ("CommandLine", "cmd.exe /c wevtutil cl Security"),
            ],
        );
        assert!(detect_wevtutil_cl(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_log_name() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\wevtutil.exe"),
                ("CommandLine", "wevtutil cl System"),
            ],
        );
        let hits = detect_wevtutil_cl(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("wevtutil") || combined.contains("System"));
    }
}
