//! Detect Defender / EDR disablement via PowerShell or Defender EID 5001 (T1562.001).

use forensicnomicon::heuristics::evtx::{
    DEFENDER_CHANNEL, DEFENDER_TAMPER_PATTERNS, EID_DEFENDER_REALTIME_DISABLED,
    EID_PS_SCRIPT_BLOCK, POWERSHELL_OPERATIONAL_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect Windows Defender / EDR disablement.
///
/// Two signals:
/// 1. **PowerShell EID 4104** — `ScriptBlockText` contains any of
///    `DEFENDER_TAMPER_PATTERNS` (e.g. `Set-MpPreference -DisableRealtimeMonitoring`).
/// 2. **Defender EID 5001** on the Defender Operational channel — real-time
///    protection disabled.
///
/// ~30/76 ransomware families attempt Defender disablement (T1562.001).
pub fn detect_defender_disable(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter_map(|ev| {
            // Signal 1: PowerShell EID 4104 with Defender tamper patterns
            if ev.event_id == EID_PS_SCRIPT_BLOCK && ev.channel == POWERSHELL_OPERATIONAL_CHANNEL {
                let script = ev
                    .data
                    .get("ScriptBlockText")
                    .map(String::as_str)
                    .unwrap_or("");
                if let Some(&pat) = DEFENDER_TAMPER_PATTERNS
                    .iter()
                    .find(|&&p| script.contains(p))
                {
                    return Some(EvtxDetection {
                        kind: EvtxDetectionKind::DefenderDisabled,
                        mitre_technique_id: "T1562.001",
                        tactic: "Defense Evasion",
                        description: format!(
                            "Defender/AV tamper pattern '{pat}' in PowerShell script block"
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
            // Signal 2: Defender EID 5001 — real-time protection disabled
            if ev.event_id == EID_DEFENDER_REALTIME_DISABLED && ev.channel == DEFENDER_CHANNEL {
                return Some(EvtxDetection {
                    kind: EvtxDetectionKind::DefenderDisabled,
                    mitre_technique_id: "T1562.001",
                    tactic: "Defense Evasion",
                    description: "Windows Defender real-time protection was disabled (EID 5001)"
                        .to_string(),
                    evidence: vec![
                        format!("event_id={}", ev.event_id),
                        format!("channel={}", ev.channel),
                    ],
                    timestamp_ns: ev.timestamp_ns,
                    event_id: ev.event_id,
                    channel: ev.channel.clone(),
                });
            }
            None
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    #[test]
    fn set_mppreference_disable_realtime_detected() {
        let ev = make_event(
            EID_PS_SCRIPT_BLOCK,
            POWERSHELL_OPERATIONAL_CHANNEL,
            &[(
                "ScriptBlockText",
                "Set-MpPreference -DisableRealtimeMonitoring $true",
            )],
        );
        let hits = detect_defender_disable(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::DefenderDisabled);
        assert_eq!(hits[0].mitre_technique_id, "T1562.001");
    }

    #[test]
    fn add_mppreference_exclusionpath_detected() {
        let ev = make_event(
            EID_PS_SCRIPT_BLOCK,
            POWERSHELL_OPERATIONAL_CHANNEL,
            &[(
                "ScriptBlockText",
                "Add-MpPreference -ExclusionPath C:\\Temp",
            )],
        );
        assert!(!detect_defender_disable(&[ev]).is_empty());
    }

    #[test]
    fn defender_eid_5001_detected() {
        let ev = make_event(
            EID_DEFENDER_REALTIME_DISABLED,
            DEFENDER_CHANNEL,
            &[("Category", "1009")],
        );
        let hits = detect_defender_disable(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::DefenderDisabled);
    }

    #[test]
    fn benign_mppreference_get_not_detected() {
        let ev = make_event(
            EID_PS_SCRIPT_BLOCK,
            POWERSHELL_OPERATIONAL_CHANNEL,
            &[("ScriptBlockText", "Get-MpPreference")],
        );
        assert!(detect_defender_disable(&[ev]).is_empty());
    }

    #[test]
    fn wrong_powershell_channel_not_detected() {
        let ev = make_event(
            EID_PS_SCRIPT_BLOCK,
            "Application",
            &[(
                "ScriptBlockText",
                "Set-MpPreference -DisableRealtimeMonitoring $true",
            )],
        );
        assert!(detect_defender_disable(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_tamper_pattern() {
        let ev = make_event(
            EID_PS_SCRIPT_BLOCK,
            POWERSHELL_OPERATIONAL_CHANNEL,
            &[(
                "ScriptBlockText",
                "Set-MpPreference -DisableRealtimeMonitoring $true",
            )],
        );
        let hits = detect_defender_disable(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(
            combined.contains("DisableRealtimeMonitoring") || combined.contains("MpPreference")
        );
    }
}
