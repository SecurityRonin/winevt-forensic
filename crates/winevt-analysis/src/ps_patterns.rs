//! Detect QWCrypt-specific PowerShell script block patterns (T1059.001).

use forensicnomicon::heuristics::evtx::{
    EID_PS_SCRIPT_BLOCK, POWERSHELL_OPERATIONAL_CHANNEL, QWCRYPT_PS_PATTERNS,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect QWCrypt/RedCurl-specific PowerShell script block patterns.
///
/// Fires on PowerShell/Operational EID 4104 (script block logged) where
/// `ScriptBlockText` contains any substring from [`QWCRYPT_PS_PATTERNS`]
/// — Hyper-V cmdlets (`Get-VM`, `Stop-VM`, etc.), shadow-copy deletion
/// commands, and recovery-disable commands observed in RedCurl intrusions
/// (T1059.001).
///
/// Returns one detection per matching event.
pub fn detect_ps_qwcrypt_patterns(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!("implement ps_patterns detector")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn ps_event(script: &str) -> winevt_core::EvtxEvent {
        make_event(
            EID_PS_SCRIPT_BLOCK,
            POWERSHELL_OPERATIONAL_CHANNEL,
            &[("ScriptBlockText", script)],
        )
    }

    #[test]
    fn stop_vm_in_script_block_detected() {
        let ev = ps_event("$vms = Get-VM; foreach ($vm in $vms) { Stop-VM -Name $vm.Name -Force }");
        let hits = detect_ps_qwcrypt_patterns(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::PsScriptBlockQwcrypt);
        assert_eq!(hits[0].mitre_technique_id, "T1059.001");
    }

    #[test]
    fn vssadmin_delete_in_script_block_detected() {
        let ev = ps_event("Invoke-Expression 'vssadmin delete shadows /all /quiet'");
        assert!(!detect_ps_qwcrypt_patterns(&[ev]).is_empty());
    }

    #[test]
    fn wrong_channel_not_detected() {
        let ev = make_event(
            EID_PS_SCRIPT_BLOCK,
            "Security",
            &[("ScriptBlockText", "Stop-VM -Name vm01")],
        );
        assert!(detect_ps_qwcrypt_patterns(&[ev]).is_empty());
    }

    #[test]
    fn unrelated_script_not_detected() {
        let ev = ps_event("Get-Process | Where-Object { $_.CPU -gt 10 }");
        assert!(detect_ps_qwcrypt_patterns(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_matched_pattern() {
        let ev = ps_event("Stop-VM -Name redcurl-target -TurnOff");
        let hits = detect_ps_qwcrypt_patterns(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(
            combined.contains("Stop-VM"),
            "evidence should contain the matched pattern"
        );
    }

    #[test]
    fn wbadmin_delete_detected() {
        let ev = ps_event("cmd /c wbadmin delete catalog -quiet");
        assert!(!detect_ps_qwcrypt_patterns(&[ev]).is_empty());
    }
}
