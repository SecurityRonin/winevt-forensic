//! MITRE-tagged forensic detectors for Windows Event Log artifacts.
//!
//! All detectors accept a slice of parsed [`winevt_core::EvtxEvent`] records
//! and return a `Vec<EvtxDetection>`.  They are pure functions with no I/O.
//!
//! Call [`detect_all`] to run every detector and get results sorted by
//! timestamp then MITRE technique ID.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
)]

pub mod adexplorer_recon;
pub mod byovd;
pub mod dll_sideload;
pub mod fake_browser_task;
pub mod hvci;
pub mod hyperv;
pub mod ps_history_wipe;
pub mod ps_patterns;
pub mod qwcrypt_proc;
pub mod ransom_note;
pub mod rpivot_chisel;
pub mod scheduled_task;
pub mod sevenz_staging;
pub mod vss;
pub mod webclient_service;
pub mod webdav_lolbin;
pub mod wmi_lateral;
pub mod workers_dev_dns;
pub mod zemana_driver_load;

pub use adexplorer_recon::detect_adexplorer_recon;
pub use byovd::detect_byovd_driver_install;
pub use dll_sideload::detect_dll_sideload;
pub use fake_browser_task::detect_fake_browser_task;
pub use hvci::detect_hvci_registry_tamper;
pub use hyperv::detect_hyperv_vm_shutdown;
pub use ps_history_wipe::detect_ps_history_wipe;
pub use ps_patterns::detect_ps_qwcrypt_patterns;
pub use qwcrypt_proc::detect_qwcrypt_process;
pub use ransom_note::detect_ransom_note_creation;
pub use rpivot_chisel::detect_rpivot_chisel;
pub use scheduled_task::detect_scheduled_task_creation;
pub use sevenz_staging::detect_sevenz_staging;
pub use vss::detect_vss_deletion;
pub use webclient_service::detect_webclient_service_start;
pub use webdav_lolbin::detect_webdav_lolbin;
pub use wmi_lateral::detect_wmi_lateral_movement;
pub use workers_dev_dns::detect_workers_dev_dns;
pub use zemana_driver_load::detect_zemana_driver_load;

use winevt_core::EvtxEvent;

/// Category of a Windows Event Log detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum EvtxDetectionKind {
    /// A known-vulnerable driver service was installed (T1068 — Exploit Public-Facing Application / BYOVD).
    ByovdDriverInstall,
    /// A security-sensitive registry value controlling HVCI or VBS was modified (T1562.001).
    HvciRegistryTamper,
    /// Shadow copies were deleted — inhibit system recovery (T1490).
    VssDeletion,
    /// Hyper-V VM(s) shut down — pre-encryption step in QWCrypt-style ransomware (T1486).
    HypervVmShutdown,
    /// A scheduled task was created — persistence mechanism (T1053.005).
    ScheduledTaskCreation,
    /// A known QWCrypt/RedCurl binary executed (T1486).
    QwcryptProcessExecution,
    /// A PowerShell script block matched QWCrypt/RedCurl-specific patterns (T1059.001).
    PsScriptBlockQwcrypt,
    /// A LOLBin process initiated a WebDAV connection — staging or exfiltration (T1102).
    WebdavLolbinUsage,
    /// A ransom note file was created on disk (T1486 — Data Encrypted for Impact).
    RansomNoteCreated,
    /// WebClient (Mini-Redirector) service started — precursor to WebDAV payload delivery (T1102).
    WebClientServiceStart,
    /// Sysinternals AD Explorer first-run registry key created — domain recon tombstone (T1087).
    AdExplorerRecon,
    /// Zemana signed driver loaded from a non-standard path — BYOVD EDR killer (T1068).
    ZemanaDriverLoad,
    /// srvcli.dll or netutils.dll loaded from a user-writable path — DLL sideload (T1574.002).
    DllSideloadHijack,
    /// ConsoleHost_history.txt deleted — PowerShell history anti-forensics (T1070.003).
    PsHistoryWipe,
    /// RPivot or Chisel tunnel tool executed — reverse proxy / SOCKS5 (T1090).
    RpivotChisel,
    /// WMI permanent event consumer created or Impacket wmiexec output-redirect detected (T1047).
    WmiLateralMovement,
    /// 7-Zip executed with header-encryption flag (-mhe) from a suspicious parent (T1560.001).
    SevenZipStagingEncrypted,
    /// Scheduled task with browser-update name but action path outside Program Files (T1053.005).
    FakeBrowserTask,
    /// Non-browser process issued a DNS query for a .workers.dev domain — Cloudflare C2 (T1102).
    WorkersDevDnsQuery,
}

/// A single detection produced by an EVTX detector.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvtxDetection {
    pub kind: EvtxDetectionKind,
    /// MITRE ATT&CK technique ID.
    pub mitre_technique_id: &'static str,
    /// ATT&CK tactic name.
    pub tactic: &'static str,
    /// Human-readable finding description.
    pub description: String,
    /// Evidence items: field names and values that triggered this detection.
    pub evidence: Vec<String>,
    /// Nanosecond-precision timestamp of the triggering event.
    pub timestamp_ns: i64,
    /// Windows Event ID of the triggering event.
    pub event_id: u32,
    /// Event log channel the event was read from.
    pub channel: String,
}

/// Run all EVTX detectors over a slice of events.
///
/// Results are sorted by `timestamp_ns` then `mitre_technique_id` for
/// deterministic, diff-friendly output.
pub fn detect_all(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    let mut results = Vec::new();
    results.extend(detect_byovd_driver_install(events));
    results.extend(detect_hvci_registry_tamper(events));
    results.extend(detect_vss_deletion(events));
    results.extend(detect_hyperv_vm_shutdown(events));
    results.extend(detect_scheduled_task_creation(events));
    results.extend(detect_qwcrypt_process(events));
    results.extend(detect_ps_qwcrypt_patterns(events));
    results.extend(detect_webdav_lolbin(events));
    results.extend(detect_ransom_note_creation(events));
    results.extend(detect_webclient_service_start(events));
    results.extend(detect_adexplorer_recon(events));
    results.extend(detect_zemana_driver_load(events));
    results.extend(detect_dll_sideload(events));
    results.extend(detect_ps_history_wipe(events));
    results.extend(detect_rpivot_chisel(events));
    results.extend(detect_wmi_lateral_movement(events));
    results.extend(detect_sevenz_staging(events));
    results.extend(detect_fake_browser_task(events));
    results.extend(detect_workers_dev_dns(events));
    results.sort_by(|a, b| {
        a.timestamp_ns
            .cmp(&b.timestamp_ns)
            .then(a.mitre_technique_id.cmp(b.mitre_technique_id))
    });
    results
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::collections::HashMap;
    use winevt_core::EvtxEvent;

    pub fn make_event(event_id: u32, channel: &str, data: &[(&str, &str)]) -> EvtxEvent {
        EvtxEvent {
            event_id,
            channel: channel.to_string(),
            timestamp_ns: 1_700_000_000_000_000_000,
            computer: "test-pc".to_string(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data: data
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::make_event;

    #[test]
    fn detect_all_empty_returns_empty() {
        assert!(detect_all(&[]).is_empty());
    }

    #[test]
    fn detect_all_byovd_event_detected() {
        let ev = make_event(7045, "System", &[("ServiceName", "zamguard64")]);
        let hits = detect_all(&[ev]);
        assert!(hits.iter().any(|h| h.kind == EvtxDetectionKind::ByovdDriverInstall));
    }

    #[test]
    fn detect_all_results_sorted_by_timestamp_then_mitre() {
        let ev1 = make_event(7045, "System", &[("ServiceName", "zamguard64")]);
        let ev2 = make_event(8193, "Application", &[("Source", "VSS")]);
        let hits = detect_all(&[ev1, ev2]);
        for w in hits.windows(2) {
            assert!(
                w[0].timestamp_ns <= w[1].timestamp_ns,
                "results must be sorted by timestamp"
            );
        }
    }
}
