//! Detect non-browser DNS queries to .workers.dev — Cloudflare C2 (T1102).

use forensicnomicon::heuristics::evtx::{
    BROWSER_PROCESS_NAMES, CLOUDFLARE_WORKERS_DOMAIN_SUFFIX, EID_SYSMON_DNS_QUERY, SYSMON_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect non-browser processes querying `.workers.dev` domains.
///
/// QWCrypt/RedCurl uses Cloudflare Workers as rotating C2 redirectors (T1102).
/// Sysmon EID 22 (DnsQuery) captures `QueryName` and `Image` (the process).
/// Browsers legitimately query `.workers.dev`; every other process doing so is
/// suspicious — especially `rundll32.exe`, `powershell.exe`, `pcalua.exe`,
/// `python.exe`, and `ADNotificationManager.exe`.
pub fn detect_workers_dev_dns(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| ev.event_id == EID_SYSMON_DNS_QUERY && ev.channel == SYSMON_CHANNEL)
        .filter_map(|ev| {
            let query = ev.data.get("QueryName")?;
            if !query.ends_with(CLOUDFLARE_WORKERS_DOMAIN_SUFFIX) {
                return None;
            }
            let image = ev.data.get("Image").map(String::as_str).unwrap_or("");
            if is_browser(image) {
                return None;
            }
            Some(EvtxDetection {
                kind: EvtxDetectionKind::WorkersDevDnsQuery,
                mitre_technique_id: "T1102",
                tactic: "Command and Control",
                description: format!(
                    "Non-browser process queried Cloudflare Workers domain: '{query}' (process: '{image}')"
                ),
                evidence: vec![
                    format!("QueryName={query}"),
                    format!("Image={image}"),
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

fn is_browser(image: &str) -> bool {
    let base = basename(image).to_lowercase();
    BROWSER_PROCESS_NAMES
        .iter()
        .any(|b| b.to_lowercase() == base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn dns_query(image: &str, query: &str) -> EvtxEvent {
        make_event(
            EID_SYSMON_DNS_QUERY,
            SYSMON_CHANNEL,
            &[("Image", image), ("QueryName", query)],
        )
    }

    #[test]
    fn rundll32_workers_dev_detected() {
        let ev = dns_query(
            "C:\\Windows\\System32\\rundll32.exe",
            "live.itsmartuniverse.workers.dev",
        );
        let hits = detect_workers_dev_dns(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::WorkersDevDnsQuery);
        assert_eq!(hits[0].mitre_technique_id, "T1102");
    }

    #[test]
    fn powershell_workers_dev_detected() {
        let ev = dns_query(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "datascience.iotconnectivity.workers.dev",
        );
        assert!(!detect_workers_dev_dns(&[ev]).is_empty());
    }

    #[test]
    fn python_workers_dev_detected() {
        let ev = dns_query(
            "C:\\ProgramData\\redcurl\\python.exe",
            "automatinghrservices.workers.dev",
        );
        assert!(!detect_workers_dev_dns(&[ev]).is_empty());
    }

    #[test]
    fn chrome_workers_dev_not_detected() {
        let ev = dns_query(
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "some-app.workers.dev",
        );
        assert!(detect_workers_dev_dns(&[ev]).is_empty());
    }

    #[test]
    fn edge_workers_dev_not_detected() {
        let ev = dns_query(
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "example.workers.dev",
        );
        assert!(detect_workers_dev_dns(&[ev]).is_empty());
    }

    #[test]
    fn non_workers_dev_domain_not_detected() {
        let ev = dns_query("C:\\Windows\\System32\\rundll32.exe", "microsoft.com");
        assert!(detect_workers_dev_dns(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(
            1,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\rundll32.exe"),
                ("QueryName", "evil.workers.dev"),
            ],
        );
        assert!(detect_workers_dev_dns(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_domain_and_process() {
        let ev = dns_query(
            "C:\\Windows\\System32\\rundll32.exe",
            "live.itsmartuniverse.workers.dev",
        );
        let hits = detect_workers_dev_dns(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("workers.dev") || combined.contains("rundll32"));
    }
}
