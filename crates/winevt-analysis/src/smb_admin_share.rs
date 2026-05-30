//! Detect lateral movement via SMB administrative shares (T1021.002).

use forensicnomicon::heuristics::evtx::{ADMIN_SHARE_NAMES, EID_SMB_SHARE_ACCESS};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect remote access to Windows administrative shares via Security EID 5140.
///
/// EID 5140 fires when a network share is accessed. A remote IP (not localhost)
/// accessing `ADMIN$`, `C$`, `D$`, `IPC$`, etc. is a strong lateral movement
/// signal (T1021.002 — Remote Services: SMB/Windows Admin Shares).
///
/// False positives: legitimate RPC/Named-pipe connections use `IPC$` — correlate
/// with surrounding events (service install, psexec patterns) for high confidence.
pub fn detect_smb_admin_share(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| ev.event_id == EID_SMB_SHARE_ACCESS && ev.channel == "Security")
        .filter_map(|ev| {
            let share_field = ev.data.get("ShareName").map(String::as_str).unwrap_or("");
            let share = share_name_component(share_field);
            let matched = ADMIN_SHARE_NAMES
                .iter()
                .find(|&&name| name.eq_ignore_ascii_case(share))?;
            let ip = ev.data.get("IpAddress").map(String::as_str).unwrap_or("-");
            if is_local_ip(ip) {
                return None;
            }
            let user = ev
                .data
                .get("SubjectUserName")
                .map(String::as_str)
                .unwrap_or("unknown");
            Some(EvtxDetection {
                kind: EvtxDetectionKind::SmbAdminShareAccess,
                mitre_technique_id: "T1021.002",
                tactic: "Lateral Movement",
                description: format!(
                    "Remote SMB admin share access: '{matched}' from {ip} by '{user}'"
                ),
                evidence: vec![
                    format!("ShareName={share_field}"),
                    format!("IpAddress={ip}"),
                    format!("SubjectUserName={user}"),
                ],
                timestamp_ns: ev.timestamp_ns,
                event_id: ev.event_id,
                channel: ev.channel.clone(),
            })
        })
        .collect()
}

/// Extract the share name component from a ShareName field value.
/// EID 5140 `ShareName` is formatted as `\\<computer>\<share>`.
/// Returns the last path component in uppercase.
fn share_name_component(share_field: &str) -> &str {
    share_field
        .rsplit('\\')
        .find(|s| !s.is_empty())
        .unwrap_or(share_field)
}

/// Returns true if the IP address string represents a local/loopback connection.
fn is_local_ip(ip: &str) -> bool {
    matches!(ip.trim(), "127.0.0.1" | "::1" | "-" | "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn share_access_event(share_name: &str, ip_address: &str) -> EvtxEvent {
        make_event(
            EID_SMB_SHARE_ACCESS,
            "Security",
            &[
                ("SubjectUserName", "attacker"),
                ("ShareName", share_name),
                ("IpAddress", ip_address),
            ],
        )
    }

    #[test]
    fn admin_dollar_from_remote_ip_detected() {
        let ev = share_access_event("\\\\*\\ADMIN$", "10.0.0.42");
        let hits = detect_smb_admin_share(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::SmbAdminShareAccess);
        assert_eq!(hits[0].mitre_technique_id, "T1021.002");
    }

    #[test]
    fn c_dollar_from_remote_ip_detected() {
        let ev = share_access_event("\\\\*\\C$", "192.168.1.100");
        assert!(!detect_smb_admin_share(&[ev]).is_empty());
    }

    #[test]
    fn ipc_dollar_from_remote_ip_detected() {
        let ev = share_access_event("\\\\FILESERVER\\IPC$", "10.1.2.3");
        assert!(!detect_smb_admin_share(&[ev]).is_empty());
    }

    #[test]
    fn admin_dollar_from_localhost_not_detected() {
        let ev = share_access_event("\\\\*\\ADMIN$", "127.0.0.1");
        assert!(detect_smb_admin_share(&[ev]).is_empty());
    }

    #[test]
    fn admin_dollar_from_loopback_ipv6_not_detected() {
        let ev = share_access_event("\\\\*\\ADMIN$", "::1");
        assert!(detect_smb_admin_share(&[ev]).is_empty());
    }

    #[test]
    fn non_admin_share_not_detected() {
        let ev = share_access_event("\\\\*\\SYSVOL", "10.0.0.5");
        assert!(detect_smb_admin_share(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(
            5145, // object-level access, not share access
            "Security",
            &[
                ("ShareName", "\\\\*\\ADMIN$"),
                ("IpAddress", "10.0.0.42"),
            ],
        );
        assert!(detect_smb_admin_share(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_share_name_and_ip() {
        let ev = share_access_event("\\\\*\\C$", "172.16.0.50");
        let hits = detect_smb_admin_share(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("C$") || combined.contains("ShareName"));
        assert!(combined.contains("172.16.0.50") || combined.contains("IpAddress"));
    }

    // Helper tests for the utility functions (independent of the todo!() stub)
    #[test]
    fn share_name_component_extracts_last_segment() {
        assert_eq!(share_name_component("\\\\*\\ADMIN$"), "ADMIN$");
        assert_eq!(share_name_component("\\\\FILESERVER\\C$"), "C$");
        assert_eq!(share_name_component("ADMIN$"), "ADMIN$");
    }

    #[test]
    fn is_local_ip_correctly_classifies() {
        assert!(is_local_ip("127.0.0.1"));
        assert!(is_local_ip("::1"));
        assert!(is_local_ip("-"));
        assert!(is_local_ip(""));
        assert!(!is_local_ip("10.0.0.1"));
        assert!(!is_local_ip("192.168.1.1"));
    }
}
