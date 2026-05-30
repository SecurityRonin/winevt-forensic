//! Detect local administrator account creation (T1136.001 / T1098).

use forensicnomicon::heuristics::evtx::{
    EID_USER_ACCOUNT_CREATED, EID_USER_ADDED_TO_LOCAL_GROUP, LOCAL_ADMINS_GROUP_SID,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect creation of a new local Windows account (T1136.001 — Create Account: Local).
///
/// Two signals, both in the Security channel:
/// 1. **EID 4720** — A user account was created.  Always actionable — legitimate
///    admin account provisioning is rare on endpoints and usually scripted through
///    existing tooling that generates different event patterns.
/// 2. **EID 4732** — A member was added to a security-enabled local group.
///    When `GroupSid` = S-1-5-32-544 (local Administrators), indicates privilege
///    escalation or a newly created account being elevated.
///
/// ~20/76 ransomware families create local admin accounts for persistence
/// or lateral movement RDP (T1098 — Account Manipulation).
pub fn detect_local_admin_creation(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| ev.channel == "Security")
        .filter_map(|ev| {
            // Signal 1: EID 4720 — user account created
            if ev.event_id == EID_USER_ACCOUNT_CREATED {
                let user = ev
                    .data
                    .get("TargetUserName")
                    .map(String::as_str)
                    .unwrap_or("unknown");
                let domain = ev
                    .data
                    .get("TargetDomainName")
                    .map(String::as_str)
                    .unwrap_or("unknown");
                return Some(EvtxDetection {
                    kind: EvtxDetectionKind::LocalAdminCreation,
                    mitre_technique_id: "T1136.001",
                    tactic: "Persistence",
                    description: format!(
                        "Local user account created: '{domain}\\{user}'"
                    ),
                    evidence: vec![
                        format!("TargetUserName={user}"),
                        format!("TargetDomainName={domain}"),
                    ],
                    timestamp_ns: ev.timestamp_ns,
                    event_id: ev.event_id,
                    channel: ev.channel.clone(),
                });
            }
            // Signal 2: EID 4732 — member added to local Administrators group
            if ev.event_id == EID_USER_ADDED_TO_LOCAL_GROUP {
                let group_sid = ev
                    .data
                    .get("GroupSid")
                    .map(String::as_str)
                    .unwrap_or("");
                if group_sid != LOCAL_ADMINS_GROUP_SID {
                    return None;
                }
                let user = ev
                    .data
                    .get("TargetUserName")
                    .map(String::as_str)
                    .unwrap_or("unknown");
                let group = ev
                    .data
                    .get("GroupName")
                    .map(String::as_str)
                    .unwrap_or("Administrators");
                return Some(EvtxDetection {
                    kind: EvtxDetectionKind::LocalAdminCreation,
                    mitre_technique_id: "T1136.001",
                    tactic: "Persistence",
                    description: format!(
                        "User '{user}' added to local group '{group}' (SID {LOCAL_ADMINS_GROUP_SID})"
                    ),
                    evidence: vec![
                        format!("TargetUserName={user}"),
                        format!("GroupSid={group_sid}"),
                        format!("GroupName={group}"),
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
    fn eid_4720_user_created_detected() {
        let ev = make_event(
            EID_USER_ACCOUNT_CREATED,
            "Security",
            &[
                ("TargetUserName", "backdoor"),
                ("TargetDomainName", "WORKGROUP"),
                ("SubjectUserName", "victim-pc$"),
            ],
        );
        let hits = detect_local_admin_creation(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::LocalAdminCreation);
        assert_eq!(hits[0].mitre_technique_id, "T1136.001");
    }

    #[test]
    fn eid_4732_add_to_admins_detected() {
        let ev = make_event(
            EID_USER_ADDED_TO_LOCAL_GROUP,
            "Security",
            &[
                ("TargetUserName", "backdoor"),
                ("GroupSid", LOCAL_ADMINS_GROUP_SID),
                ("GroupName", "Administrators"),
            ],
        );
        let hits = detect_local_admin_creation(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::LocalAdminCreation);
        assert_eq!(hits[0].mitre_technique_id, "T1136.001");
    }

    #[test]
    fn eid_4732_add_to_non_admin_group_not_detected() {
        let ev = make_event(
            EID_USER_ADDED_TO_LOCAL_GROUP,
            "Security",
            &[
                ("TargetUserName", "user1"),
                ("GroupSid", "S-1-5-32-545"), // Users group, not Admins
                ("GroupName", "Users"),
            ],
        );
        assert!(detect_local_admin_creation(&[ev]).is_empty());
    }

    #[test]
    fn wrong_channel_4720_not_detected() {
        let ev = make_event(
            EID_USER_ACCOUNT_CREATED,
            "Application",
            &[("TargetUserName", "backdoor")],
        );
        assert!(detect_local_admin_creation(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_username() {
        let ev = make_event(
            EID_USER_ACCOUNT_CREATED,
            "Security",
            &[
                ("TargetUserName", "ransomhacker"),
                ("TargetDomainName", "WORKGROUP"),
            ],
        );
        let hits = detect_local_admin_creation(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("ransomhacker") || combined.contains("TargetUserName"));
    }
}
