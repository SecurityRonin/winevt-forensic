//! Detect unexpected WebClient service start (SCM EID 7036) — T1102.

use forensicnomicon::heuristics::evtx::{EID_SCM_SERVICE_STATE_CHANGE, WEBCLIENT_SERVICE_NAME};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect the WebClient (Mini-Redirector) service transitioning to Running.
///
/// EID 7036 in the System channel fires when SCM changes a service's state.
/// `param1` = service name, `param2` = new state.  WebClient starting is a
/// near-zero-FP precursor to any rundll32/certutil WebDAV payload download on
/// enterprise hosts that don't use WebDAV legitimately (T1102, T1105).
pub fn detect_webclient_service_start(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    events
        .iter()
        .filter(|ev| ev.event_id == EID_SCM_SERVICE_STATE_CHANGE && ev.channel == "System")
        .filter_map(|ev| {
            let svc = ev.data.get("param1")?;
            let state = ev.data.get("param2")?;
            if !svc.eq_ignore_ascii_case(WEBCLIENT_SERVICE_NAME) {
                return None;
            }
            if !state.eq_ignore_ascii_case("Running") {
                return None;
            }
            Some(EvtxDetection {
                kind: EvtxDetectionKind::WebClientServiceStart,
                mitre_technique_id: "T1102",
                tactic: "Command and Control",
                description: format!(
                    "WebClient (Mini-Redirector) service started — enables WebDAV UNC path delivery"
                ),
                evidence: vec![
                    format!("service={svc}"),
                    format!("state={state}"),
                ],
                timestamp_ns: ev.timestamp_ns,
                event_id: ev.event_id,
                channel: ev.channel.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    fn webclient_running() -> EvtxEvent {
        make_event(
            EID_SCM_SERVICE_STATE_CHANGE,
            "System",
            &[("param1", WEBCLIENT_SERVICE_NAME), ("param2", "Running")],
        )
    }

    #[test]
    fn webclient_service_start_detected() {
        let ev = webclient_running();
        let hits = detect_webclient_service_start(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::WebClientServiceStart);
        assert_eq!(hits[0].mitre_technique_id, "T1102");
    }

    #[test]
    fn webclient_stopped_not_detected() {
        let ev = make_event(
            EID_SCM_SERVICE_STATE_CHANGE,
            "System",
            &[("param1", WEBCLIENT_SERVICE_NAME), ("param2", "Stopped")],
        );
        assert!(detect_webclient_service_start(&[ev]).is_empty());
    }

    #[test]
    fn other_service_start_not_detected() {
        let ev = make_event(
            EID_SCM_SERVICE_STATE_CHANGE,
            "System",
            &[("param1", "Spooler"), ("param2", "Running")],
        );
        assert!(detect_webclient_service_start(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(7045, "System", &[("param1", WEBCLIENT_SERVICE_NAME), ("param2", "Running")]);
        assert!(detect_webclient_service_start(&[ev]).is_empty());
    }

    #[test]
    fn wrong_channel_not_detected() {
        let ev = make_event(
            EID_SCM_SERVICE_STATE_CHANGE,
            "Application",
            &[("param1", WEBCLIENT_SERVICE_NAME), ("param2", "Running")],
        );
        assert!(detect_webclient_service_start(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_service_name() {
        let ev = webclient_running();
        let hits = detect_webclient_service_start(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("WebClient"));
    }
}
