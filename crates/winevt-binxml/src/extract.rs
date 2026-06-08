//! Project a decoded BinXml [`ir`](crate::ir) tree into a flat
//! [`DecodedRecord`] — the shape issen and winevt-extract actually consume.
//!
//! This walks the `<Event>` tree once, pulling the `<System>` envelope fields
//! and flattening `<EventData>`/`<UserData>` into a `name → value` map (the same
//! two serialization shapes the rest of the fleet handles: `<Data Name="…">`
//! audit records and flat Sysmon-style named elements). No intermediate JSON.

use std::collections::BTreeMap;

use crate::ir::{Element, Node};

/// A decoded Windows event record in the flat form downstream consumers want.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecodedRecord {
    /// Windows Event ID from `<System><EventID>`.
    pub event_id: u32,
    /// Provider name from `<System><Provider Name="…">`.
    pub provider: Option<String>,
    /// Channel from `<System><Channel>`.
    pub channel: Option<String>,
    /// Computer from `<System><Computer>`.
    pub computer: Option<String>,
    /// Level from `<System><Level>`.
    pub level: Option<u8>,
    /// `SystemTime` attribute of `<System><TimeCreated>`.
    pub time_created: Option<String>,
    /// Flattened `EventData`/`UserData` fields.
    pub data: BTreeMap<String, String>,
}

/// Extract a [`DecodedRecord`] from a decoded fragment's top-level nodes.
/// Lenient: missing pieces yield defaults rather than errors.
#[must_use]
pub fn extract_record(nodes: &[Node]) -> DecodedRecord {
    // RED stub — implemented in the GREEN commit.
    let _ = nodes;
    DecodedRecord::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Node {
        Node::Text(s.to_string())
    }

    fn el(name: &str, attrs: &[(&str, &str)], children: Vec<Node>) -> Node {
        Node::Element(Element {
            name: name.to_string(),
            attributes: attrs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            children,
        })
    }

    /// `<Event><System>…</System><EventData>…</EventData></Event>`
    fn security_event() -> Vec<Node> {
        vec![el(
            "Event",
            &[],
            vec![
                el(
                    "System",
                    &[],
                    vec![
                        el("Provider", &[("Name", "Microsoft-Windows-Security-Auditing")], vec![]),
                        el("EventID", &[], vec![text("4624")]),
                        el("Level", &[], vec![text("0")]),
                        el("Channel", &[], vec![text("Security")]),
                        el("Computer", &[], vec![text("DC01")]),
                        el("TimeCreated", &[("SystemTime", "2024-01-01T00:00:00.000000Z")], vec![]),
                    ],
                ),
                el(
                    "EventData",
                    &[],
                    vec![
                        el("Data", &[("Name", "TargetUserName")], vec![text("jdoe")]),
                        el("Data", &[("Name", "LogonType")], vec![text("10")]),
                    ],
                ),
            ],
        )]
    }

    #[test]
    fn extracts_system_envelope_fields() {
        let r = extract_record(&security_event());
        assert_eq!(r.event_id, 4624);
        assert_eq!(r.provider.as_deref(), Some("Microsoft-Windows-Security-Auditing"));
        assert_eq!(r.channel.as_deref(), Some("Security"));
        assert_eq!(r.computer.as_deref(), Some("DC01"));
        assert_eq!(r.level, Some(0));
        assert_eq!(r.time_created.as_deref(), Some("2024-01-01T00:00:00.000000Z"));
    }

    #[test]
    fn flattens_named_data_eventdata() {
        let r = extract_record(&security_event());
        assert_eq!(r.data.get("TargetUserName").map(String::as_str), Some("jdoe"));
        assert_eq!(r.data.get("LogonType").map(String::as_str), Some("10"));
    }

    #[test]
    fn flattens_flat_sysmon_eventdata() {
        let nodes = vec![el(
            "Event",
            &[],
            vec![
                el("System", &[], vec![el("EventID", &[], vec![text("1")])]),
                el(
                    "EventData",
                    &[],
                    vec![
                        el("Image", &[], vec![text("C:\\evil.exe")]),
                        el("CommandLine", &[], vec![text("evil.exe -enc AAAA")]),
                    ],
                ),
            ],
        )];
        let r = extract_record(&nodes);
        assert_eq!(r.event_id, 1);
        assert_eq!(r.data.get("Image").map(String::as_str), Some("C:\\evil.exe"));
        assert_eq!(r.data.get("CommandLine").map(String::as_str), Some("evil.exe -enc AAAA"));
    }

    #[test]
    fn flattens_userdata_recursively() {
        let nodes = vec![el(
            "Event",
            &[],
            vec![el(
                "UserData",
                &[],
                vec![el(
                    "RuleAndFileData",
                    &[],
                    vec![
                        el("PolicyName", &[], vec![text("Script Rules")]),
                        el("FilePath", &[], vec![text("%OSDRIVE%\\evil.ps1")]),
                    ],
                )],
            )],
        )];
        let r = extract_record(&nodes);
        assert_eq!(r.data.get("PolicyName").map(String::as_str), Some("Script Rules"));
        assert_eq!(r.data.get("FilePath").map(String::as_str), Some("%OSDRIVE%\\evil.ps1"));
    }

    #[test]
    fn missing_fields_are_none_and_empty() {
        let nodes = vec![el("Event", &[], vec![el("System", &[], vec![])])];
        let r = extract_record(&nodes);
        assert_eq!(r.event_id, 0);
        assert!(r.provider.is_none());
        assert!(r.channel.is_none());
        assert!(r.data.is_empty());
    }

    #[test]
    fn no_event_element_yields_default() {
        assert_eq!(extract_record(&[]), DecodedRecord::default());
        assert_eq!(extract_record(&[text("loose")]), DecodedRecord::default());
    }

    #[test]
    fn unnamed_data_elements_kept_positionally() {
        let nodes = vec![el(
            "Event",
            &[],
            vec![el(
                "EventData",
                &[],
                vec![
                    el("Data", &[], vec![text("alpha")]),
                    el("Data", &[], vec![text("beta")]),
                ],
            )],
        )];
        let r = extract_record(&nodes);
        assert_eq!(r.data.get("Data0").map(String::as_str), Some("alpha"));
        assert_eq!(r.data.get("Data1").map(String::as_str), Some("beta"));
    }
}
