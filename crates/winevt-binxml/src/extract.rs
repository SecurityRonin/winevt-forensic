//! Project a decoded BinXml [`ir`](crate::ir) tree into a flat
//! [`DecodedRecord`] — the shape issen and winevt-extract actually consume.
//!
//! This walks the `<Event>` tree once, pulling the `<System>` envelope fields
//! and flattening `<EventData>`/`<UserData>` into a `name → value` map (the same
//! two serialization shapes the rest of the fleet handles: `<Data Name="…">`
//! audit records and flat Sysmon-style named elements). No intermediate JSON.

#![allow(clippy::doc_markdown)] // "BinXml"/"EventData" appear throughout these docs

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
    let mut rec = DecodedRecord::default();
    let Some(event) = find_element(nodes, "Event") else {
        return rec;
    };
    if let Some(system) = find_child(event, "System") {
        rec.provider = find_child(system, "Provider")
            .and_then(|p| attr(p, "Name"))
            .map(str::to_string);
        if let Some(eid) = find_child(system, "EventID") {
            rec.event_id = element_text(eid).trim().parse().unwrap_or(0);
        }
        rec.channel = find_child(system, "Channel").and_then(text_opt);
        rec.computer = find_child(system, "Computer").and_then(text_opt);
        rec.level = find_child(system, "Level").and_then(|l| element_text(l).trim().parse().ok());
        rec.time_created = find_child(system, "TimeCreated")
            .and_then(|t| attr(t, "SystemTime"))
            .map(str::to_string);
    }
    for block in ["EventData", "UserData"] {
        if let Some(ed) = find_child(event, block) {
            collect_data(ed, &mut rec.data);
        }
    }
    rec
}

/// First top-level element named `name`.
fn find_element<'a>(nodes: &'a [Node], name: &str) -> Option<&'a Element> {
    nodes.iter().find_map(|n| match n {
        Node::Element(el) if el.name == name => Some(el),
        _ => None,
    })
}

/// First child element of `parent` named `name`.
fn find_child<'a>(parent: &'a Element, name: &str) -> Option<&'a Element> {
    find_element(&parent.children, name)
}

/// Value of attribute `name`, if present.
fn attr<'a>(el: &'a Element, name: &str) -> Option<&'a str> {
    el.attributes
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Concatenated direct text children of `el`.
fn element_text(el: &Element) -> String {
    let mut s = String::new();
    for child in &el.children {
        if let Node::Text(t) = child {
            s.push_str(t);
        }
    }
    s
}

/// Element text as `Some` when non-empty, else `None`.
fn text_opt(el: &Element) -> Option<String> {
    let t = element_text(el);
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// Flatten an `EventData`/`UserData` element into `out`, handling the
/// `<Data Name="…">` shape, unnamed positional `<Data>`, flat named elements
/// (Sysmon) and nested provider blocks (UserData).
fn collect_data(element: &Element, out: &mut BTreeMap<String, String>) {
    let mut unnamed = 0usize;
    for child in &element.children {
        let Node::Element(el) = child else {
            continue;
        };
        if el.name == "Data" {
            if let Some(name) = attr(el, "Name") {
                out.insert(name.to_string(), element_text(el));
            } else {
                out.insert(format!("Data{unnamed}"), element_text(el));
                unnamed += 1;
            }
        } else if el.children.iter().any(|c| matches!(c, Node::Element(_))) {
            collect_data(el, out); // nested provider block
        } else {
            out.insert(el.name.clone(), element_text(el)); // flat named element
        }
    }
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
    fn empty_channel_is_none_and_loose_text_is_skipped() {
        let nodes = vec![el(
            "Event",
            &[],
            vec![
                el("System", &[], vec![el("Channel", &[], vec![])]), // empty → None
                el(
                    "EventData",
                    &[],
                    vec![
                        text("loose"), // a non-element child must be skipped
                        el("Data", &[("Name", "K")], vec![text("v")]),
                    ],
                ),
            ],
        )];
        let r = extract_record(&nodes);
        assert!(r.channel.is_none());
        assert_eq!(r.data.get("K").map(String::as_str), Some("v"));
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
