//! Render a decoded BinXml [`ir`](crate::ir) tree to a `serde_json::Value`.
//!
//! This is the general-purpose / debug projection (issen itself consumes the
//! flat [`DecodedRecord`](crate::extract::DecodedRecord) instead). The shape
//! follows the common omerbenamram-style convention: attributes become `@name`
//! keys, character data becomes `#text`, a leaf element with only text becomes a
//! bare string, and repeated same-named child elements become a JSON array.

#![allow(clippy::doc_markdown)] // "BinXml"/"EventData" appear throughout these docs

use serde_json::{Map, Value};

use crate::ir::{Element, Node};

/// Render a decoded fragment's top-level nodes to a JSON object keyed by element
/// name (e.g. `{"Event": {...}}`).
#[must_use]
pub fn record_to_json(nodes: &[Node]) -> Value {
    // RED stub — implemented in the GREEN commit.
    let _ = nodes;
    Value::Null
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

    #[test]
    fn leaf_text_element_is_bare_string() {
        let v = record_to_json(&[el("Channel", &[], vec![text("Security")])]);
        assert_eq!(v, serde_json::json!({ "Channel": "Security" }));
    }

    #[test]
    fn attribute_only_element() {
        let v = record_to_json(&[el("Provider", &[("Name", "MS-Security")], vec![])]);
        assert_eq!(v, serde_json::json!({ "Provider": { "@Name": "MS-Security" } }));
    }

    #[test]
    fn attribute_plus_text_uses_text_key() {
        let v = record_to_json(&[el("Data", &[("Name", "Target")], vec![text("jdoe")])]);
        assert_eq!(
            v,
            serde_json::json!({ "Data": { "@Name": "Target", "#text": "jdoe" } })
        );
    }

    #[test]
    fn repeated_children_become_array() {
        let v = record_to_json(&[el(
            "EventData",
            &[],
            vec![
                el("Data", &[("Name", "A")], vec![text("1")]),
                el("Data", &[("Name", "B")], vec![text("2")]),
            ],
        )]);
        assert_eq!(
            v,
            serde_json::json!({
                "EventData": {
                    "Data": [
                        { "@Name": "A", "#text": "1" },
                        { "@Name": "B", "#text": "2" }
                    ]
                }
            })
        );
    }

    #[test]
    fn nested_event_structure() {
        let v = record_to_json(&[el(
            "Event",
            &[],
            vec![el(
                "System",
                &[],
                vec![
                    el("EventID", &[], vec![text("4624")]),
                    el("Channel", &[], vec![text("Security")]),
                ],
            )],
        )]);
        assert_eq!(
            v,
            serde_json::json!({
                "Event": { "System": { "EventID": "4624", "Channel": "Security" } }
            })
        );
    }

    #[test]
    fn empty_nodes_is_empty_object() {
        assert_eq!(record_to_json(&[]), serde_json::json!({}));
    }

    #[test]
    fn loose_text_node_is_ignored_at_top_level() {
        assert_eq!(record_to_json(&[text("loose")]), serde_json::json!({}));
    }
}
