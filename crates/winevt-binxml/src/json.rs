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
    Value::Object(nodes_to_map(nodes))
}

/// Group a node list's child elements by name into a JSON object: a name seen
/// once maps to its value, a name seen more than once maps to an array (in
/// document order). Non-element nodes are skipped.
fn nodes_to_map(nodes: &[Node]) -> Map<String, Value> {
    let mut groups: Vec<(String, Vec<Value>)> = Vec::new();
    for node in nodes {
        if let Node::Element(el) = node {
            let value = element_to_value(el);
            if let Some(group) = groups.iter_mut().find(|(name, _)| *name == el.name) {
                group.1.push(value);
            } else {
                groups.push((el.name.clone(), vec![value]));
            }
        }
    }
    let mut map = Map::new();
    for (name, values) in groups {
        let value = match values.len() {
            1 => values.into_iter().next().unwrap_or(Value::Null),
            _ => Value::Array(values),
        };
        map.insert(name, value);
    }
    map
}

/// Render one element: a leaf (only text, no attributes) becomes a bare string;
/// otherwise an object with `@attr` keys, grouped child elements, and `#text`.
fn element_to_value(el: &Element) -> Value {
    let text = element_text(el);
    let has_child_elements = el.children.iter().any(|c| matches!(c, Node::Element(_)));
    if el.attributes.is_empty() && !has_child_elements {
        return Value::String(text);
    }
    let mut map = nodes_to_map(&el.children);
    for (key, val) in &el.attributes {
        map.insert(format!("@{key}"), Value::String(val.clone()));
    }
    if !text.is_empty() {
        map.insert("#text".to_string(), Value::String(text));
    }
    Value::Object(map)
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
