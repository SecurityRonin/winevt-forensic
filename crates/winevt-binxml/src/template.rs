//! Template instance decoding.
//!
//! A real EVTX record's payload is almost always a single template instance: a
//! reference to a reusable definition (the System/EventData *structure* with
//! substitution placeholders) plus the per-record substitution *values*. This
//! module reads the instance header + values, then parses the definition body
//! with those values in scope so the deserializer resolves placeholders inline.
//!
//! Correctness first: the definition body is re-parsed per instance (a GUID
//! cache is a later optimization). Array and embedded-BinXml substitution values
//! are not yet handled (scalar values only).

#![allow(clippy::doc_markdown)] // "BinXml" appears throughout these docs

use crate::cursor::Cursor;
use crate::deserializer::{run, DeserializeError, Limits};
use crate::ir::Node;
use crate::name::NameCache;
use crate::value::{read_value, BinXmlValue};

/// Allocation cap on the substitution-value count of one instance.
const MAX_SUBSTITUTIONS: usize = 4096;

/// Read a template instance (the bytes after the `0x0c` token) and return the
/// resolved content nodes. `chunk` is the full chunk slice (the addressing base
/// for the definition + its names).
pub(crate) fn read_template_instance(
    cur: &mut Cursor<'_>,
    chunk: &[u8],
    names: &mut NameCache,
    limits: Limits,
) -> Result<Vec<Node>, DeserializeError> {
    // RED stub — implemented in the GREEN commit.
    let _ = (cur, chunk, names, limits);
    Err(DeserializeError::Unsupported("template instance"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deserializer::deserialize_fragment;
    use crate::ir::Element;

    fn name_struct(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes()); // next_string
        v.extend_from_slice(&0u16.to_le_bytes()); // hash
        v.extend_from_slice(&(units.len() as u16).to_le_bytes()); // char_count
        for u in &units {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v.extend_from_slice(&0u16.to_le_bytes()); // NUL
        v
    }

    fn push_inline_name(buf: &mut Vec<u8>, name: &str) {
        let struct_start = (buf.len() + 4) as u32;
        buf.extend_from_slice(&struct_start.to_le_bytes());
        buf.extend_from_slice(&name_struct(name));
    }

    /// Build a record whose payload is one template instance:
    /// definition body `<Event>{subst 0}</Event>`, with `subst[0]` a string.
    fn build_record(value: &str) -> Vec<u8> {
        let mut b = Vec::new();
        // top-level fragment header
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
        // template instance
        b.push(0x0c);
        b.push(0x00); // unused
        b.extend_from_slice(&1u32.to_le_bytes()); // template_id
        let def_off_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes()); // def_offset (patched below)
        let def_offset = b.len() as u32; // inline: definition header starts here
        b[def_off_pos..def_off_pos + 4].copy_from_slice(&def_offset.to_le_bytes());
        // definition header: next u32, guid[16], data_size u32
        b.extend_from_slice(&0u32.to_le_bytes()); // next
        b.extend_from_slice(&[0u8; 16]); // guid
        let data_size_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes()); // data_size (patched)
        let body_start = b.len();
        // definition body (template-definition mode → open element carries dep_id):
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]); // fragment header
        b.push(0x01); // open start element, no attrs
        b.extend_from_slice(&0u16.to_le_bytes()); // dependency_id
        b.extend_from_slice(&0u32.to_le_bytes()); // element data_size
        push_inline_name(&mut b, "Event");
        b.push(0x02); // close start element
        b.push(0x0d); // normal substitution
        b.extend_from_slice(&0u16.to_le_bytes()); // index 0
        b.push(0x01); // value_type String
        b.push(0x04); // end element
        b.push(0x00); // end of stream (definition body)
        let body_len = (b.len() - body_start) as u32;
        b[data_size_pos..data_size_pos + 4].copy_from_slice(&body_len.to_le_bytes());
        // substitution value array
        b.extend_from_slice(&1u32.to_le_bytes()); // count
        let units: Vec<u16> = value.encode_utf16().collect();
        let byte_len = (units.len() * 2) as u16;
        b.extend_from_slice(&byte_len.to_le_bytes()); // size
        b.push(0x01); // value_type String
        b.push(0x00); // unused
        for u in &units {
            b.extend_from_slice(&u.to_le_bytes()); // sized value, no length prefix
        }
        // top-level end of stream
        b.push(0x00);
        b
    }

    #[test]
    fn template_instance_resolves_scalar_substitution() {
        let b = build_record("hello");
        let mut names = NameCache::new();
        let mut cur = Cursor::new(&b);
        let nodes = deserialize_fragment(&mut cur, &b, &mut names).unwrap();
        let mut event = Element {
            name: "Event".to_string(),
            ..Default::default()
        };
        event.children.push(Node::Text("hello".to_string()));
        assert_eq!(nodes, vec![Node::Element(event)]);
    }

    #[test]
    fn another_substitution_value_resolves() {
        let b = build_record("C:\\evil.exe");
        let mut names = NameCache::new();
        let mut cur = Cursor::new(&b);
        let nodes = deserialize_fragment(&mut cur, &b, &mut names).unwrap();
        let Node::Element(event) = &nodes[0] else {
            panic!("expected element");
        };
        assert_eq!(event.children, vec![Node::Text("C:\\evil.exe".to_string())]);
    }
}
