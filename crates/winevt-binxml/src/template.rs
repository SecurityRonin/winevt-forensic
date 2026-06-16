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
use crate::deserializer::{deserialize_fragment, run, DeserializeError, Limits, SubstitutionValue};
use crate::ir::Node;
use crate::name::NameCache;
use crate::value::{read_value, VT_BINXML};

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
    // Instance header: unused u8, template_id u32, definition offset u32.
    let _unused = cur.read_u8()?;
    let _template_id = cur.read_u32_le()?;
    let def_offset = cur.read_u32_le()? as usize;

    // The definition is either present inline here (first use in the chunk) or
    // already written elsewhere in the chunk (a back-reference).
    let (body_offset, body_len) = if cur.position() == def_offset {
        let data_size = read_def_header(cur)?;
        let body_offset = cur.position();
        cur.skip(data_size)?; // skip past the inline definition body
        (body_offset, data_size)
    } else {
        let mut at_def = Cursor::at(chunk, def_offset);
        let data_size = read_def_header(&mut at_def)?;
        (at_def.position(), data_size)
    };

    // Substitution value array: count, then count×(size u16, type u8, unused u8),
    // then the raw values back-to-back.
    let count = cur.read_u32_le()? as usize;
    if count > MAX_SUBSTITUTIONS {
        return Err(DeserializeError::Unsupported("too many substitutions"));
    }
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        let size = cur.read_u16_le()? as usize;
        let value_type = cur.read_u8()?;
        let _unused = cur.read_u8()?;
        descriptors.push((size, value_type));
    }
    let mut values = Vec::with_capacity(count);
    for (size, value_type) in &descriptors {
        if *value_type == VT_BINXML {
            // Embedded BinXml: the `size` value bytes are themselves a fragment
            // (commonly the entire EventData). Decode it against the chunk, then
            // step the main cursor past the value.
            let mut frag = Cursor::at(chunk, cur.position());
            let nodes = deserialize_fragment(&mut frag, chunk, names)?;
            cur.skip(*size)?;
            values.push(SubstitutionValue::Nodes(nodes));
        } else {
            // Scalar value (array types still surface as ValueError::Unsupported).
            values.push(SubstitutionValue::Scalar(read_value(
                cur,
                *value_type,
                Some(*size),
            )?));
        }
    }

    // Parse the definition body with the values in scope so placeholders resolve
    // inline. Names resolve against the full chunk; the cursor is bounded to the
    // body's declared end.
    let body_end = body_offset
        .checked_add(body_len)
        .filter(|end| *end <= chunk.len())
        .ok_or(DeserializeError::Unsupported("template body out of bounds"))?;
    let mut body_cur = Cursor::at(chunk, body_offset);
    run(&mut body_cur, chunk, names, Some(&values), body_end, limits)
}

/// Read a definition header (`next u32, guid[16], data_size u32`) and return the
/// definition body's `data_size`.
fn read_def_header(cur: &mut Cursor<'_>) -> Result<usize, DeserializeError> {
    let _next = cur.read_u32_le()?;
    let _guid = cur.take(16)?;
    Ok(cur.read_u32_le()? as usize)
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

    fn decode_all(b: &[u8]) -> Vec<Node> {
        let mut names = NameCache::new();
        let mut cur = Cursor::new(b);
        deserialize_fragment(&mut cur, b, &mut names).unwrap()
    }

    fn event_with(children: Vec<Node>) -> Vec<Node> {
        vec![Node::Element(Element {
            name: "Event".to_string(),
            attributes: Vec::new(),
            children,
        })]
    }

    #[test]
    fn another_substitution_value_resolves() {
        assert_eq!(
            decode_all(&build_record("C:\\evil.exe")),
            event_with(vec![Node::Text("C:\\evil.exe".to_string())])
        );
    }

    /// Generalized builder: definition body `<Event>{subst}</Event>` where the
    /// def-body substitution is `subst_token` (0x0d/0x0e) with declared
    /// `decl_type`, and the single instance value has `value_type` + `value_bytes`.
    fn build_subst(subst_token: u8, decl_type: u8, value_type: u8, value_bytes: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
        b.push(0x0c);
        b.push(0x00);
        b.extend_from_slice(&1u32.to_le_bytes());
        let def_off_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let def_offset = b.len() as u32;
        b[def_off_pos..def_off_pos + 4].copy_from_slice(&def_offset.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&[0u8; 16]);
        let data_size_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let body_start = b.len();
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
        b.push(0x01);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        push_inline_name(&mut b, "Event");
        b.push(0x02);
        b.push(subst_token);
        b.extend_from_slice(&0u16.to_le_bytes()); // index 0
        b.push(decl_type);
        b.push(0x04);
        b.push(0x00);
        let body_len = (b.len() - body_start) as u32;
        b[data_size_pos..data_size_pos + 4].copy_from_slice(&body_len.to_le_bytes());
        // one instance value
        b.extend_from_slice(&1u32.to_le_bytes()); // count
        b.extend_from_slice(&(value_bytes.len() as u16).to_le_bytes());
        b.push(value_type);
        b.push(0x00); // unused
        b.extend_from_slice(value_bytes);
        b.push(0x00);
        b
    }

    #[test]
    fn optional_null_substitution_is_omitted() {
        // 0x0e optional + declared Null type → ignored placeholder, no child.
        let b = build_subst(0x0e, 0x00, 0x00, &[]);
        assert_eq!(decode_all(&b), event_with(vec![]));
    }

    #[test]
    fn null_substitution_value_is_omitted() {
        // 0x0d normal, but the instance value is Null → no child.
        let b = build_subst(0x0d, 0x01, 0x00, &[]);
        assert_eq!(decode_all(&b), event_with(vec![]));
    }

    #[test]
    fn excessive_substitution_count_is_rejected() {
        // A crafted instance claiming more substitutions than the cap must be
        // rejected before allocating per-descriptor storage.
        let big = build_excess_count();
        let mut names = NameCache::new();
        let mut cur = Cursor::new(&big);
        assert!(matches!(
            deserialize_fragment(&mut cur, &big, &mut names),
            Err(DeserializeError::Unsupported(_))
        ));
    }

    /// A record whose declared substitution count exceeds [`MAX_SUBSTITUTIONS`].
    fn build_excess_count() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
        b.push(0x0c);
        b.push(0x00);
        b.extend_from_slice(&1u32.to_le_bytes());
        let def_off_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let def_offset = b.len() as u32;
        b[def_off_pos..def_off_pos + 4].copy_from_slice(&def_offset.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&[0u8; 16]);
        let data_size_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let body_start = b.len();
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00, 0x00]); // minimal body: header + EOS
        let body_len = (b.len() - body_start) as u32;
        b[data_size_pos..data_size_pos + 4].copy_from_slice(&body_len.to_le_bytes());
        b.extend_from_slice(&(MAX_SUBSTITUTIONS as u32 + 1).to_le_bytes()); // count
        b
    }

    #[test]
    fn back_referenced_definition_resolves() {
        // Two instances sharing one definition: the second references the first's
        // definition by offset (the non-inline path).
        let b = build_two_instances("aaa", "bbb");
        let nodes = decode_all(&b);
        assert_eq!(nodes.len(), 2, "two instances → two elements");
        assert_eq!(
            nodes[0],
            Node::Element(Element {
                name: "Event".to_string(),
                attributes: Vec::new(),
                children: vec![Node::Text("aaa".to_string())],
            })
        );
        assert_eq!(
            nodes[1],
            Node::Element(Element {
                name: "Event".to_string(),
                attributes: Vec::new(),
                children: vec![Node::Text("bbb".to_string())],
            })
        );
    }

    fn push_value_array(b: &mut Vec<u8>, value: &str) {
        let units: Vec<u16> = value.encode_utf16().collect();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&((units.len() * 2) as u16).to_le_bytes());
        b.push(0x01);
        b.push(0x00);
        for u in &units {
            b.extend_from_slice(&u.to_le_bytes());
        }
    }

    fn build_two_instances(v1: &str, v2: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
        // instance 1 (inline definition)
        b.push(0x0c);
        b.push(0x00);
        b.extend_from_slice(&1u32.to_le_bytes());
        let def_off_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let def_offset = b.len() as u32;
        b[def_off_pos..def_off_pos + 4].copy_from_slice(&def_offset.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&[0u8; 16]);
        let data_size_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let body_start = b.len();
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
        b.push(0x01);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        push_inline_name(&mut b, "Event");
        b.push(0x02);
        b.push(0x0d);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.push(0x01);
        b.push(0x04);
        b.push(0x00);
        let body_len = (b.len() - body_start) as u32;
        b[data_size_pos..data_size_pos + 4].copy_from_slice(&body_len.to_le_bytes());
        push_value_array(&mut b, v1);
        // instance 2 (back-reference to instance 1's definition)
        b.push(0x0c);
        b.push(0x00);
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&def_offset.to_le_bytes()); // def_offset != current pos → non-inline
        push_value_array(&mut b, v2);
        b.push(0x00);
        b
    }

    /// Append a direct-mode BinXml fragment `<name>value</name>` (used as an
    /// embedded-BinXml substitution value; inline name offsets are absolute).
    fn push_embedded_fragment(b: &mut Vec<u8>, name: &str, value: &str) {
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
        b.push(0x01); // open, no attrs, no dep_id (direct mode)
        b.extend_from_slice(&0u32.to_le_bytes());
        push_inline_name(b, name);
        b.push(0x02);
        b.push(0x05);
        b.push(0x01);
        let units: Vec<u16> = value.encode_utf16().collect();
        b.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in &units {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b.push(0x04);
        b.push(0x00);
    }

    /// Record whose def body is `<Event>{subst0}</Event>` with `subst0` an
    /// embedded BinXml `<Data>hello</Data>` (value type 0x21).
    fn build_embedded_record() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
        b.push(0x0c);
        b.push(0x00);
        b.extend_from_slice(&1u32.to_le_bytes());
        let def_off_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let def_offset = b.len() as u32;
        b[def_off_pos..def_off_pos + 4].copy_from_slice(&def_offset.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&[0u8; 16]);
        let ds_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let body_start = b.len();
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
        b.push(0x01);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        push_inline_name(&mut b, "Event");
        b.push(0x02);
        b.push(0x0d);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.push(0x21); // declared type: embedded BinXml
        b.push(0x04);
        b.push(0x00);
        let body_len = (b.len() - body_start) as u32;
        b[ds_pos..ds_pos + 4].copy_from_slice(&body_len.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // count
        let size_pos = b.len();
        b.extend_from_slice(&0u16.to_le_bytes()); // size (patched)
        b.push(0x21); // value type: embedded BinXml
        b.push(0x00);
        let val_start = b.len();
        push_embedded_fragment(&mut b, "Data", "hello");
        let val_len = (b.len() - val_start) as u16;
        b[size_pos..size_pos + 2].copy_from_slice(&val_len.to_le_bytes());
        b.push(0x00);
        b
    }

    #[test]
    fn embedded_binxml_substitution_splices_subtree() {
        let nodes = decode_all(&build_embedded_record());
        let mut data = Element {
            name: "Data".to_string(),
            ..Default::default()
        };
        data.children.push(Node::Text("hello".to_string()));
        assert_eq!(nodes, event_with(vec![Node::Element(data)]));
    }

    /// Record whose def body is `<Event attr="{subst0}"/>`; the single instance
    /// value has `value_type`/`value_bytes`.
    fn build_attr_record(value_type: u8, value_bytes: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
        b.push(0x0c);
        b.push(0x00);
        b.extend_from_slice(&1u32.to_le_bytes());
        let def_off_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let def_offset = b.len() as u32;
        b[def_off_pos..def_off_pos + 4].copy_from_slice(&def_offset.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&[0u8; 16]);
        let ds_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let body_start = b.len();
        b.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
        b.push(0x41); // open WITH attributes
        b.extend_from_slice(&0u16.to_le_bytes()); // dep_id
        b.extend_from_slice(&0u32.to_le_bytes()); // data_size
        push_inline_name(&mut b, "Event");
        b.extend_from_slice(&0u32.to_le_bytes()); // attr_list_size
        b.push(0x06); // attribute
        push_inline_name(&mut b, "attr");
        b.push(0x0d); // value is a substitution
        b.extend_from_slice(&0u16.to_le_bytes()); // index 0
        b.push(value_type);
        b.push(0x03); // close empty element
        b.push(0x00);
        let body_len = (b.len() - body_start) as u32;
        b[ds_pos..ds_pos + 4].copy_from_slice(&body_len.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // count
        let size_pos = b.len();
        b.extend_from_slice(&0u16.to_le_bytes());
        b.push(value_type);
        b.push(0x00);
        let val_start = b.len();
        b.extend_from_slice(value_bytes);
        let val_len = (b.len() - val_start) as u16;
        b[size_pos..size_pos + 2].copy_from_slice(&val_len.to_le_bytes());
        b.push(0x00);
        b
    }

    #[test]
    fn substituted_scalar_attribute_resolves() {
        let units: Vec<u8> = "DC01".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let nodes = decode_all(&build_attr_record(0x01, &units));
        assert_eq!(
            nodes,
            vec![Node::Element(Element {
                name: "Event".to_string(),
                attributes: vec![("attr".to_string(), "DC01".to_string())],
                children: vec![],
            })]
        );
    }

    #[test]
    fn null_attribute_value_is_empty() {
        // A Null (or otherwise non-scalar) substitution used as an attribute
        // renders to the empty string.
        let nodes = decode_all(&build_attr_record(0x00, &[]));
        assert_eq!(
            nodes,
            vec![Node::Element(Element {
                name: "Event".to_string(),
                attributes: vec![("attr".to_string(), String::new())],
                children: vec![],
            })]
        );
    }
}
