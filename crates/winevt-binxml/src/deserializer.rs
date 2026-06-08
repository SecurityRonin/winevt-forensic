//! The BinXml token-loop deserializer: a token stream → an [`ir`] tree.
//!
//! Element nesting is tracked with an explicit work-stack (not native
//! recursion), so adversarial nesting hits a depth cap rather than overflowing
//! the call stack. Every iteration consumes at least one byte and is bounded by
//! a token cap; both caps are configurable internally so the limit branches are
//! testable.
//!
//! This module decodes the *template-free* token set (fragment header, element
//! open/close, attributes, inline values, text). Template instances and
//! substitutions are decoded by the template layer, which builds on this loop.

#![allow(clippy::doc_markdown)] // "BinXml" appears throughout these docs

use crate::cursor::{Cursor, CursorError};
use crate::ir::{Element, Node};
use crate::name::NameCache;
use crate::tokens::{
    read_attribute_name, read_fragment_header, read_open_start_element, token_base,
    token_has_more, TokenError, TOK_ATTRIBUTE, TOK_CLOSE_EMPTY_ELEMENT, TOK_CLOSE_START_ELEMENT,
    TOK_END_ELEMENT, TOK_END_OF_STREAM, TOK_FRAGMENT_HEADER, TOK_NORMAL_SUBSTITUTION,
    TOK_OPEN_START_ELEMENT, TOK_OPTIONAL_SUBSTITUTION, TOK_TEMPLATE_INSTANCE, TOK_VALUE,
};
use crate::value::{read_value, ValueError};
use thiserror::Error;

/// Maximum element-nesting depth before bailing.
pub const MAX_DEPTH: usize = 256;
/// Maximum number of tokens decoded from a single fragment.
pub const MAX_TOKENS: usize = 1 << 20;

/// Error decoding a BinXml fragment.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum DeserializeError {
    /// A bounds-checked cursor read failed.
    #[error("cursor: {0}")]
    Cursor(#[from] CursorError),
    /// A token reader failed.
    #[error("token: {0}")]
    Token(#[from] TokenError),
    /// A value decode failed.
    #[error("value: {0}")]
    Value(#[from] ValueError),
    /// Element nesting exceeded the depth cap.
    #[error("element nesting exceeds depth cap {limit}")]
    DepthLimit { limit: usize },
    /// The token loop exceeded the iteration cap.
    #[error("token loop exceeds iteration cap {limit}")]
    IterationLimit { limit: usize },
    /// A close/end token had no matching open element.
    #[error("unbalanced element close")]
    UnbalancedClose,
    /// A structurally invalid token byte was encountered.
    #[error("unknown token {token:#04x} at offset {offset}")]
    UnknownToken { token: u8, offset: usize },
    /// A token not handled by this layer (templates/substitutions).
    #[error("unsupported in this layer: {0}")]
    Unsupported(&'static str),
}

/// Internal decode limits (production values via [`deserialize_fragment`]).
#[derive(Debug, Clone, Copy)]
struct Limits {
    max_depth: usize,
    max_tokens: usize,
}

/// Decode a template-free BinXml fragment into a list of top-level nodes.
///
/// `chunk` is the full chunk slice (the addressing base for name references).
/// `has_dep_id` is true only when decoding a template-definition body.
pub fn deserialize_fragment(
    cur: &mut Cursor<'_>,
    chunk: &[u8],
    names: &mut NameCache,
    has_dep_id: bool,
) -> Result<Vec<Node>, DeserializeError> {
    run(
        cur,
        chunk,
        names,
        has_dep_id,
        Limits {
            max_depth: MAX_DEPTH,
            max_tokens: MAX_TOKENS,
        },
    )
}

/// The token loop with explicit limits.
fn run(
    cur: &mut Cursor<'_>,
    chunk: &[u8],
    names: &mut NameCache,
    has_dep_id: bool,
    limits: Limits,
) -> Result<Vec<Node>, DeserializeError> {
    // RED stub — implemented in the GREEN commit.
    let _ = (cur, chunk, names, has_dep_id, limits);
    Err(DeserializeError::Unsupported("not implemented"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── fragment builders ──────────────────────────────────────────────────
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

    /// Append an inline name reference (offset points right after the u32).
    fn push_inline_name(buf: &mut Vec<u8>, name: &str) {
        let struct_start = (buf.len() + 4) as u32;
        buf.extend_from_slice(&struct_start.to_le_bytes());
        buf.extend_from_slice(&name_struct(name));
    }

    fn push_open(buf: &mut Vec<u8>, name: &str, has_attrs: bool) {
        buf.push(if has_attrs { 0x41 } else { 0x01 });
        buf.extend_from_slice(&0u32.to_le_bytes()); // data_size
        push_inline_name(buf, name);
        if has_attrs {
            buf.extend_from_slice(&0u32.to_le_bytes()); // attr_list_size
        }
    }

    fn push_text(buf: &mut Vec<u8>, s: &str) {
        buf.push(TOK_VALUE);
        buf.push(0x01); // value_type String
        let units: Vec<u16> = s.encode_utf16().collect();
        buf.extend_from_slice(&(units.len() as u16).to_le_bytes()); // len-prefixed
        for u in &units {
            buf.extend_from_slice(&u.to_le_bytes());
        }
    }

    fn push_attr(buf: &mut Vec<u8>, name: &str, value: &str) {
        buf.push(TOK_ATTRIBUTE);
        push_inline_name(buf, name);
        push_text(buf, value);
    }

    fn frag_header(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[TOK_FRAGMENT_HEADER, 0x01, 0x01, 0x00]);
    }

    fn decode(buf: &[u8]) -> Result<Vec<Node>, DeserializeError> {
        let mut names = NameCache::new();
        let mut cur = Cursor::new(buf);
        deserialize_fragment(&mut cur, buf, &mut names, false)
    }

    fn elem(name: &str) -> Element {
        Element {
            name: name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_element_with_children_close() {
        // <Event></Event>
        let mut b = Vec::new();
        frag_header(&mut b);
        push_open(&mut b, "Event", false);
        b.push(TOK_CLOSE_START_ELEMENT);
        b.push(TOK_END_ELEMENT);
        b.push(TOK_END_OF_STREAM);
        assert_eq!(decode(&b).unwrap(), vec![Node::Element(elem("Event"))]);
    }

    #[test]
    fn self_closing_empty_element() {
        // <Event/>
        let mut b = Vec::new();
        frag_header(&mut b);
        push_open(&mut b, "Event", false);
        b.push(TOK_CLOSE_EMPTY_ELEMENT);
        b.push(TOK_END_OF_STREAM);
        assert_eq!(decode(&b).unwrap(), vec![Node::Element(elem("Event"))]);
    }

    #[test]
    fn element_with_text_child() {
        // <Event>hello</Event>
        let mut b = Vec::new();
        frag_header(&mut b);
        push_open(&mut b, "Event", false);
        b.push(TOK_CLOSE_START_ELEMENT);
        push_text(&mut b, "hello");
        b.push(TOK_END_ELEMENT);
        b.push(TOK_END_OF_STREAM);
        let mut e = elem("Event");
        e.children.push(Node::Text("hello".to_string()));
        assert_eq!(decode(&b).unwrap(), vec![Node::Element(e)]);
    }

    #[test]
    fn element_with_attribute() {
        // <Event Name="val"></Event>
        let mut b = Vec::new();
        frag_header(&mut b);
        push_open(&mut b, "Event", true);
        push_attr(&mut b, "Name", "val");
        b.push(TOK_CLOSE_START_ELEMENT);
        b.push(TOK_END_ELEMENT);
        b.push(TOK_END_OF_STREAM);
        let mut e = elem("Event");
        e.attributes.push(("Name".to_string(), "val".to_string()));
        assert_eq!(decode(&b).unwrap(), vec![Node::Element(e)]);
    }

    #[test]
    fn nested_elements() {
        // <a><b/></a>
        let mut b = Vec::new();
        frag_header(&mut b);
        push_open(&mut b, "a", false);
        b.push(TOK_CLOSE_START_ELEMENT);
        push_open(&mut b, "b", false);
        b.push(TOK_CLOSE_EMPTY_ELEMENT);
        b.push(TOK_END_ELEMENT);
        b.push(TOK_END_OF_STREAM);
        let mut a = elem("a");
        a.children.push(Node::Element(elem("b")));
        assert_eq!(decode(&b).unwrap(), vec![Node::Element(a)]);
    }

    #[test]
    fn template_instance_token_is_unsupported_here() {
        let mut b = Vec::new();
        frag_header(&mut b);
        b.push(TOK_TEMPLATE_INSTANCE);
        assert!(matches!(
            decode(&b),
            Err(DeserializeError::Unsupported(_))
        ));
    }

    #[test]
    fn substitution_tokens_are_unsupported_here() {
        for tok in [TOK_NORMAL_SUBSTITUTION, TOK_OPTIONAL_SUBSTITUTION] {
            let mut b = Vec::new();
            frag_header(&mut b);
            b.push(tok);
            assert!(matches!(decode(&b), Err(DeserializeError::Unsupported(_))));
        }
    }

    #[test]
    fn unknown_token_is_error() {
        let b = vec![0x80u8]; // invalid token byte
        assert!(matches!(
            decode(&b),
            Err(DeserializeError::UnknownToken { .. })
        ));
    }

    #[test]
    fn unbalanced_close_is_error() {
        // EndElement with no open element
        let mut b = Vec::new();
        frag_header(&mut b);
        b.push(TOK_END_ELEMENT);
        assert!(matches!(decode(&b), Err(DeserializeError::UnbalancedClose)));
    }

    #[test]
    fn truncated_value_is_error() {
        let mut b = Vec::new();
        frag_header(&mut b);
        push_open(&mut b, "Event", false);
        b.push(TOK_CLOSE_START_ELEMENT);
        b.push(TOK_VALUE);
        b.push(0x07); // Int32, but no data follows
        assert!(decode(&b).is_err());
    }

    #[test]
    fn depth_cap_is_enforced() {
        // build N+1 nested opens; run with a tiny depth cap via the internal fn
        let mut b = Vec::new();
        frag_header(&mut b);
        for _ in 0..5 {
            push_open(&mut b, "x", false);
            b.push(TOK_CLOSE_START_ELEMENT);
        }
        let mut names = NameCache::new();
        let mut cur = Cursor::new(&b);
        let limits = Limits {
            max_depth: 2,
            max_tokens: MAX_TOKENS,
        };
        assert!(matches!(
            run(&mut cur, &b, &mut names, false, limits),
            Err(DeserializeError::DepthLimit { limit: 2 })
        ));
    }

    #[test]
    fn iteration_cap_is_enforced() {
        let mut b = Vec::new();
        frag_header(&mut b);
        push_open(&mut b, "x", false);
        b.push(TOK_CLOSE_START_ELEMENT);
        b.push(TOK_END_ELEMENT);
        b.push(TOK_END_OF_STREAM);
        let mut names = NameCache::new();
        let mut cur = Cursor::new(&b);
        let limits = Limits {
            max_depth: MAX_DEPTH,
            max_tokens: 1,
        };
        assert!(matches!(
            run(&mut cur, &b, &mut names, false, limits),
            Err(DeserializeError::IterationLimit { limit: 1 })
        ));
    }

    #[test]
    fn flushes_unclosed_elements_without_data_loss() {
        // <a><b>  (no end tags before EOS) — both elements must survive nested
        let mut b = Vec::new();
        frag_header(&mut b);
        push_open(&mut b, "a", false);
        b.push(TOK_CLOSE_START_ELEMENT);
        push_open(&mut b, "b", false);
        b.push(TOK_CLOSE_START_ELEMENT);
        b.push(TOK_END_OF_STREAM);
        let mut a = elem("a");
        a.children.push(Node::Element(elem("b")));
        assert_eq!(decode(&b).unwrap(), vec![Node::Element(a)]);
    }
}
