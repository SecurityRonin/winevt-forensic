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
    is_valid_token_byte, read_attribute_name, read_fragment_header, read_open_start_element,
    token_base, token_has_more, TokenError, TOK_ATTRIBUTE, TOK_CLOSE_EMPTY_ELEMENT,
    TOK_CLOSE_START_ELEMENT, TOK_END_ELEMENT, TOK_END_OF_STREAM, TOK_FRAGMENT_HEADER,
    TOK_NORMAL_SUBSTITUTION, TOK_OPEN_START_ELEMENT, TOK_OPTIONAL_SUBSTITUTION,
    TOK_TEMPLATE_INSTANCE, TOK_VALUE,
};
use crate::value::{read_value, BinXmlValue, ValueError};
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
pub(crate) struct Limits {
    pub(crate) max_depth: usize,
    pub(crate) max_tokens: usize,
}

/// Decode a (top-level, template-free or template-instance) BinXml fragment
/// into a list of top-level nodes. `chunk` is the full chunk slice (the
/// addressing base for name references).
pub fn deserialize_fragment(
    cur: &mut Cursor<'_>,
    chunk: &[u8],
    names: &mut NameCache,
) -> Result<Vec<Node>, DeserializeError> {
    let end = chunk.len();
    run(
        cur,
        chunk,
        names,
        None,
        end,
        Limits {
            max_depth: MAX_DEPTH,
            max_tokens: MAX_TOKENS,
        },
    )
}

/// The token loop with explicit limits.
///
/// `substitutions` is `Some` only when decoding a template-definition body —
/// it both enables substitution resolution and signals the `dependency_id` that
/// open-element headers carry in that context. `end` is a hard stop position in
/// the chunk (the def body's declared end, or `chunk.len()` at top level).
pub(crate) fn run(
    cur: &mut Cursor<'_>,
    chunk: &[u8],
    names: &mut NameCache,
    substitutions: Option<&[BinXmlValue]>,
    end: usize,
    limits: Limits,
) -> Result<Vec<Node>, DeserializeError> {
    let has_dep_id = substitutions.is_some();
    let mut stack: Vec<Element> = Vec::new();
    let mut roots: Vec<Node> = Vec::new();
    let mut steps = 0usize;

    while cur.position() < end && !cur.is_empty() {
        steps += 1;
        if steps > limits.max_tokens {
            return Err(DeserializeError::IterationLimit {
                limit: limits.max_tokens,
            });
        }
        let token_offset = cur.position();
        let token = cur.read_u8()?;
        // Reject high-bit garbage early: 0x80's low nibble is 0x00, which would
        // otherwise be misread as EndOfStream (and 0x81 as OpenStartElement…).
        if !is_valid_token_byte(token) {
            return Err(DeserializeError::UnknownToken {
                token,
                offset: token_offset,
            });
        }
        let has_more = token_has_more(token);
        match token_base(token) {
            TOK_END_OF_STREAM => break,
            TOK_FRAGMENT_HEADER => {
                read_fragment_header(cur)?;
            }
            TOK_OPEN_START_ELEMENT => {
                if stack.len() >= limits.max_depth {
                    return Err(DeserializeError::DepthLimit {
                        limit: limits.max_depth,
                    });
                }
                let oe = read_open_start_element(cur, chunk, names, has_dep_id, has_more)?;
                let mut el = Element {
                    name: oe.name,
                    ..Default::default()
                };
                if has_more {
                    read_attributes(cur, chunk, names, &mut el)?;
                }
                stack.push(el);
            }
            TOK_CLOSE_START_ELEMENT => {
                // The element is now open for children — nothing to materialize.
            }
            TOK_CLOSE_EMPTY_ELEMENT | TOK_END_ELEMENT => {
                let el = stack.pop().ok_or(DeserializeError::UnbalancedClose)?;
                attach(&mut stack, &mut roots, Node::Element(el));
            }
            TOK_VALUE => {
                let text = read_value_token(cur)?;
                attach(&mut stack, &mut roots, Node::Text(text));
            }
            TOK_TEMPLATE_INSTANCE => {
                let nodes =
                    crate::template::read_template_instance(cur, chunk, names, limits)?;
                for node in nodes {
                    attach(&mut stack, &mut roots, node);
                }
            }
            TOK_NORMAL_SUBSTITUTION => {
                resolve_substitution(cur, substitutions, false, &mut stack, &mut roots)?;
            }
            TOK_OPTIONAL_SUBSTITUTION => {
                resolve_substitution(cur, substitutions, true, &mut stack, &mut roots)?;
            }
            _ => {
                return Err(DeserializeError::UnknownToken {
                    token,
                    offset: token_offset,
                });
            }
        }
    }

    // Flush any unclosed elements, innermost first, preserving nesting.
    while let Some(el) = stack.pop() {
        attach(&mut stack, &mut roots, Node::Element(el));
    }
    Ok(roots)
}

/// Read the attribute list following an open-start-element: a run of attribute
/// tokens (`name` + inline `Value`) until a non-attribute token is seen.
fn read_attributes(
    cur: &mut Cursor<'_>,
    chunk: &[u8],
    names: &mut NameCache,
    el: &mut Element,
) -> Result<(), DeserializeError> {
    while !cur.is_empty() {
        let save = cur.position();
        let tok = cur.read_u8()?;
        if is_valid_token_byte(tok) && token_base(tok) == TOK_ATTRIBUTE {
            let name = read_attribute_name(cur, chunk, names)?;
            let vtok = cur.read_u8()?;
            if is_valid_token_byte(vtok) && token_base(vtok) == TOK_VALUE {
                let value = read_value_token(cur)?;
                el.attributes.push((name, value));
            } else {
                return Err(DeserializeError::Unsupported("non-inline attribute value"));
            }
        } else {
            cur.seek(save)?; // not an attribute — rewind for the main loop
            break;
        }
    }
    Ok(())
}

/// Read a value token's body: `value_type u8` then the inline (self-describing)
/// value, rendered to text.
fn read_value_token(cur: &mut Cursor<'_>) -> Result<String, DeserializeError> {
    let value_type = cur.read_u8()?;
    Ok(read_value(cur, value_type, None)?.render())
}

/// Attach a node to the current open element, or to the roots if none is open.
fn attach(stack: &mut [Element], roots: &mut Vec<Node>, node: Node) {
    match stack.last_mut() {
        Some(parent) => parent.children.push(node),
        None => roots.push(node),
    }
}

/// Resolve a `0x0d`/`0x0e` substitution against the template instance's value
/// array. A substitution outside a template body (no values in scope) is an
/// error; an ignored optional placeholder or a `Null`/out-of-range value
/// produces no node.
fn resolve_substitution(
    cur: &mut Cursor<'_>,
    substitutions: Option<&[BinXmlValue]>,
    optional: bool,
    stack: &mut [Element],
    roots: &mut Vec<Node>,
) -> Result<(), DeserializeError> {
    // RED stub — implemented in the GREEN commit.
    let _ = (cur, substitutions, optional, stack, roots);
    Err(DeserializeError::Unsupported("substitution"))
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
        deserialize_fragment(&mut cur, buf, &mut names)
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
    fn valid_but_unexpected_token_is_unknown() {
        // 0x07 (CDATA) is a structurally valid token byte but is not handled at
        // this position — must error, not be silently skipped.
        let mut b = Vec::new();
        frag_header(&mut b);
        b.push(0x07);
        assert!(matches!(
            decode(&b),
            Err(DeserializeError::UnknownToken { token: 0x07, .. })
        ));
    }

    #[test]
    fn non_inline_attribute_value_is_unsupported() {
        // An attribute whose value is a substitution (not an inline Value) is
        // outside this template-free layer.
        let mut b = Vec::new();
        frag_header(&mut b);
        push_open(&mut b, "Event", true);
        b.push(TOK_ATTRIBUTE);
        push_inline_name(&mut b, "Attr");
        b.push(TOK_NORMAL_SUBSTITUTION);
        assert!(matches!(decode(&b), Err(DeserializeError::Unsupported(_))));
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
            run(&mut cur, &b, &mut names, None, b.len(), limits),
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
            run(&mut cur, &b, &mut names, None, b.len(), limits),
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
