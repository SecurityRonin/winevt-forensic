//! BinXml token ids and fixed-layout token readers.
//!
//! Each token in the stream is a 1-byte id (`0x00..=0x0f`); the `0x40` bit is a
//! "has-attributes / has-more" flag OR'd onto element, value and attribute
//! tokens. This module exposes the token constants, the bit helpers, and the
//! readers for the fixed-layout token bodies (fragment header, substitution
//! descriptor, open-start-element header, attribute name). The recursive tree
//! walk and template-value reading live in the deserializer.

#![allow(clippy::doc_markdown)] // "BinXml" appears throughout these docs

use crate::cursor::{Cursor, CursorError};
use crate::name::{NameCache, NameError};
use crate::value::VT_NULL;
use thiserror::Error;

/// Error reading a token body.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum TokenError {
    /// A bounds-checked cursor read failed.
    #[error("cursor: {0}")]
    Cursor(#[from] CursorError),
    /// Name resolution failed.
    #[error("name: {0}")]
    Name(#[from] NameError),
}

// ── Token ids (base values, before the 0x40 flag) ───────────────────────────
pub const TOK_END_OF_STREAM: u8 = 0x00;
pub const TOK_OPEN_START_ELEMENT: u8 = 0x01;
pub const TOK_CLOSE_START_ELEMENT: u8 = 0x02;
pub const TOK_CLOSE_EMPTY_ELEMENT: u8 = 0x03;
pub const TOK_END_ELEMENT: u8 = 0x04;
pub const TOK_VALUE: u8 = 0x05;
pub const TOK_ATTRIBUTE: u8 = 0x06;
pub const TOK_CDATA: u8 = 0x07;
pub const TOK_CHAR_REF: u8 = 0x08;
pub const TOK_ENTITY_REF: u8 = 0x09;
pub const TOK_PI_TARGET: u8 = 0x0a;
pub const TOK_PI_DATA: u8 = 0x0b;
pub const TOK_TEMPLATE_INSTANCE: u8 = 0x0c;
pub const TOK_NORMAL_SUBSTITUTION: u8 = 0x0d;
pub const TOK_OPTIONAL_SUBSTITUTION: u8 = 0x0e;
pub const TOK_FRAGMENT_HEADER: u8 = 0x0f;
/// The "has-attributes / has-more" flag bit.
pub const TOKEN_FLAG_MORE: u8 = 0x40;

/// The base token id (low nibble), discarding the `0x40` flag.
#[must_use]
pub fn token_base(byte: u8) -> u8 {
    byte & 0x0F
}

/// Whether the `0x40` has-attributes/has-more flag is set.
#[must_use]
pub fn token_has_more(byte: u8) -> bool {
    byte & TOKEN_FLAG_MORE != 0
}

/// Whether `byte` is a structurally valid token id: only the low nibble and the
/// `0x40` flag may be set (rejects `0x80`+ and other garbage early).
#[must_use]
pub fn is_valid_token_byte(byte: u8) -> bool {
    byte & 0xB0 == 0
}

/// A decoded fragment header (`0x0f`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentHeader {
    pub major: u8,
    pub minor: u8,
    pub flags: u8,
}

/// A substitution descriptor (`0x0d` normal / `0x0e` optional).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstitutionDescriptor {
    /// Index into the template instance's value array.
    pub index: u16,
    /// The declared value type id.
    pub value_type: u8,
    /// Whether this was an optional substitution token.
    pub optional: bool,
    /// `optional && value_type == Null` — a deleted placeholder to omit.
    pub ignore: bool,
}

/// The header of an open-start-element token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenElement {
    /// The element (tag) name.
    pub name: String,
    /// Declared size of the element content that follows.
    pub data_size: u32,
}

/// Read a fragment header: `major u8, minor u8, flags u8`.
pub fn read_fragment_header(cur: &mut Cursor<'_>) -> Result<FragmentHeader, TokenError> {
    Ok(FragmentHeader {
        major: cur.read_u8()?,
        minor: cur.read_u8()?,
        flags: cur.read_u8()?,
    })
}

/// Read a substitution descriptor: `index u16, value_type u8`.
pub fn read_substitution_descriptor(
    cur: &mut Cursor<'_>,
    optional: bool,
) -> Result<SubstitutionDescriptor, TokenError> {
    let index = cur.read_u16_le()?;
    let value_type = cur.read_u8()?;
    let ignore = optional && value_type == VT_NULL;
    Ok(SubstitutionDescriptor {
        index,
        value_type,
        optional,
        ignore,
    })
}

/// Read an open-start-element header: `[dep_id u16], data_size u32, name,
/// [attr_list_size u32]`. `has_dep_id` is true only in template definitions.
pub fn read_open_start_element(
    cur: &mut Cursor<'_>,
    chunk: &[u8],
    names: &mut NameCache,
    has_dep_id: bool,
    has_attributes: bool,
) -> Result<OpenElement, TokenError> {
    if has_dep_id {
        let _dependency_identifier = cur.read_u16_le()?;
    }
    let data_size = cur.read_u32_le()?;
    let name = names.read_name_ref(cur, chunk)?;
    if has_attributes {
        let _attribute_list_data_size = cur.read_u32_le()?;
    }
    Ok(OpenElement { name, data_size })
}

/// Read an attribute token's name reference.
pub fn read_attribute_name(
    cur: &mut Cursor<'_>,
    chunk: &[u8],
    names: &mut NameCache,
) -> Result<String, TokenError> {
    Ok(names.read_name_ref(cur, chunk)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `next=0, hash=0, char_count, "<s>", NUL` name struct body.
    fn name_struct(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in &units {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v.extend_from_slice(&0u16.to_le_bytes());
        v
    }

    #[test]
    fn token_base_and_flag() {
        assert_eq!(token_base(0x41), TOK_OPEN_START_ELEMENT);
        assert!(token_has_more(0x41));
        assert_eq!(token_base(0x01), TOK_OPEN_START_ELEMENT);
        assert!(!token_has_more(0x01));
        assert_eq!(token_base(0x0f), TOK_FRAGMENT_HEADER);
    }

    #[test]
    fn valid_token_bytes() {
        assert!(is_valid_token_byte(0x00));
        assert!(is_valid_token_byte(0x0f));
        assert!(is_valid_token_byte(0x41)); // value with flag
        assert!(!is_valid_token_byte(0x80));
        assert!(!is_valid_token_byte(0xFF));
        assert!(!is_valid_token_byte(0x10));
    }

    #[test]
    fn fragment_header_reads_three_bytes() {
        let mut cur = Cursor::new(&[0x01, 0x01, 0x00, 0x99]);
        let h = read_fragment_header(&mut cur).unwrap();
        assert_eq!(
            h,
            FragmentHeader {
                major: 1,
                minor: 1,
                flags: 0
            }
        );
        assert_eq!(cur.position(), 3);
    }

    #[test]
    fn substitution_descriptor_normal() {
        // index=5, type=0x01 (String), not optional
        let mut cur = Cursor::new(&[0x05, 0x00, 0x01]);
        let d = read_substitution_descriptor(&mut cur, false).unwrap();
        assert_eq!(
            d,
            SubstitutionDescriptor {
                index: 5,
                value_type: 0x01,
                optional: false,
                ignore: false
            }
        );
    }

    #[test]
    fn substitution_descriptor_optional_null_is_ignored() {
        // index=0, type=Null, optional → ignore
        let mut cur = Cursor::new(&[0x00, 0x00, VT_NULL]);
        let d = read_substitution_descriptor(&mut cur, true).unwrap();
        assert!(d.optional && d.ignore);
    }

    #[test]
    fn open_element_plain_inline_name() {
        // data_size u32 @0, then name_offset u32 @4 = 8 (inline), name struct @8
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&0x10u32.to_le_bytes());
        chunk.extend_from_slice(&8u32.to_le_bytes());
        chunk.extend_from_slice(&name_struct("Event"));

        let mut names = NameCache::new();
        let mut cur = Cursor::new(&chunk);
        let e = read_open_start_element(&mut cur, &chunk, &mut names, false, false).unwrap();
        assert_eq!(
            e,
            OpenElement {
                name: "Event".to_string(),
                data_size: 0x10
            }
        );
    }

    #[test]
    fn open_element_with_dependency_id_and_attributes() {
        // dep_id u16 @0, data_size u32 @2, name_offset u32 @6 = 10 (inline),
        // name struct @10, then attr_list_size u32 after the name.
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&0xAAAAu16.to_le_bytes());
        chunk.extend_from_slice(&0x20u32.to_le_bytes());
        chunk.extend_from_slice(&10u32.to_le_bytes());
        let name = name_struct("System");
        chunk.extend_from_slice(&name);
        chunk.extend_from_slice(&0x44u32.to_le_bytes()); // attr_list_size

        let mut names = NameCache::new();
        let mut cur = Cursor::new(&chunk);
        let e = read_open_start_element(&mut cur, &chunk, &mut names, true, true).unwrap();
        assert_eq!(e.name, "System");
        assert_eq!(e.data_size, 0x20);
        // cursor consumed dep_id + data_size + name + attr_list_size
        assert_eq!(cur.position(), 2 + 4 + 4 + name.len() + 4);
    }

    #[test]
    fn attribute_name_resolves() {
        // name_offset u32 @0 = 4 (inline), name struct @4
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&4u32.to_le_bytes());
        chunk.extend_from_slice(&name_struct("Name"));
        let mut names = NameCache::new();
        let mut cur = Cursor::new(&chunk);
        assert_eq!(
            read_attribute_name(&mut cur, &chunk, &mut names).unwrap(),
            "Name"
        );
    }

    #[test]
    fn truncated_fragment_header_is_error() {
        let mut cur = Cursor::new(&[0x01]);
        assert!(read_fragment_header(&mut cur).is_err());
    }
}
