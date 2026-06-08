//! Per-chunk BinXml name resolution (the element/attribute string table).
//!
//! A name reference in the token stream is a `u32` **chunk-relative** offset. If
//! that offset equals the stream position right after it, the name is defined
//! *inline* (read it here, advance the cursor); otherwise it is a back-reference
//! to a name defined earlier in the chunk.
//!
//! Each name structure is self-describing at its offset —
//! `next_string u32, hash u16, char_count u16, UTF-16LE chars, NUL u16` — so
//! resolution is **lazy and per-offset**. We never follow the `next_string`
//! hash-bucket chain, which makes a hostile linked-list cycle structurally
//! impossible (the reference walks those chains; we do not).

#![allow(clippy::doc_markdown)] // "BinXml" appears throughout these docs

use std::collections::HashMap;

use crate::cursor::{Cursor, CursorError};
use thiserror::Error;

/// Error resolving a BinXml name.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum NameError {
    /// A bounds-checked cursor read failed (truncated / out-of-range offset).
    #[error("cursor: {0}")]
    Cursor(#[from] CursorError),
}

/// Cache of resolved names keyed by chunk-relative offset.
#[derive(Debug, Default)]
pub struct NameCache {
    map: HashMap<usize, String>,
}

impl NameCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct names resolved so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether no names have been resolved yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Read a name reference at `cur` and return the name. `chunk` is the full
    /// chunk slice `cur` is reading (the addressing base for back-references).
    pub fn read_name_ref(
        &mut self,
        cur: &mut Cursor<'_>,
        chunk: &[u8],
    ) -> Result<String, NameError> {
        let name_offset = cur.read_u32_le()? as usize;
        let pos_after = cur.position();
        if name_offset == pos_after {
            // Inline definition: the struct begins here — read from the main
            // cursor so it advances past the whole inline name.
            let name = read_name_fields(cur)?;
            cur.skip(2)?; // NUL terminator
            self.map.insert(name_offset, name.clone());
            Ok(name)
        } else if let Some(cached) = self.map.get(&name_offset) {
            Ok(cached.clone())
        } else {
            // Back-reference: read the self-describing struct at the offset via a
            // throwaway sub-cursor (the main cursor is not advanced into it).
            let mut sub = Cursor::at(chunk, name_offset);
            let name = read_name_fields(&mut sub)?;
            self.map.insert(name_offset, name.clone());
            Ok(name)
        }
    }
}

/// Read `next_string u32, hash u16, char_count u16, UTF-16LE chars` and return
/// the decoded name. Does not consume the trailing NUL terminator.
fn read_name_fields(cur: &mut Cursor<'_>) -> Result<String, NameError> {
    cur.skip(4)?; // next_string
    cur.skip(2)?; // hash
    let count = cur.read_u16_le()?;
    Ok(cur.read_utf16le_chars(usize::from(count))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `next=0, hash=0, char_count, "<s>", NUL` — a name struct body.
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

    #[test]
    fn inline_name_is_read_and_cursor_advances() {
        // offset 0: name_offset = 4 (points right after the u32 → inline)
        // offset 4: name struct "Hi"
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&4u32.to_le_bytes());
        chunk.extend_from_slice(&name_struct("Hi"));

        let mut cache = NameCache::new();
        let mut cur = Cursor::new(&chunk);
        let name = cache.read_name_ref(&mut cur, &chunk).unwrap();
        assert_eq!(name, "Hi");
        // cursor must end past the whole inline struct (4 offset + 10 + 2*2 = 18)
        assert_eq!(cur.position(), 18);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn back_reference_resolves_from_offset() {
        // offset 0: a name struct "Channel" at 0
        // then a ref u32 = 0 read from a later position
        let mut chunk = name_struct("Channel");
        let ref_pos = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes()); // name_offset = 0 (back-ref)

        let mut cache = NameCache::new();
        let mut cur = Cursor::new(&chunk);
        cur.seek(ref_pos).unwrap();
        let name = cache.read_name_ref(&mut cur, &chunk).unwrap();
        assert_eq!(name, "Channel");
        // back-ref does not advance into the struct; only the u32 was consumed
        assert_eq!(cur.position(), ref_pos + 4);
    }

    #[test]
    fn back_reference_uses_cache_on_second_hit() {
        let mut chunk = name_struct("System");
        let p1 = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let p2 = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes());

        let mut cache = NameCache::new();
        let mut cur = Cursor::new(&chunk);
        cur.seek(p1).unwrap();
        assert_eq!(cache.read_name_ref(&mut cur, &chunk).unwrap(), "System");
        cur.seek(p2).unwrap();
        assert_eq!(cache.read_name_ref(&mut cur, &chunk).unwrap(), "System");
        assert_eq!(cache.len(), 1, "same offset resolved once, then cached");
    }

    #[test]
    fn out_of_range_offset_is_error_not_panic() {
        // name_offset points way past the chunk → Err
        let chunk = 9999u32.to_le_bytes().to_vec();
        let mut cache = NameCache::new();
        let mut cur = Cursor::new(&chunk);
        assert!(cache.read_name_ref(&mut cur, &chunk).is_err());
    }

    #[test]
    fn new_cache_is_empty() {
        let c = NameCache::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }
}
