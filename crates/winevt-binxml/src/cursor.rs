//! Bounds-checked, panic-free cursor over a byte slice.
//!
//! Every read is bounds-checked and returns a [`CursorError`] on out-of-range
//! access — never a panic, never an unchecked index. All multi-byte reads are
//! little-endian (the EVTX/BinXml on-disk convention). Length arithmetic uses
//! checked operations so a hostile size field cannot overflow into a small
//! in-bounds read.

use thiserror::Error;

/// Error from a bounds-checked cursor read.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum CursorError {
    /// A read needed more bytes than remain in the slice.
    #[error("out of bounds at offset {offset}: need {need} bytes, {available} available")]
    OutOfBounds {
        offset: usize,
        need: usize,
        available: usize,
    },
    /// A seek target was past the end of the slice.
    #[error("seek to {target} exceeds length {len}")]
    InvalidSeek { target: usize, len: usize },
    /// A length computation (e.g. `char_count * 2`) overflowed `usize`.
    #[error("length overflow computing {need} units at offset {offset}")]
    LengthOverflow { offset: usize, need: usize },
}

/// A forward/seekable cursor over `&[u8]` with bounds-checked reads.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Create a cursor at offset 0 over `data`.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Create a cursor positioned at `pos` (clamped to the slice length).
    #[must_use]
    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Self {
            data,
            pos: pos.min(data.len()),
        }
    }

    /// Current offset from the start of the slice.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Total length of the underlying slice.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Bytes remaining from the current position to the end.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Whether the cursor is at (or past) the end.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Move the cursor to an absolute offset. `target` may equal `len()`
    /// (end position) but not exceed it.
    pub fn seek(&mut self, target: usize) -> Result<(), CursorError> {
        if target > self.data.len() {
            return Err(CursorError::InvalidSeek {
                target,
                len: self.data.len(),
            });
        }
        self.pos = target;
        Ok(())
    }

    /// Advance the cursor by `n` bytes, bounds-checked.
    pub fn skip(&mut self, n: usize) -> Result<(), CursorError> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.oob(n))?;
        if end > self.data.len() {
            return Err(self.oob(n));
        }
        self.pos = end;
        Ok(())
    }

    /// Borrow the next `n` bytes and advance past them.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], CursorError> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.oob(n))?;
        let slice = self.data.get(self.pos..end).ok_or_else(|| self.oob(n))?;
        self.pos = end;
        Ok(slice)
    }

    /// Read exactly `N` bytes into a fixed array. Infallible length by
    /// construction (`take(N)` yields exactly `N` bytes).
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CursorError> {
        let slice = self.take(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Ok(arr)
    }

    /// Read a `u8`.
    pub fn read_u8(&mut self) -> Result<u8, CursorError> {
        Ok(u8::from_le_bytes(self.read_array::<1>()?))
    }

    /// Read an `i8`.
    pub fn read_i8(&mut self) -> Result<i8, CursorError> {
        Ok(i8::from_le_bytes(self.read_array::<1>()?))
    }

    /// Read a little-endian `u16`.
    pub fn read_u16_le(&mut self) -> Result<u16, CursorError> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    /// Read a little-endian `i16`.
    pub fn read_i16_le(&mut self) -> Result<i16, CursorError> {
        Ok(i16::from_le_bytes(self.read_array::<2>()?))
    }

    /// Read a little-endian `u32`.
    pub fn read_u32_le(&mut self) -> Result<u32, CursorError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    /// Read a little-endian `i32`.
    pub fn read_i32_le(&mut self) -> Result<i32, CursorError> {
        Ok(i32::from_le_bytes(self.read_array::<4>()?))
    }

    /// Read a little-endian `u64`.
    pub fn read_u64_le(&mut self) -> Result<u64, CursorError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    /// Read a little-endian `i64`.
    pub fn read_i64_le(&mut self) -> Result<i64, CursorError> {
        Ok(i64::from_le_bytes(self.read_array::<8>()?))
    }

    /// Read a little-endian `f32`.
    pub fn read_f32_le(&mut self) -> Result<f32, CursorError> {
        Ok(f32::from_le_bytes(self.read_array::<4>()?))
    }

    /// Read a little-endian `f64`.
    pub fn read_f64_le(&mut self) -> Result<f64, CursorError> {
        Ok(f64::from_le_bytes(self.read_array::<8>()?))
    }

    /// Read `units` UTF-16LE code units (`units * 2` bytes) and decode lossily
    /// (replacement char for unpaired surrogates — robust against hostile data).
    pub fn read_utf16le_chars(&mut self, units: usize) -> Result<String, CursorError> {
        let nbytes = units.checked_mul(2).ok_or(CursorError::LengthOverflow {
            offset: self.pos,
            need: units,
        })?;
        let bytes = self.take(nbytes)?;
        let code_units = bytes.chunks_exact(2).map(|pair| {
            let mut b = [0u8; 2];
            b.copy_from_slice(pair);
            u16::from_le_bytes(b)
        });
        Ok(char::decode_utf16(code_units)
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect())
    }

    /// Read a `u16` code-unit count, then that many UTF-16LE code units.
    pub fn read_utf16le_len_prefixed(&mut self) -> Result<String, CursorError> {
        let units = self.read_u16_le()? as usize;
        self.read_utf16le_chars(units)
    }

    /// Build an `OutOfBounds` error at the current position.
    fn oob(&self, need: usize) -> CursorError {
        CursorError::OutOfBounds {
            offset: self.pos,
            need,
            available: self.remaining(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn new_and_getters() {
        let c = Cursor::new(&[1, 2, 3]);
        assert_eq!(c.position(), 0);
        assert_eq!(c.len(), 3);
        assert_eq!(c.remaining(), 3);
        assert!(!c.is_empty());
        assert!(Cursor::new(&[]).is_empty());
    }

    #[test]
    fn at_clamps_position() {
        let c = Cursor::at(&[1, 2, 3], 99);
        assert_eq!(c.position(), 3);
        assert!(c.is_empty());
    }

    #[test]
    fn read_u8_and_i8() {
        let mut c = Cursor::new(&[0xAB, 0xFF]);
        assert_eq!(c.read_u8().unwrap(), 0xAB);
        assert_eq!(c.position(), 1);
        assert_eq!(c.read_i8().unwrap(), -1);
        assert_eq!(c.position(), 2);
    }

    #[test]
    fn read_u16_i16_le() {
        let mut c = Cursor::new(&[0x01, 0x02]);
        assert_eq!(c.read_u16_le().unwrap(), 0x0201);
        let mut c = Cursor::new(&[0xFF, 0xFF]);
        assert_eq!(c.read_i16_le().unwrap(), -1);
    }

    #[test]
    fn read_u32_i32_le() {
        let mut c = Cursor::new(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(c.read_u32_le().unwrap(), 0x0403_0201);
        let mut c = Cursor::new(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(c.read_i32_le().unwrap(), -1);
    }

    #[test]
    fn read_u64_i64_le() {
        let mut c = Cursor::new(&[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(c.read_u64_le().unwrap(), 1);
        let mut c = Cursor::new(&[0xFF; 8]);
        assert_eq!(c.read_i64_le().unwrap(), -1);
    }

    #[test]
    fn read_f32_f64_le() {
        // 1.0f32 = 0x3F800000 LE
        let mut c = Cursor::new(&[0x00, 0x00, 0x80, 0x3F]);
        assert_eq!(c.read_f32_le().unwrap(), 1.0_f32);
        // 1.0f64 = 0x3FF0000000000000 LE
        let mut c = Cursor::new(&[0, 0, 0, 0, 0, 0, 0xF0, 0x3F]);
        assert_eq!(c.read_f64_le().unwrap(), 1.0_f64);
    }

    #[test]
    fn take_advances_and_borrows() {
        let mut c = Cursor::new(&[1, 2, 3, 4]);
        assert_eq!(c.take(2).unwrap(), &[1, 2]);
        assert_eq!(c.position(), 2);
        assert_eq!(c.take(2).unwrap(), &[3, 4]);
        assert!(c.is_empty());
    }

    #[test]
    fn take_past_end_is_error() {
        let mut c = Cursor::new(&[1, 2]);
        assert!(matches!(
            c.take(3),
            Err(CursorError::OutOfBounds {
                need: 3,
                available: 2,
                ..
            })
        ));
        // position must not move on error
        assert_eq!(c.position(), 0);
    }

    #[test]
    fn read_u32_truncated_is_error() {
        let mut c = Cursor::new(&[1, 2, 3]);
        assert!(matches!(
            c.read_u32_le(),
            Err(CursorError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn seek_valid_and_to_end() {
        let mut c = Cursor::new(&[1, 2, 3]);
        c.seek(2).unwrap();
        assert_eq!(c.position(), 2);
        c.seek(3).unwrap(); // end position is valid
        assert!(c.is_empty());
    }

    #[test]
    fn seek_past_end_is_error() {
        let mut c = Cursor::new(&[1, 2, 3]);
        assert!(matches!(
            c.seek(4),
            Err(CursorError::InvalidSeek { target: 4, len: 3 })
        ));
    }

    #[test]
    fn skip_valid_and_past_end() {
        let mut c = Cursor::new(&[1, 2, 3, 4]);
        c.skip(2).unwrap();
        assert_eq!(c.position(), 2);
        assert!(matches!(c.skip(99), Err(CursorError::OutOfBounds { .. })));
        assert_eq!(c.position(), 2, "skip error must not advance");
    }

    #[test]
    fn utf16le_chars() {
        // "Hi" UTF-16LE
        let mut c = Cursor::new(&[b'H', 0, b'i', 0]);
        assert_eq!(c.read_utf16le_chars(2).unwrap(), "Hi");
        assert_eq!(c.position(), 4);
    }

    #[test]
    fn utf16le_chars_lossy_on_bad_surrogate() {
        // Lone high surrogate 0xD800 → replacement char, no panic.
        let mut c = Cursor::new(&[0x00, 0xD8]);
        let s = c.read_utf16le_chars(1).unwrap();
        assert_eq!(s, "\u{FFFD}");
    }

    #[test]
    fn utf16le_len_prefixed() {
        // count=2, then "Hi"
        let mut c = Cursor::new(&[0x02, 0x00, b'H', 0, b'i', 0]);
        assert_eq!(c.read_utf16le_len_prefixed().unwrap(), "Hi");
        assert_eq!(c.position(), 6);
    }

    #[test]
    fn utf16le_chars_overflow_guard() {
        let mut c = Cursor::new(&[0u8; 8]);
        // units * 2 overflows usize → LengthOverflow, not a panic.
        assert!(matches!(
            c.read_utf16le_chars(usize::MAX),
            Err(CursorError::LengthOverflow { .. })
        ));
    }

    #[test]
    fn utf16le_chars_truncated_is_error() {
        let mut c = Cursor::new(&[b'H', 0]);
        assert!(matches!(
            c.read_utf16le_chars(5),
            Err(CursorError::OutOfBounds { .. })
        ));
    }
}
