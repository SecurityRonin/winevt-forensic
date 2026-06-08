//! BinXml value-type decoding (scalar types).
//!
//! Each substitution value / inline value carries a 1-byte type id. This module
//! decodes the scalar types into [`BinXmlValue`] and renders them to their
//! canonical string form. Array variants (`0x80 | base`) and embedded BinXml
//! (`0x21`) are handled by the deserializer (they expand / recurse in element
//! context) and are reported here as [`ValueError::Unsupported`].
//!
//! Byte semantics follow the omerbenamram `evtx` crate (Apache/MIT) and libevtx:
//! `String` is either *sized* (descriptor byte length, no prefix) or
//! *len-prefixed* (`u16` char count); `Bool` is 4 bytes (nonzero = true);
//! `SizeT` renders as hex; `Sid` is `8 + sub_count*4` bytes; FILETIME/SYSTEMTIME
//! render as UTC ISO-8601.

#![allow(clippy::doc_markdown)] // "BinXml" et al. appear throughout these docs

use crate::cursor::{Cursor, CursorError};
use thiserror::Error;

/// Error decoding a BinXml value.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ValueError {
    /// A bounds-checked cursor read failed.
    #[error("cursor: {0}")]
    Cursor(#[from] CursorError),
    /// The type id is not a known BinXml value type.
    #[error("unknown value type {type_id:#04x}")]
    UnknownType { type_id: u8 },
    /// The type is known but handled elsewhere (arrays, embedded BinXml).
    #[error("value type {type_id:#04x} is not handled by read_value (array/binxml)")]
    Unsupported { type_id: u8 },
    /// A SID sub-authority count exceeded the sane cap.
    #[error("invalid SID: sub-authority count {count} exceeds cap")]
    InvalidSid { count: u8 },
    /// A FILETIME/SYSTEMTIME could not be represented.
    #[error("invalid timestamp")]
    InvalidTimestamp,
}

// ── Value-type ids ──────────────────────────────────────────────────────────
pub const VT_NULL: u8 = 0x00;
pub const VT_STRING: u8 = 0x01;
pub const VT_ANSI_STRING: u8 = 0x02;
pub const VT_INT8: u8 = 0x03;
pub const VT_UINT8: u8 = 0x04;
pub const VT_INT16: u8 = 0x05;
pub const VT_UINT16: u8 = 0x06;
pub const VT_INT32: u8 = 0x07;
pub const VT_UINT32: u8 = 0x08;
pub const VT_INT64: u8 = 0x09;
pub const VT_UINT64: u8 = 0x0a;
pub const VT_REAL32: u8 = 0x0b;
pub const VT_REAL64: u8 = 0x0c;
pub const VT_BOOL: u8 = 0x0d;
pub const VT_BINARY: u8 = 0x0e;
pub const VT_GUID: u8 = 0x0f;
pub const VT_SIZET: u8 = 0x10;
pub const VT_FILETIME: u8 = 0x11;
pub const VT_SYSTIME: u8 = 0x12;
pub const VT_SID: u8 = 0x13;
pub const VT_HEX32: u8 = 0x14;
pub const VT_HEX64: u8 = 0x15;
/// Embedded BinXml fragment — decoded recursively by the deserializer.
pub const VT_BINXML: u8 = 0x21;
/// Bit set on a type id to mark an array variant.
pub const VT_ARRAY_FLAG: u8 = 0x80;

/// Maximum SID sub-authority count (real SIDs have ≤ 15).
const MAX_SID_SUBAUTHORITIES: u8 = 64;

/// A decoded scalar BinXml value. Complex types (GUID/SID/timestamps) carry
/// their already-rendered canonical string.
#[derive(Debug, Clone, PartialEq)]
pub enum BinXmlValue {
    Null,
    String(String),
    AnsiString(String),
    Int8(i8),
    UInt8(u8),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Real32(f32),
    Real64(f64),
    Bool(bool),
    Binary(Vec<u8>),
    Guid(String),
    SizeT(String),
    FileTime(String),
    SysTime(String),
    Sid(String),
    HexInt32(u32),
    HexInt64(u64),
}

impl BinXmlValue {
    /// Render the value to its canonical UTF-8 string (the text that appears in
    /// the decoded XML/JSON). `Null` renders as the empty string.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::String(s)
            | Self::AnsiString(s)
            | Self::Guid(s)
            | Self::SizeT(s)
            | Self::FileTime(s)
            | Self::SysTime(s)
            | Self::Sid(s) => s.clone(),
            Self::Int8(v) => v.to_string(),
            Self::UInt8(v) => v.to_string(),
            Self::Int16(v) => v.to_string(),
            Self::UInt16(v) => v.to_string(),
            Self::Int32(v) => v.to_string(),
            Self::UInt32(v) => v.to_string(),
            Self::Int64(v) => v.to_string(),
            Self::UInt64(v) => v.to_string(),
            Self::Real32(v) => v.to_string(),
            Self::Real64(v) => v.to_string(),
            Self::Bool(b) => b.to_string(),
            Self::Binary(b) => to_hex(b),
            Self::HexInt32(v) => format!("0x{v:08x}"),
            Self::HexInt64(v) => format!("0x{v:016x}"),
        }
    }
}

/// Decode a value of `type_id` from `cur`. `size` is the descriptor byte length
/// when the value is in a sized context (template substitution); `None` for
/// inline self-describing values.
pub fn read_value(
    cur: &mut Cursor<'_>,
    type_id: u8,
    size: Option<usize>,
) -> Result<BinXmlValue, ValueError> {
    // Array variants expand the containing element — the deserializer's job.
    if type_id & VT_ARRAY_FLAG != 0 {
        return Err(ValueError::Unsupported { type_id });
    }
    match type_id {
        VT_NULL => Ok(BinXmlValue::Null),
        VT_STRING => {
            let s = match size {
                Some(bytes) => cur.read_utf16le_chars(bytes / 2)?,
                None => cur.read_utf16le_len_prefixed()?,
            };
            Ok(BinXmlValue::String(s))
        }
        VT_ANSI_STRING => {
            let n = match size {
                Some(n) => n,
                None => usize::from(cur.read_u16_le()?),
            };
            Ok(BinXmlValue::AnsiString(ansi_to_string(cur.take(n)?)))
        }
        VT_INT8 => Ok(BinXmlValue::Int8(cur.read_i8()?)),
        VT_UINT8 => Ok(BinXmlValue::UInt8(cur.read_u8()?)),
        VT_INT16 => Ok(BinXmlValue::Int16(cur.read_i16_le()?)),
        VT_UINT16 => Ok(BinXmlValue::UInt16(cur.read_u16_le()?)),
        VT_INT32 => Ok(BinXmlValue::Int32(cur.read_i32_le()?)),
        VT_UINT32 => Ok(BinXmlValue::UInt32(cur.read_u32_le()?)),
        VT_INT64 => Ok(BinXmlValue::Int64(cur.read_i64_le()?)),
        VT_UINT64 => Ok(BinXmlValue::UInt64(cur.read_u64_le()?)),
        VT_REAL32 => Ok(BinXmlValue::Real32(cur.read_f32_le()?)),
        VT_REAL64 => Ok(BinXmlValue::Real64(cur.read_f64_le()?)),
        VT_BOOL => Ok(BinXmlValue::Bool(cur.read_u32_le()? != 0)),
        VT_BINARY => {
            let n = match size {
                Some(n) => n,
                None => usize::from(cur.read_u16_le()?),
            };
            Ok(BinXmlValue::Binary(cur.take(n)?.to_vec()))
        }
        VT_GUID => Ok(BinXmlValue::Guid(read_guid(cur)?)),
        VT_SIZET => match size {
            Some(4) => Ok(BinXmlValue::SizeT(format!("0x{:08x}", cur.read_u32_le()?))),
            _ => Ok(BinXmlValue::SizeT(format!("0x{:016x}", cur.read_u64_le()?))),
        },
        VT_FILETIME => Ok(BinXmlValue::FileTime(render_filetime(cur.read_u64_le()?)?)),
        VT_SYSTIME => Ok(BinXmlValue::SysTime(read_systime(cur)?)),
        VT_SID => Ok(BinXmlValue::Sid(read_sid(cur)?)),
        VT_HEX32 => Ok(BinXmlValue::HexInt32(cur.read_u32_le()?)),
        VT_HEX64 => Ok(BinXmlValue::HexInt64(cur.read_u64_le()?)),
        // Embedded BinXml recurses in element context — handled by the deserializer.
        VT_BINXML => Err(ValueError::Unsupported { type_id }),
        _ => Err(ValueError::UnknownType { type_id }),
    }
}

/// Lower-case hex of a byte slice, no separator.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode an ANSI (latin-1) string, dropping NUL bytes.
fn ansi_to_string(raw: &[u8]) -> String {
    raw.iter().filter(|&&b| b != 0).map(|&b| b as char).collect()
}

/// Read a 16-byte GUID and render it canonically (`xxxxxxxx-xxxx-…`, lower-case).
fn read_guid(cur: &mut Cursor<'_>) -> Result<String, ValueError> {
    let d1 = cur.read_u32_le()?;
    let d2 = cur.read_u16_le()?;
    let d3 = cur.read_u16_le()?;
    let d4 = cur.take(8)?;
    let (clock, node) = d4.split_at(2);
    Ok(format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{}-{}",
        to_hex(clock),
        to_hex(node)
    ))
}

/// Read a SID (`revision u8, sub_count u8, authority 48-bit BE, sub×u32 LE`) and
/// render `S-…`. Rejects an absurd sub-authority count before allocating.
fn read_sid(cur: &mut Cursor<'_>) -> Result<String, ValueError> {
    use std::fmt::Write;
    let revision = cur.read_u8()?;
    let sub_count = cur.read_u8()?;
    if sub_count > MAX_SID_SUBAUTHORITIES {
        return Err(ValueError::InvalidSid { count: sub_count });
    }
    let authority = cur
        .take(6)?
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let mut s = format!("S-{revision}-{authority}");
    for _ in 0..sub_count {
        let sub = cur.read_u32_le()?;
        let _ = write!(s, "-{sub}");
    }
    Ok(s)
}

/// Convert a Windows FILETIME (100ns since 1601-01-01 UTC) to UTC ISO-8601.
fn render_filetime(filetime: u64) -> Result<String, ValueError> {
    /// Seconds between 1601-01-01 and the Unix epoch.
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let secs_1601 = i64::try_from(filetime / 10_000_000).unwrap_or(i64::MAX);
    let nanos = u32::try_from((filetime % 10_000_000) * 100).unwrap_or(0);
    let unix_secs = secs_1601.saturating_sub(EPOCH_DIFF_SECS);
    let dt = chrono::DateTime::from_timestamp(unix_secs, nanos)
        .ok_or(ValueError::InvalidTimestamp)?;
    Ok(dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
}

/// Read a 16-byte SYSTEMTIME and render as UTC ISO-8601.
fn read_systime(cur: &mut Cursor<'_>) -> Result<String, ValueError> {
    let year = cur.read_u16_le()?;
    let month = cur.read_u16_le()?;
    let _day_of_week = cur.read_u16_le()?;
    let day = cur.read_u16_le()?;
    let hour = cur.read_u16_le()?;
    let minute = cur.read_u16_le()?;
    let second = cur.read_u16_le()?;
    let milli = cur.read_u16_le()?;
    let date = chrono::NaiveDate::from_ymd_opt(i32::from(year), u32::from(month), u32::from(day))
        .ok_or(ValueError::InvalidTimestamp)?;
    let dt = date
        .and_hms_milli_opt(
            u32::from(hour),
            u32::from(minute),
            u32::from(second),
            u32::from(milli),
        )
        .ok_or(ValueError::InvalidTimestamp)?;
    Ok(dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    fn cur(b: &[u8]) -> Cursor<'_> {
        Cursor::new(b)
    }

    #[test]
    fn null_renders_empty() {
        let v = read_value(&mut cur(&[]), VT_NULL, Some(0)).unwrap();
        assert_eq!(v, BinXmlValue::Null);
        assert_eq!(v.render(), "");
    }

    #[test]
    fn string_sized_reads_byte_length_no_prefix() {
        // "Hi" = 4 bytes UTF-16LE; sized context passes byte length.
        let v = read_value(&mut cur(&[b'H', 0, b'i', 0]), VT_STRING, Some(4)).unwrap();
        assert_eq!(v, BinXmlValue::String("Hi".to_string()));
        assert_eq!(v.render(), "Hi");
    }

    #[test]
    fn string_len_prefixed_when_unsized() {
        // count=2 then "Hi"
        let v = read_value(&mut cur(&[0x02, 0x00, b'H', 0, b'i', 0]), VT_STRING, None).unwrap();
        assert_eq!(v, BinXmlValue::String("Hi".to_string()));
    }

    #[test]
    fn signed_and_unsigned_ints() {
        assert_eq!(read_value(&mut cur(&[0xFF]), VT_INT8, Some(1)).unwrap(), BinXmlValue::Int8(-1));
        assert_eq!(read_value(&mut cur(&[0xFF]), VT_UINT8, Some(1)).unwrap(), BinXmlValue::UInt8(255));
        assert_eq!(read_value(&mut cur(&[0xFF, 0xFF]), VT_INT16, Some(2)).unwrap(), BinXmlValue::Int16(-1));
        assert_eq!(read_value(&mut cur(&[0x34, 0x12]), VT_UINT16, Some(2)).unwrap(), BinXmlValue::UInt16(0x1234));
        assert_eq!(read_value(&mut cur(&[0xFF, 0xFF, 0xFF, 0xFF]), VT_INT32, Some(4)).unwrap(), BinXmlValue::Int32(-1));
        assert_eq!(read_value(&mut cur(&[1, 0, 0, 0]), VT_UINT32, Some(4)).unwrap(), BinXmlValue::UInt32(1));
        assert_eq!(read_value(&mut cur(&[0xFF; 8]), VT_INT64, Some(8)).unwrap(), BinXmlValue::Int64(-1));
        assert_eq!(read_value(&mut cur(&[2, 0, 0, 0, 0, 0, 0, 0]), VT_UINT64, Some(8)).unwrap(), BinXmlValue::UInt64(2));
        assert_eq!(read_value(&mut cur(&[7, 0, 0, 0]), VT_INT32, Some(4)).unwrap().render(), "7");
    }

    #[test]
    fn reals() {
        assert_eq!(read_value(&mut cur(&[0, 0, 0x80, 0x3F]), VT_REAL32, Some(4)).unwrap(), BinXmlValue::Real32(1.0));
        assert_eq!(read_value(&mut cur(&[0, 0, 0, 0, 0, 0, 0xF0, 0x3F]), VT_REAL64, Some(8)).unwrap(), BinXmlValue::Real64(1.0));
    }

    #[test]
    fn bool_is_four_bytes_nonzero_true() {
        assert_eq!(read_value(&mut cur(&[0, 0, 0, 0]), VT_BOOL, Some(4)).unwrap(), BinXmlValue::Bool(false));
        assert_eq!(read_value(&mut cur(&[1, 0, 0, 0]), VT_BOOL, Some(4)).unwrap(), BinXmlValue::Bool(true));
        assert_eq!(read_value(&mut cur(&[0xFF, 0, 0, 0]), VT_BOOL, Some(4)).unwrap().render(), "true");
    }

    #[test]
    fn binary_renders_hex() {
        let v = read_value(&mut cur(&[0xDE, 0xAD, 0xBE, 0xEF]), VT_BINARY, Some(4)).unwrap();
        assert_eq!(v.render(), "deadbeef");
    }

    #[test]
    fn hex_ints_render_prefixed() {
        assert_eq!(read_value(&mut cur(&[0x78, 0x56, 0x34, 0x12]), VT_HEX32, Some(4)).unwrap().render(), "0x12345678");
        assert_eq!(read_value(&mut cur(&[0, 0, 0, 0, 0, 0, 0, 0x01]), VT_HEX64, Some(8)).unwrap().render(), "0x0100000000000000");
    }

    #[test]
    fn sizet_renders_hex_by_width() {
        assert_eq!(read_value(&mut cur(&[0x01, 0, 0, 0]), VT_SIZET, Some(4)).unwrap().render(), "0x00000001");
        assert_eq!(read_value(&mut cur(&[0x01, 0, 0, 0, 0, 0, 0, 0]), VT_SIZET, Some(8)).unwrap().render(), "0x0000000000000001");
    }

    #[test]
    fn guid_renders_canonical() {
        // data1=0x11223344 LE, data2=0x5566 LE, data3=0x7788 LE, d4 = 99 aa bb cc dd ee ff 00
        let bytes = [0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];
        let v = read_value(&mut cur(&bytes), VT_GUID, Some(16)).unwrap();
        assert_eq!(v.render(), "11223344-5566-7788-99aa-bbccddeeff00");
    }

    #[test]
    fn sid_renders_s_string() {
        // revision=1, sub_count=2, authority=5 (NT), subs: 32 (0x20), 544 (0x220)
        let bytes = [
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // rev, count, 48-bit BE authority
            0x20, 0x00, 0x00, 0x00, // sub 0 = 32
            0x20, 0x02, 0x00, 0x00, // sub 1 = 544
        ];
        let v = read_value(&mut cur(&bytes), VT_SID, Some(bytes.len())).unwrap();
        assert_eq!(v.render(), "S-1-5-32-544");
    }

    #[test]
    fn sid_rejects_absurd_subauthority_count() {
        let bytes = [0x01, 0xFF, 0, 0, 0, 0, 0, 5];
        assert!(matches!(
            read_value(&mut cur(&bytes), VT_SID, Some(8)),
            Err(ValueError::InvalidSid { count: 0xFF })
        ));
    }

    #[test]
    fn filetime_renders_utc_iso() {
        // 2017-01-01T00:00:00Z in FILETIME = 131277024000000000
        let ft: u64 = 131_277_024_000_000_000;
        let v = read_value(&mut cur(&ft.to_le_bytes()), VT_FILETIME, Some(8)).unwrap();
        assert_eq!(v.render(), "2017-01-01T00:00:00.000000Z");
    }

    #[test]
    fn systime_renders_utc_iso() {
        // year=2017 month=1 dow=0 day=1 hour=2 min=3 sec=4 ms=5
        let mut b = Vec::new();
        for v in [2017u16, 1, 0, 1, 2, 3, 4, 5] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        let v = read_value(&mut cur(&b), VT_SYSTIME, Some(16)).unwrap();
        assert_eq!(v.render(), "2017-01-01T02:03:04.005000Z");
    }

    #[test]
    fn array_and_binxml_are_unsupported_here() {
        assert!(matches!(
            read_value(&mut cur(&[0u8; 8]), VT_ARRAY_FLAG | VT_STRING, Some(4)),
            Err(ValueError::Unsupported { .. })
        ));
        assert!(matches!(
            read_value(&mut cur(&[0u8; 8]), VT_BINXML, None),
            Err(ValueError::Unsupported { type_id: 0x21 })
        ));
    }

    #[test]
    fn unknown_type_errors() {
        assert!(matches!(
            read_value(&mut cur(&[0u8; 4]), 0x7E, Some(4)),
            Err(ValueError::UnknownType { type_id: 0x7E })
        ));
    }

    #[test]
    fn truncated_value_is_error_not_panic() {
        assert!(matches!(
            read_value(&mut cur(&[0x01]), VT_INT32, Some(4)),
            Err(ValueError::Cursor(_))
        ));
    }

    #[test]
    fn ansi_string_sized_and_len_prefixed_drops_nul() {
        let v = read_value(&mut cur(&[b'O', b'K', 0x00]), VT_ANSI_STRING, Some(3)).unwrap();
        assert_eq!(v, BinXmlValue::AnsiString("OK".to_string()));
        // unsized: u16 byte-count prefix
        let v = read_value(&mut cur(&[0x02, 0x00, b'H', b'i']), VT_ANSI_STRING, None).unwrap();
        assert_eq!(v.render(), "Hi");
    }

    #[test]
    fn binary_unsized_uses_u16_prefix() {
        let v = read_value(&mut cur(&[0x02, 0x00, 0xAB, 0xCD]), VT_BINARY, None).unwrap();
        assert_eq!(v.render(), "abcd");
    }

    #[test]
    fn render_covers_every_scalar_arm() {
        assert_eq!(BinXmlValue::Int8(-2).render(), "-2");
        assert_eq!(BinXmlValue::UInt8(2).render(), "2");
        assert_eq!(BinXmlValue::Int16(-3).render(), "-3");
        assert_eq!(BinXmlValue::UInt16(3).render(), "3");
        assert_eq!(BinXmlValue::UInt32(33).render(), "33");
        assert_eq!(BinXmlValue::Int64(-4).render(), "-4");
        assert_eq!(BinXmlValue::UInt64(4).render(), "4");
        assert_eq!(BinXmlValue::Real32(1.5).render(), "1.5");
        assert_eq!(BinXmlValue::Real64(2.5).render(), "2.5");
        assert_eq!(BinXmlValue::AnsiString("a".to_string()).render(), "a");
    }
}
