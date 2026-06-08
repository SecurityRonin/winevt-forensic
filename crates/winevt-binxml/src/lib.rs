//! `BinXml` decoding for Windows Event Log (EVTX) record payloads.
//!
//! [`validate_binxml`] / [`scan_binxml`] are the legacy best-effort scanners.
//! The [`cursor`] module is the foundation of a full, panic-free, bounds-checked
//! BinXml decoder (ported with attribution from the omerbenamram `evtx` crate,
//! Apache-2.0/MIT; format cross-checked against libevtx). See
//! `docs/plans/binxml-decoder-architecture.md`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod cursor;

/// Structural error returned by [`validate_binxml`].
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum BinXmlError {
    #[error("payload too short: {len} bytes, minimum is 4")]
    TooShort { len: usize },
    #[error("invalid fragment header at offset {offset}: got {got:#04x}, expected 0x0F")]
    InvalidFragmentHeader { offset: usize, got: u8 },
    #[error("unknown BinXML opcode {opcode:#04x} at offset {offset}")]
    UnknownOpcode { opcode: u8, offset: usize },
    #[error("string table name_offset {offset} exceeds chunk boundary {chunk_size}")]
    StringTableOverflow { offset: usize, chunk_size: usize },
    #[error("payload truncated at offset {offset}")]
    Truncated { offset: usize },
    #[error("iteration limit of {limit} steps exceeded — possible infinite-loop attack")]
    IterationLimitExceeded { limit: usize },
}

/// Maximum EVTX chunk size (65 536 bytes) — string table offsets must be within this.
const CHUNK_BOUNDARY: u32 = 0x1_0000;

/// BinXML token bytes — values outside [0x00, 0x0F] are invalid.
const MAX_TOKEN: u8 = 0x0F;

/// Validate the structural integrity of a BinXML payload.
///
/// Performs three checks:
/// 1. Minimum size (≥ 4 bytes) and `FragmentHeader` token (`0x0F`) at offset 0.
/// 2. Token walk: each token byte must be in `[0x00, 0x0F]`.
/// 3. `OpenStartElement` (0x01): the 4-byte `name_offset` field must be ≤ 65536.
///
/// Returns `Ok(())` on success, or the first `BinXmlError` encountered.
pub fn validate_binxml(bytes: &[u8]) -> Result<(), BinXmlError> {
    if bytes.len() < 4 {
        return Err(BinXmlError::TooShort { len: bytes.len() });
    }
    if bytes[0] != 0x0F {
        return Err(BinXmlError::InvalidFragmentHeader { offset: 0, got: bytes[0] });
    }
    // Walk tokens starting after the 4-byte fragment header (token + major + minor + flags)
    const MAX_STEPS: usize = 65_536; // one step per byte is the worst-case legitimate payload
    let mut steps = 0usize;
    let mut pos = 4usize;
    while pos < bytes.len() {
        steps += 1;
        if steps > MAX_STEPS {
            return Err(BinXmlError::IterationLimitExceeded { limit: MAX_STEPS });
        }
        let token = bytes[pos];
        if token == 0x00 {
            // EndOfStream — valid termination
            return Ok(());
        }
        // Strip the "has-more" flag bit (bit 6 in some token encodings) — base token is low 6 bits
        // However, the standard EVTX tokens are in [0x01..0x0F]; > 0x0F is invalid.
        if token > MAX_TOKEN {
            return Err(BinXmlError::UnknownOpcode { opcode: token, offset: pos });
        }
        match token {
            0x01 => {
                // OpenStartElement: flags(1) + dependency_id(2) + attribute_count(2) + name_offset(4)
                let field_start = pos + 1;
                let name_off_start = field_start + 5; // skip flags(1) + dep_id(2) + attr_count(2)
                if bytes.len() < name_off_start + 4 {
                    return Err(BinXmlError::Truncated { offset: pos });
                }
                let name_offset = u32::from_le_bytes(
                    bytes[name_off_start..name_off_start + 4].try_into().unwrap_or([0; 4]),
                );
                if name_offset > CHUNK_BOUNDARY {
                    return Err(BinXmlError::StringTableOverflow {
                        offset: name_offset as usize,
                        chunk_size: CHUNK_BOUNDARY as usize,
                    });
                }
                pos += 1 + 1 + 2 + 2 + 4; // token + flags + dep_id + attr_count + name_offset
            }
            0x02 | 0x03 | 0x04 => {
                // CloseStartElement, CloseEmptyElement, EndElement — no data
                pos += 1;
            }
            _ => {
                // Other known tokens — advance by 1; a full parser would handle each
                pos += 1;
            }
        }
    }
    Ok(())
}

/// Summary of fields extracted from a `BinXml` event payload.
#[derive(Debug, Clone)]
pub struct BinXmlSummary {
    pub event_id: Option<u16>,
    pub channel: Option<String>,
    pub computer: Option<String>,
    pub provider_name: Option<String>,
    pub level: Option<u8>,
}

/// Scan a `BinXml` payload for known fields. Best-effort: all fields may be `None`.
///
/// # Limitations
/// This is not a full `BinXml` parser. It uses heuristic byte-pattern scanning
/// and is intentionally conservative — it returns `None` rather than guessing.
pub fn scan_binxml(payload: &[u8]) -> BinXmlSummary {
    // BinXml is a complex binary format. A full parser requires tracking
    // the string table, template substitution slots, and element nesting.
    // This stub returns all None to ensure no panics on arbitrary input.
    // Future work: implement a proper BinXml token walker.
    let _ = payload; // suppress unused warning while remaining a no-op
    BinXmlSummary {
        event_id: None,
        channel: None,
        computer: None,
        provider_name: None,
        level: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_binxml_empty_payload_returns_all_none() {
        let summary = scan_binxml(&[]);
        assert!(summary.event_id.is_none());
        assert!(summary.channel.is_none());
        assert!(summary.computer.is_none());
        assert!(summary.provider_name.is_none());
        assert!(summary.level.is_none());
    }

    #[test]
    fn scan_binxml_random_bytes_does_not_panic() {
        let data = vec![0xFFu8; 128];
        let _ = scan_binxml(&data);
    }

    #[test]
    fn scan_binxml_very_large_payload_does_not_panic() {
        let data = vec![0u8; 65536];
        let _ = scan_binxml(&data);
    }

    #[test]
    fn binxml_summary_fields_are_optional() {
        let summary = BinXmlSummary {
            event_id: Some(4624),
            channel: Some("Security".to_string()),
            computer: None,
            provider_name: Some("Microsoft-Windows-Security-Auditing".to_string()),
            level: Some(0),
        };
        assert_eq!(summary.event_id, Some(4624));
        assert_eq!(summary.channel.as_deref(), Some("Security"));
        assert!(summary.computer.is_none());
    }

    // ── §4: validate_binxml ───────────────────────────────────────────────────

    fn minimal_valid_binxml() -> Vec<u8> {
        // FragmentHeader (0x0F), major=1, minor=1, flags=0x00, EndOfStream (0x00)
        vec![0x0F, 0x01, 0x01, 0x00, 0x00]
    }

    #[test]
    fn valid_binxml_passes_validation() {
        let result = validate_binxml(&minimal_valid_binxml());
        assert!(result.is_ok(), "valid BinXML must pass; got {:?}", result);
    }

    #[test]
    fn empty_binxml_returns_error() {
        let result = validate_binxml(&[]);
        assert!(result.is_err(), "empty bytes must return error");
        assert!(matches!(result, Err(BinXmlError::TooShort { .. })));
    }

    #[test]
    fn truncated_binxml_returns_error() {
        // Only 2 bytes — not enough for a fragment header
        let result = validate_binxml(&[0x0F, 0x01]);
        assert!(result.is_err(), "truncated header must return error");
    }

    #[test]
    fn wrong_first_byte_returns_error() {
        let mut bytes = minimal_valid_binxml();
        bytes[0] = 0xAA; // not 0x0F
        let result = validate_binxml(&bytes);
        assert!(result.is_err(), "wrong fragment header must return error");
        assert!(
            matches!(result, Err(BinXmlError::InvalidFragmentHeader { .. })),
            "got {:?}", result
        );
    }

    #[test]
    fn unknown_opcode_returns_error() {
        // Valid header, then an unknown token 0x7F
        let bytes = vec![0x0F, 0x01, 0x01, 0x00, 0x7F];
        let result = validate_binxml(&bytes);
        assert!(result.is_err(), "unknown opcode must return error");
        assert!(
            matches!(result, Err(BinXmlError::UnknownOpcode { opcode: 0x7F, .. })),
            "got {:?}", result
        );
    }

    #[test]
    fn string_table_overflow_returns_error() {
        // OpenStartElement token (0x01), then name_offset exceeding 65536
        // Layout: 0x01 flags(u1) dep_id(u2) attr_count(u2) name_offset(u4)
        let mut bytes = vec![0x0F, 0x01, 0x01, 0x00]; // fragment header
        bytes.push(0x01); // OpenStartElement token
        bytes.push(0x00); // flags
        bytes.extend_from_slice(&0u16.to_le_bytes()); // dependency_id
        bytes.extend_from_slice(&0u16.to_le_bytes()); // attribute_count
        bytes.extend_from_slice(&0x0001_0001u32.to_le_bytes()); // name_offset = 65537 > 65536
        bytes.push(0x00); // EndOfStream
        let result = validate_binxml(&bytes);
        assert!(result.is_err(), "string table overflow must return error");
        assert!(
            matches!(result, Err(BinXmlError::StringTableOverflow { .. })),
            "got {:?}", result
        );
    }

    #[test]
    fn end_of_stream_terminates_successfully() {
        // Header + EndOfStream immediately = valid minimal fragment
        let bytes = vec![0x0F, 0x01, 0x01, 0x00, 0x00];
        assert!(validate_binxml(&bytes).is_ok());
    }

    #[test]
    fn iteration_limit_is_enforced() {
        // Craft a payload that hits the iteration limit:
        // Fragment header (4 bytes) + MAX_STEPS repetitions of a 1-byte token (0x02 = CloseStartElement)
        // without an EndOfStream terminator.
        let mut bytes = vec![0x0F, 0x01, 0x01, 0x00]; // fragment header
        bytes.extend(std::iter::repeat(0x02u8).take(65_537)); // one past the limit
        let result = validate_binxml(&bytes);
        assert!(
            matches!(result, Err(BinXmlError::IterationLimitExceeded { .. })),
            "expected IterationLimitExceeded, got {:?}", result
        );
    }

    #[test]
    fn iteration_limit_not_triggered_on_normal_payload() {
        // A normal short payload should not hit the limit.
        let bytes = vec![0x0F, 0x01, 0x01, 0x00, 0x00]; // header + EndOfStream
        assert!(validate_binxml(&bytes).is_ok());
    }
}
