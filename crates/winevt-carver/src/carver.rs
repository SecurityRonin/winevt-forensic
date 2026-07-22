//! Fleet `forensic-carve::Carver` impl for orphaned EVTX `ElfChnk` regions.
//!
//! Wraps the existing chunk / free-space carving so an unallocated-space or memory
//! sweep (the single-pass [`forensic_carve::sweep`] engine) recovers loose `ElfChnk`
//! regions that have no containing `.evtx` file to re-parse. The engine hands each
//! `ElfChnk` magic hit a capped window; this carver validates the chunk (magic + the
//! chunk-header CRC32 the format itself stores) and, on success, emits a
//! records-payload [`CarvedItem`] — an orphaned chunk is already the recovered unit,
//! so there is no whole file to re-classify.
//!
//! The recovery method is **echoed from the [`CarveContext`]**, never hardcoded, so
//! the *same* carver stamps `UnallocatedCarve` on a disk sweep and `MemoryCarve` on a
//! memory sweep (ADR 0001 §3/§4).

use forensic_carve::{CarveContext, CarvedItem, Carver, CarverRegistration, Signature};
use winevt_core::binary::{EvtxChunkHeader, CHUNK_SIZE, ELFCHNK_MAGIC};
use winevt_integrity::verify_chunk_header_checksum;

use crate::{carve_chunk_free_space, carve_from_bytes};

/// The signature that anchors a candidate window: the 8-byte `ElfChnk\0` magic at
/// the chunk header start (offset 0 within the artifact).
static EVTX_CHUNK_SIGNATURES: [Signature; 1] = [Signature::new(b"ElfChnk\x00", 0)];

/// Carver that recovers orphaned EVTX `ElfChnk` chunks from an unallocated or memory
/// sweep. Medium-agnostic: it sees only the `&[u8]` window and echoes the sweep's
/// `RecoveryMethod`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvtxChunkCarver;

/// The registered singleton (a zero-field unit struct), referenced by the inventory
/// registration so any binary that force-links this crate auto-collects the carver.
pub static EVTX_CHUNK_CARVER: EvtxChunkCarver = EvtxChunkCarver;

impl Carver for EvtxChunkCarver {
    fn format(&self) -> &'static str {
        "evtx-chunk"
    }

    fn signatures(&self) -> &[Signature] {
        &EVTX_CHUNK_SIGNATURES
    }

    fn max_window(&self) -> u64 {
        // An EVTX chunk is a fixed 64 KiB; one hit never claims more.
        CHUNK_SIZE
    }

    fn carve(&self, window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
        // 1. Structural gate: the header block (0x80 bytes) and its magic must be present.
        if window.len() < 0x80 || window[0..8] != ELFCHNK_MAGIC {
            return Vec::new();
        }
        if EvtxChunkHeader::parse(window).is_none() {
            return Vec::new();
        }

        // 2. Second independent check (the format's own CRC32): a bare magic is not
        //    enough to emit. An empty indicator set means the stored header CRC matched.
        if !verify_chunk_header_checksum(window, 0).is_empty() {
            return Vec::new();
        }

        // 3. Run the existing record + free-space carve over the window so confidence
        //    reflects whether the chunk actually yielded records.
        let live_records: usize = carve_from_bytes(window)
            .chunks
            .iter()
            .map(|c| c.records.len())
            .sum();
        let freespace_records = carve_chunk_free_space(window, 0).len();

        // A CRC-valid header alone is a strong recovery; recovered records raise it.
        let confidence = if live_records + freespace_records > 0 {
            0.95
        } else {
            0.8
        };

        vec![CarvedItem::records(
            "evtx-chunk",
            ctx.base_offset(),
            confidence,
            ctx.recovery_method(),
        )]
    }
}

inventory::submit! { CarverRegistration::new(&EVTX_CHUNK_CARVER) }

#[cfg(test)]
mod tests {
    use super::EvtxChunkCarver;
    use forensic_carve::registered_carvers;

    #[test]
    fn carver_is_registered_via_inventory() {
        assert!(
            registered_carvers()
                .iter()
                .any(|c| c.format() == "evtx-chunk"),
            "EvtxChunkCarver should be discoverable via inventory"
        );
    }

    #[test]
    fn crc_invalid_header_emits_nothing() {
        use forensic_carve::{CarveContext, Carver, RecoveryMethod};
        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        // Header parses structurally but the stored CRC (left 0) will not verify.
        chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes());
        chunk[44..48].copy_from_slice(&0x200u32.to_le_bytes());
        chunk[48..52].copy_from_slice(&0x200u32.to_le_bytes());
        let ctx = CarveContext::at(0).with_method(RecoveryMethod::UnallocatedCarve);
        assert!(EvtxChunkCarver.carve(&chunk, &ctx).is_empty());
    }
}
