# 1. Adopt the fleet `forensic-carve::Carver` contract for orphaned EVTX chunk recovery

Date: 2026-07-24
Status: Accepted

## Context

`winevt-carver` recovers EVTX structure from three sources: intact `.evtx`
files, corrupt/partially-overwritten files, and *loose* `ElfChnk` regions that
have no containing file at all — the residue left in unallocated disk space or
in a memory image after a log is cleared or truncated.

That last case is not EVTX-specific. Every fleet carver (SQLite pages, LNK,
registry hives, EVTX chunks) faces the same problem: a single-pass sweep over a
raw byte stream must find magic hits, hand each candidate a bounded window, and
let the format-specific carver validate and emit. Re-implementing the sweep loop
per format duplicates the scan, fragments the recovery-method bookkeeping, and
means a disk carve and a memory carve stamp their provenance differently in each
crate. The fleet already publishes `forensic-carve` (the `Carver` trait +
`Signature` + `CarveContext` + the single-pass `sweep` engine) as the shared
contract, and *prefer-our-own-crates* (constitution: "Dependency Preference")
makes reuse the default over a bespoke loop.

The original chunk carving predates the contract: `carve_from_bytes` /
`carve_chunk_free_space` already existed as free functions. The decision was how
to expose them to a fleet-wide sweep without a second scanner.

Evidence: `crates/winevt-carver/src/carver.rs`; workspace `Cargo.toml`
(`forensic-carve = "0.1"`, `inventory = "0.3"`, comment "Fleet carving contract +
single-pass sweep engine. ADR 0001"); commits `17a4d6a` (RED — carver satisfies
the contract), `13de27c` (GREEN — `EvtxChunkCarver`), `c08852f` (switch from a
path dep to published `forensic-carve 0.1`).

## Decision

1. Implement `forensic_carve::Carver` for a zero-field `EvtxChunkCarver`,
   wrapping the existing `carve_from_bytes` / `carve_chunk_free_space` logic
   rather than writing a second scanner.

2. Anchor the sweep on the 8-byte `ElfChnk\0` magic at window offset 0
   (`Signature::new(b"ElfChnk\x00", 0)`) and cap each hit at exactly one chunk
   (`max_window = CHUNK_SIZE`, 64 KiB) — a chunk is a fixed size, so one hit
   never claims more.

3. **Disk sweeps** (unallocated space) run the same carver; the engine stamps
   the recovered item's `RecoveryMethod` as `UnallocatedCarve`. The method is
   **echoed from the `CarveContext`, never hardcoded** in the carver.

4. **Memory sweeps** run the *same* carver; the engine stamps `MemoryCarve`.
   Because the method comes from context, one carver serves both media and a
   caller cannot mislabel provenance. (`crates/winevt-carver/src/lib.rs:689`
   references this section directly.)

5. Emit only after two independent checks pass: the structural gate (header
   block present, magic matches, `EvtxChunkHeader::parse` succeeds) **and** the
   format's own stored header CRC32 (`verify_chunk_header_checksum` returns no
   indicators). A bare magic match never emits — an orphaned chunk is already the
   recovered unit, so a validated chunk becomes a records-payload `CarvedItem`
   with no whole file to re-classify.

6. Auto-register via `inventory::submit!` so any binary that force-links
   `winevt-carver` collects `EVTX_CHUNK_CARVER` into the fleet sweep with no
   manual wiring.

## Consequences

- A disk-image or memory sweep run by any fleet tool recovers loose EVTX chunks
  through the shared engine, with correct per-medium provenance, and no
  EVTX-specific scan loop to maintain.
- The provenance guarantee is structural: the recovery method is a property of
  the sweep context, so `UnallocatedCarve` vs `MemoryCarve` cannot drift out of
  sync with where the bytes actually came from.
- `winevt-carver` gained runtime deps on `forensic-carve` and `inventory`; the
  contract is a published `0.1`, so the crate tracks that line's stability.
- The two-check emit rule (magic + stored CRC) keeps false positives out of a
  raw sweep, where a coincidental `ElfChnk\0` byte sequence is otherwise
  plausible.
