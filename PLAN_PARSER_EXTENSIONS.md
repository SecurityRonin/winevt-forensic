# winevt-forensic Parser Extension Plan

Extensions to the `winevt-forensic` crate family that the `issen-evtx` detection layer
has surfaced as necessary. Ordered by implementation priority.

---

## 1. Free-Space Slack Carving (`winevt-carve`) ✅ DONE

**Problem:** Windows Event Log overwrites old records in a ring-buffer. Deleted or overwritten
records leave slack bytes inside EVTX chunks that can be recovered.

**Design:**
- New crate `winevt-carve` (or `winevt-forensic-carve`), no dependency below PARSER layer.
- Input: `&[u8]` (raw chunk bytes or full file bytes).
- Scanner: walk chunk boundaries (`ElfChk` magic, offset 0 within each 65 536-byte chunk).
  Between `RecordLength`-delimited live records, collect gap regions.
- Pattern: each EVTX record starts with `\x2a\x2a\x00\x00` (little-endian `0x0000_2A2A`).
  Scan gap regions for this magic to find candidate carved records.
- Output: `Vec<CarvedRecord>` — raw bytes + chunk offset + confidence (`Definite` / `Probable`).
- Validation: attempt BinXML decode; demote to `Probable` if decode partially fails.

**Key types:**
```rust
pub struct CarvedRecord {
    pub chunk_offset: u64,
    pub record_offset_within_chunk: u16,
    pub raw: Vec<u8>,
    pub confidence: CarveConfidence,
    pub decoded: Option<EvtxRecord>,
}
pub enum CarveConfidence { Definite, Probable }
```

**Tests (TDD first):**
- `carve_empty_slice_returns_empty`
- `carve_single_deleted_record_recovers_it` (inject known record bytes into gap region)
- `carve_invalid_binxml_demotes_to_probable`
- `carve_does_not_return_live_records` (live records excluded from carved output)

---

## 2. Chunk Header Integrity Checks (`winevt-integrity`) ✅ DONE

**Problem:** Anti-forensic tools tamper with chunk headers to hide record counts or corrupt
checksums to prevent log analysis tools from opening files.

**Design:**
- New module `winevt-forensic-integrity` (or add `integrity.rs` to `winevt-forensic-core`).
- Input: `&[u8]` chunk, `&ChunkHeader`.
- Checks:
  1. `file_first_record_number` vs `file_last_record_number` monotonicity.
  2. CRC32 of first 120 bytes of header matches `header_crc32` field.
  3. CRC32 of event records array (bytes 128..chunk_data_length) matches `event_records_crc32`.
  4. `chunk_data_length` within `[512, 65536]`.
  5. `log_file_guid` consistent across all chunks in the file.
- Output: `Vec<IntegrityViolation>` with `{ kind: ViolationKind, chunk_index: usize, detail: String }`.

**Key enum:**
```rust
pub enum ViolationKind {
    CrcMismatch { field: &'static str, expected: u32, actual: u32 },
    NonMonotonicRecordNumbers { prev_last: u64, this_first: u64 },
    InvalidChunkLength(u32),
    GuidMismatch { chunk: usize, expected: u128, actual: u128 },
}
```

**Tests:**
- `no_violations_on_valid_chunk`
- `detects_header_crc_flip` (flip one byte in header, expect CrcMismatch)
- `detects_record_sequence_gap` (set first_record_number backwards)
- `detects_guid_mismatch_across_chunks`

---

## 3. Phantom Record Detection (`winevt-integrity`) ✅ DONE

**Problem:** Adversaries inject phantom record IDs — the `record_id` sequence jumps without
a corresponding time gap, indicating manual injection or log replay.

**Design:** Add to `winevt-integrity`.
- Input: ordered `&[EvtxRecord]` (sorted by `record_id`).
- Walk consecutive pairs: if `next.record_id != prev.record_id + 1`, emit a gap event.
  Correlate with timestamp: a record_id gap with no timestamp gap → `PhantomRecord`.
  A record_id gap with a matching timestamp gap → normal rollover or cleared period.
- Output: `Vec<PhantomAlert>`.

**Key type:**
```rust
pub struct PhantomAlert {
    pub gap_start_id: u64,
    pub gap_end_id: u64,
    pub prev_timestamp_ns: i64,
    pub next_timestamp_ns: i64,
    pub suspicious: bool, // true if timestamp gap doesn't explain record gap
}
```

**Tests:**
- `no_alerts_on_contiguous_records`
- `no_alerts_on_timestamp_proportional_gap` (record gap matches time gap)
- `alerts_on_gap_without_time_gap` (record_id jumps, timestamps contiguous)

---

## 4. BinXML Validity / Decode Fuzzing (`winevt-forensic-core`) ✅ DONE

**Problem:** Corrupt or hand-crafted BinXML payloads cause panics or silently produce wrong
field values. The parser needs a hardened validation pass.

**Design:** Add `validate_binxml(bytes: &[u8]) -> Result<(), BinXmlError>` to `winevt-forensic-core`.
- Check token opcodes are within known range (0x00–0x0F for BinXML).
- Verify string table offsets don't exceed chunk boundary.
- Verify `SubstitutionArray` lengths are consistent with declared element count.
- Integrate libFuzzer target: `fuzz/fuzz_targets/binxml_parse.rs` already exists — add
  `validate_binxml` as a second entry point.

**Tests:**
- `valid_binxml_passes_validation`
- `truncated_binxml_returns_error`
- `unknown_opcode_returns_error`
- `string_table_overflow_returns_error`

---

## 5. Forged Provider Heuristics (`winevt-forensic-core`) ✅ DONE

**Problem:** Attackers inject synthetic events with legitimate-looking `ProviderName`/`ProviderGuid`
fields but content inconsistent with the real provider's schema.

**Design:** Add `provider_heuristics.rs` to `winevt-forensic-core`.
- Maintain a const table of `(provider_guid, expected_event_ids[])` for the 20 most abused
  providers (Security, System, Microsoft-Windows-Sysmon, etc.) — source from `forensicnomicon`.
- `check_provider_consistency(record: &EvtxRecord) -> Vec<ProviderAnomaly>`:
  - If `provider_guid` is in the table but `event_id` not in the expected set → `UnexpectedEventId`.
  - If `provider_name` matches a known name but `provider_guid` doesn't match → `GuidSpoofing`.
  - If `channel` doesn't match the known channel for that provider → `ChannelMismatch`.

**Tests:**
- `known_provider_valid_event_id_no_anomaly`
- `known_provider_unexpected_event_id_flagged`
- `provider_name_guid_mismatch_flagged`
- `unknown_provider_passes_unchecked`

---

## 6. EVTX Repair Tool (`winevt-repair` binary or `winevt-forensic-cli` subcommand) ✅ DONE

**Problem:** Tools like Chainsaw and Hayabusa silently skip corrupt chunks. A repair mode
can recover partial data by skipping bad chunks and re-sequencing the remaining records.

**Design:** `winevt repair <input.evtx> <output.evtx>`
- Read all chunks. For each chunk: run integrity checks (§2). If CRC fails → log warning,
  skip chunk, continue.
- For surviving chunks: re-sequence `record_id` fields monotonically.
- Write new EVTX file with repaired file header (update `next_record_id`, chunk count).
- Report: `{ chunks_total, chunks_recovered, chunks_skipped, records_recovered }`.

**Implementation notes:**
- Must NOT alter event content — only structural fields (record IDs, file header counts).
- Idempotent: repairing an already-valid file produces an equivalent output.
- Add to `winevt-forensic-cli` as `wef repair` subcommand.

**Tests:**
- `repair_valid_file_produces_equivalent_output`
- `repair_single_corrupt_chunk_skips_it`
- `repair_updates_file_header_counts`

---

## 7. Provider Manifest Resolver (`winevt-forensic-core` or new `winevt-manifest`) 🔄 IN PROGRESS

**Problem:** `EvtxRecord.data` is a flat `HashMap<String, String>` built from BinXML
substitution arrays. Field names come from the provider's manifest (`.man` file registered
in the registry). Without the manifest, fields are anonymous (`Param1`, `Param2`, etc.).

**Design:**
- New crate `winevt-manifest` (no dependency below PARSER).
- Parses Windows provider manifest XML (the same XML embedded in provider DLLs, extractable
  with `wevtutil gp <provider> /ge /gm`).
- `ManifestDb`: load from a directory of `.man` files or from a bundled snapshot.
- `resolve_fields(record: &mut EvtxRecord, db: &ManifestDb)` — replaces `Param1` → actual
  field name using the manifest's `<template>` definition for that event ID.
- Ship a bundled snapshot of the 30 most common Microsoft provider manifests as
  `winevt-manifest/data/*.man`.

**Tests:**
- `resolve_known_event_renames_param_fields`
- `resolve_unknown_provider_leaves_fields_unchanged`
- `manifest_db_loads_from_directory`
- `bundled_snapshot_covers_security_channel` (EID 4624, 4688 fields resolve correctly)

---

## 8. Memory-Mapped BinXML Scanner (`winevt-forensic-memory`) ✅ DONE

**Problem:** EVTX records reside in memory (Event Log service buffer, hiberfil.sys).
Finding and decoding them from a raw page stream requires a pure byte-pattern approach —
no file I/O, no OS APIs.

**Design:** New crate `winevt-forensic-memory` (PARSER layer; no dependency below PARSER).
- Input: `&[u8]` (arbitrary page region, not necessarily chunk-aligned).
- Phase 1 — Magic scan: find `ElfChk` (chunk magic) and `\x2a\x2a\x00\x00` (record magic)
  occurrences using a fast SIMD byte-search (or `memchr` crate).
- Phase 2 — Heuristic validation: check `record_length` field plausibility
  (`[56, 65536]` range), check BinXML token at offset +24.
- Phase 3 — Decode: attempt full BinXML parse for candidate regions; collect successes.
- Output: `Vec<MemoryCarvedRecord>` — offset in input buffer + decoded `EvtxRecord`.
- Integration: `memf-windows` calls this crate when it finds a memory region with
  EventLog VAD tags.

**Tests:**
- `scan_empty_buffer_returns_empty`
- `scan_buffer_with_injected_record_finds_it`
- `scan_ignores_random_bytes_matching_magic_only` (magic hit, invalid record_length)
- `scan_multi_record_buffer_finds_all`

---

## Implementation Order

| Priority | Item | Effort | Status |
|----------|------|--------|--------|
| 1 | Chunk header integrity (§2) | S | ✅ DONE |
| 2 | Phantom record detection (§3) | S | ✅ DONE |
| 3 | BinXML validation (§4) | M | ✅ DONE |
| 4 | Free-space carving (§1) | M | ✅ DONE |
| 5 | Provider heuristics (§5) | M | ✅ DONE |
| 6 | EVTX repair tool (§6) | M | ✅ DONE |
| 7 | Provider manifest resolver (§7) | L | 🔄 IN PROGRESS |
| 8 | Memory-mapped scanner (§8) | L | ✅ DONE |

S = 1-2 days, M = 2-4 days, L = 1 week

---

## Dependency Map

```
forensicnomicon   ←── winevt-forensic-core (BinXML, types, provider heuristics, manifest)
                  ←── winevt-integrity     (chunk CRC, phantom record)
                  ←── winevt-carve         (free-space carving)
                  ←── winevt-manifest      (manifest XML parser + bundled data)
                  ←── winevt-forensic-memory (memory-mapped scanner)
                  ←── winevt-forensic-cli  (repair subcommand)
issen-evtx        ←── all of the above via issen workspace re-export
```

All new crates follow the zero-external-dependency-on-layer-below rule: they accept
`&[u8]` or `Path`; they never import container, filesystem, or paging crates.
