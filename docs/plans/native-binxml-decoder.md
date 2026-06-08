# Plan — Native EVTX/BinXML decoder (replace the third-party `evtx` crate)

Status: BACKLOG / spare-time. Author: Claude (Opus 4.8), 2026-06-08.

## Goal

Give winevt-forensic its **own** full EVTX record decoder (`winevt-binxml`)
producing structured records (System + EventData + UserData), and migrate every
consumer — `winevt-extract`, `issen-parser-evtx`, `issen-evtx` — off the
third-party omerbenamram `evtx` crate. Today `winevt-binxml` is a 263-line
*validator/scanner only*; the actual record decode is delegated to `evtx 0.11`.

## Why (and why it's worth the effort)

- **Dependency ownership** — the "always prefer our own crates" rule. EVTX is a
  core forensic capability; we shouldn't rent it.
- **Control over attacker-controlled parsing** — we parse untrusted disk images.
  Owning the decoder lets us apply the Paranoid Gatekeeper standard end-to-end
  (panic-free, bounds-checked, allocation-capped, fuzzed) rather than trusting a
  third party's robustness posture.
- **Integrity coupling** — `winevt-carver` / `winevt-integrity` already own the
  container/chunk layer for recovery + tamper detection; a native decoder closes
  the gap between "we can carve/validate chunks" and "we can read records".
- **No new detections by itself** — this is ownership, not capability. The
  EventData *flattening* (Track A, shipped) already unlocked Sigma matching. Do
  not block detection work on this.

## Sourcing & licensing (clean-room discipline)

- **Public format spec (primary):** Joachim Metz's *libevtx* documentation —
  the canonical public reference for the EVTX + BinXML on-disk format (file
  header, chunk, record, BinXML token stream, templates, value types). Public,
  citable, not GPL. This is the gold source.
- **omerbenamram `evtx` (Apache-2.0/MIT):** legal to read and even port with
  attribution. Use as an implementation reference and as the **differential
  oracle** (parity gate), not as a copy-paste source.
- **Hayabusa (GPL-3.0):** clean-room ONLY. Do **not** read its source for the
  decoder. It may inform *which* events/fields are forensically valuable
  (knowledge → `forensicnomicon`), never code.
- Keep a `docs/provenance.md` noting which reference informed each module.

## Format scope (what a full decoder must handle)

1. **Container** (partly done in winevt-binxml/carver/integrity):
   file header (`ElfFile\0`, CRC), chunk headers (`ElfChnk\0`, CRC, record
   offsets), record headers (`**\0\0`, size, id, FILETIME).
2. **BinXML token stream:** fragment header (0x0F), open/close start element
   (0x01/0x02/0x03/0x04), value text (0x05/0x06), attribute (0x06), cdata,
   char/entity refs, PI, template instance (0x0C), normal substitution (0x0D),
   optional substitution (0x0E), end-of-stream (0x00).
3. **Templates:** template definition + per-chunk template cache (by offset);
   template instances with a substitution-array descriptor (count, then
   size/type pairs, then values).
4. **Name table:** per-chunk name cache (offset → UTF-16LE name + hash).
5. **Value types (~30):** Null, String (UTF-16LE), AnsiString, Int8/16/32/64,
   UInt8/16/32/64, Real32/64, Bool, Binary, GUID, SizeT, FILETIME, SYSTEMTIME,
   SID, HexInt32/64, and the *array* (0x80-flagged) variants, plus
   BinXML-typed substitutions (a nested fragment).

## Phased TDD plan (strict RED/GREEN, winevt-forensic gates: 100% cov + fuzz)

- **Phase 0 — corpus & harness.** Reuse `tests/data/` (fox-it Security, Sysmon,
  hayabusa-samples). Add a differential harness: for each fixture, decode with
  both omerbenamram and ours, assert field-map parity. (Oracle in dev-deps only.)
- **Phase 1 — container iterator.** `chunks()` + `records()` yielding raw record
  byte slices + header metadata. Largely portable from existing
  carver/integrity code. Gate: parity on record counts + record ids vs oracle.
- **Phase 2 — name table + token skeleton.** Per-chunk name cache; walk tokens
  enough to reconstruct element/attribute *structure* (no substitutions yet).
  Gate: element tree shape matches for template-free records.
- **Phase 3 — templates + substitutions.** Template definition/instance parsing,
  substitution array, wire substitutions into the element tree.
- **Phase 4 — value types.** Implement all scalar + array types incl. SID /
  FILETIME / SYSTEMTIME / GUID / Hex. One RED test per type from real records.
- **Phase 5 — JSON projection.** Emit a `serde_json::Value` identical in shape
  to what `records_json_value()` produces today (default settings: `@Name`/
  `#text` array + flat) so `flatten_event_data` is a *drop-in* consumer — zero
  downstream change. Gate: full-corpus field-map parity vs oracle = 100%.
- **Phase 6 — robustness/fuzz.** Add cargo-fuzz targets (record, binxml,
  template, value) to the existing `fuzz/` workspace; invariant: never panic on
  arbitrary bytes. Allocation caps on counts/sizes.
- **Phase 7 — migration.** Swap `winevt-extract`, `issen-parser-evtx`,
  `issen-evtx` onto `winevt-binxml`; drop the `evtx` dep (keep it as a dev-only
  differential oracle for the parity test). Sweep dependents.

## Validation = differential parity (the Doer-Checker gate)

The decoder is "done" when, across the entire real fixture corpus, our
`flatten_event_data`-ready JSON is field-for-field identical to the omerbenamram
output, AND all fuzz targets survive. Parity against an independent
implementation on real artifacts is the validation — not our own fixtures alone.

## Risks / honest unknowns

- BinXML's long tail (rare value types, malformed templates, mixed
  UTF-16/ANSI, chunk-spanning templates) is where the effort hides — the last
  5% of records is most of the work.
- Performance: omerbenamram is tuned; a naïve walker may be slower. Acceptable
  for forensic batch use; profile in Phase 6.
- Effort: realistically multi-week of focused TDD. This is a deliberate,
  spare-time build, not a sprint.

## Sequencing vs Track A

Track A (EventData flattening) is **shipped** and decoder-agnostic by design:
`flatten_event_data(record_json)` consumes whatever produces the JSON. When this
decoder lands and Phase 5 matches the JSON shape, only the *bytes-→-JSON* source
changes; `flatten_event_data` and all of issen are untouched. That insulation is
exactly why Track A went into `winevt-extract` rather than issen.
