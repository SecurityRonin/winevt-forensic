# winevt-forensic: Forensic Robustness & Detection Plan

> **Status: IMPLEMENTED — archived 2026-06-15.** All three phases shipped; retained
> as a historical design record, not an active plan.
> - **Phase 1** ✅ `IntegrityAnomaly::severity()` + the four new variants
>   (`TrailingData`, `TruncatedFile`, `EmptyLog`, `OverlappingChunks`) in
>   `winevt-core::binary`. Implemented against the canonical
>   `forensicnomicon::report::Severity` scale (Info/Low/Medium/High/Critical) rather
>   than the bespoke Info/Warning/Error/Critical proposed below — a fleet-consistency
>   improvement on the original plan.
> - **Phase 2** ✅ `WinevtIntegrity` unified analyser (`WinevtIntegrity::analyse`,
>   layer checks, severity-gated filtering) in `winevt-integrity`. Phantom-record
>   detection ships as the existing `PhantomAlert` type (kept rather than folded into
>   a `PhantomRecordInjection` anomaly variant as sketched in Phase 2).
> - **Phase 3** ✅ input-robustness hardening with fuzz targets
>   (`fuzz_integrity_analyse`, `fuzz_chunk_header`, `fuzz_record_header`,
>   `fuzz_file_header`, `fuzz_validate_binxml`, …) and `robustness_tests.rs` in both
>   `winevt-core` and `winevt-integrity`.

Modelled on the `vhdx-forensic` integrity implementation. **Scope: detection and robustness only — no repair.**

Windows Event Logs are the single most-commonly tampered artifact in Windows incident response. The existing `winevt-integrity` crate has strong detection coverage (15 anomaly variants), but lacks severity stratification, a unified entry-point analyser, and input robustness guarantees against adversarial input.

---

## Current state

### What exists

| Component | Location | Notes |
|---|---|---|
| `IntegrityAnomaly` enum (15 variants) | `winevt-core::binary` | No `severity()` method |
| 13 detection functions | `winevt-integrity::lib` | Scattered, each called individually |
| `PhantomAlert` struct | `winevt-integrity::lib` | Separate type, not unified with anomaly |
| `ProviderAnomaly` enum | `winevt-integrity::provider_heuristics` | Separate type |
| `winevt-carver` | recovery only | Returns `CarvedChunk` with integrity field |

### What is missing

- **`Severity` enum** — no `Info / Warning / Error / Critical` stratification on any anomaly type
- **`WinevtIntegrity` entry-point struct** — callers must invoke 13+ individual functions and merge results manually; no single `analyse(&[u8]) -> Vec<IntegrityAnomaly>` API
- **New anomaly variants** — `TrailingData`, `TruncatedFile`, `EmptyLog`, `OverlappingChunks` are undetected
- **Input robustness** — no fuzz corpus; size fields are trusted; BinXML recursion is unbounded; chunk count integer overflow is possible
- **`PhantomAlert` unified** — not folded into `IntegrityAnomaly`; callers handle two separate result types
- **Severity-gated filtering** — no way to ask "give me only `Error` and above"

---

## Proposed changes

### Phase 1 — `Severity` enum + `severity()` on `IntegrityAnomaly`

**Crate:** `winevt-core`  
**Files modified:** `crates/winevt-core/src/binary.rs`

Add to `winevt-core`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Consistent with legitimate operation; worth noting.
    Info,
    /// Suspicious; plausible legitimate explanation but warrants investigation.
    Warning,
    /// Strong indicator of tampering or structural corruption.
    Error,
    /// File cannot be reliably decoded; forensic conclusions unsupported.
    Critical,
}
```

Implement `IntegrityAnomaly::severity()`:

| Anomaly | Severity | Rationale |
|---|---|---|
| `SurgicalRecordDeletion` | Critical | NSA DanderSpritz fingerprint; unambiguous deliberate tampering |
| `ChunkChecksumMismatch` | Error | CRC32 protected; mismatch means bytes changed after write |
| `FileHeaderChecksumMismatch` | Error | File header CRC32 protected; modification detected |
| `RecordIdGap` | Error | Missing record IDs indicate deletion (manual or tool-based) |
| `RecordChecksumMismatch` | Error | Individual record CRC mismatch |
| `LogFileGuidMismatch` | Error | Chunks disagree on log identity; one set was moved or transplanted |
| `TimestampAnomaly` | Warning | Out-of-order timestamps; could be NTP drift or clock manipulation |
| `NextRecordIdInconsistency` | Warning | File header claims higher next-ID than actual max; suspicious but not definitive |
| `ExportTimestampCorruption` | Warning | Known wevtutil export bug; not an attack, but evidence integrity affected |
| `ChunkCountMismatch` | Warning | Header chunk count differs from actual; structural inconsistency |
| `InvalidChunkDataLength` | Warning | Chunk length field outside expected range |
| `ChecksumMismatch` (generic) | Warning | Non-specific; legacy variant |
| `LogCleared` | Info | EventID 1102/104 is normal administrative action; may be legitimate |
| `FileNotCleanlyShutdown` | Info | File flags indicate unclean state; normal for live captures |
| `FileFull` | Info | Log rotation; expected in production environments |

**New variants added in this phase:**

```rust
/// Non-zero bytes exist after the last valid chunk. May indicate
/// appended data, a partial write, or concealed content.
TrailingData { start_offset: u64, size: u64 },

/// File ends before the declared chunk boundary. The log was
/// truncated — either during acquisition or deliberately.
TruncatedFile { declared_end: u64, actual_size: u64 },

/// The file header reports zero chunks. May indicate the log was
/// cleared and the file was recreated but never written to.
EmptyLog,

/// Two chunks claim overlapping byte ranges within the file.
/// Indicates structural corruption or manual chunk transplantation.
OverlappingChunks { chunk_a_offset: u64, chunk_b_offset: u64 },
```

Severity for new variants:

| New Anomaly | Severity |
|---|---|
| `TrailingData` | Warning |
| `TruncatedFile` | Error |
| `EmptyLog` | Warning |
| `OverlappingChunks` | Error |

**TDD plan — Phase 1:**

RED commit: Add stub `severity()` returning `Severity::Info` for all variants; add new variant stubs; write tests asserting exact severity for every variant.

GREEN commit: Implement `severity()` per the table above; add detection logic for new variants.

---

### Phase 2 — `WinevtIntegrity` unified analyser

**Crate:** `winevt-integrity`  
**Files modified:** `crates/winevt-integrity/src/lib.rs`

Add a single entry-point struct analogous to `VhdxIntegrity`:

```rust
/// Read-only forensic analyser for a raw EVTX byte buffer.
///
/// Operates directly on raw bytes so it can detect anomalies that
/// would prevent normal parsing (bad CRCs, missing chunks, truncation).
pub struct WinevtIntegrity<'a> {
    data: &'a [u8],
}

impl<'a> WinevtIntegrity<'a> {
    pub fn new(data: &'a [u8]) -> Self { ... }

    /// Run all checks and return every detected anomaly.
    /// Returns an empty Vec for a structurally sound log file.
    pub fn analyse(&self) -> Vec<IntegrityAnomaly> { ... }

    // Layer-specific checks (also public for targeted use):
    pub fn check_file_header(&self) -> Vec<IntegrityAnomaly> { ... }
    pub fn check_chunks(&self) -> Vec<IntegrityAnomaly> { ... }
    pub fn check_record_ids(&self) -> Vec<IntegrityAnomaly> { ... }
    pub fn check_timestamps(&self) -> Vec<IntegrityAnomaly> { ... }
    pub fn check_layout(&self) -> Vec<IntegrityAnomaly> { ... }  // trailing, truncated, overlapping
}
```

`analyse()` calls each layer in order and short-circuits after `Critical` findings where decoding is impossible (analogous to `VhdxIntegrity::analyse()` halting after `ContainerTruncated`).

**Unify `PhantomAlert` into `IntegrityAnomaly`:**

```rust
/// A record-ID gap with temporal context suggesting deliberate injection
/// rather than log rotation. Both the gap and the surrounding timestamps
/// are preserved for forensic reporting.
PhantomRecordInjection {
    gap_start_id: u64,
    gap_end_id: u64,
    prev_timestamp_ns: i64,
    next_timestamp_ns: i64,
},
```

Severity: `Error`. The existing `PhantomAlert::suspicious` flag maps to severity filtering by callers.

**TDD plan — Phase 2:**

RED commit: Add `WinevtIntegrity` struct with stub `analyse()` returning empty vec; move `PhantomAlert` to `PhantomRecordInjection` variant with stub; write tests for unified API.

GREEN commit: Implement `analyse()` by composing existing detection functions; implement `PhantomRecordInjection` detection.

---

### Phase 3 — Input robustness hardening

**Crates:** `winevt-core`, `winevt-integrity`  
**Files modified:** `crates/winevt-core/src/binary.rs`, `crates/winevt-integrity/src/lib.rs`

#### Specific robustness gaps to close

**1. Chunk size field trust**

`EvtxChunkHeader::parse()` reads `last_event_record_data_offset` and `free_space_offset` without bounds-checking against the actual buffer length. A crafted image with `free_space_offset = 0xFFFFFFFF` causes a panic or incorrect slice.

Fix: validate all offsets against `CHUNK_SIZE` (65536) before use; return `Err` or emit `InvalidChunkDataLength` anomaly.

**2. Record size field trust**

`EvtxRecordHeader::parse()` reads `size` (u32) and uses it for slice indexing. A zero-size or overflow-size record panics.

Fix: check `size >= 24` (minimum valid record) and `size <= remaining_chunk_space` before advancing.

**3. Chunk count integer overflow**

`EvtxFileHeader` stores `chunk_count: u16`. Iteration over declared chunks multiplies by `CHUNK_SIZE`. No overflow check.

Fix: add explicit `usize` overflow check on `chunk_count as usize * CHUNK_SIZE`.

**4. BinXML recursion depth**

`winevt-binxml` has no recursion depth limit. A crafted template with deeply nested elements causes stack overflow.

Fix: add a depth counter (max 128 levels); return `Err` on exceeding limit.

**5. Fuzz corpus**

No fuzz targets exist for raw byte parsing. Add `fuzz/fuzz_targets/parse_evtx.rs` using `libfuzzer-sys`.

**6. Minimum container size guard**

`WinevtIntegrity::analyse()` should immediately return `ContainerTruncated` (Critical) if the buffer is smaller than the minimum valid EVTX file (file header = 128 bytes).

**TDD plan — Phase 3:**

For each robustness gap: write a test with a crafted malformed buffer that currently panics or gives wrong output, then fix the parsing path. Tests live in `winevt-core/tests/robustness_tests.rs` and `winevt-integrity/tests/robustness_tests.rs`.

---

## Files to create / modify

| Action | Path | Purpose |
|---|---|---|
| Modify | `crates/winevt-core/src/binary.rs` | Add `Severity`, `severity()`, 4 new anomaly variants |
| Modify | `crates/winevt-integrity/src/lib.rs` | Add `WinevtIntegrity` struct, unify `PhantomAlert` |
| Modify | `crates/winevt-core/src/binary.rs` | Bounds-check chunk/record size fields |
| Modify | `crates/winevt-binxml/src/*.rs` | Add recursion depth limit |
| Create | `crates/winevt-core/tests/robustness_tests.rs` | Malformed input tests |
| Create | `crates/winevt-integrity/tests/integrity_tests.rs` | Unified analyser tests |
| Create | `fuzz/fuzz_targets/parse_evtx.rs` | Libfuzzer target for raw EVTX bytes |

---

## What is deliberately excluded

**No `winevt-repair` crate.** EVTX has no backup copies of its file header or chunks (unlike VHDX which has H1+H2, RT1+RT2). The only structurally repairable case would be CRC recomputation on a chunk whose records are intact — but rewriting an evidence file CRC without an out-of-band reference is forensically dangerous. Detection and documentation of the anomaly is the correct forensic response. Callers who need a working-but-annotated EVTX file can use `winevt-carver` for recovery.

**No severity override mechanism.** Severity is a fixed property of each anomaly type derived from the MS-EVTX specification and known attack patterns. Callers can filter by severity; they cannot reassign it.

---

## Implementation order

1. Phase 1 RED → Phase 1 GREEN (severity + new variants) — self-contained, no new crates
2. Phase 2 RED → Phase 2 GREEN (unified analyser) — depends on Phase 1 severity enum
3. Phase 3 (robustness hardening) — independent; can be done in parallel with Phase 2
