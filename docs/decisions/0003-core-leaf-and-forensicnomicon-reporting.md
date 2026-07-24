# 3. `winevt-core` as the leaf; findings via `forensicnomicon::report`

Date: 2026-07-24
Status: Accepted

## Context

Every analyzer in the suite (integrity, carver, memory, analysis) produces
findings, and every one needs the same binary-format facts: the `ElfFile\0` /
`ElfChnk\0` / `\x2a\x2a\x00\x00` magics, header offsets, the 64 KiB chunk size,
the records-area offset. If each crate carried its own copy of those constants
and its own bespoke `XxxAnalysis` output type, the constants would drift and
ORCHESTRATION (issen, a future GUI) would have to special-case N incompatible
result shapes.

The fleet already solves both halves. The KNOWLEDGE leaf pattern says format
constants and domain types live in one zero-analysis crate that everything
depends *down* onto. And `forensicnomicon::report` is the fleet's single
normalized reporting vocabulary — `Finding` / `Severity` / `Category` /
`Observation` — so an analyzer keeps its own typed anomaly enum (domain
knowledge) but converts to canonical Findings that Issen renders uniformly.

Evidence: `crates/winevt-core/src/lib.rs` (`pub mod binary`, `EvtxEvent`,
`IntegrityAnomaly`); every analyzer `Cargo.toml` depends on both `winevt-core`
and `forensicnomicon` (core, integrity, carver, memory, analysis, extract);
`winevt-integrity` imports `winevt_core::binary::{… ELFCHNK_MAGIC, CHUNK_SIZE …}`;
commits `577f349` / `482612d` / `f667fe8` (forensicnomicon 0.5 → 0.11 → 1.0
sweep). Constitution: "The Reporting Model — `forensicnomicon::report`" and the
layer dependency rules.

## Decision

1. `winevt-core` holds all binary format constants and shared domain types
   (`EvtxEvent`, `LogonSession`, `IntegrityAnomaly`, the `binary` module) and
   performs no I/O and no analysis. It is the dependency leaf of the suite.

2. Every analyzer crate depends **down** onto `winevt-core` for those facts —
   `winevt-integrity`, `winevt-carver`, `winevt-memory`, `winevt-analysis`,
   `winevt-binxml`. No analyzer re-declares a magic or an offset locally.

3. Analyzers emit findings through `forensicnomicon::report`, keeping their own
   typed anomaly kinds and converting to canonical `Finding`s, so the whole
   suite feeds one `Report` aggregation upward. All crates track one
   `forensicnomicon` major (`= "1"`).

4. Findings are stated as observations ("chunk header CRC does not match"), never
   legal conclusions; MITRE tags are rendered "consistent with", not a verdict
   (see `winevt-analysis`).

## Consequences

- A format constant is defined once; a spec correction is a one-line change in
  `winevt-core` that every analyzer inherits.
- Issen (and a future GUI) render EVTX findings through the same
  `forensicnomicon::report` pipeline as every other artifact family — no
  EVTX-specific output adapter.
- The suite is coupled to the `forensicnomicon` major; a facade major bump is a
  coordinated workspace-wide sweep (as commits `577f349`/`482612d` show).
- The dependency arrow only ever points down onto `winevt-core`; a cycle back up
  into an analyzer is structurally impossible.
