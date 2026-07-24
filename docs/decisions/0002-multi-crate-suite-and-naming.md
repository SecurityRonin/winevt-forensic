# 2. Multi-crate suite with `winevt-*` role-suffix naming; `ev4n6` binary

Date: 2026-07-24
Status: Accepted

## Context

Windows Event Log forensics spans several distinct concerns: raw binary format
constants, BinXML decoding, structural integrity checking, record carving from
disk and memory, typed field extraction, EVTX reconstruction, provider-manifest
resolution, MITRE-tagged detection, an E01→report pipeline, and a user-facing
CLI. Packing all of that into one crate would force every library consumer (for
example a downstream tool that only wants integrity checks) to pull the whole
dependency graph, and would give the crates.io reader no way to depend on just
the piece it needs.

The fleet constitution defines two repo shapes. Pattern A (single-format
container/filesystem repos) uses exactly `<x>-core` + `<x>-forensic`. Pattern B
(a multi-crate PARSER/domain suite — browser, winevt, memf) decomposes *by
concern* with role suffixes under a distinctive short prefix, and the umbrella
repo name is **not itself a crate**. EVTX is squarely Pattern B.

The prefix choice matters because a crate name is read *bare* on crates.io. The
repo is `winevt-forensic`, but `winevt-` is a distinctive, self-describing short
prefix that stands alone in search and `cargo add`, so the suite uses `winevt-*`
(not the longer `winevt-forensic-*` that a *generic-word* prefix like `browser-`
would require).

The CLI was originally `wt-cli` shipping a `wt` binary; both were too generic and
`wt` collides with common tooling. Commit `8d71dde` renamed the crate to
`winevt-cli` and the binary to `ev4n6`, matching the fleet's `<x>4n6` binary
convention (br4n6, ev4n6, sqlite4n6, mem4n6, disk4n6).

Evidence: workspace `Cargo.toml` members list (11 crates); per-crate
`description` fields; commit `8d71dde` (`wt-cli -> winevt-cli, binary wt ->
ev4n6`); commit `c1b4df6` (release CI rename fallout). Constitution: "Crate
naming grammar" and "Front-end binaries follow the `<x>4n6` convention".

## Decision

1. Ship the suite as a Cargo workspace of role-suffixed crates under the
   `winevt-*` prefix; `winevt-forensic` is the repo/umbrella name only, never a
   published crate.

2. Assign crates by the knowledge each owns, following the fleet suffix grammar:
   - `winevt-core` — domain types + binary format constants (the leaf);
   - `winevt-binxml` — BinXML decoding;
   - `winevt-integrity` — tamper/integrity detection (`-integrity` analyzer slot);
   - `winevt-carver` — record/chunk carving (`-carve` recovery slot);
   - `winevt-memory` — medium-agnostic memory-image types (`-memory` slot);
   - `winevt-writer` — EVTX reconstruction to new bytes;
   - `winevt-manifest` — provider-manifest resolution;
   - `winevt-extract` — typed field extraction;
   - `winevt-analysis` — MITRE-tagged detectors (`-analysis` semantic slot);
   - `winevt-triage` — the one-click orchestrated report (`-triage`, never
     `-orchestrator`/`-rt`);
   - `winevt-cli` — the front-end (`-cli`), binary `ev4n6`.

3. Name the CLI crate `winevt-cli` and its binary `ev4n6`, per the `<x>4n6`
   convention; do not resurrect the `wt`/`wt-cli` names.

## Consequences

- A downstream developer depends on exactly the concern they need
  (`winevt-integrity = "0.3"`) without the CLI, carver, or extractor graph.
- Each crate versions independently and is published on its own SemVer cadence
  via release-plz (see the release wiring in commit `578a86c`).
- The `-writer` name carries the "evidence editor" misread risk; it is
  read-only-safe because `records_to_evtx` emits *new* reconstructed bytes to a
  new path (`crates/winevt-writer/src/lib.rs:290`), never the source.
- `ev4n6` accrues its own SmartScreen/Homebrew identity under the fleet naming;
  the earlier `wt` name is retired and must not reappear in docs or CI.
