# 4. Two BinXML strategies: a native panic-free decoder for carved bytes, the `evtx` crate for intact files

Date: 2026-07-24
Status: Accepted

## Context

BinXML is the payload encoding inside every EVTX record. The suite needs to
decode it in two very different situations:

1. **Intact or reconstructed `.evtx` files**, where a mature full parser is the
   right tool and re-implementing one would be wasted effort and a fresh source
   of bugs.
2. **Carved and memory-recovered bytes** — loose chunks, partially-overwritten
   records, fragments with no valid file header — where a happy-path reader that
   assumes a well-formed container either rejects the input outright or panics on
   a truncated/forged length field. Forensic recovery needs a decoder that reads
   the raw, possibly-broken structure and *never panics* on attacker-controlled
   input.

The omerbenamram `evtx` crate is the settled community reference for (1). But it
is built to read valid files, so it does not serve (2) — exactly the "an auditor
must go lower than the happy-path reader" principle in the constitution's
crate-structure standard. The fleet also prohibits validating a decoder only
against fixtures you hand-encoded yourself (the LZNT1 trap / Doer-Checker): a
native decoder needs an *independent* oracle.

Evidence: `crates/winevt-binxml/src/lib.rs` header ("the foundation of a full,
panic-free, bounds-checked BinXml decoder, ported with attribution from the
omerbenamram `evtx` crate, Apache-2.0/MIT; format cross-checked against
libevtx"); `crates/winevt-binxml/Cargo.toml` dev-dependency `evtx = "0.11"`
("Differential oracle for the real-fixture parity test only — NOT a runtime
dep"); `crates/winevt-extract/Cargo.toml` runtime dependency `evtx = "0.11"`;
`crates/winevt-extract/src/lib.rs` ("Builds on the `evtx` crate (full BinXml
parser)…"); the TDD BinXML series (commits `3ee332f`…`8b2b122`, `6160721` 100%
lib coverage, `66c6a17` fuzz targets).

## Decision

1. **Intact files** are decoded with the omerbenamram `evtx` crate. `winevt-extract`
   takes it as a runtime dependency for typed field extraction (timeline,
   sessions, PowerShell blocks, frequency) over clean or reconstructed EVTX.

2. **Carved / memory / partial bytes** are decoded by the native, panic-free,
   bounds-checked `winevt-binxml` decoder (its `cursor`/`deserializer`/`reader`
   modules), which is written to tolerate malformed structure and surface a loud
   error rather than crash. It is ported *with attribution* from the `evtx`
   crate and cross-checked against libevtx for format fidelity, rather than
   coded from memory of the format.

3. The native decoder is validated against `evtx` as a **differential oracle** —
   `evtx` appears as a `winevt-binxml` dev-dependency solely for a real-fixture
   parity test, not at runtime — plus fuzz targets on the native path.

## Consequences

- The suite reuses a mature parser exactly where a mature parser fits (clean
  files) and owns a robust decoder exactly where recovery demands one (carved and
  memory bytes) — no single decoder is forced to do both jobs badly.
- Correctness of the native path is tier-2/independent (parity against `evtx` on
  real fixtures) rather than self-referential fixtures; the fuzz targets back the
  never-panic claim empirically.
- The port carries upstream attribution and the Apache-2.0/MIT provenance; the
  fleet Apache-2.0 relicense (ADR 0008) is compatible.
- `winevt-extract` inherits `evtx`'s parser characteristics for intact files; if
  the native decoder ever reaches full parity it could displace that runtime dep,
  but there is no reason to today.
