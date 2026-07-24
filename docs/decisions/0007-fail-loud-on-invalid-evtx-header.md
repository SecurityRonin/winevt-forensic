# 7. Fail loud on an invalid EVTX header, never return an empty log

Date: 2026-07-24
Status: Accepted

## Context

When the top-level `ElfFile\0` header of an EVTX file fails to validate — the
magic is wrong, the file is truncated before the header, or the header was forged
— a decoder can react two ways: surface the failure as a loud error, or return an
empty record list. The second is the dangerous choice. An empty result from a
*bootstrap* failure is indistinguishable from a genuinely empty log, so a cleared
or corrupted file reads to the analyst as "nothing to see here" — the exact
silent-wrong-output failure the constitution's Robustness discipline exists to
prevent (a bootstrap failure must be loud; degrade-to-empty is legitimate only
for a per-item miss *after* a validated bootstrap).

This was a real bug, fixed by test-first work: an invalid EVTX header was being
treated the same as an empty log.

Evidence: commit `7a7a574` (RED — "invalid EVTX header must error, not be
indistinguishable from an empty log"), commit `86bb39b` (GREEN — "surface invalid
EVTX header as a loud error (`decode_file_checked`)");
`crates/winevt-binxml/src/reader.rs` (`decode_file_checked` returns
`Result<…, DecodeFileError>`; `DecodeFileError::InvalidHeader`; doc comment
"which must be surfaced loudly, never masked as 'no records'" and "bootstrap as a
loud error"). Constitution: "Bootstrap failure ≠ artifact-not-found — fail LOUD".

## Decision

1. `decode_file_checked` returns a `Result`; an invalid `ElfFile` header yields
   `DecodeFileError::InvalidHeader`, never `Ok(empty)`.

2. Header validation is treated as a *bootstrap* step. A failure there is a loud
   error carrying context; only a per-record miss *after* the header validates
   may degrade to skipping that record.

3. The distinction is preserved at the type level — the checked entry point hands
   the caller a `Result` it cannot ignore, rather than an ambiguous `Vec`.

## Consequences

- A cleared, truncated, or forged EVTX file is reported as an error, not as a
  clean empty timeline — the failure is visible to the examiner.
- Callers that want the lenient behavior must opt into it explicitly; the safe,
  loud path is the default (secure-by-default).
- Regression is guarded by the RED test committed before the fix, so the
  empty-vs-error distinction cannot silently regress.
