# winevt-forensic — Product Requirements (`ev4n6`)

*Reverse-written from the shipped code, README, and git history (2026-07-24).
Every current-state claim is grounded in a same-session read of `crates/` and
`README.md`. The load-bearing engineering decisions live as ADRs under
[`docs/decisions/`](decisions/); this document is the requirements/scope view of
the product an examiner runs — the `ev4n6` CLI.*

## Executive Summary

`ev4n6` (the `winevt-cli` crate over the `winevt-*` library suite) recovers and
analyzes Windows Event Logs when they cannot be trusted intact — cleared,
truncated, partially overwritten, or encrypted mid-stream by ransomware. Its
premise, stated on the tin: **recover the logs first, analyze them second.**
Every mainstream detection tool assumes the EVTX file is well-formed; in a real
incident it often isn't. `ev4n6` carves what can be recovered, verifies
structural integrity at the binary level, and then runs threat-hunting-focused
analysis — as a single static binary with no Python or .NET runtime, on Linux,
macOS, and Windows.

It is deliberately **not** a Sigma detection engine. It owns the recovery and
structural-analysis layer that runs *before* tools like Hayabusa, and can hand
off to Hayabusa when logs are clean.

## 1. Problem

- **Detection tools assume intact input.** A cleared Security log, a chunk with
  a rewritten CRC, or a file truncated by ransomware is invisible to a
  Sigma-rule scanner — or, worse, decodes to an empty timeline that reads as
  "clean." The recovery and tamper-detection layer is missing from most
  workflows.
- **EVTX residue survives outside files.** Loose `ElfChnk` chunks persist in
  unallocated disk space and in memory images after the containing `.evtx` file
  is deleted or cleared; a file-oriented parser never sees them.
- **Analysts need answers on any input shape**, not a pre-extraction chore: a
  single `.evtx`, a directory of them, or a full E01 disk image.
- **Integrity claims must be raw facts, not conclusions.** An examiner who will
  stand behind a finding needs the observable ("stored CRC at 0x78 does not
  match computed CRC of 0x00..0x78"), not a black-box "tampered" verdict.

## 2. Users

- **DFIR analysts / incident responders** triaging a compromised host, who need
  recovered logs and a fast structural read before deep detection.
- **Forensic examiners** who must defend findings, needing binary-level
  observations (CRC mismatch, record-ID gap, header inconsistency) stated as
  facts.
- **Threat hunters** looking for the rare event — least-frequent-first ordering,
  LOLBin invocations, PowerShell script blocks, WMI persistence, IOCs.
- **Fleet tooling** (Issen, RapidTriage) that links the `winevt-*` libraries for
  EVTX carving and analysis rather than shelling out.

## 3. What it does (shipped capability)

Input auto-detection: every subcommand accepts a `.evtx` file, a directory
(walked recursively), an E01/Ex01 image (NTFS extracted, EVTX parsed), or any
other blob (raw-carved for `ElfChnk` magic). A global `--carve` flag additionally
sweeps unallocated space for deleted/overwritten records.

Subcommands (from `ev4n6` / README):
- `verify` — integrity check: chunk-header CRC32 mismatch, record-ID gap,
  file-header inconsistency, out-of-order timestamps, log-cleared (EID 1102/104).
  Exit 0 clean / 1 indicators.
- `info` — file-structure summary (chunk counts, records recovered, indicators).
- `timeline` — chronological event stream with EID/time filters, limit, and
  NDJSON streaming.
- `login` — logon-session correlation (EID 4624/4634 pairing; Mermaid output).
- `frequency` — event-ID distribution, least-frequent-first; process counts;
  z-score anomaly mode.
- `extract` — targeted indicators: IOCs, PowerShell script blocks (reassembled,
  deobfuscated), WMI persistence (5860/5861), scheduled tasks (4698/4702),
  process command lines with LOLBin flagging, ATT&CK technique tags.
- `search` — literal or regex full-text event search (streamable).
- `diff` — events present in one EVTX but absent from another.
- `process-tree` — parent/child process visualization (Mermaid).
- `repair` — reconstruct a valid EVTX from surviving CRC-valid chunks,
  re-sequencing record IDs; writes to a **new** output path.
- `report` — one-click triage: integrity → optional carving → IOC → ATT&CK →
  optional Hayabusa → JSON/HTML.

Recovery reach: intact files, corrupt/partial files, unallocated-space carving,
and memory-image carving — the last two through the shared fleet
`forensic-carve` sweep (ADR 0001), with per-medium provenance.

## 4. Scope / Non-goals

**In scope**
- EVTX recovery (files, corrupt files, unallocated space, memory images).
- Binary-level integrity/tamper detection stated as observations.
- Threat-hunting-oriented extraction and correlation.
- E01/EWF ingestion and NTFS-based EVTX extraction (`winevt-triage`).
- MITRE ATT&CK tagging as "consistent with", never a verdict.
- Single static binary; JSON / NDJSON / HTML output; scriptable exit codes.

**Non-goals**
- **Not a Sigma/Sigma-rule detection engine** — that is Hayabusa's job; `ev4n6`
  runs before it and can invoke it.
- **Not a general clean-file EVTX parser to displace `evtx`** — intact files use
  the omerbenamram `evtx` crate (ADR 0004); the differentiator is recovery.
- **Not an evidence editor** — `repair`/`winevt-writer` emit reconstructed bytes
  to new paths only; the source image is never modified.
- **No legal conclusions** — findings are observations for the analyst/tribunal
  to weigh.
- Not a live-collection agent, not a SIEM.

## 5. Artifact family

Windows Event Log (EVTX) — `ElfFile\0` files, `ElfChnk\0` 64 KiB chunks,
`\x2a\x2a\x00\x00` records, BinXML payloads, Windows FILETIME timestamps; plus
EVTX/ETW residue recovered from unallocated space and memory images. Security /
System / PowerShell / WMI-Activity channels are first-class (the extract modes
target their EIDs). Provider manifests (`winevt-manifest`) map anonymous
Param1/Param2 fields to real names.

## 6. Validation approach

- **Differential oracle for BinXML.** The native panic-free decoder is checked
  for parity against the omerbenamram `evtx` crate on real fixtures (ADR 0004) —
  an independent oracle, not self-authored fixtures.
- **Fuzzing.** BinXML decode targets under `fuzz/` back the never-panic posture
  on attacker-controlled bytes (commit `66c6a17`).
- **CRC as ground truth.** Chunk/record recovery gates on the format's own stored
  CRC32 (`crc32fast`, standard ISO 3309), so a recovered chunk is validated by
  the artifact itself, not by a self-consistent round-trip.
- **Fail-loud bootstrap.** An invalid EVTX header errors rather than returning an
  empty log (ADR 0007), with a RED regression test.
- **Coverage.** Library crates carry high line coverage (BinXML at 100% lib,
  commit `6160721`); the CLI is the thin front-end over tested libraries.

## 7. Success criteria

- Recovers records from a cleared/truncated/overwritten EVTX that a clean-file
  parser rejects or reads as empty.
- Surfaces CRC mismatches, record-ID gaps, and header inconsistencies as
  binary-level observations with offsets.
- Runs on Linux/macOS/Windows as one `cargo install winevt-cli` binary, no
  runtime.
- Scriptable: exit 0 clean / 1 detections / 2 processing error / 3 path-not-found.
- Library crates are independently linkable by fleet tools (Issen, RapidTriage).
