# winevt-forensic

**Recover the logs first. Analyze them second.**

Every detection tool assumes the event log is intact. In a real incident it often isn't — cleared, truncated, partially overwritten, or encrypted mid-stream by ransomware. `winevt-forensic` recovers what can be recovered, verifies structural integrity, and then analyzes events with threat-hunting–focused CLI commands.

## Quick start

```bash
cargo install wt-cli

# One-click triage: carve + verify + extract + hayabusa, output JSON/HTML
wt report /evidence/Security.evtx

# Analyze a directory, an E01 image, or a single EVTX file
wt timeline /evidence/
wt extract --ioc /evidence/Security.evtx
wt extract --wmi /evidence/Security.evtx
```

## What it does

`winevt-forensic` parses the EVTX binary format directly — over a path, a directory, an E01 image, or any `&[u8]` — and pairs recovery with analysis:

- **Recovery** — `wt repair` recovers partial EVTX files; `wt report --carved` carves corrupt chunks before analysis.
- **Integrity** — structural checks before you trust the timeline (`wt verify`), so a manipulated log is flagged rather than silently analyzed.
- **Threat-hunting CLI** — `wt timeline`, `wt extract` (IOC, PowerShell script blocks, WMI persistence, scheduled tasks, process command lines, ATT&CK tags), `wt frequency` (least-frequent-first anomaly surfacing), `wt search`, `wt diff`, `wt process-tree`, and one-click `wt report`.

## Where this fits

`winevt-forensic` is the Windows event-log LOG-FORMAT reader and analyzer for the SecurityRonin forensic family — it navigates an EVTX stream by chunk and record ID, decodes BinXML fields, and emits findings onto the shared [`forensicnomicon`](https://crates.io/crates/forensicnomicon) reporting vocabulary so they aggregate with the rest of the fleet.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/winevt-forensic) · © 2026 Security Ronin Ltd
