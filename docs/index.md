# winevt-forensic

**Recover the logs first. Analyze them second.**

Every detection tool assumes the event log is intact. In a real incident it often isn't — cleared, truncated, partially overwritten, or encrypted mid-stream by ransomware. `winevt-forensic` recovers what can be recovered, verifies structural integrity, and then analyzes events with threat-hunting–focused CLI commands.

## Quick start

```bash
cargo install winevt-cli

# One-click triage: carve + verify + extract + hayabusa, output JSON/HTML
ev4n6 report /evidence/Security.evtx

# Analyze a directory, an E01 image, or a single EVTX file
ev4n6 timeline /evidence/
ev4n6 extract --ioc /evidence/Security.evtx
ev4n6 extract --wmi /evidence/Security.evtx
```

## What it does

`winevt-forensic` parses the EVTX binary format directly — over a path, a directory, an E01 image, or any `&[u8]` — and pairs recovery with analysis:

- **Recovery** — `ev4n6 repair` recovers partial EVTX files; `ev4n6 report --carved` carves corrupt chunks before analysis.
- **Integrity** — structural checks before you trust the timeline (`ev4n6 verify`), so a manipulated log is flagged rather than silently analyzed.
- **Threat-hunting CLI** — `ev4n6 timeline`, `ev4n6 extract` (IOC, PowerShell script blocks, WMI persistence, scheduled tasks, process command lines, ATT&CK tags), `ev4n6 frequency` (least-frequent-first anomaly surfacing), `ev4n6 search`, `ev4n6 diff`, `ev4n6 process-tree`, and one-click `ev4n6 report`.

## Where this fits

`winevt-forensic` is the Windows event-log LOG-FORMAT reader and analyzer for the SecurityRonin forensic family — it navigates an EVTX stream by chunk and record ID, decodes BinXML fields, and emits findings onto the shared [`forensicnomicon`](https://crates.io/crates/forensicnomicon) reporting vocabulary so they aggregate with the rest of the fleet.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/winevt-forensic) · © 2026 Security Ronin Ltd
