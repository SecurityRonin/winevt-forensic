<p align="center">
  <strong>wt-evtx</strong>
</p>

<p align="center">
  <a href="https://crates.io/crates/wt-evtx"><img src="https://img.shields.io/crates/v/wt-evtx.svg" alt="Crates.io" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="https://github.com/SecurityRonin/winevt-forensic/actions/workflows/ci.yml"><img src="https://github.com/SecurityRonin/winevt-forensic/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/SecurityRonin/winevt-forensic/releases"><img src="https://github.com/SecurityRonin/winevt-forensic/actions/workflows/release.yml/badge.svg" alt="Release" /></a>
  <a href="https://github.com/sponsors/h4x0r"><img src="https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors" alt="Sponsor" /></a>
</p>

**Parse. Correlate. Hunt.**

You're already running hayabusa. `wt-evtx` is what comes after: hayabusa-compatible timelines plus the session correlation and frequency analysis that hayabusa can't do. Feed it an EVTX directory and get a pivot table of every logon session — who, from where, how long, what processes — and a ranked list of command lines that appeared exactly once in 90 days of logs.

```bash
cargo install wt-evtx
```

---

## Three Things You Do With This

### Reconstruct the attacker's session — who, from where, for how long

```bash
wt-evtx sessions -d /mnt/evidence/winevt/logs
```

Every 4624 logon is correlated to its matching 4634 logoff. Orphaned sessions (no logoff found) are flagged. Source IP, logon type, duration, and process list all in one table.

```
LogonID     Type   User              SrcIP           Logon                 Duration    Processes
0x3e7       2      SYSTEM            —               2024-03-15T08:00:01Z  ongoing     —
0xf6d8b     10     jsmith            192.168.1.45    2024-03-15T09:12:33Z  00:47:22    3
0x1a2b3c    3      Administrator     10.10.0.200     2024-03-15T09:58:11Z  ORPHANED    1
```

[Session correlation guide →](docs/sessions.md)

### Build the process tree — linked to the session that spawned it

```bash
wt-evtx processes -d /mnt/evidence/winevt/logs --link-sessions
```

Every 4688 process creation event, parent PID, command line, and the logon session it belongs to. Pivot from a suspicious process straight back to the originating logon.

[Process tree guide →](docs/processes.md)

### Surface the one command that ran once in 90 days

```bash
wt-evtx frequency -d /mnt/evidence/winevt/logs --cap 5
```

Events Ripper-style frequency analysis: all command lines and process images ranked by how rarely they appear. Anything seen 5 times or fewer is flagged. The living-off-the-land binary that ran once stands out immediately.

```
Count  CommandLine
1      C:\Windows\Temp\svc32.exe -install
2      powershell -enc JABjAGw...
3      net user /domain
5      certutil -decode payload.b64 out.exe
```

[Frequency analysis guide →](docs/frequency.md)

### Export a full timeline (hayabusa-compatible)

```bash
wt-evtx timeline -d /mnt/evidence/winevt/logs -o timeline.csv --format csv
wt-evtx timeline -d /mnt/evidence/winevt/logs -o timeline.jsonl --format jsonl
```

Produces the same columns hayabusa emits. Drop it into Timeline Explorer or import into your SIEM without reformatting.

---

## What wt-evtx Does That hayabusa Doesn't

Every hayabusa feature it overlaps with, it's compatible. These are the additions:

|                                         | wt-evtx | hayabusa |
|-----------------------------------------|:-------:|:--------:|
| Hayabusa-compatible CSV/JSONL timeline  |    Y    |    Y     |
| Session correlation (4624→4634)         |    Y    |    —     |
| Session pivot by source IP              |    Y    |    —     |
| Orphaned session detection              |    Y    |    —     |
| Process–session linking (4688)          |    Y    |    —     |
| Frequency analysis (rare cmdlines)      |    Y    |    —     |
| Events Ripper-style cap threshold       |    Y    |    —     |
| Pure Rust, single static binary         |    Y    |    —     |
| Sigma rule detection                    |    —    |    Y     |
| HTML timeline reports                   |    —    |    Y     |

`wt-evtx` is a complement, not a replacement. Run both.

---

## Install

**Cargo (all platforms)**
```bash
cargo install wt-evtx
```

**Build from source**
```bash
git clone https://github.com/SecurityRonin/winevt-forensic
cd winevt-forensic
cargo build --release
# binary at target/release/wt-evtx
```

**Requirements:** Rust 1.75+, a directory of `.evtx` files.

---

## Subcommands

```
wt-evtx <SUBCOMMAND> -d <EVTX_DIRECTORY> [OPTIONS]

SUBCOMMANDS:
  timeline    Chronological event timeline (CSV / JSONL / text)
  sessions    Correlate 4624→4634 logon sessions
  processes   4688 process creation with optional session linking
  frequency   Rare command-line / process image frequency table

OPTIONS (all subcommands):
  -d, --directory <DIR>   EVTX directory (searched recursively)
  -o, --output <FILE>     Output file (default: stdout)
  -f, --format <FMT>      csv | jsonl | text (default: text)
      --cap <N>           Frequency cap — flag events seen ≤ N times (default: 5)
      --link-sessions     Link processes to correlated sessions (processes only)
```

---

## Crate Architecture

```
winevt-forensic/
├── crates/
│   ├── winevt-core       # EvtxEvent type, logon type names, substatus codes
│   ├── winevt-session    # 4624/4634 correlation, 4688 process linking
│   ├── winevt-handlers   # Per-event-ID handler implementations
│   ├── winevt-analyze    # Frequency analysis, pivot tables
│   └── wt-evtx           # CLI binary (clap)
```

Each crate is independently usable as a library. Embed session correlation or frequency analysis in your own tooling without pulling in the full CLI.

---

## Event IDs Processed

| Event ID | Source           | Purpose                        |
|----------|------------------|--------------------------------|
| 4624     | Security         | Logon (session start)          |
| 4625     | Security         | Failed logon                   |
| 4634     | Security         | Logoff (session end)           |
| 4648     | Security         | Explicit credentials logon     |
| 4672     | Security         | Special privileges assigned    |
| 4688     | Security         | Process creation               |
| 4720     | Security         | User account created           |
| 4732     | Security         | Member added to local group    |
| 4768     | Security         | Kerberos TGT request           |
| 4769     | Security         | Kerberos service ticket        |
| 4776     | Security         | NTLM authentication            |
| 7045     | System           | New service installed          |

---

## Credits

Built on the excellent [evtx](https://github.com/omerbenamram/evtx) crate by Omer Ben-Amram.
[hayabusa](https://github.com/Yamato-Security/hayabusa) by Yamato Security — the reference implementation for Windows event timeline analysis.

---

*If this saved you time on a case, consider [sponsoring](https://github.com/sponsors/h4x0r).*
