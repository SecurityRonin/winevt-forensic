<p align="center">
  <strong>winevt-forensic</strong>
</p>

<p align="center">
  <a href="https://crates.io/crates/winevt-core"><img src="https://img.shields.io/crates/v/winevt-core.svg" alt="Crates.io" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="https://github.com/SecurityRonin/winevt-forensic/actions/workflows/ci.yml"><img src="https://github.com/SecurityRonin/winevt-forensic/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/sponsors/h4x0r"><img src="https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors" alt="Sponsor" /></a>
</p>

**Carve. Verify. Detect.**

Low-level EVTX forensic library suite. Recovers Windows Event Log records from corrupt files, disk images, and memory dumps. Detects anti-forensic tampering — cleared logs, checksum mismatches, record ID gaps — without trusting the file header.

This is not an event viewer. It is what you use when the log file has been tampered with or the EVTX parser fails.

```toml
[dependencies]
winevt-core         = "0.1"   # types + binary format
winevt-integrity = "0.1"   # tampering detection
winevt-carver       = "0.1"   # record carving from raw bytes
```

**For event correlation, session analysis, and frequency analysis → use [RapidTriage](https://github.com/SecurityRonin/rapidtriage), which depends on this library.**

---

## Three Things You Do With This

### Carve records from a corrupt or cleared EVTX file

```rust
use winevt_carver::{carve_from_file, Integrity};

let result = carve_from_file("/evidence/Security.evtx")?;

println!("Chunks found: {}", result.stats.chunks_found);
println!("Records recovered: {}", result.stats.records_recovered);

for chunk in &result.chunks {
    println!("  Chunk @ 0x{:x}: {:?}", chunk.offset, chunk.integrity);
    for record in &chunk.records {
        println!("    Record #{} ts={} [{:?}]",
            record.header.record_id,
            record.header.timestamp,
            record.integrity,
        );
    }
}
```

Recovers records even from chunks where the header CRC32 has been tampered with. Falls back to aggressive magic-byte scan when sequential record walk fails.

### Detect anti-forensic indicators

```rust
use winevt_carver::verify_integrity;
use winevt_core::binary::IntegrityIndicator;

let indicators = verify_integrity("/evidence/Security.evtx")?;

for ind in &indicators {
    match ind {
        IntegrityIndicator::RecordIdGap { expected, found, chunk_offset } =>
            println!("TAMPERED: records {expected}..{} missing at chunk 0x{chunk_offset:x}", found - 1),
        IntegrityIndicator::ChunkChecksumMismatch { chunk_offset, .. } =>
            println!("CORRUPT/TAMPERED: chunk header checksum mismatch at 0x{chunk_offset:x}"),
        IntegrityIndicator::TimestampAnomaly { record_id, .. } =>
            println!("ANOMALY: out-of-order timestamp at record #{record_id}"),
        IntegrityIndicator::NextRecordIdInconsistency { header_next, actual_highest } =>
            println!("INCONSISTENT: header says next={header_next}, highest seen={actual_highest}"),
        _ => println!("{ind:?}"),
    }
}
```

### Carve from raw bytes (disk image, memory dump, slack space)

```rust
use winevt_carver::carve_from_bytes;

// Read raw disk sector, unallocated space, or memory region
let raw: Vec<u8> = std::fs::read("/dev/sda")?; // or a memory dump slice

let result = carve_from_bytes(&raw);

// Finds ElfChnk magic at any 8-byte offset — no alignment assumptions
println!("Scanned {} bytes, found {} chunks, recovered {} records",
    result.stats.bytes_scanned,
    result.stats.chunks_found,
    result.stats.records_recovered,
);
```

---

## Crate Architecture

```
winevt-forensic/
└── crates/
    ├── winevt-core          Zero external deps. Binary format constants and
    │                        structs (EvtxFileHeader, EvtxChunkHeader,
    │                        EvtxRecordHeader). Domain types: EvtxEvent,
    │                        LogonSession, ProcessEvent. Lookup tables.
    │                        IntegrityIndicator enum.
    │
    ├── winevt-integrity  Detection algorithms over parsed types. No raw
    │                        bytes, no memory access. Consumed by both
    │                        winevt-carver (disk) and memf-windows (memory).
    │
    ├── winevt-carver        Chunk discovery and record recovery from &[u8],
    │                        file paths, and Read+Seek readers. Integrates
    │                        anti-forensic checks post-carve.
    │
    └── winevt-memory        (in progress) Typed output for EVTX/ETW data
                             recovered from memory dumps. No memory-reader
                             dependency — populated by memf-windows.
```

**Dependency graph:**
```
winevt-core  ←  winevt-integrity  ←  winevt-carver
                                     ←  winevt-memory
```

---

## What This Detects

| Indicator | Detection Method |
|-----------|-----------------|
| Log cleared (EID 1102 / 104) | Event record parsing |
| Record ID gap between chunks | `detect_record_id_gaps()` |
| Chunk header CRC32 mismatch | `verify_chunk_header_checksum()` |
| Records area CRC32 mismatch | `verify_records_checksum()` |
| Out-of-order timestamps | `check_timestamp_monotonicity()` |
| File header NextRecordId inconsistency | `check_file_header_consistency()` |
| Truncated chunks (partial file) | Carved with `Integrity::Truncated` |
| Corrupt header, valid records | Carved with `Integrity::HeaderCorrupt` |

---

## EVTX Binary Format Reference

### File Header (128 bytes at offset 0)

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 8 | Magic `ElfFile\0` |
| 0x08 | 8 | FirstChunkNumber |
| 0x10 | 8 | LastChunkNumber |
| 0x18 | 8 | NextRecordId |
| 0x28 | 2 | HeaderBlockSize (0x1000) |
| 0x2A | 2 | ChunkCount |
| 0x78 | 4 | FileFlags (0x1=dirty, 0x2=full) |
| 0x7C | 4 | Checksum (CRC32 of 0x00..0x78) |

### Chunk Header (128 bytes at chunk start, chunk size = 64 KiB)

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 8 | Magic `ElfChnk\0` |
| 0x08 | 8 | FirstEventRecordNumber |
| 0x10 | 8 | LastEventRecordNumber |
| 0x34 | 4 | EventRecordsChecksum (CRC32 of records area) |
| 0x78 | 4 | HeaderChecksum (CRC32 of 0x00..0x78) |

### Event Record

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 | Magic `\x2a\x2a\x00\x00` |
| 0x04 | 4 | Size (total including header + trailer) |
| 0x08 | 8 | RecordId |
| 0x10 | 8 | Timestamp (Windows FILETIME) |
| 0x18 | … | BinXml payload |
| Size-4 | 4 | CopyOfSize (for backward traversal) |

Records start at chunk offset `0x200`. Each chunk is exactly `0x10000` bytes.

---

## Related Projects

- **[RapidTriage](https://github.com/SecurityRonin/rapidtriage)** — uses winevt-forensic for EVTX carving; provides session correlation, frequency analysis, and the `rt` CLI
- **[evtx](https://github.com/omerbenamram/evtx)** — EVTX parser this library builds on top of for normal (non-corrupt) files
- **[hayabusa](https://github.com/Yamato-Security/hayabusa)** — Sigma-based EVTX detection; complement to this library

---

*If this helped with a case, consider [sponsoring](https://github.com/sponsors/h4x0r).*
