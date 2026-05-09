//! `wt` — EVTX forensic analysis CLI.
//!
//! Subcommands:
//! - `wt carve <path>`        — carve EVTX records from raw blob (disk image, memory dump), output JSON
//! - `wt verify <path>`       — verify EVTX integrity, output JSON indicators
//! - `wt stats [--json] <path>` — print file statistics
//!
//! Exit codes:
//! - `0` = success, no detections / indicators
//! - `1` = success, detections / indicators found
//! - `2` = I/O or argument error
//! - `3` = input path not found

const EXIT_CLEAN: i32 = 0;
const EXIT_DETECTIONS: i32 = 1;
const EXIT_ERROR: i32 = 2;
const EXIT_NOT_FOUND: i32 = 3;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod report;

/// EVTX forensic analysis tool.
///
/// Carves records from corrupt or cleared EVTX files and reports
/// structural integrity indicators.
#[derive(Parser)]
#[command(name = "wt", about = "EVTX forensic analysis tool", version)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Carve EVTX records from a raw blob (disk image, memory dump, unallocated slice).
    ///
    /// Scans for `ElfChnk` magic, recovers records from each chunk,
    /// and runs integrity checks. Outputs a `CarveResult` as JSON.
    ///
    /// Example: `wt carve /evidence/hdd001.dd`
    Carve {
        /// Path to the raw blob (disk image, memory dump, or any binary file).
        path: PathBuf,
    },
    /// Verify the integrity of an EVTX file and report tampering indicators.
    ///
    /// Checks chunk header checksums, record ID continuity, timestamp
    /// monotonicity, and file header consistency.
    Verify {
        /// Path to the EVTX file.
        path: PathBuf,
    },
    /// Print statistics about an EVTX file (chunk count, record count, hash, time range).
    Stats {
        /// Output machine-readable JSON instead of plain text.
        #[arg(long)]
        json: bool,
        /// Path to the EVTX file.
        path: PathBuf,
    },
    /// Carve EVTX records from an E01/EWF forensic disk image.
    ///
    /// Reads the image via the EWF reader, then carves records from all bytes.
    /// Outputs a `CarveResult` as JSON.
    CarveEwf {
        /// Path to the E01 image (first segment).
        path: PathBuf,
    },
    /// Output all events in chronological order as a JSON array.
    ///
    /// Each entry contains `record_id`, timestamp, `event_id`, level, channel,
    /// computer, and provider.  Requires an intact or reconstructed EVTX file.
    Timeline {
        /// Path to the EVTX file.
        path: PathBuf,
        /// Emit one JSON object per line (NDJSON) instead of a pretty-printed array.
        #[arg(long)]
        stream: bool,
        /// Only include events with this event ID (may be repeated for multiple IDs).
        #[arg(long, value_name = "EID")]
        filter_eid: Vec<u32>,
        /// Return at most N events (applied after --filter-eid and time filters).
        #[arg(long, value_name = "N")]
        limit: Option<usize>,
        /// Only include events with timestamp >= this value (ISO 8601 UTC string).
        #[arg(long, value_name = "TS")]
        after: Option<String>,
        /// Only include events with timestamp < this value (ISO 8601 UTC string).
        #[arg(long, value_name = "TS")]
        before: Option<String>,
    },
    /// Reconstruct logon sessions from EID 4624 / 4634 / 4647 events.
    ///
    /// Outputs a JSON array of sessions, each with `logon_id` (LUID), `username`,
    /// `domain`, `logon_type`, `ip_address`, `logon_time`, `logoff_time`, and
    /// `duration_secs`.  Sessions without a matching logoff have null
    /// `logoff_time`.
    Sessions {
        /// Path to the Security EVTX file.
        path: PathBuf,
        /// Emit one JSON object per line (NDJSON).
        #[arg(long)]
        stream: bool,
        /// Only include sessions with this logon type (e.g. 3 = Network, 10 = RemoteInteractive).
        #[arg(long, value_name = "TYPE")]
        logon_type: Option<u32>,
    },
    /// Reassemble `PowerShell` script blocks from EID 4104 events.
    ///
    /// Groups events by `ScriptBlockId`, sorts fragments by `MessageNumber`,
    /// and concatenates `ScriptBlockText`.  Outputs a JSON array of script
    /// blocks with their full reassembled text.
    Powershell {
        /// Path to the `PowerShell` Operational EVTX file.
        path: PathBuf,
        /// Emit one JSON object per line (NDJSON).
        #[arg(long)]
        stream: bool,
        /// Suppress automatic decoding of base64 `-EncodedCommand` payloads.
        /// By default, detected encoded commands are decoded and added as
        /// `decoded_command` to each script block object.
        #[arg(long)]
        no_deobfuscate: bool,
    },
    /// Compute event ID frequency distribution, rare-process analysis, or z-score anomaly detection.
    ///
    /// Default (no flags): JSON object with `total_events` and `by_event_id` array.
    /// `--by process`  : JSON array of rare process images (those seen < `--threshold` times).
    /// `--anomaly`     : JSON array of event IDs with |z_score| >= `--min-z` (default 2.0).
    /// Use `--sort asc` for least-frequent-first (LFO) threat-hunting output.
    Frequency {
        /// Path to the EVTX file.
        path: PathBuf,
        /// Sort order: `desc` (most-frequent-first, default) or `asc` (LFO).
        #[arg(long, default_value = "desc")]
        sort: String,
        /// Emit one JSON object per line (NDJSON) — one EventFrequency per line.
        #[arg(long)]
        stream: bool,
        /// Return only the top N entries after sorting (standard mode only).
        #[arg(long, value_name = "N")]
        top: Option<usize>,
        /// Group by dimension: `event` (default) or `process`.
        /// `--by process` surfaces rare process images from EID 4688 events.
        #[arg(long, value_name = "DIM")]
        by: Option<String>,
        /// Count threshold for `--by process`; images seen < N times are reported.
        #[arg(long, default_value_t = 3)]
        threshold: usize,
        /// Score event IDs by z-score and return those with |z| >= `--min-z`.
        #[arg(long)]
        anomaly: bool,
        /// Minimum absolute z-score threshold when `--anomaly` is active (default 2.0).
        #[arg(long, default_value_t = 2.0)]
        min_z: f64,
    },
    /// Fix bad EVTX checksums and write the repaired file.
    ///
    /// Recomputes per-chunk header CRC32 and records-area CRC32 where wrong.
    /// Outputs a JSON report with `chunks_checked`, `chunks_repaired`, `header_repaired`.
    Repair {
        /// Path to the (possibly corrupt) EVTX file.
        path: PathBuf,
        /// Path for the repaired output file.
        #[arg(long, short)]
        output: PathBuf,
    },
    /// Search all event fields for a substring (case-insensitive).
    /// Exits 1 if matches found, 0 if none.
    Pivot {
        /// Case-insensitive search query.
        query: String,
        /// Path to the EVTX file.
        path: PathBuf,
        /// Emit one JSON object per line (NDJSON).
        #[arg(long)]
        stream: bool,
    },
    /// Diff two EVTX files by record ID.
    /// Outputs `{"added": [...], "removed": [...]}`. Exits 1 if differences found.
    Diff {
        /// First (baseline) EVTX file.
        a: PathBuf,
        /// Second (comparison) EVTX file.
        b: PathBuf,
    },
    /// Extract process-creation events and show parent-child relationships.
    /// Outputs a JSON array of nodes or a Mermaid diagram with `--mermaid`.
    ProcessTree {
        /// Path to the EVTX file (Security or Sysmon).
        path: PathBuf,
        /// Emit a Mermaid `graph LR` diagram instead of JSON.
        #[arg(long)]
        mermaid: bool,
    },
    /// Build a logon source→target graph from EID 4624 events.
    /// Outputs JSON `{nodes, edges}` or a Mermaid diagram with `--mermaid`.
    LogonGraph {
        /// Path to the Security EVTX file.
        path: PathBuf,
        /// Emit a Mermaid `graph LR` diagram instead of JSON.
        #[arg(long)]
        mermaid: bool,
    },
    /// Extract unique field values or IOCs from all events.
    ///
    /// Without `--ioc`: extracts all unique values for the given field name,
    /// output as a JSON array of `{value, count}` sorted by frequency.
    /// Usage: `wt extract <PATH> <FIELD>`
    ///
    /// With `--ioc`: scans every event for SHA-256/SHA-1/MD5 hashes, IPv4
    /// addresses, and Windows file paths. Outputs a JSON object with
    /// `events_scanned` and an `iocs` array. Exits 1 when IOCs are found.
    /// Usage: `wt extract --ioc <PATH>`
    Extract {
        /// Path to the EVTX file (always required).
        path: PathBuf,
        /// Field name to search for in event data (e.g. `SubjectUserName`).
        /// Required unless `--ioc` is given.
        #[arg(required_unless_present = "ioc")]
        field: Option<String>,
        /// Extract indicators of compromise instead of a named field.
        #[arg(long)]
        ioc: bool,
    },
    /// One-line forensic overview of an EVTX file.
    ///
    /// Outputs a JSON object with `file`, `total_events`, `time_range` (first/last),
    /// `top_event_ids` (up to 5 most frequent), `integrity_indicators` (count),
    /// and `ioc_count`. Ideal for the first look at an unknown file.
    Info {
        /// Path to the EVTX file.
        path: PathBuf,
    },
    /// One-click triage: extract EVTX, verify integrity, run Hayabusa.
    ///
    /// Accepts:
    ///   `*.E01 / *.Ex01` — NTFS filesystem extraction; `--carved` adds full-image carve
    ///   `*.evtx`          — direct pass-through to Hayabusa
    ///   directory         — all `*.evtx` files in the tree
    ///   any other blob    — raw carve for `ElfChnk` magic
    ///
    /// Outputs a JSON report with `input`, `evtx_files` (name, source, size,
    /// `integrity_indicators`), and an optional `hayabusa` section.
    Report {
        /// Path to the evidence (E01 image, EVTX file, directory, or raw blob).
        path: PathBuf,
        /// For E01 images: also carve the full raw image for deleted/unallocated EVTX data.
        #[arg(long)]
        carved: bool,
        /// Directory to write extracted EVTX files and Hayabusa output.
        /// Defaults to a temporary directory (path printed to stderr).
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// Path to the hayabusa binary.  Defaults to `hayabusa` on `PATH`.
        #[arg(long)]
        hayabusa_bin: Option<PathBuf>,
        /// Minimum Hayabusa detection level to load
        /// (`informational`, `low`, `medium`, `high`, `critical`).
        /// Lower levels are noisier; `medium` or `high` gives better SNR for triage.
        /// Defaults to `informational` (all rules).
        #[arg(long, default_value = "medium")]
        min_level: String,
        /// Output format: `json` (default) or `md` (Markdown).
        #[arg(long, default_value = "json")]
        format: String,
    },
}

/// Sanitize a string for use as a Mermaid node label (no spaces or special chars).
fn sanitize_mermaid(s: &str) -> String {
    // Keep only the last path component for readability
    let base = s.rsplit(['/', '\\']).next().unwrap_or(s);
    base.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '.' { c } else { '_' })
        .collect()
}

/// Convert Windows FILETIME (100-ns intervals since 1601-01-01) to a UTC string.
fn filetime_to_utc_string(ft: u64) -> String {
    if ft == 0 {
        return "N/A".to_string();
    }
    // Unix timestamp = filetime / 10_000_000 - 11644473600
    let unix_secs = (ft / 10_000_000).saturating_sub(11_644_473_600);
    let secs = unix_secs % 60;
    let mins = (unix_secs / 60) % 60;
    let hours = (unix_secs / 3600) % 24;
    let days_since_epoch = unix_secs / 86400;
    // Rough date from days since epoch (1970-01-01)
    // Use a simple algorithm (not leap-year perfect, good enough for display)
    let year_400 = days_since_epoch / 146_097;
    let remaining = days_since_epoch % 146_097;
    let year_100 = (remaining.min(146_096)) / 36524;
    let remaining = remaining - year_100 * 36524;
    let year_4 = remaining / 1461;
    let remaining = remaining % 1461;
    let year_1 = remaining.min(1460) / 365;
    let remaining = remaining - year_1 * 365;
    let year = 1970 + year_400 * 400 + year_100 * 100 + year_4 * 4 + year_1;
    // Approximate month/day from day of year
    let month_days = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    let mut day = remaining + 1;
    for &md in &month_days {
        if day > md {
            day -= md;
            month += 1;
        } else {
            break;
        }
    }
    format!("{year}-{month:02}-{day:02} {hours:02}:{mins:02}:{secs:02} UTC")
}

fn print_stats(path: &std::path::Path, result: &winevt_carver::CarveResult, as_json: bool) {
    let file_name = path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let hash = result.source_hash.as_deref().unwrap_or("N/A");
    let chunks_total = result.stats.chunks_found;
    let chunks_valid = result.stats.chunks_valid;
    let chunks_corrupt = result.stats.chunks_corrupt;
    let records_recovered = result.stats.records_recovered;
    let records_corrupt = result.stats.records_corrupt;
    let indicators_count = result.indicators.len();
    let first_indicator = result
        .indicators
        .first()
        .map_or_else(String::new, |i| format!("{i:?}"));

    let timestamps: Vec<u64> = result
        .chunks
        .iter()
        .flat_map(|c| c.records.iter())
        .map(|r| r.header.timestamp)
        .filter(|&t| t > 0)
        .collect();
    let first_ts = timestamps.iter().copied().min().unwrap_or(0);
    let last_ts = timestamps.iter().copied().max().unwrap_or(0);
    let first_id = result
        .chunks
        .iter()
        .flat_map(|c| c.records.iter())
        .map(|r| r.header.record_id)
        .min()
        .unwrap_or(0);
    let last_id = result
        .chunks
        .iter()
        .flat_map(|c| c.records.iter())
        .map(|r| r.header.record_id)
        .max()
        .unwrap_or(0);

    if as_json {
        let obj = serde_json::json!({
            "file": file_name,
            "hash": hash,
            "chunks": { "total": chunks_total, "valid": chunks_valid, "corrupt": chunks_corrupt },
            "records": { "recovered": records_recovered, "corrupt": records_corrupt },
            "time_range": {
                "first": filetime_to_utc_string(first_ts),
                "last": filetime_to_utc_string(last_ts)
            },
            "record_ids": { "first": first_id, "last": last_id },
            "indicators": { "count": indicators_count, "first": first_indicator }
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
    } else {
        println!("File:       {file_name}");
        println!("Hash:       {hash}");
        println!(
            "Chunks:     {chunks_total} total ({chunks_valid} valid, {chunks_corrupt} corrupt)"
        );
        println!("Records:    {records_recovered} recovered ({records_corrupt} corrupt)");
        println!(
            "Time range: {} → {}",
            filetime_to_utc_string(first_ts),
            filetime_to_utc_string(last_ts)
        );
        println!("Record IDs: {first_id} → {last_id}");
        if indicators_count > 0 {
            println!("Indicators: {indicators_count} ({first_indicator})");
        } else {
            println!("Indicators: 0");
        }
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Cmd::Carve { path } => match winevt_carver::carve_from_file(&path) {
            Ok(result) => {
                match serde_json::to_string_pretty(&result) {
                    Ok(json) => println!("{json}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(2);
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                2
            }
        },
        Cmd::Verify { path } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            match winevt_carver::verify_integrity(&path) {
                Ok(indicators) => {
                    match serde_json::to_string_pretty(&indicators) {
                        Ok(json) => println!("{json}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(EXIT_ERROR);
                        }
                    }
                    if indicators.is_empty() { EXIT_CLEAN } else { EXIT_DETECTIONS }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    EXIT_ERROR
                }
            }
        }
        Cmd::Stats { path, json } => match winevt_carver::carve_from_file(&path) {
            Ok(result) => {
                print_stats(&path, &result, json);
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                2
            }
        },
        Cmd::CarveEwf { path } => match winevt_carver::carve_from_ewf(&path) {
            Ok(result) => {
                match serde_json::to_string_pretty(&result) {
                    Ok(json) => println!("{json}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(2);
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                2
            }
        },
        Cmd::Timeline { path, stream, filter_eid, limit, after, before } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            match winevt_analyze::timeline(&path) {
                Ok(all_entries) => {
                    // Apply --filter-eid, --after, --before, then --limit.
                    let filtered: Vec<_> = all_entries
                        .into_iter()
                        .filter(|e| filter_eid.is_empty() || filter_eid.contains(&e.event_id))
                        .filter(|e| after.as_deref().map_or(true, |a| e.timestamp.as_str() >= a))
                        .filter(|e| before.as_deref().map_or(true, |b| e.timestamp.as_str() < b))
                        .take(limit.unwrap_or(usize::MAX))
                        .collect();
                    if stream {
                        for e in &filtered {
                            if let Ok(line) = serde_json::to_string(e) {
                                println!("{line}");
                            }
                        }
                    } else {
                        match serde_json::to_string_pretty(&filtered) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                    }
                    EXIT_CLEAN
                }
                Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
            }
        }
        Cmd::Sessions { path, stream, logon_type } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            match winevt_analyze::sessions(&path) {
                Ok(all_sessions) => {
                    let filtered: Vec<_> = all_sessions
                        .into_iter()
                        .filter(|s| logon_type.map_or(true, |lt| s.logon_type == lt))
                        .collect();
                    if stream {
                        for s in &filtered {
                            if let Ok(line) = serde_json::to_string(s) {
                                println!("{line}");
                            }
                        }
                    } else {
                        match serde_json::to_string_pretty(&filtered) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                    }
                    EXIT_CLEAN
                }
                Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
            }
        }
        Cmd::Powershell { path, stream, no_deobfuscate } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            match winevt_analyze::powershell_blocks(&path) {
                Ok(blocks) => {
                    // Enrich blocks with decoded_command unless --no-deobfuscate.
                    let enriched: Vec<serde_json::Value> = blocks.iter().map(|b| {
                        let mut v = serde_json::to_value(b).unwrap_or(serde_json::Value::Null);
                        if !no_deobfuscate {
                            if let Some(decoded) = winevt_analyze::deobfuscate_ps(&b.text) {
                                if let Some(obj) = v.as_object_mut() {
                                    obj.insert("decoded_command".to_string(), serde_json::Value::String(decoded));
                                }
                            }
                        }
                        v
                    }).collect();
                    if stream {
                        for v in &enriched {
                            if let Ok(line) = serde_json::to_string(v) {
                                println!("{line}");
                            }
                        }
                    } else {
                        match serde_json::to_string_pretty(&enriched) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                    }
                    EXIT_CLEAN
                }
                Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
            }
        }
        Cmd::Frequency { path, sort, stream, top, by, threshold, anomaly, min_z } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            // --by process: rare-process mode
            if by.as_deref() == Some("process") {
                match winevt_analyze::rare_processes(&path, threshold) {
                    Ok(procs) => {
                        match serde_json::to_string_pretty(&procs) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                        EXIT_CLEAN
                    }
                    Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
                }
            } else if anomaly {
                // --anomaly: z-score anomaly detection mode
                match winevt_analyze::anomaly(&path, min_z) {
                    Ok(entries) => {
                        let has_anomalies = !entries.is_empty();
                        match serde_json::to_string_pretty(&entries) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                        if has_anomalies { EXIT_DETECTIONS } else { EXIT_CLEAN }
                    }
                    Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
                }
            } else {
                // standard event-ID frequency mode
                match winevt_analyze::frequency(&path) {
                    Ok(mut report) => {
                        if sort == "asc" {
                            report.by_event_id.sort_by_key(|f| f.count);
                        }
                        if let Some(n) = top {
                            report.by_event_id.truncate(n);
                        }
                        if stream {
                            for f in &report.by_event_id {
                                if let Ok(line) = serde_json::to_string(f) {
                                    println!("{line}");
                                }
                            }
                        } else {
                            match serde_json::to_string_pretty(&report) {
                                Ok(json) => println!("{json}"),
                                Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                            }
                        }
                        EXIT_CLEAN
                    }
                    Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
                }
            }
        }
        Cmd::Repair { path, output } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            match winevt_carver::repair_evtx(&path, &output) {
                Ok(report) => {
                    match serde_json::to_string_pretty(&report) {
                        Ok(json) => println!("{json}"),
                        Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                    }
                    EXIT_CLEAN
                }
                Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
            }
        }
        Cmd::Pivot { query, path, stream } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            match winevt_analyze::pivot(&path, &query) {
                Ok(entries) => {
                    let has_matches = !entries.is_empty();
                    if stream {
                        for e in &entries {
                            if let Ok(line) = serde_json::to_string(e) {
                                println!("{line}");
                            }
                        }
                    } else {
                        match serde_json::to_string_pretty(&entries) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                    }
                    if has_matches { EXIT_DETECTIONS } else { EXIT_CLEAN }
                }
                Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
            }
        }
        Cmd::Diff { a, b } => {
            if !a.exists() {
                eprintln!("error: path not found: {}", a.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            if !b.exists() {
                eprintln!("error: path not found: {}", b.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            match winevt_analyze::diff(&a, &b) {
                Ok(d) => {
                    let is_different = !d.added.is_empty() || !d.removed.is_empty();
                    match serde_json::to_string_pretty(&d) {
                        Ok(json) => println!("{json}"),
                        Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                    }
                    if is_different { EXIT_DETECTIONS } else { EXIT_CLEAN }
                }
                Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
            }
        }
        Cmd::ProcessTree { path, mermaid } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            match winevt_analyze::process_tree(&path) {
                Ok(nodes) => {
                    if mermaid {
                        println!("graph LR");
                        for n in &nodes {
                            let label = sanitize_mermaid(&n.image);
                            let parent_label = format!("PID_{}", n.parent_pid);
                            let node_label = format!("PID_{}", n.pid);
                            println!("  {parent_label}[\"{label}\"] --> {node_label}");
                        }
                    } else {
                        match serde_json::to_string_pretty(&nodes) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                    }
                    EXIT_CLEAN
                }
                Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
            }
        }
        Cmd::LogonGraph { path, mermaid } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            match winevt_analyze::logon_graph(&path) {
                Ok(g) => {
                    if mermaid {
                        println!("graph LR");
                        for edge in &g.edges {
                            let src = sanitize_mermaid(&edge.source);
                            let tgt = sanitize_mermaid(&edge.target);
                            println!(
                                "  {} -->|\"Type {} x{}\"| {}",
                                src, edge.logon_type, edge.count, tgt
                            );
                        }
                    } else {
                        match serde_json::to_string_pretty(&g) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                    }
                    EXIT_CLEAN
                }
                Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
            }
        }
        Cmd::Extract { field, path, ioc } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            if ioc {
                match winevt_analyze::ioc_extract(&path) {
                    Ok(report) => {
                        let has_iocs = !report.iocs.is_empty();
                        match serde_json::to_string_pretty(&report) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                        if has_iocs { EXIT_DETECTIONS } else { EXIT_CLEAN }
                    }
                    Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
                }
            } else {
                let field_name = field.as_deref().unwrap_or("");
                match winevt_analyze::extract_field(&path, field_name) {
                    Ok(values) => {
                        match serde_json::to_string_pretty(&values) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                        EXIT_CLEAN
                    }
                    Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
                }
            }
        }
        Cmd::Info { path } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            // Compose frequency, integrity, and IOC data into one overview object.
            let freq = winevt_analyze::frequency(&path);
            let indicators = winevt_carver::verify_integrity(&path).unwrap_or_default();
            let ioc_report = winevt_analyze::ioc_extract(&path);

            let file_name = path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string());

            let (total_events, top_event_ids, first_ts, last_ts) = match freq {
                Ok(report) => {
                    let top: Vec<serde_json::Value> = report.by_event_id.iter()
                        .take(5)
                        .map(|f| serde_json::json!({ "event_id": f.event_id, "count": f.count }))
                        .collect();
                    // Derive time range from timeline (best-effort; skip on error).
                    let (first, last) = match winevt_analyze::timeline(&path) {
                        Ok(entries) => {
                            let first = entries.iter().map(|e| e.timestamp.as_str()).min().map(str::to_owned);
                            let last  = entries.iter().map(|e| e.timestamp.as_str()).max().map(str::to_owned);
                            (first, last)
                        }
                        Err(_) => (None, None),
                    };
                    (report.total_events, top, first, last)
                }
                Err(_) => (0, vec![], None, None),
            };

            let ioc_count = ioc_report.map(|r| r.iocs.len()).unwrap_or(0);

            let out = serde_json::json!({
                "file": file_name,
                "total_events": total_events,
                "time_range": { "first": first_ts, "last": last_ts },
                "top_event_ids": top_event_ids,
                "integrity_indicators": indicators.len(),
                "ioc_count": ioc_count,
            });
            match serde_json::to_string_pretty(&out) {
                Ok(json) => println!("{json}"),
                Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
            }
            EXIT_CLEAN
        }
        Cmd::Report { path, carved, output, hayabusa_bin, min_level, format } => {
            match report::run(
                &path,
                carved,
                output.as_deref(),
                hayabusa_bin.as_deref(),
                Some(min_level.as_str()),
            ) {
                Ok(out) => {
                    if format == "md" {
                        print!("{}", report::to_markdown(&out));
                    } else {
                        match serde_json::to_string_pretty(&out) {
                            Ok(json) => println!("{json}"),
                            Err(e) => {
                                eprintln!("error: {e}");
                                std::process::exit(EXIT_ERROR);
                            }
                        }
                    }
                    EXIT_CLEAN
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    EXIT_ERROR
                }
            }
        }
    };
    std::process::exit(code);
}
