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
    /// Carve EVTX records from a raw blob, EVTX file, or E01/EWF image.
    ///
    /// E01/EWF images are auto-detected by file extension (`.e01`, `.ex01`)
    /// or by EWF magic bytes. All other inputs are scanned for `ElfChnk` magic.
    ///
    /// Outputs a `CarveResult` as JSON.
    ///
    /// Example: `wt carve /evidence/hdd001.dd`
    Carve {
        /// Path to the raw blob, EVTX file, or E01 image.
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
    /// Analyse logon activity from EID 4624 / 4634 / 4647 / 4648 events.
    ///
    /// Default: JSON array of reconstructed sessions (logon_id, username, domain,
    /// logon_type, ip_address, logon_time, logoff_time, duration_secs).
    ///
    /// `--graph`: JSON object `{nodes, edges}` — source→target logon graph.
    /// `--mermaid`: Mermaid `graph LR` diagram (implies --graph output).
    Login {
        /// Path to the Security EVTX file.
        path: PathBuf,
        /// Emit one JSON object per line (NDJSON, sessions mode only).
        #[arg(long)]
        stream: bool,
        /// Filter sessions by logon type (e.g. 3 = Network, 10 = RemoteInteractive).
        #[arg(long, value_name = "TYPE")]
        logon_type: Option<u32>,
        /// Output the logon source→target graph instead of the session list.
        #[arg(long)]
        graph: bool,
        /// Output a Mermaid `graph LR` diagram (implies --graph).
        #[arg(long)]
        mermaid: bool,
    },
    /// Compute event ID frequency distribution, rare-process analysis, or z-score anomaly detection.
    ///
    /// Default (no flags): JSON object with `total_events` and `by_event_id` array,
    /// sorted ascending (LFO — least-frequent-first) for threat hunting.
    /// `--sort desc`   : flip to most-frequent-first.
    /// `--by process`  : JSON array of rare process images (those seen < `--threshold` times).
    /// `--anomaly`     : JSON array of event IDs with |z_score| >= `--min-z` (default 2.0).
    ///
    /// To cap output use Unix `| head -n N`.
    Frequency {
        /// Path to the EVTX file.
        path: PathBuf,
        /// Sort order: `asc` (LFO, default) or `desc` (most-frequent-first).
        #[arg(long, default_value = "asc")]
        sort: String,
        /// Emit one JSON object per line (NDJSON) — one EventFrequency per line.
        #[arg(long)]
        stream: bool,
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
    /// Search all event string values for a substring or regex pattern.
    ///
    /// Without `--regex`: case-insensitive substring match (fast).
    /// With `--regex`: query is compiled as a regular expression.
    ///
    /// Exits 1 if matches are found, 0 if none.
    Search {
        /// Search query (substring or regex pattern).
        query: String,
        /// Path to the EVTX file.
        path: PathBuf,
        /// Treat query as a regular expression.
        #[arg(long)]
        regex: bool,
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
    /// Extract unique field values, IOCs, PowerShell blocks, WMI events,
    /// scheduled tasks, or process command lines from events.
    ///
    /// Modes (mutually exclusive):
    ///   `wt extract <PATH> <FIELD>`              — unique field values as `{value, count}` array
    ///   `wt extract --ioc <PATH>`               — IOC scan; exits 1 if IOCs found
    ///   `wt extract --powershell <PATH>`        — reassemble EID 4104 script blocks
    ///   `wt extract --wmi <PATH>`               — WMI provider/subscription events (EID 5857-5861)
    ///   `wt extract --scheduled-task <PATH>`    — scheduled task XML (EID 4698/4702)
    ///   `wt extract --cmdline <PATH>`           — process command lines with LOLBin tagging (EID 4688)
    Extract {
        /// Path to the EVTX file (always required).
        path: PathBuf,
        /// Field name to search for in event data (e.g. `SubjectUserName`).
        /// Required unless a mode flag is given.
        #[arg(required_unless_present_any = &["ioc", "powershell", "wmi", "scheduled_task", "cmdline"])]
        field: Option<String>,
        /// Extract indicators of compromise instead of a named field.
        #[arg(long, conflicts_with_all = &["powershell", "wmi", "scheduled_task", "cmdline"])]
        ioc: bool,
        /// Reassemble PowerShell EID 4104 script blocks instead of a named field.
        #[arg(long, conflicts_with_all = &["ioc", "wmi", "scheduled_task", "cmdline"])]
        powershell: bool,
        /// With `--powershell`: suppress base64 `-EncodedCommand` decoding.
        #[arg(long, requires = "powershell")]
        no_deobfuscate: bool,
        /// Extract WMI provider/subscription events (EID 5857/5858/5860/5861).
        #[arg(long, conflicts_with_all = &["ioc", "powershell", "scheduled_task", "cmdline"])]
        wmi: bool,
        /// Extract scheduled task XML from EID 4698 (created) and EID 4702 (updated).
        #[arg(long, conflicts_with_all = &["ioc", "powershell", "wmi", "cmdline"])]
        scheduled_task: bool,
        /// Extract EID 4688 process command lines with LOLBin (wscript, mshta, …) tagging.
        #[arg(long, conflicts_with_all = &["ioc", "powershell", "wmi", "scheduled_task"])]
        cmdline: bool,
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

/// Detect E01/EWF images by extension or magic bytes.
fn is_ewf_path(path: &std::path::Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext = ext.to_ascii_lowercase();
        if ext == "e01" || ext == "ex01" || ext == "ewf" {
            return true;
        }
    }
    // EWF magic: EVF\x09\x0d\x0a\xff\x00
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut magic = [0u8; 8];
        if f.read_exact(&mut magic).is_ok() {
            return magic == [0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00];
        }
    }
    false
}

#[allow(clippy::too_many_lines)]
fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Cmd::Carve { path } => {
            let result = if is_ewf_path(&path) {
                winevt_carver::carve_from_ewf(&path)
            } else {
                winevt_carver::carve_from_file(&path)
            };
            match result {
                Ok(result) => {
                    match serde_json::to_string_pretty(&result) {
                        Ok(json) => println!("{json}"),
                        Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                    }
                    EXIT_CLEAN
                }
                Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
            }
        }
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
        Cmd::Login { path, stream, logon_type, graph, mermaid } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            if mermaid || graph {
                match winevt_analyze::logon_graph(&path) {
                    Ok(g) => {
                        if mermaid {
                            println!("graph LR");
                            for edge in &g.edges {
                                let src = sanitize_mermaid(&edge.source);
                                let tgt = sanitize_mermaid(&edge.target);
                                println!("  {} -->|\"Type {} x{}\"| {}", src, edge.logon_type, edge.count, tgt);
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
            } else {
                match winevt_analyze::sessions(&path) {
                    Ok(all_sessions) => {
                        let filtered: Vec<_> = all_sessions
                            .into_iter()
                            .filter(|s| logon_type.map_or(true, |lt| s.logon_type == lt))
                            .collect();
                        if stream {
                            for s in &filtered {
                                if let Ok(line) = serde_json::to_string(s) { println!("{line}"); }
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
        }
        Cmd::Frequency { path, sort, stream, by, threshold, anomaly, min_z } => {
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
                        if sort == "desc" {
                            report.by_event_id.sort_by(|a, b| b.count.cmp(&a.count).then(a.event_id.cmp(&b.event_id)));
                        } else {
                            report.by_event_id.sort_by(|a, b| a.count.cmp(&b.count).then(a.event_id.cmp(&b.event_id)));
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
        Cmd::Search { query, path, regex, stream } => {
            if !path.exists() {
                eprintln!("error: path not found: {}", path.display());
                std::process::exit(EXIT_NOT_FOUND);
            }
            match winevt_analyze::search(&path, &query, regex) {
                Ok(entries) => {
                    let has_matches = !entries.is_empty();
                    if stream {
                        for e in &entries {
                            if let Ok(line) = serde_json::to_string(e) { println!("{line}"); }
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
        Cmd::Extract { field, path, ioc, powershell, no_deobfuscate, wmi, scheduled_task, cmdline } => {
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
            } else if powershell {
                match winevt_analyze::powershell_blocks(&path) {
                    Ok(blocks) => {
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
                        match serde_json::to_string_pretty(&enriched) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                        EXIT_CLEAN
                    }
                    Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
                }
            } else if wmi {
                match winevt_analyze::wmi_events(&path) {
                    Ok(events) => {
                        match serde_json::to_string_pretty(&events) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                        EXIT_CLEAN
                    }
                    Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
                }
            } else if scheduled_task {
                match winevt_analyze::scheduled_tasks(&path) {
                    Ok(tasks) => {
                        match serde_json::to_string_pretty(&tasks) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                        EXIT_CLEAN
                    }
                    Err(e) => { eprintln!("error: {e}"); EXIT_ERROR }
                }
            } else if cmdline {
                match winevt_analyze::process_cmdlines(&path) {
                    Ok(execs) => {
                        match serde_json::to_string_pretty(&execs) {
                            Ok(json) => println!("{json}"),
                            Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                        }
                        EXIT_CLEAN
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
            let file_name = path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string());

            // Carve for stats (hash, chunk/record counts).
            let (hash, chunks_json, records_json) = match winevt_carver::carve_from_file(&path) {
                Ok(r) => {
                    let h = r.source_hash.unwrap_or_else(|| "N/A".to_string());
                    let c = serde_json::json!({
                        "total": r.stats.chunks_found,
                        "valid": r.stats.chunks_valid,
                        "corrupt": r.stats.chunks_corrupt,
                    });
                    let rec = serde_json::json!({
                        "recovered": r.stats.records_recovered,
                        "corrupt": r.stats.records_corrupt,
                    });
                    (h, c, rec)
                }
                Err(_) => ("N/A".to_string(), serde_json::json!(null), serde_json::json!(null)),
            };

            let freq = winevt_analyze::frequency(&path);
            let indicators = winevt_carver::verify_integrity(&path).unwrap_or_default();
            let ioc_report = winevt_analyze::ioc_extract(&path);

            let (total_events, top_event_ids, first_ts, last_ts) = match freq {
                Ok(report) => {
                    let top: Vec<serde_json::Value> = report.by_event_id.iter()
                        .take(5)
                        .map(|f| serde_json::json!({ "event_id": f.event_id, "count": f.count }))
                        .collect();
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
                "hash": hash,
                "chunks": chunks_json,
                "records": records_json,
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
