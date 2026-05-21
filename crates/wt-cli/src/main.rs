//! `wt` — EVTX forensic analysis CLI.
//!
//! Subcommands:
//! - `wt carve <path>`        — carve EVTX records from raw blob (disk image, memory dump), output JSON
//! - `wt verify <path…>`      — verify EVTX integrity, output JSON indicators
//! - `wt timeline <path…>`    — all events in chronological order
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

/// Output format for `wt extract`.
#[derive(clap::ValueEnum, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Csv,
}

/// Minimum anomaly severity filter for `wt verify --min-severity`.
///
/// Maps to broad severity bands (info < warning < error < critical).
#[derive(clap::ValueEnum, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SeverityFilter {
    Info,
    Warning,
    Error,
    Critical,
}

impl SeverityFilter {
    /// Classify an [`IntegrityAnomaly`] into a [`SeverityFilter`] band.
    fn from_anomaly(a: &winevt_carver::IntegrityAnomaly) -> Self {
        use winevt_carver::IntegrityAnomaly as A;
        match a {
            A::SurgicalRecordDeletion { .. }
            | A::RecordIdGap { .. }
            | A::TimestampAnomaly { .. } => Self::Critical,

            A::FileFull
            | A::ChunkCountMismatch { .. }
            | A::InvalidChunkDataLength(_)
            | A::ChunkChecksumMismatch { .. }
            | A::RecordChecksumMismatch { .. }
            | A::NextRecordIdInconsistency { .. }
            | A::FileHeaderChecksumMismatch { .. }
            | A::FileNotCleanlyShutdown
            | A::TruncatedFile { .. }
            | A::OverlappingChunks { .. }
            | A::LogFileGuidMismatch { .. }
            | A::TrailingData { .. } => Self::Warning,

            A::ExportTimestampCorruption { .. }
            | A::ChecksumMismatch
            | A::EmptyLog
            | A::LogCleared { .. } => Self::Info,

            A::PhantomRecordInjection { .. } => Self::Error,
        }
    }
}

mod report;

/// EVTX forensic analysis tool.
///
/// Every command accepts one or more EVTX files, directories of EVTX files,
/// E01/EWF images, or raw blobs.  The input type is auto-detected:
///
///   file.evtx    → parse directly
///   image.E01    → NTFS extraction, then parse each *.evtx found
///   rawblob.dd   → carve for ElfChnk magic, parse recovered records
///   directory/   → walk recursively and parse all *.evtx files found
///
/// Add `--carve` to additionally scan unallocated space / free-space chunks.
#[derive(Parser)]
#[command(name = "wt", about = "EVTX forensic analysis tool", version)]
struct Cli {
    /// Also carve unallocated/free-space data for deleted EVTX records.
    /// For EVTX files: scan free space in each chunk.
    /// For E01 images: carve the full raw image after NTFS extraction.
    #[arg(long, global = true)]
    carve: bool,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify the integrity of one or more EVTX files and report tampering indicators.
    ///
    /// Checks chunk header checksums, record ID continuity, timestamp
    /// monotonicity, and file header consistency.
    Verify {
        /// Path(s) to EVTX files or directories (recursive).
        #[arg(num_args = 1..)]
        paths: Vec<PathBuf>,
        /// Emit one JSON object per line (NDJSON) instead of a JSON array.
        #[arg(long)]
        stream: bool,
        /// Only report anomalies at or above this severity (info|warning|error|critical).
        #[arg(long, value_enum)]
        min_severity: Option<SeverityFilter>,
    },
    /// Output all events in chronological order as a JSON array.
    ///
    /// Each entry contains `record_id`, timestamp, `event_id`, level, channel,
    /// computer, and provider.  Requires an intact or reconstructed EVTX file.
    Timeline {
        /// Path(s) to EVTX files or directories (recursive).
        #[arg(num_args = 1..)]
        paths: Vec<PathBuf>,
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
        /// Path(s) to the Security EVTX file(s) or directories (recursive).
        #[arg(num_args = 1..)]
        paths: Vec<PathBuf>,
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
    /// `--by process`  : JSON array of rare process images (those seen < `--threshold` times).
    /// `--anomaly`     : JSON array of event IDs with |z_score| >= `--min-z` (default 2.0).
    ///
    /// To reorder or cap output, pipe: `wt frequency … | jq '.by_event_id | sort_by(.count) | reverse'`
    Frequency {
        /// Path(s) to EVTX files or directories (recursive).
        #[arg(num_args = 1..)]
        paths: Vec<PathBuf>,
        /// Emit one JSON object per line (NDJSON) — one EventFrequency per line.
        #[arg(long)]
        stream: bool,
        /// Surface process images from EID 4688 sorted LFO (rare first).
        /// Use `| head -n N` to cap results.
        #[arg(long)]
        process: bool,
        /// Score event IDs by z-score and return those with |z| >= `--min-z`.
        #[arg(long)]
        anomaly: bool,
        /// Minimum absolute z-score threshold when `--anomaly` is active (default 2.0).
        #[arg(long, default_value_t = 2.0)]
        min_z: f64,
    },
    /// Fix bad EVTX checksums and write the repaired file.
    ///
    /// Recomputes per-chunk header CRC32 and records-area CRC32.
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
        /// Path(s) to EVTX files or directories (recursive).
        #[arg(num_args = 1..)]
        paths: Vec<PathBuf>,
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
        /// Path(s) to EVTX files or directories (Security or Sysmon).
        #[arg(num_args = 1..)]
        paths: Vec<PathBuf>,
        /// Emit a Mermaid `graph LR` diagram instead of JSON.
        #[arg(long)]
        mermaid: bool,
    },
    /// Extract unique field values, IOCs, PowerShell blocks, WMI events,
    /// scheduled tasks, process command lines, lateral movement indicators,
    /// RDP sessions, SMB share access, or Defender detections from events.
    ///
    /// Modes (mutually exclusive):
    ///   `wt extract <PATH…> <FIELD>`              — unique field values as `{value, count}` array
    ///   `wt extract --ioc <PATH…>`               — IOC scan; exits 1 if IOCs found
    ///   `wt extract --powershell <PATH…>`        — reassemble EID 4104 script blocks
    ///   `wt extract --wmi <PATH…>`               — WMI provider/subscription events (EID 5857-5861)
    ///   `wt extract --scheduled-task <PATH…>`    — scheduled task XML (EID 4698/4702)
    ///   `wt extract --cmdline <PATH…>`           — process command lines with LOLBin tagging (EID 4688)
    ///   `wt extract --lateral <PATH…>`           — lateral movement indicators (EID 4648/4769/4776)
    ///   `wt extract --rdp <PATH…>`               — RDP session events (EID 4778/4779)
    ///   `wt extract --smb <PATH…>`               — SMB share access events (EID 5140/5145)
    ///   `wt extract --defender <PATH…>`          — Windows Defender detections (EID 1116/1117/1006)
    Extract {
        /// Path(s) to EVTX files or directories (always required).
        #[arg(num_args = 1..)]
        paths: Vec<PathBuf>,
        /// Field name to extract unique values for (e.g. `SubjectUserName`).
        /// Required unless a mode flag is given.
        #[arg(long, required_unless_present_any = &["ioc", "powershell", "wmi", "scheduled_task", "cmdline", "lateral", "rdp", "smb", "defender"])]
        field: Option<String>,
        /// Extract indicators of compromise instead of a named field.
        #[arg(long, conflicts_with_all = &["powershell", "wmi", "scheduled_task", "cmdline", "lateral", "rdp", "smb", "defender"])]
        ioc: bool,
        /// Reassemble PowerShell EID 4104 script blocks instead of a named field.
        #[arg(long, conflicts_with_all = &["ioc", "wmi", "scheduled_task", "cmdline", "lateral", "rdp", "smb", "defender"])]
        powershell: bool,
        /// With `--powershell`: suppress base64 `-EncodedCommand` decoding.
        #[arg(long, requires = "powershell")]
        no_deobfuscate: bool,
        /// Extract WMI provider/subscription events (EID 5857/5858/5860/5861).
        #[arg(long, conflicts_with_all = &["ioc", "powershell", "scheduled_task", "cmdline", "lateral", "rdp", "smb", "defender"])]
        wmi: bool,
        /// Extract scheduled task XML from EID 4698 (created) and EID 4702 (updated).
        #[arg(long, conflicts_with_all = &["ioc", "powershell", "wmi", "cmdline", "lateral", "rdp", "smb", "defender"])]
        scheduled_task: bool,
        /// Extract EID 4688 process command lines with LOLBin (wscript, mshta, …) tagging.
        #[arg(long, conflicts_with_all = &["ioc", "powershell", "wmi", "scheduled_task", "lateral", "rdp", "smb", "defender"])]
        cmdline: bool,
        /// Extract lateral movement indicators (EID 4648/4769/4776).
        #[arg(long, conflicts_with_all = &["ioc", "powershell", "wmi", "scheduled_task", "cmdline", "rdp", "smb", "defender"])]
        lateral: bool,
        /// Extract RDP session events (EID 4778/4779).
        #[arg(long, conflicts_with_all = &["ioc", "powershell", "wmi", "scheduled_task", "cmdline", "lateral", "smb", "defender"])]
        rdp: bool,
        /// Extract SMB share access events (EID 5140/5145).
        #[arg(long, conflicts_with_all = &["ioc", "powershell", "wmi", "scheduled_task", "cmdline", "lateral", "rdp", "defender"])]
        smb: bool,
        /// Extract Windows Defender detections (EID 1116/1117/1006).
        #[arg(long, conflicts_with_all = &["ioc", "powershell", "wmi", "scheduled_task", "cmdline", "lateral", "rdp", "smb"])]
        defender: bool,
        /// Output format: json (default) or csv.
        #[arg(long, value_enum, default_value = "json")]
        format: OutputFormat,
        /// Emit one JSON object per line (NDJSON) instead of a JSON array.
        #[arg(long)]
        stream: bool,
    },
    /// Extract all supported semantic event types and emit a timestamp-sorted
    /// unified event list.
    ///
    /// Each event object includes a `"kind"` discriminant field:
    /// `LateralMovement`, `RdpSession`, `SmbAccess`, `Defender`, `Wmi`,
    /// `ScheduledTask`, or `ProcessExecution`.
    #[command(name = "extract-all")]
    ExtractAll {
        /// Path(s) to EVTX files or directories (recursive).
        #[arg(num_args = 1..)]
        paths: Vec<PathBuf>,
        /// Emit one JSON object per line (NDJSON) instead of a JSON array.
        #[arg(long)]
        stream: bool,
    },
    /// One-line forensic overview of an EVTX file.
    ///
    /// Outputs a JSON object with `file`, `total_events`, `time_range` (first/last),
    /// `top_event_ids` (up to 5 most frequent), `integrity_indicators` (count),
    /// and `ioc_count`. Ideal for the first look at an unknown file.
    Info {
        /// Path(s) to EVTX files or directories (recursive).
        #[arg(num_args = 1..)]
        paths: Vec<PathBuf>,
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
        /// Minimum Hayabusa alert level to include (default: `low`).
        #[arg(long, default_value = "low")]
        min_level: String,
        /// Output format: `json` (default) or `md` (Markdown).
        #[arg(long, default_value = "json")]
        format: String,
    },
}

/// Resolve a single input path to a list of EVTX file paths.
///
/// - `.evtx` file → `vec![path]`
/// - E01/EWF image → pass through (handled inline by callers)
/// - Directory → walk recursively for all `*.evtx` files
/// - Any other blob → carve for `ElfChnk` magic and write recovered records
///
/// When `_carve` is true, the caller additionally wants unallocated-space
/// carving; that is handled per-command (stub for now).
fn resolve_evtx_sources(path: &std::path::Path, _carve: bool) -> Vec<PathBuf> {
    if !path.exists() {
        return vec![];
    }
    if path.is_dir() {
        let mut files: Vec<PathBuf> = walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(|p| {
                p.extension()
                    .map(|x| x.eq_ignore_ascii_case("evtx"))
                    .unwrap_or(false)
            })
            .collect();
        files.sort();
        return files;
    }
    if let Some(ext) = path.extension() {
        if ext.eq_ignore_ascii_case("evtx") {
            return vec![path.to_path_buf()];
        }
    }
    // E01/EWF: delegate to existing carver
    if is_ewf_path(path) {
        return vec![path.to_path_buf()]; // ewf handled inline in callers via is_ewf_path
    }
    // Unknown blob: carve for ElfChnk magic and write recovered records to a temp EVTX
    match winevt_carver::carve_from_file(path) {
        Ok(result) => {
            use winevt_writer::{records_to_evtx, WriteRecord};
            let wrecords: Vec<WriteRecord> = result.chunks.iter()
                .flat_map(|c| c.records.iter())
                .map(|r| WriteRecord {
                    record_id: r.header.record_id,
                    timestamp: r.header.timestamp,
                    payload: r.bxml_payload.clone(),
                })
                .collect();
            if wrecords.is_empty() {
                return vec![];
            }
            let bytes = records_to_evtx(&wrecords);
            let tmp = std::env::temp_dir().join(format!(
                "wt_carved_{}.evtx",
                path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
            ));
            if std::fs::write(&tmp, &bytes).is_ok() {
                return vec![tmp];
            }
            vec![]
        }
        Err(_) => vec![],
    }
}

/// Resolve multiple input paths to a deduplicated, sorted list of EVTX sources.
fn resolve_sources_multi(paths: &[PathBuf], carve: bool) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for path in paths {
        for src in resolve_evtx_sources(path, carve) {
            if seen.insert(src.clone()) {
                result.push(src);
            }
        }
    }
    result.sort();
    result
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
    let _carve = cli.carve;
    let code = match cli.command {
        Cmd::Verify { paths, stream, min_severity } => {
            for p in &paths {
                if !p.exists() {
                    eprintln!("error: path not found: {}", p.display());
                    std::process::exit(EXIT_NOT_FOUND);
                }
            }
            let sources = resolve_sources_multi(&paths, _carve);
            if sources.is_empty() {
                println!("[]");
                std::process::exit(EXIT_CLEAN);
            }
            let mut all_indicators = Vec::new();
            for src in &sources {
                match winevt_carver::verify_integrity(src) {
                    Ok(mut indicators) => {
                        if let Some(min) = min_severity {
                            indicators.retain(|a| SeverityFilter::from_anomaly(a) >= min);
                        }
                        all_indicators.extend(indicators);
                    }
                    Err(e) => { eprintln!("warning: {}: {e}", src.display()); }
                }
            }
            if stream {
                for a in &all_indicators {
                    if let Ok(line) = serde_json::to_string(a) { println!("{line}"); }
                }
            } else {
                match serde_json::to_string_pretty(&all_indicators) {
                    Ok(json) => println!("{json}"),
                    Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                }
            }
            if all_indicators.is_empty() { EXIT_CLEAN } else { EXIT_DETECTIONS }
        }
        Cmd::Timeline { paths, stream, filter_eid, limit, after, before } => {
            for p in &paths {
                if !p.exists() {
                    eprintln!("error: path not found: {}", p.display());
                    std::process::exit(EXIT_NOT_FOUND);
                }
            }
            let sources = resolve_sources_multi(&paths, _carve);
            if sources.is_empty() {
                println!("[]");
                std::process::exit(EXIT_CLEAN);
            }
            let mut all_entries: Vec<winevt_extract::TimelineEntry> = Vec::new();
            for src in &sources {
                if let Ok(mut entries) = winevt_extract::timeline(src) {
                    all_entries.append(&mut entries);
                }
            }
            all_entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
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
                    if let Ok(line) = serde_json::to_string(e) { println!("{line}"); }
                }
            } else {
                match serde_json::to_string_pretty(&filtered) {
                    Ok(json) => println!("{json}"),
                    Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                }
            }
            EXIT_CLEAN
        }
        Cmd::Login { paths, stream, logon_type, graph, mermaid } => {
            for p in &paths {
                if !p.exists() {
                    eprintln!("error: path not found: {}", p.display());
                    std::process::exit(EXIT_NOT_FOUND);
                }
            }
            let sources = resolve_sources_multi(&paths, _carve);
            let source_refs: Vec<&std::path::Path> = sources.iter().map(|p| p.as_path()).collect();
            if mermaid || graph {
                match winevt_extract::logon_graph_multi(&source_refs) {
                    Ok(g) => {
                        if mermaid {
                            println!("graph LR");
                            for edge in &g.edges {
                                let src = sanitize_mermaid(&edge.source);
                                let dst = sanitize_mermaid(&edge.target);
                                println!("  {src} -->|{}| {dst}", edge.logon_type);
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
                match winevt_extract::sessions_multi(&source_refs) {
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
        Cmd::Frequency { paths, stream, process, anomaly, min_z } => {
            for p in &paths {
                if !p.exists() {
                    eprintln!("error: path not found: {}", p.display());
                    std::process::exit(EXIT_NOT_FOUND);
                }
            }
            let sources = resolve_sources_multi(&paths, _carve);
            if sources.is_empty() {
                std::process::exit(EXIT_CLEAN);
            }
            if process {
                let mut all_procs: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    if let Ok(procs) = winevt_extract::rare_processes(src, usize::MAX) {
                        for p in procs {
                            if let Ok(v) = serde_json::to_value(p) { all_procs.push(v); }
                        }
                    }
                }
                match serde_json::to_string_pretty(&all_procs) {
                    Ok(json) => println!("{json}"),
                    Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                }
                EXIT_CLEAN
            } else if anomaly {
                let mut all_anomalies: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    if let Ok(entries) = winevt_extract::anomaly(src, min_z) {
                        for e in entries {
                            if let Ok(v) = serde_json::to_value(e) { all_anomalies.push(v); }
                        }
                    }
                }
                let has_anomalies = !all_anomalies.is_empty();
                match serde_json::to_string_pretty(&all_anomalies) {
                    Ok(json) => println!("{json}"),
                    Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                }
                if has_anomalies { EXIT_DETECTIONS } else { EXIT_CLEAN }
            } else {
                // Merge frequency counts across all sources, then emit as one report.
                let mut total_events: usize = 0;
                let mut by_id: std::collections::HashMap<u32, usize> =
                    std::collections::HashMap::new();
                for src in &sources {
                    if let Ok(report) = winevt_extract::frequency(src) {
                        total_events += report.total_events;
                        for f in report.by_event_id {
                            *by_id.entry(f.event_id).or_insert(0) += f.count;
                        }
                    }
                }
                // LFO: least-frequent-first for threat hunting
                let mut by_event_id: Vec<(u32, usize)> = by_id.into_iter().collect();
                by_event_id.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
                if stream {
                    for (eid, cnt) in &by_event_id {
                        if let Ok(line) = serde_json::to_string(
                            &serde_json::json!({"event_id": eid, "count": cnt})
                        ) { println!("{line}"); }
                    }
                } else {
                    let out = serde_json::json!({
                        "total_events": total_events,
                        "by_event_id": by_event_id.iter()
                            .map(|(eid, cnt)| serde_json::json!({"event_id": eid, "count": cnt}))
                            .collect::<Vec<_>>()
                    });
                    match serde_json::to_string_pretty(&out) {
                        Ok(json) => println!("{json}"),
                        Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                    }
                }
                EXIT_CLEAN
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
        Cmd::Search { query, paths, regex, stream } => {
            for p in &paths {
                if !p.exists() {
                    eprintln!("error: path not found: {}", p.display());
                    std::process::exit(EXIT_NOT_FOUND);
                }
            }
            let sources = resolve_sources_multi(&paths, _carve);
            let mut all_entries: Vec<serde_json::Value> = Vec::new();
            for src in &sources {
                if let Ok(entries) = winevt_extract::search(src, &query, regex) {
                    for e in entries {
                        if let Ok(v) = serde_json::to_value(e) { all_entries.push(v); }
                    }
                }
            }
            let has_matches = !all_entries.is_empty();
            if stream {
                for e in &all_entries {
                    if let Ok(line) = serde_json::to_string(e) { println!("{line}"); }
                }
            } else {
                match serde_json::to_string_pretty(&all_entries) {
                    Ok(json) => println!("{json}"),
                    Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                }
            }
            if has_matches { EXIT_DETECTIONS } else { EXIT_CLEAN }
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
            match winevt_extract::diff(&a, &b) {
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
        Cmd::ProcessTree { paths, mermaid } => {
            for p in &paths {
                if !p.exists() {
                    eprintln!("error: path not found: {}", p.display());
                    std::process::exit(EXIT_NOT_FOUND);
                }
            }
            let sources = resolve_sources_multi(&paths, _carve);
            let mut all_nodes: Vec<serde_json::Value> = Vec::new();
            for src in &sources {
                if let Ok(nodes) = winevt_extract::process_tree(src) {
                    for n in nodes {
                        if let Ok(v) = serde_json::to_value(n) { all_nodes.push(v); }
                    }
                }
            }
            if mermaid {
                println!("graph LR");
                for n in &all_nodes {
                    let image = n.get("image").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let parent_pid = n.get("parent_pid").and_then(|v| v.as_u64()).unwrap_or(0);
                    let pid = n.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                    let label = sanitize_mermaid(image);
                    let parent_label = format!("PID_{parent_pid}");
                    let node_label = format!("PID_{pid}");
                    println!("  {parent_label}[\"{label}\"] --> {node_label}");
                }
            } else {
                match serde_json::to_string_pretty(&all_nodes) {
                    Ok(json) => println!("{json}"),
                    Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                }
            }
            EXIT_CLEAN
        }
        Cmd::Extract { field, paths, ioc, powershell, no_deobfuscate, wmi, scheduled_task, cmdline, lateral, rdp, smb, defender, format, stream } => {
            // Emit a serializable slice as JSON (array or NDJSON).
            fn emit_json<T: serde::Serialize>(items: &[T], ndjson: bool) {
                if ndjson {
                    for item in items {
                        if let Ok(line) = serde_json::to_string(item) {
                            println!("{line}");
                        }
                    }
                } else {
                    match serde_json::to_string_pretty(items) {
                        Ok(json) => println!("{json}"),
                        Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                    }
                }
            }

            // Emit a serializable slice as CSV (header from field names).
            fn emit_csv<T: serde::Serialize>(items: &[T]) {
                let mut wtr = csv::Writer::from_writer(std::io::stdout());
                for item in items {
                    if let Err(e) = wtr.serialize(item) {
                        eprintln!("error: {e}");
                        std::process::exit(EXIT_ERROR);
                    }
                }
                if let Err(e) = wtr.flush() {
                    eprintln!("error: {e}");
                    std::process::exit(EXIT_ERROR);
                }
            }

            for p in &paths {
                if !p.exists() {
                    eprintln!("error: path not found: {}", p.display());
                    std::process::exit(EXIT_NOT_FOUND);
                }
            }
            let sources = resolve_sources_multi(&paths, _carve);
            if sources.is_empty() {
                println!("[]");
                std::process::exit(EXIT_CLEAN);
            }

            if ioc {
                let mut has_iocs = false;
                let mut all_reports: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    match winevt_extract::ioc_extract(src) {
                        Ok(report) => {
                            has_iocs = has_iocs || !report.iocs.is_empty();
                            if let Ok(v) = serde_json::to_value(&report) {
                                all_reports.push(v);
                            }
                        }
                        Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                    }
                }
                // Single source: preserve original single-object format for back-compat.
                if all_reports.len() == 1 {
                    match serde_json::to_string_pretty(&all_reports[0]) {
                        Ok(json) => println!("{json}"),
                        Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                    }
                } else {
                    match serde_json::to_string_pretty(&all_reports) {
                        Ok(json) => println!("{json}"),
                        Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                    }
                }
                if has_iocs { EXIT_DETECTIONS } else { EXIT_CLEAN }
            } else if powershell {
                let mut all_blocks: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    if let Ok(blocks) = winevt_extract::powershell_blocks(src) {
                        for b in &blocks {
                            let mut v = serde_json::to_value(b).unwrap_or(serde_json::Value::Null);
                            if !no_deobfuscate {
                                if let Some(decoded) = winevt_extract::deobfuscate_ps(&b.text) {
                                    if let Some(obj) = v.as_object_mut() {
                                        obj.insert(
                                            "decoded_command".to_string(),
                                            serde_json::Value::String(decoded),
                                        );
                                    }
                                }
                            }
                            all_blocks.push(v);
                        }
                    }
                }
                emit_json(&all_blocks, stream);
                EXIT_CLEAN
            } else if wmi {
                let mut all_events: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    if let Ok(events) = winevt_extract::wmi_events(src) {
                        for e in events {
                            if let Ok(v) = serde_json::to_value(e) { all_events.push(v); }
                        }
                    }
                }
                emit_json(&all_events, stream);
                EXIT_CLEAN
            } else if scheduled_task {
                let mut all_tasks: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    if let Ok(tasks) = winevt_extract::scheduled_tasks(src) {
                        for t in tasks {
                            if let Ok(v) = serde_json::to_value(t) { all_tasks.push(v); }
                        }
                    }
                }
                if format == OutputFormat::Csv { emit_csv(&all_tasks); } else { emit_json(&all_tasks, stream); }
                EXIT_CLEAN
            } else if cmdline {
                let mut all_execs: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    if let Ok(execs) = winevt_extract::process_cmdlines(src) {
                        for e in execs {
                            if let Ok(v) = serde_json::to_value(e) { all_execs.push(v); }
                        }
                    }
                }
                if format == OutputFormat::Csv { emit_csv(&all_execs); } else { emit_json(&all_execs, stream); }
                EXIT_CLEAN
            } else if lateral {
                let mut all_events: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    if let Ok(events) = winevt_extract::lateral_movement(src) {
                        for e in events {
                            if let Ok(v) = serde_json::to_value(e) { all_events.push(v); }
                        }
                    }
                }
                if format == OutputFormat::Csv { emit_csv(&all_events); } else { emit_json(&all_events, stream); }
                EXIT_CLEAN
            } else if rdp {
                let mut all_events: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    if let Ok(events) = winevt_extract::rdp_sessions(src) {
                        for e in events {
                            if let Ok(v) = serde_json::to_value(e) { all_events.push(v); }
                        }
                    }
                }
                if format == OutputFormat::Csv { emit_csv(&all_events); } else { emit_json(&all_events, stream); }
                EXIT_CLEAN
            } else if smb {
                let mut all_events: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    if let Ok(events) = winevt_extract::smb_access(src) {
                        for e in events {
                            if let Ok(v) = serde_json::to_value(e) { all_events.push(v); }
                        }
                    }
                }
                if format == OutputFormat::Csv { emit_csv(&all_events); } else { emit_json(&all_events, stream); }
                EXIT_CLEAN
            } else if defender {
                let mut all_events: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    if let Ok(events) = winevt_extract::defender_events(src) {
                        for e in events {
                            if let Ok(v) = serde_json::to_value(e) { all_events.push(v); }
                        }
                    }
                }
                if format == OutputFormat::Csv { emit_csv(&all_events); } else { emit_json(&all_events, stream); }
                EXIT_CLEAN
            } else {
                let field_name = field.as_deref().unwrap_or("");
                let mut all_values: Vec<serde_json::Value> = Vec::new();
                for src in &sources {
                    if let Ok(values) = winevt_extract::extract_field(src, field_name) {
                        for v in values {
                            if let Ok(jv) = serde_json::to_value(v) { all_values.push(jv); }
                        }
                    }
                }
                if format == OutputFormat::Csv { emit_csv(&all_values); } else { emit_json(&all_values, stream); }
                EXIT_CLEAN
            }
        }
        Cmd::ExtractAll { paths, stream } => {
            for p in &paths {
                if !p.exists() {
                    eprintln!("error: path not found: {}", p.display());
                    std::process::exit(EXIT_NOT_FOUND);
                }
            }
            let sources = resolve_sources_multi(&paths, _carve);
            let mut all_events: Vec<serde_json::Value> = Vec::new();
            for src in &sources {
                if let Ok(events) = winevt_extract::extract_all(src) {
                    for ev in events {
                        if let Ok(v) = serde_json::to_value(ev) { all_events.push(v); }
                    }
                }
            }
            if stream {
                for ev in &all_events {
                    println!("{}", serde_json::to_string(ev).unwrap_or_default());
                }
            } else {
                match serde_json::to_string_pretty(&all_events) {
                    Ok(json) => println!("{json}"),
                    Err(e) => { eprintln!("error: {e}"); std::process::exit(EXIT_ERROR); }
                }
            }
            EXIT_CLEAN
        }
        Cmd::Info { paths } => {
            for p in &paths {
                if !p.exists() {
                    eprintln!("error: path not found: {}", p.display());
                    std::process::exit(EXIT_NOT_FOUND);
                }
            }
            let sources = resolve_sources_multi(&paths, _carve);
            if sources.is_empty() {
                std::process::exit(EXIT_CLEAN);
            }
            let mut results: Vec<serde_json::Value> = Vec::new();
            for path in &sources {
                let file_name = path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string());

                // Carve for stats (hash, chunk/record counts).
                let (hash, chunks_json, records_json) = match winevt_carver::carve_from_file(path) {
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

                let freq = winevt_extract::frequency(path);
                let indicators = winevt_carver::verify_integrity(path).unwrap_or_default();
                let ioc_report = winevt_extract::ioc_extract(path);

                let (total_events, top_event_ids, first_ts, last_ts) = match freq {
                    Ok(report) => {
                        let top: Vec<serde_json::Value> = report.by_event_id.iter()
                            .take(5)
                            .map(|f| serde_json::json!({ "event_id": f.event_id, "count": f.count }))
                            .collect();
                        let (first, last) = match winevt_extract::timeline(path) {
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

                results.push(serde_json::json!({
                    "file": file_name,
                    "hash": hash,
                    "chunks": chunks_json,
                    "records": records_json,
                    "total_events": total_events,
                    "time_range": { "first": first_ts, "last": last_ts },
                    "top_event_ids": top_event_ids,
                    "integrity_indicators": indicators.len(),
                    "ioc_count": ioc_count,
                }));
            }
            // Single source: preserve original single-object format for back-compat.
            let out = if results.len() == 1 {
                results.remove(0)
            } else {
                serde_json::Value::Array(results)
            };
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
