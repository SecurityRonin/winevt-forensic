//! `wt` — EVTX forensic analysis CLI.
//!
//! Subcommands:
//! - `wt carve <path>`        — carve EVTX records from file, output JSON
//! - `wt verify <path>`       — verify EVTX integrity, output JSON indicators
//! - `wt stats [--json] <path>` — print file statistics
//!
//! Exit codes:
//! - `0` = success, no integrity indicators
//! - `1` = success, integrity indicators found (verify only)
//! - `2` = I/O or argument error

use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    /// Carve EVTX records from a file, including corrupt or cleared files.
    ///
    /// Scans for `ElfChnk` magic, recovers records from each chunk,
    /// and runs integrity checks. Outputs a `CarveResult` as JSON.
    Carve {
        /// Path to the EVTX file (or raw disk image slice).
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
    let file_name = path
        .file_name()
        .map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned());
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
        println!("Chunks:     {chunks_total} total ({chunks_valid} valid, {chunks_corrupt} corrupt)");
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
        Cmd::Verify { path } => match winevt_carver::verify_integrity(&path) {
            Ok(indicators) => {
                match serde_json::to_string_pretty(&indicators) {
                    Ok(json) => println!("{json}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(2);
                    }
                }
                i32::from(!indicators.is_empty())
            }
            Err(e) => {
                eprintln!("error: {e}");
                2
            }
        },
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
    };
    std::process::exit(code);
}
