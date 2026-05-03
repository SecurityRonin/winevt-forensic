//! `wt-evtx` — Windows Event Log forensic CLI.
//!
//! Subcommands:
//! - `timeline`  — hayabusa-compatible event timeline
//! - `sessions`  — correlate 4624→4634 logon sessions (our differentiator)
//! - `processes` — 4688 process creation events with optional session linking
//! - `frequency` — rare command-line frequency analysis

mod format;
mod parse;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::io::{self, Write};
use std::path::PathBuf;
use winevt_analyze::{frequency_analysis, FrequencyKey};
use winevt_session::{correlate_sessions, extract_process_events, link_processes_to_sessions};

// ── CLI model ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "wt-evtx",
    version,
    about = "Windows Event Log forensic analysis tool",
    long_about = "wt-evtx provides hayabusa-compatible event timelines plus session \
                  correlation and frequency analysis that hayabusa cannot do."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a chronological event timeline from EVTX files.
    Timeline(TimelineArgs),
    /// Correlate logon sessions (4624->4634) and show session table.
    Sessions(SessionsArgs),
    /// Show process creation events (4688) with optional session linking.
    Processes(ProcessesArgs),
    /// Frequency analysis — surface rare command lines / process images.
    Frequency(FrequencyArgs),
}

#[derive(clap::Args)]
struct TimelineArgs {
    /// Directory containing EVTX files (searched recursively).
    #[arg(short, long)]
    directory: PathBuf,

    /// Output file path (default: stdout).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output format.
    #[arg(short, long, default_value = "csv")]
    format: OutputFormat,
}

#[derive(clap::Args)]
struct SessionsArgs {
    /// Directory containing EVTX files (searched recursively).
    #[arg(short, long)]
    directory: PathBuf,

    /// Output format.
    #[arg(short, long, default_value = "text")]
    format: TextOrCsv,
}

#[derive(clap::Args)]
struct ProcessesArgs {
    /// Directory containing EVTX files (searched recursively).
    #[arg(short, long)]
    directory: PathBuf,

    /// Link process events to correlated logon sessions.
    #[arg(long)]
    link_sessions: bool,

    /// Output format.
    #[arg(short, long, default_value = "text")]
    format: TextOrCsv,
}

#[derive(clap::Args)]
struct FrequencyArgs {
    /// Directory containing EVTX files (searched recursively).
    #[arg(short, long)]
    directory: PathBuf,

    /// Maximum occurrence count to flag as anomaly (Events Ripper cap).
    #[arg(long, default_value = "5")]
    cap: usize,

    /// Output format.
    #[arg(short, long, default_value = "text")]
    format: TextOrCsv,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Csv,
    Jsonl,
    Text,
}

#[derive(Clone, ValueEnum)]
enum TextOrCsv {
    Csv,
    Text,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    match cli.command {
        Commands::Timeline(args) => cmd_timeline(&args, &mut out),
        Commands::Sessions(args) => cmd_sessions(&args, &mut out),
        Commands::Processes(args) => cmd_processes(&args, &mut out),
        Commands::Frequency(args) => cmd_frequency(&args, &mut out),
    }
}

// ── timeline ──────────────────────────────────────────────────────────────────

fn cmd_timeline(args: &TimelineArgs, out: &mut impl Write) -> Result<()> {
    let events = parse::parse_directory(&args.directory)?;

    match args.format {
        OutputFormat::Csv => {
            writeln!(out, "{}", format::TIMELINE_CSV_HEADER)?;
            for ev in &events {
                writeln!(out, "{}", format::event_to_csv_row(ev))?;
            }
        }
        OutputFormat::Jsonl => {
            for ev in &events {
                writeln!(out, "{}", format::event_to_jsonl(ev))?;
            }
        }
        OutputFormat::Text => {
            for ev in &events {
                writeln!(out, "{}", format::event_to_text(ev))?;
            }
        }
    }

    Ok(())
}

// ── sessions ──────────────────────────────────────────────────────────────────

fn cmd_sessions(args: &SessionsArgs, out: &mut impl Write) -> Result<()> {
    let events = parse::parse_directory(&args.directory)?;
    let sessions = correlate_sessions(&events);

    let mut sorted: Vec<_> = sessions.values().collect();
    sorted.sort_by_key(|s| s.logon_time_ns);

    match args.format {
        TextOrCsv::Csv => {
            writeln!(out, "{}", format::SESSIONS_CSV_HEADER)?;
            for s in sorted {
                writeln!(out, "{}", format::session_to_csv_row(s))?;
            }
        }
        TextOrCsv::Text => {
            for s in sorted {
                writeln!(out, "{}", format::session_to_text(s))?;
            }
        }
    }

    Ok(())
}

// ── processes ─────────────────────────────────────────────────────────────────

fn cmd_processes(args: &ProcessesArgs, out: &mut impl Write) -> Result<()> {
    let events = parse::parse_directory(&args.directory)?;
    let mut process_events = extract_process_events(&events);
    process_events.sort_by_key(|p| p.timestamp_ns);

    if args.link_sessions {
        let mut sessions = correlate_sessions(&events);
        link_processes_to_sessions(&mut sessions, &process_events);
    }

    match args.format {
        TextOrCsv::Csv => {
            writeln!(out, "{}", format::PROCESSES_CSV_HEADER)?;
            for p in &process_events {
                writeln!(out, "{}", format::process_to_csv_row(p))?;
            }
        }
        TextOrCsv::Text => {
            for p in &process_events {
                writeln!(out, "{}", format::process_to_text(p))?;
            }
        }
    }

    Ok(())
}

// ── frequency ─────────────────────────────────────────────────────────────────

fn cmd_frequency(args: &FrequencyArgs, out: &mut impl Write) -> Result<()> {
    let events = parse::parse_directory(&args.directory)?;
    let mut anomalies = frequency_analysis(&events, FrequencyKey::CommandLine, args.cap);
    // Sort by count ascending (rarest first)
    anomalies.sort_by_key(|a| a.count);

    match args.format {
        TextOrCsv::Csv => {
            writeln!(out, "{}", format::FREQUENCY_CSV_HEADER)?;
            for a in &anomalies {
                writeln!(out, "{}", format::anomaly_to_csv_row(a.count, &a.key))?;
            }
        }
        TextOrCsv::Text => {
            for a in &anomalies {
                writeln!(out, "{}", format::anomaly_to_text(a.count, &a.key))?;
            }
        }
    }

    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use winevt_core::EvtxEvent;

    /// Unit test 11: constructing EvtxEvent from empty HashMap works.
    #[test]
    fn parse_evtx_event_from_record_data_empty_map() {
        let event = EvtxEvent {
            event_id: 4624,
            channel: "Security".into(),
            timestamp_ns: 0,
            computer: "test-host".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data: HashMap::new(),
        };
        assert_eq!(event.event_id, 4624);
        assert_eq!(event.channel, "Security");
        assert!(event.data.is_empty());
    }

    /// Unit test 12: format_timestamp_ns converts nanoseconds to ISO 8601.
    #[test]
    fn format_timestamp_ns_to_rfc3339() {
        // 1_700_000_000_000_000_000 ns = 2023-11-14T22:13:20Z
        let ns: i64 = 1_700_000_000_000_000_000;
        let result = crate::format::format_timestamp_ns(ns);
        assert!(
            result.starts_with("2023-11-14T22:13:20"),
            "got: {result}"
        );
    }
}
