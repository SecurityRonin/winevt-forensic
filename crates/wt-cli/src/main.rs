//! `wt` — EVTX forensic analysis CLI.
//!
//! Subcommands:
//! - `wt carve <path>`  — carve EVTX records from file, output JSON
//! - `wt verify <path>` — verify EVTX integrity, output JSON indicators

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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Carve { path } => {
            let result = winevt_carver::carve_from_file(&path)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Cmd::Verify { path } => {
            let indicators = winevt_carver::verify_integrity(&path)?;
            println!("{}", serde_json::to_string_pretty(&indicators)?);
        }
    }
    Ok(())
}
