//! Implementation of `wt report` — one-click triage pipeline.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use winevt_carver::{verify_integrity, CarveResult};

// ── Output types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ReportInput {
    pub path: PathBuf,
    pub kind: InputKind,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub enum InputKind {
    E01,
    Evtx,
    Directory,
    RawBlob,
}

#[derive(Debug, Serialize)]
pub struct EvtxEntry {
    pub name: String,
    pub path: PathBuf,
    pub source: EvtxSource,
    pub size: u64,
    pub integrity_indicators: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EvtxSource {
    Filesystem,
    Carved,
}

#[derive(Debug, Serialize)]
pub struct HayabusaResult {
    pub binary: PathBuf,
    pub output_file: PathBuf,
    pub exit_code: i32,
}

#[derive(Debug, Serialize)]
pub struct TriageOutput {
    pub input: ReportInput,
    pub evtx_files: Vec<EvtxEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hayabusa: Option<HayabusaResult>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run(
    path: &Path,
    carved: bool,
    output_dir: Option<&Path>,
    hayabusa_bin: Option<&Path>,
    min_level: Option<&str>,
) -> Result<TriageOutput, String> {
    if !path.exists() {
        return Err(format!("path not found: {}", path.display()));
    }

    let kind = detect_kind(path);
    let work_dir = resolve_work_dir(output_dir);
    std::fs::create_dir_all(&work_dir).map_err(|e| e.to_string())?;

    let evtx_dir = work_dir.join("evtx");
    std::fs::create_dir_all(&evtx_dir).map_err(|e| e.to_string())?;

    let mut evtx_files = match &kind {
        InputKind::E01 => extract_from_e01(path, &evtx_dir, carved)?,
        InputKind::Evtx => passthrough_evtx(path, &evtx_dir)?,
        InputKind::Directory => collect_evtx_from_dir(path, &evtx_dir)?,
        InputKind::RawBlob => carve_blob(path, &evtx_dir)?,
    };

    // Attach integrity indicators to each extracted EVTX.
    for entry in &mut evtx_files {
        entry.integrity_indicators = integrity_for(&entry.path);
    }

    // Optionally run Hayabusa.
    let hayabusa = try_run_hayabusa(hayabusa_bin, &evtx_dir, &work_dir, min_level);

    Ok(TriageOutput {
        input: ReportInput {
            path: path.to_path_buf(),
            kind,
        },
        evtx_files,
        hayabusa,
    })
}

// ── Input-type detection ──────────────────────────────────────────────────────

fn detect_kind(path: &Path) -> InputKind {
    if path.is_dir() {
        return InputKind::Directory;
    }
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("e01" | "ex01") => InputKind::E01,
        Some("evtx") => InputKind::Evtx,
        _ => InputKind::RawBlob,
    }
}

// ── Extraction strategies ─────────────────────────────────────────────────────

fn extract_from_e01(
    e01: &Path,
    evtx_dir: &Path,
    also_carve: bool,
) -> Result<Vec<EvtxEntry>, String> {
    // Filesystem extraction via winevt-triage (NTFS traversal).
    let report = winevt_triage::extract_evtx_from_e01(e01, evtx_dir).map_err(|e| e.to_string())?;

    let mut entries: Vec<EvtxEntry> = report
        .evtx_files
        .into_iter()
        .map(|f| EvtxEntry {
            size: f.size,
            name: f.name,
            path: f.path,
            source: EvtxSource::Filesystem,
            integrity_indicators: vec![],
        })
        .collect();

    // Optional: carve each extracted EVTX for ghost/deleted records within it.
    // (Full raw-image carving of a multi-GB E01 requires a streaming carver —
    // future work.  Carving the extracted files surfaces DanderSpritz ghost
    // records and intra-file deleted chunks at negligible cost.)
    if also_carve {
        let fs_paths: Vec<PathBuf> = entries.iter().map(|e| e.path.clone()).collect();
        for evtx_path in &fs_paths {
            let carved = carve_blob(evtx_path, evtx_dir)?;
            entries.extend(carved);
        }
    }

    Ok(entries)
}

fn passthrough_evtx(evtx: &Path, evtx_dir: &Path) -> Result<Vec<EvtxEntry>, String> {
    let name = evtx.file_name().map_or_else(
        || "unknown.evtx".into(),
        |n| n.to_string_lossy().into_owned(),
    );
    let dest = evtx_dir.join(&name);
    std::fs::copy(evtx, &dest).map_err(|e| e.to_string())?;
    let size = dest.metadata().map(|m| m.len()).unwrap_or(0);
    Ok(vec![EvtxEntry {
        name,
        path: dest,
        source: EvtxSource::Filesystem,
        size,
        integrity_indicators: vec![],
    }])
}

fn collect_evtx_from_dir(dir: &Path, evtx_dir: &Path) -> Result<Vec<EvtxEntry>, String> {
    let mut entries = Vec::new();
    for entry in walkdir(dir)? {
        let dest = evtx_dir.join(entry.file_name().unwrap_or(entry.as_os_str()));
        std::fs::copy(&entry, &dest).map_err(|e| e.to_string())?;
        let size = dest.metadata().map(|m| m.len()).unwrap_or(0);
        entries.push(EvtxEntry {
            name: entry
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            path: dest,
            source: EvtxSource::Filesystem,
            size,
            integrity_indicators: vec![],
        });
    }
    Ok(entries)
}

fn carve_blob(blob: &Path, evtx_dir: &Path) -> Result<Vec<EvtxEntry>, String> {
    let result = winevt_carver::carve_from_file(blob).map_err(|e| e.to_string())?;
    carved_chunks_to_evtx(&result, evtx_dir, &EvtxSource::Carved)
}

/// Write each chunk from a `CarveResult` as a reconstructed EVTX file.
fn carved_chunks_to_evtx(
    result: &CarveResult,
    evtx_dir: &Path,
    source: &EvtxSource,
) -> Result<Vec<EvtxEntry>, String> {
    use winevt_writer::{records_to_evtx, WriteRecord};

    let mut entries = Vec::new();
    for (i, chunk) in result.chunks.iter().enumerate() {
        if chunk.records.is_empty() {
            continue;
        }
        let records: Vec<WriteRecord> = chunk
            .records
            .iter()
            .map(|r| WriteRecord {
                record_id: r.header.record_id,
                timestamp: r.header.timestamp,
                payload: r.bxml_payload.clone(),
            })
            .collect();
        let bytes = records_to_evtx(&records);
        let name = format!("carved_chunk_{i:04}.evtx");
        let dest = evtx_dir.join(&name);
        std::fs::write(&dest, &bytes).map_err(|e| e.to_string())?;
        let size = bytes.len() as u64;
        entries.push(EvtxEntry {
            name,
            path: dest,
            source: EvtxSource::Carved,
            size,
            integrity_indicators: vec![],
        });
    }
    // Keep source field consistent — only carved entries here.
    let _ = source;
    Ok(entries)
}

// ── Integrity ─────────────────────────────────────────────────────────────────

fn integrity_for(evtx: &Path) -> Vec<String> {
    match verify_integrity(evtx) {
        Ok(indicators) => indicators.iter().map(|i| format!("{i:?}")).collect(),
        Err(_) => vec![],
    }
}

// ── Hayabusa ──────────────────────────────────────────────────────────────────

fn try_run_hayabusa(
    bin_override: Option<&Path>,
    evtx_dir: &Path,
    work_dir: &Path,
    min_level: Option<&str>,
) -> Option<HayabusaResult> {
    let bin = bin_override.map(PathBuf::from).or_else(which_hayabusa)?;

    let out_file = work_dir.join("hayabusa_timeline.jsonl");
    let level = min_level.unwrap_or("informational");

    // Silence hayabusa's stdout/stderr — results go to -o file only.
    // Without this, ANSI progress output mixes with our JSON on stdout.
    let status = Command::new(&bin)
        .args([
            "json-timeline",
            "-d",
            evtx_dir.to_str()?,
            "-o",
            out_file.to_str()?,
            "--no-wizard",
            "--quiet",
            "-m",
            level,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;

    Some(HayabusaResult {
        binary: bin,
        output_file: out_file,
        exit_code: status.code().unwrap_or(-1),
    })
}

fn which_hayabusa() -> Option<PathBuf> {
    let out = Command::new("which").arg("hayabusa").output().ok()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !s.is_empty() {
            return Some(PathBuf::from(s));
        }
    }
    None
}

// ── Markdown renderer ─────────────────────────────────────────────────────────

pub fn to_markdown(out: &TriageOutput) -> String {
    use std::fmt::Write as _;

    let mut md = String::new();
    md.push_str("# Triage Report\n\n");

    md.push_str("## Input\n\n");
    let _ = writeln!(md, "- **Path**: `{}`", out.input.path.display());
    let _ = writeln!(md, "- **Kind**: `{:?}`\n", out.input.kind);

    md.push_str("## EVTX Files\n\n");
    if out.evtx_files.is_empty() {
        md.push_str("_No EVTX files found._\n\n");
    } else {
        md.push_str("| File | Source | Size | Indicators |\n");
        md.push_str("|------|--------|------|------------|\n");
        for f in &out.evtx_files {
            let indicators = if f.integrity_indicators.is_empty() {
                "none".to_owned()
            } else {
                f.integrity_indicators.join(", ")
            };
            let _ = writeln!(
                md,
                "| `{}` | {:?} | {} | {} |",
                f.name, f.source, f.size, indicators
            );
        }
        md.push('\n');
    }

    if let Some(h) = &out.hayabusa {
        md.push_str("## Hayabusa\n\n");
        let _ = writeln!(md, "- **Binary**: `{}`", h.binary.display());
        let _ = writeln!(md, "- **Output**: `{}`", h.output_file.display());
        let _ = writeln!(md, "- **Exit code**: {}\n", h.exit_code);
    }

    md
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn resolve_work_dir(requested: Option<&Path>) -> PathBuf {
    if let Some(p) = requested {
        p.to_path_buf()
    } else {
        // Use a stable temp path so the user can find the files.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        std::env::temp_dir().join(format!("wt_report_{ts}"))
    }
}

/// Recursively collect `*.evtx` paths from `dir`.
fn walkdir(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut result = Vec::new();
    let rd = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
    for entry in rd {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            result.extend(walkdir(&path)?);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
        {
            result.push(path);
        }
    }
    Ok(result)
}
