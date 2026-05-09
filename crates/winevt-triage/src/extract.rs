//! EVTX extraction from E01 via ewf + ntfs crates.

use std::io::{Read, Seek, Write};
use std::path::Path;

use crate::{ExtractedEvtx, TriageError, TriageReport, partition::PartitionReader};

const SECTOR_SIZE: u64 = 512;
const EVTX_LOGS_PATH: &[&str] = &["Windows", "System32", "winevt", "Logs"];

pub(crate) fn run(e01_path: &Path, out_dir: &Path) -> Result<TriageReport, TriageError> {
    // 1. Read MBR (sector 0) to find NTFS partition.
    let mut sector0 = [0u8; 512];
    let ntfs_offset_sectors = {
        let mut mbr_reader =
            ewf::EwfReader::open(e01_path).map_err(|e| TriageError::Ewf(e.to_string()))?;
        mbr_reader.read_exact(&mut sector0)?;
        crate::mbr::parse_ntfs_offset(&sector0).ok_or(TriageError::NoNtfsPartition)?
    };

    // 2. Open E01 for NTFS traversal — EwfReader implements Read + Seek.
    let reader =
        ewf::EwfReader::open(e01_path).map_err(|e| TriageError::Ewf(e.to_string()))?;

    // 3. Wrap reader so the ntfs crate sees the NTFS volume at position 0.
    let mut part = PartitionReader::new(reader, ntfs_offset_sectors * SECTOR_SIZE)?;

    // 4. Mount NTFS.
    let mut ntfs = ntfs::Ntfs::new(&mut part).map_err(|e| TriageError::Ntfs(e.to_string()))?;
    ntfs.read_upcase_table(&mut part)
        .map_err(|e| TriageError::Ntfs(e.to_string()))?;

    // 5. Navigate to Windows/System32/winevt/Logs.
    let logs_record = navigate_to_logs(&ntfs, &mut part)?;

    // 6. List *.evtx files and extract each.
    let evtx_files = extract_evtx_files(&ntfs, &mut part, logs_record, out_dir)?;

    if evtx_files.is_empty() {
        return Err(TriageError::NoEvtxFiles);
    }

    Ok(TriageReport {
        image: e01_path.to_path_buf(),
        ntfs_offset_sectors,
        evtx_files,
    })
}

/// Navigate from root to `Windows/System32/winevt/Logs`.
/// Returns the MFT record number of the Logs directory.
fn navigate_to_logs<T>(ntfs: &ntfs::Ntfs, fs: &mut T) -> Result<u64, TriageError>
where
    T: Read + Seek,
{
    let root = ntfs
        .root_directory(fs)
        .map_err(|e| TriageError::Ntfs(e.to_string()))?;
    let mut record_number = root.file_record_number();

    for &component in EVTX_LOGS_PATH {
        record_number = find_subdir(ntfs, fs, record_number, component)?;
    }
    Ok(record_number)
}

/// Return the MFT record number of `name` inside the directory at `dir_record`.
/// Case-insensitive match against the Win32 filename namespace.
fn find_subdir<T>(
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    dir_record: u64,
    name: &str,
) -> Result<u64, TriageError>
where
    T: Read + Seek,
{
    // Open the directory, collect record numbers inside a scope so all borrows drop.
    let dir = ntfs
        .file(fs, dir_record)
        .map_err(|e| TriageError::Ntfs(e.to_string()))?;
    let index = dir
        .directory_index(fs)
        .map_err(|e| TriageError::Ntfs(e.to_string()))?;
    let mut iter = index.entries();

    while let Some(entry) = iter.next(fs) {
        let entry = entry.map_err(|e| TriageError::Ntfs(e.to_string()))?;
        let Some(Ok(fname)) = entry.key() else { continue };
        let Ok(fname_str) = fname.name().to_string() else { continue };
        if fname_str.eq_ignore_ascii_case(name) {
            let file = entry
                .to_file(ntfs, fs)
                .map_err(|e| TriageError::Ntfs(e.to_string()))?;
            return Ok(file.file_record_number());
        }
    }
    Err(TriageError::DirNotFound(name.to_string()))
}

/// Iterate the Logs directory; collect (record_number, name) for *.evtx,
/// then open each by record number and stream to `out_dir`.
fn extract_evtx_files<T>(
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    logs_record: u64,
    out_dir: &Path,
) -> Result<Vec<ExtractedEvtx>, TriageError>
where
    T: Read + Seek,
{
    // Phase 1: collect (record, name) without holding iterators alive.
    let evtx_entries: Vec<(u64, String)> = {
        let dir = ntfs
            .file(fs, logs_record)
            .map_err(|e| TriageError::Ntfs(e.to_string()))?;
        let index = dir
            .directory_index(fs)
            .map_err(|e| TriageError::Ntfs(e.to_string()))?;
        let mut iter = index.entries();
        let mut entries = Vec::new();

        while let Some(entry) = iter.next(fs) {
            let entry = entry.map_err(|e| TriageError::Ntfs(e.to_string()))?;
            let Some(Ok(fname)) = entry.key() else { continue };
            let Ok(name) = fname.name().to_string() else { continue };
            if name.to_ascii_lowercase().ends_with(".evtx") {
                let file = entry
                    .to_file(ntfs, fs)
                    .map_err(|e| TriageError::Ntfs(e.to_string()))?;
                entries.push((file.file_record_number(), name));
            }
        }
        entries
    };

    // Phase 2: open each by record number and write to out_dir.
    let mut extracted = Vec::new();
    for (record, name) in evtx_entries {
        let file = ntfs
            .file(fs, record)
            .map_err(|e| TriageError::Ntfs(e.to_string()))?;
        let out_path = out_dir.join(&name);
        let size = stream_file_data(fs, &file, &out_path)?;
        extracted.push(ExtractedEvtx { name, path: out_path, size });
    }
    Ok(extracted)
}

/// Stream the default `$DATA` attribute of `file` into `out_path`.
/// Returns the number of bytes written.
fn stream_file_data<T>(
    fs: &mut T,
    file: &ntfs::NtfsFile<'_>,
    out_path: &Path,
) -> Result<u64, TriageError>
where
    T: Read + Seek,
{
    use ntfs::NtfsReadSeek as _;

    let data_item = file
        .data(fs, "")
        .ok_or_else(|| TriageError::Ntfs("no $DATA attribute".into()))?
        .map_err(|e| TriageError::Ntfs(e.to_string()))?;

    let data_attr = data_item
        .to_attribute()
        .map_err(|e| TriageError::Ntfs(e.to_string()))?;

    let mut data_value = data_attr
        .value(fs)
        .map_err(|e| TriageError::Ntfs(e.to_string()))?;

    let mut out = std::fs::File::create(out_path)?;
    let mut buf = vec![0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = data_value
            .read(fs, &mut buf)
            .map_err(|e| TriageError::Ntfs(e.to_string()))?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
        total += u64::try_from(n).unwrap_or(u64::MAX);
    }
    Ok(total)
}
