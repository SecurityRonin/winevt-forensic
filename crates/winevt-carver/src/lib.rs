#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::path::Path;

mod carver;
pub use carver::{EvtxChunkCarver, EVTX_CHUNK_CARVER};

fn compute_sha256(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in hash {
        // Writing to a String is infallible; the Result only satisfies fmt::Write.
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[derive(Debug, thiserror::Error)]
pub enum CarveError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("file too small: {size} bytes")]
    FileTooSmall { size: u64 },
    #[error("EWF error: {0}")]
    EwfError(String),
}

pub use winevt_core::binary::{
    EvtxChunkHeader, EvtxFileHeader, EvtxRecordHeader, IntegrityAnomaly, CHUNK_RECORDS_OFFSET,
    CHUNK_SIZE, ELFCHNK_MAGIC, ELFFILE_MAGIC, RECORD_MAGIC,
};
use winevt_integrity::{
    check_chunk_count, check_file_flags, check_file_header_consistency,
    detect_danderspritz_deletion, detect_export_timestamp_corruption, detect_record_id_gaps,
    verify_chunk_header_checksum, verify_file_header_checksum, verify_records_area_checksum,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Integrity {
    Valid,
    HeaderCorrupt,
    RecordCorrupt,
    SizeMismatch,
    Carved,
    Truncated,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RecoveredRecord {
    pub offset: u64,
    pub header: EvtxRecordHeader,
    pub integrity: Integrity,
    pub bxml_payload: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CarvedChunk {
    pub offset: u64,
    pub header: EvtxChunkHeader,
    pub integrity: Integrity,
    pub records: Vec<RecoveredRecord>,
    pub indicators: Vec<IntegrityAnomaly>,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct CarveStats {
    pub bytes_scanned: u64,
    pub chunks_found: usize,
    pub chunks_valid: usize,
    pub chunks_corrupt: usize,
    pub records_recovered: usize,
    pub records_corrupt: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct CarveResult {
    pub file_header: Option<EvtxFileHeader>,
    pub chunks: Vec<CarvedChunk>,
    pub indicators: Vec<IntegrityAnomaly>,
    pub stats: CarveStats,
    pub source_hash: Option<String>,
}

/// Configuration for carving.
#[derive(Debug, Clone, Default)]
pub struct CarveConfig {
    /// Added to all reported chunk/record offsets. Use when carving a slice
    /// from a larger image so that offsets are absolute within the image.
    pub offset_base: u64,
}

/// Like [`carve_from_bytes`] but with explicit configuration.
pub fn carve_from_bytes_with_config(data: &[u8], config: &CarveConfig) -> CarveResult {
    let mut result = carve_from_bytes_inner(data, config.offset_base);
    result.source_hash = None;
    result
}

/// Process a single full chunk at a given offset. Returns the carved chunk or None.
fn process_full_chunk(data: &[u8], offset: usize) -> Option<CarvedChunk> {
    let chunk_end = offset + CHUNK_SIZE as usize;
    let chunk_data = &data[offset..chunk_end];
    let header = EvtxChunkHeader::parse(chunk_data)?;

    let mut chunk_indicators = verify_chunk_header_checksum(chunk_data, offset as u64);
    let integrity = if chunk_indicators.is_empty() {
        Integrity::Valid
    } else {
        Integrity::HeaderCorrupt
    };

    // Feature 5: records area checksum (only for valid header chunks)
    if integrity == Integrity::Valid {
        chunk_indicators.extend(verify_records_area_checksum(chunk_data, offset as u64));
    }

    let records = if integrity == Integrity::HeaderCorrupt {
        recover_records_aggressive(chunk_data, offset as u64)
    } else {
        recover_records_from_slice(chunk_data, offset as u64, false)
    };

    Some(CarvedChunk {
        offset: offset as u64,
        header,
        integrity,
        records,
        indicators: chunk_indicators,
    })
}

fn carve_from_bytes_inner(data: &[u8], offset_base: u64) -> CarveResult {
    let mut result = CarveResult {
        file_header: None,
        chunks: Vec::new(),
        indicators: Vec::new(),
        stats: CarveStats {
            bytes_scanned: data.len() as u64,
            ..Default::default()
        },
        source_hash: None,
    };

    // Look for file header at start
    if data.len() >= 128 {
        result.file_header = EvtxFileHeader::parse(&data[0..128]);
    }

    // Pass 1: collect chunk offsets (sequential — order matters)
    let mut full_offsets: Vec<usize> = Vec::new();
    let mut truncated_chunks: Vec<CarvedChunk> = Vec::new();
    let mut i = 0usize;
    while i + 8 <= data.len() {
        if data[i..i + 8] == ELFCHNK_MAGIC {
            let chunk_end = i + CHUNK_SIZE as usize;
            if chunk_end > data.len() {
                // Truncated chunk — handle immediately (not parallelizable)
                if let Some(header) = EvtxChunkHeader::parse(&data[i..]) {
                    let records =
                        recover_records_from_slice(&data[i..], i as u64 + offset_base, true);
                    truncated_chunks.push(CarvedChunk {
                        offset: i as u64 + offset_base,
                        header,
                        integrity: Integrity::Truncated,
                        records,
                        indicators: vec![],
                    });
                }
                i += 8;
                continue;
            }
            full_offsets.push(i);
            // Skip to end of chunk
            i += CHUNK_SIZE as usize;
            continue;
        }
        i += 8;
    }

    // Pass 2: process full chunks in parallel, then sort by offset
    let mut carved: Vec<CarvedChunk> = full_offsets
        .par_iter()
        .filter_map(|&off| {
            let mut chunk = process_full_chunk(data, off)?;
            chunk.offset += offset_base;
            // Shift record offsets too
            for rec in &mut chunk.records {
                rec.offset += offset_base;
            }
            Some(chunk)
        })
        .collect();
    carved.sort_by_key(|c| c.offset);

    // Merge truncated chunks (already in offset order from sequential scan)
    let mut all_chunks: Vec<CarvedChunk> = carved;
    all_chunks.extend(truncated_chunks);
    all_chunks.sort_by_key(|c| c.offset);

    // Accumulate stats
    for chunk in &all_chunks {
        result.stats.chunks_found += 1;
        match chunk.integrity {
            Integrity::Valid => result.stats.chunks_valid += 1,
            Integrity::Truncated => {}
            _ => result.stats.chunks_corrupt += 1,
        }
        result.stats.records_recovered += chunk.records.len();
        result.stats.records_corrupt += chunk
            .records
            .iter()
            .filter(|r| r.integrity == Integrity::Carved)
            .count();
    }
    result.chunks = all_chunks;

    // Post-carve: detect record ID gaps across all chunks
    let chunk_ranges: Vec<(u64, u64)> = result
        .chunks
        .iter()
        .map(|c| {
            (
                c.header.first_event_record_number,
                c.header.last_event_record_number,
            )
        })
        .collect();
    result
        .indicators
        .extend(detect_record_id_gaps(&chunk_ranges));

    // Post-carve: check file header consistency if we have a file header
    if let Some(ref fh) = result.file_header {
        let actual_highest = result
            .chunks
            .iter()
            .map(|c| c.header.last_event_record_id)
            .max()
            .unwrap_or(0);
        result.indicators.extend(check_file_header_consistency(
            fh.next_record_id,
            actual_highest,
        ));
        // Feature 2: file header checksum
        if data.len() >= 0x80 {
            result
                .indicators
                .extend(verify_file_header_checksum(&data[0..0x80]));
        }
        // Feature 3: file flags
        result.indicators.extend(check_file_flags(fh.file_flags));
        // Feature 4: chunk count consistency
        result
            .indicators
            .extend(check_chunk_count(fh.chunk_count, result.chunks.len()));
    }

    // Post-carve: export timestamp corruption (Fox-IT 2019) and DanderSpritz deletion (Fox-IT 2017)
    {
        // Collect (record_id, chunk_offset, header_timestamp) for all recovered records.
        let all_records: Vec<(u64, u64, u64)> = result
            .chunks
            .iter()
            .flat_map(|c| {
                c.records
                    .iter()
                    .map(move |r| (r.header.record_id, c.offset, r.header.timestamp))
            })
            .collect();
        result
            .indicators
            .extend(detect_export_timestamp_corruption(&all_records));

        // For each full (non-truncated) chunk, scan raw bytes for ghost record magic.
        for chunk in &result.chunks {
            if chunk.integrity == Integrity::Truncated {
                continue;
            }
            let local_off = (chunk.offset - offset_base) as usize;
            let chunk_end = local_off + CHUNK_SIZE as usize;
            if chunk_end <= data.len() {
                result.indicators.extend(detect_danderspritz_deletion(
                    &data[local_off..chunk_end],
                    chunk.offset,
                ));
            }
        }
    }

    result
}

pub fn carve_from_bytes(data: &[u8]) -> CarveResult {
    carve_from_bytes_inner(data, 0)
}

/// Read an EVTX file from disk and carve chunks and records from it.
///
/// Uses `memmap2` for zero-copy access to the file bytes, then delegates to
/// [`carve_from_bytes`]. Sets `source_hash` to the SHA-256 of the file.
pub fn carve_from_file(path: &Path) -> Result<CarveResult, CarveError> {
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if meta.len() == 0 {
        let mut result = carve_from_bytes(&[]);
        result.source_hash = Some(compute_sha256(&[]));
        return Ok(result);
    }
    // The crate denies `unsafe_code`; this is the one allowed site, and the
    // complete audit surface is `rg 'allow\(unsafe_code\)' crates/winevt-carver`.
    //
    // BENEFIT: carving scans whole evidence files, frequently multi-gigabyte.
    // Mapping avoids reading the image into resident memory, which is the
    // difference between carving a large EVTX corpus and exhausting RAM.
    // ALTERNATIVE REJECTED: buffered reads would work but force either a full
    // read into memory or a windowing layer that re-implements what the kernel
    // already does; neither removes the dependency's own unsafe.
    // INVARIANT: the mapping is read-only and never written through, the file
    // is opened read-only above, and `mmap` is dropped before this function
    // returns, so no reference outlives the mapping. Undefined behaviour would
    // still follow if the underlying file were truncated by another process
    // while mapped -- inherent to mmap, and accepted for read-only evidence
    // that is not modified during examination.
    #[allow(unsafe_code)]
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let mut result = carve_from_bytes(&mmap);
    result.source_hash = Some(compute_sha256(&mmap));
    Ok(result)
}

/// Carve EVTX records from an E01/EWF forensic disk image.
///
/// Opens the image via `ewf::EwfReader`, reads all bytes into memory, then
/// delegates to [`carve_from_bytes`]. Sets `source_hash` to the SHA-256 of the image bytes.
pub fn carve_from_ewf(path: &Path) -> Result<CarveResult, CarveError> {
    use std::io::Read;
    let mut reader = ewf::EwfReader::open(path).map_err(|e| CarveError::EwfError(e.to_string()))?;
    let total = reader.total_size() as usize;
    let mut data = vec![0u8; total];
    reader
        .read_exact(&mut data)
        .map_err(|e| CarveError::EwfError(e.to_string()))?;
    let mut result = carve_from_bytes(&data);
    result.source_hash = Some(compute_sha256(&data));
    Ok(result)
}

/// Verify the structural integrity of an EVTX file.
///
/// Returns `Ok(Vec<IntegrityAnomaly>)` — empty for a sound file, or containing any
/// of: checksum mismatches, record ID gaps, timestamp anomalies, file-header
/// inconsistencies, export timestamp corruption (Fox-IT 2019), and surgical record
/// deletion (Fox-IT / DanderSpritz 2017).
///
/// Delegates to [`carve_from_bytes`] so every detection wired there is also
/// available here without duplication.
pub fn verify_integrity(path: &Path) -> Result<Vec<IntegrityAnomaly>, CarveError> {
    let data = std::fs::read(path)?;
    let result = carve_from_bytes(&data);
    // Collect file-level indicators plus per-chunk indicators (e.g. ChunkChecksumMismatch).
    let mut indicators: Vec<IntegrityAnomaly> = result.indicators;
    for chunk in &result.chunks {
        indicators.extend(chunk.indicators.iter().cloned());
    }
    Ok(indicators)
}

/// Report returned by [`repair_evtx`].
#[derive(Debug, serde::Serialize)]
pub struct RepairReport {
    pub chunks_checked: usize,
    pub chunks_repaired: usize,
    pub header_repaired: bool,
}

/// Recompute and fix bad checksums in an EVTX file, writing the result to `output`.
///
/// Checks and repairs:
/// - File header CRC32 (bytes 0x00–0x77, stored at 0x7C)
/// - Per-chunk records-area CRC32 (stored at chunk offset 0x34)
/// - Per-chunk header CRC32 (bytes 0x00–0x77 of chunk, stored at 0x78)
///
/// The chunk header CRC covers the records-area CRC field, so records-area is
/// recomputed first, then the header CRC is recomputed over the updated header.
pub fn repair_evtx(input: &Path, output: &Path) -> Result<RepairReport, CarveError> {
    let mut data = std::fs::read(input)?;
    let mut chunks_checked = 0usize;
    let mut chunks_repaired = 0usize;
    let mut header_repaired = false;

    // File header: CRC32 of 0x00–0x77 stored at 0x7C
    if data.len() >= 0x80 && data[0..8] == ELFFILE_MAGIC {
        let expected = crc32fast::hash(&data[0..0x78]);
        let stored = u32::from_le_bytes(data[0x7C..0x80].try_into().unwrap_or([0; 4]));
        if stored != expected {
            data[0x7C..0x80].copy_from_slice(&expected.to_le_bytes());
            header_repaired = true;
        }
    }

    // Chunks start after the 4096-byte file header
    let file_header_size: usize = 4096;
    let chunk_size = CHUNK_SIZE as usize;
    let mut offset = file_header_size;

    while offset + chunk_size <= data.len() {
        if data[offset..offset + 8] == ELFCHNK_MAGIC {
            chunks_checked += 1;
            let mut repaired = false;

            // 1. Records-area checksum: CRC32(chunk[0x200..free_off]), stored at chunk[0x34]
            //    Free space offset is at chunk[0x30..0x34] (bytes 48..52 relative to chunk start)
            if data.len() >= offset + 0x38 {
                let free_off =
                    u32::from_le_bytes(data[offset + 48..offset + 52].try_into().unwrap_or([0; 4]))
                        as usize;
                if free_off >= 0x200 && free_off <= chunk_size {
                    let records_end = offset + free_off;
                    if data.len() >= records_end {
                        let expected = crc32fast::hash(&data[offset + 0x200..records_end]);
                        let stored = u32::from_le_bytes(
                            data[offset + 52..offset + 56].try_into().unwrap_or([0; 4]),
                        );
                        if stored != expected {
                            data[offset + 52..offset + 56].copy_from_slice(&expected.to_le_bytes());
                            repaired = true;
                        }
                    }
                }
            }

            // 2. Chunk header checksum: CRC32(chunk[0x00..0x78]), stored at chunk[0x78]
            //    Recomputed after records-area fix so the header reflects current state.
            if data.len() >= offset + 0x7C {
                let expected = crc32fast::hash(&data[offset..offset + 0x78]);
                let stored = u32::from_le_bytes(
                    data[offset + 0x78..offset + 0x7C]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                if stored != expected {
                    data[offset + 0x78..offset + 0x7C].copy_from_slice(&expected.to_le_bytes());
                    repaired = true;
                }
            }

            if repaired {
                chunks_repaired += 1;
            }
        }
        offset += chunk_size;
    }

    std::fs::write(output, &data)?;
    Ok(RepairReport {
        chunks_checked,
        chunks_repaired,
        header_repaired,
    })
}

/// Confidence level for a free-space carved record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum CarveConfidence {
    /// Magic found, size plausible, and BinXML header looks valid.
    Definite,
    /// Magic found and size plausible, but BinXML content failed heuristic checks.
    Probable,
}

/// A record recovered from the free-space (slack) region of an EVTX chunk.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FreeSpaceCarvedRecord {
    /// Byte offset of the containing chunk within the source file.
    pub chunk_offset: u64,
    /// Byte offset of this record within the chunk (after `free_space_offset`).
    pub record_offset_within_chunk: u16,
    /// Raw bytes of the record (from magic to trailing size field).
    pub raw: Vec<u8>,
    /// BinXML validity confidence.
    pub confidence: CarveConfidence,
}

/// Scan the free-space region of an EVTX chunk for deleted records.
///
/// `chunk_data` must be the full 65 536-byte chunk starting at `ElfChnk` magic.
/// `chunk_offset` is the byte offset of the chunk in the source file.
///
/// The live-record area (`0x200..free_space_offset`) is skipped; only bytes
/// from `free_space_offset` onward are searched for record magic
/// (`0x2A 0x2A 0x00 0x00`).
pub fn carve_chunk_free_space(chunk_data: &[u8], chunk_offset: u64) -> Vec<FreeSpaceCarvedRecord> {
    if chunk_data.len() < 0x38 {
        return vec![];
    }
    let free_space_offset =
        u32::from_le_bytes(chunk_data[48..52].try_into().unwrap_or([0; 4])) as usize;
    let records_start = CHUNK_RECORDS_OFFSET as usize;

    // If free_space_offset is invalid or there's no free space, bail.
    if free_space_offset < records_start || free_space_offset >= chunk_data.len() {
        return vec![];
    }
    let free_space = &chunk_data[free_space_offset..];
    if free_space.is_empty() {
        return vec![];
    }

    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= free_space.len() {
        if free_space[pos..pos + 4] != RECORD_MAGIC {
            pos += 1;
            continue;
        }
        let size =
            u32::from_le_bytes(free_space[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;
        // Minimum valid record: 4 magic + 4 size + 8 id + 8 ts + 0 payload + 4 tail = 28
        if size < 28 || pos + size > free_space.len() {
            pos += 1;
            continue;
        }
        let raw = free_space[pos..pos + size].to_vec();
        // BinXML payload starts at offset 24 (after record header), ends before trailing 4-byte size
        let payload = &raw[24..raw.len().saturating_sub(4)];
        let confidence = if is_likely_valid_binxml(payload) {
            CarveConfidence::Definite
        } else {
            CarveConfidence::Probable
        };
        let record_offset_within_chunk = (free_space_offset + pos) as u16;
        out.push(FreeSpaceCarvedRecord {
            chunk_offset,
            record_offset_within_chunk,
            raw,
            confidence,
        });
        pos += size;
    }
    out
}

/// BinXml validity heuristic.
/// Returns `false` for payloads that are clearly not BinXml fragments.
fn is_likely_valid_binxml(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }
    // FragmentHeaderToken = 0x0F
    if payload[0] != 0x0F {
        return false;
    }
    // MajorVersion must be 1
    if payload[1] != 0x01 {
        return false;
    }
    // No excessive null runs (> 16 consecutive nulls in first 32 bytes)
    let check_len = payload.len().min(32);
    let null_run = payload[..check_len]
        .windows(16)
        .any(|w| w.iter().all(|&b| b == 0));
    !null_run
}

fn recover_records_from_slice(
    chunk_data: &[u8],
    _chunk_offset: u64,
    truncated: bool,
) -> Vec<RecoveredRecord> {
    let mut records = Vec::new();
    let start = CHUNK_RECORDS_OFFSET as usize;
    let end = if truncated {
        chunk_data.len()
    } else {
        CHUNK_SIZE as usize
    };
    if chunk_data.len() < start {
        return records;
    }
    let records_area = &chunk_data[start..chunk_data.len().min(end)];

    let mut pos = 0usize;
    while pos + 24 <= records_area.len() {
        if records_area[pos..pos + 4] == RECORD_MAGIC {
            if pos + 8 > records_area.len() {
                break;
            }
            let size =
                u32::from_le_bytes(records_area[pos + 4..pos + 8].try_into().unwrap_or([0; 4]))
                    as usize;
            if size < 24 || pos + size > records_area.len() {
                pos += 8;
                continue;
            }
            let Some(header) = EvtxRecordHeader::parse(&records_area[pos..]) else {
                pos += 8;
                continue;
            };
            // Check copy-of-size at record_end - 4
            let copy_size = u32::from_le_bytes(
                records_area[pos + size - 4..pos + size]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;
            let integrity = if copy_size == size {
                Integrity::Valid
            } else {
                Integrity::SizeMismatch
            };
            let payload_start = 24usize;
            let payload_end = if size > 4 { size - 4 } else { size };
            let bxml_payload = if payload_end > payload_start {
                records_area[pos + payload_start..pos + payload_end].to_vec()
            } else {
                vec![]
            };
            records.push(RecoveredRecord {
                offset: (start + pos) as u64,
                header,
                integrity,
                bxml_payload,
            });
            pos += size;
        } else {
            pos += 8;
        }
    }
    records
}

/// Aggressive scan: for `HeaderCorrupt` chunks, scan the records area at every 4-byte boundary
/// for `**\0\0` magic. Records found this way are marked `Integrity::Carved`.
/// Duplicate offsets (a record found at the same offset twice) are suppressed.
fn recover_records_aggressive(chunk_data: &[u8], _chunk_offset: u64) -> Vec<RecoveredRecord> {
    let mut records = Vec::new();
    let start = CHUNK_RECORDS_OFFSET as usize;
    let end = CHUNK_SIZE as usize;
    if chunk_data.len() < start {
        return records;
    }
    let records_area = &chunk_data[start..chunk_data.len().min(end)];

    let mut seen_offsets = std::collections::HashSet::new();
    let mut pos = 0usize;
    while pos + 24 <= records_area.len() {
        if records_area[pos..pos + 4] == RECORD_MAGIC {
            if seen_offsets.contains(&pos) {
                pos += 4;
                continue;
            }
            let size =
                u32::from_le_bytes(records_area[pos + 4..pos + 8].try_into().unwrap_or([0; 4]))
                    as usize;
            if size < 24 || pos + size > records_area.len() {
                pos += 4;
                continue;
            }
            let Some(header) = EvtxRecordHeader::parse(&records_area[pos..]) else {
                pos += 4;
                continue;
            };
            // Verify copy-of-size at record_end - 4
            let copy_size = u32::from_le_bytes(
                records_area[pos + size - 4..pos + size]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;
            // Only accept if copy-of-size matches (basic sanity)
            if copy_size != size {
                pos += 4;
                continue;
            }
            let payload_start = 24usize;
            let payload_end = if size > 4 { size - 4 } else { size };
            let bxml_payload = if payload_end > payload_start {
                records_area[pos + payload_start..pos + payload_end].to_vec()
            } else {
                vec![]
            };
            // Feature 10: BinXml validity heuristic — skip garbage records
            if !is_likely_valid_binxml(&bxml_payload) {
                pos += 4;
                continue;
            }
            seen_offsets.insert(pos);
            records.push(RecoveredRecord {
                offset: (start + pos) as u64,
                header,
                integrity: Integrity::Carved,
                bxml_payload,
            });
            pos += size;
        } else {
            pos += 4;
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Fleet `forensic-carve::Carver` contract (ADR 0001 §4) ----

    #[test]
    fn evtx_chunk_carver_recovers_orphaned_chunk_echoing_ctx_method() {
        use forensic_carve::{CarveContext, CarvedPayload, Carver, RecoveryMethod};

        let off = 0x4000u64;
        let chunk = make_chunk_with_one_record();

        // An unallocated sweep: method must be ECHOED from ctx, never hardcoded.
        let ctx = CarveContext::at(off).with_method(RecoveryMethod::UnallocatedCarve);
        let items = EvtxChunkCarver.carve(&chunk, &ctx);
        assert!(
            !items.is_empty(),
            "expected >=1 carved item for a valid chunk"
        );
        assert_eq!(items[0].format(), "evtx-chunk");
        assert_eq!(items[0].recovery_method(), RecoveryMethod::UnallocatedCarve);
        assert_eq!(
            items[0].image_offset(),
            off,
            "image_offset echoes ctx.base_offset()"
        );
        assert_eq!(*items[0].payload(), CarvedPayload::Records);

        // Same carver over a memory sweep must echo MemoryCarve (proves no hardcode).
        let mem_ctx = CarveContext::at(off).with_method(RecoveryMethod::MemoryCarve);
        let mem_items = EvtxChunkCarver.carve(&chunk, &mem_ctx);
        assert_eq!(mem_items[0].recovery_method(), RecoveryMethod::MemoryCarve);

        // A window with no valid ElfChnk chunk yields nothing.
        let empty = EvtxChunkCarver.carve(&[0u8; 0x10000], &ctx);
        assert!(empty.is_empty(), "no ElfChnk magic => no carved items");
    }

    #[test]
    fn evtx_chunk_carver_contract_metadata() {
        use forensic_carve::Carver;
        assert_eq!(EvtxChunkCarver.format(), "evtx-chunk");
        assert_eq!(EvtxChunkCarver.max_window(), CHUNK_SIZE);
        let sigs = EvtxChunkCarver.signatures();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].magic(), b"ElfChnk\x00");
        assert_eq!(sigs[0].offset(), 0);
    }

    fn make_minimal_chunk() -> Vec<u8> {
        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[8..16].copy_from_slice(&1u64.to_le_bytes()); // first record number
        chunk[16..24].copy_from_slice(&1u64.to_le_bytes()); // last record number
        chunk[24..32].copy_from_slice(&1u64.to_le_bytes()); // first record id
        chunk[32..40].copy_from_slice(&1u64.to_le_bytes()); // last record id
        chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes()); // header_size
        chunk[44..48].copy_from_slice(&0x200u32.to_le_bytes()); // last_event_record_data_offset
        chunk[48..52].copy_from_slice(&0x200u32.to_le_bytes()); // free_space_offset
        chunk[52..56].copy_from_slice(&0u32.to_le_bytes()); // event_records_checksum
                                                            // compute header checksum
        let crc = crc32fast::hash(&chunk[0..0x78]);
        chunk[0x78..0x7C].copy_from_slice(&crc.to_le_bytes());
        chunk
    }

    fn make_chunk_with_one_record() -> Vec<u8> {
        let mut chunk = make_minimal_chunk();
        // Write one record at offset 0x200
        let record_size: u32 = 28; // 24 header + 4 copy-of-size
        chunk[0x200..0x204].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]); // magic
        chunk[0x204..0x208].copy_from_slice(&record_size.to_le_bytes()); // size
        chunk[0x208..0x210].copy_from_slice(&42u64.to_le_bytes()); // record_id
        chunk[0x210..0x218].copy_from_slice(&133_297_085_160_000_000u64.to_le_bytes()); // timestamp
                                                                                        // bxml payload area (0 bytes here — size 28 = 24 header + 4 trailer)
        let end = 0x200 + record_size as usize;
        chunk[end - 4..end].copy_from_slice(&record_size.to_le_bytes()); // copy-of-size
        chunk
    }

    #[test]
    fn carve_empty_slice_returns_empty_result() {
        let result = carve_from_bytes(&[]);
        assert!(result.chunks.is_empty());
        assert_eq!(result.stats.chunks_found, 0);
    }

    #[test]
    fn carve_no_magic_returns_empty() {
        let data = vec![0u8; 0x20000];
        let result = carve_from_bytes(&data);
        assert!(result.chunks.is_empty());
    }

    #[test]
    fn carve_finds_single_valid_chunk() {
        let data = make_minimal_chunk();
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].integrity, Integrity::Valid);
        assert_eq!(result.chunks[0].offset, 0);
        assert_eq!(result.stats.chunks_found, 1);
        assert_eq!(result.stats.chunks_valid, 1);
    }

    #[test]
    fn carve_finds_two_back_to_back_chunks() {
        let mut data = make_minimal_chunk();
        data.extend(make_minimal_chunk());
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 2);
        assert_eq!(result.chunks[0].offset, 0);
        assert_eq!(result.chunks[1].offset, 0x10000);
    }

    #[test]
    fn truncated_chunk_at_end_marked_truncated() {
        // Provide only half a chunk
        let data: Vec<u8> = make_minimal_chunk()[..0x8000].to_vec();
        let result = carve_from_bytes(&data);
        // The magic is at offset 0, but we only have 0x8000 bytes, not a full 0x10000
        // So it should be found as truncated OR not found — we require it's found but Truncated
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].integrity, Integrity::Truncated);
    }

    #[test]
    fn corrupt_header_checksum_marked_header_corrupt() {
        let mut data = make_minimal_chunk();
        // Corrupt the header checksum
        data[0x78..0x7C].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].integrity, Integrity::HeaderCorrupt);
    }

    #[test]
    fn chunk_with_record_recovers_one_record() {
        let data = make_chunk_with_one_record();
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].records.len(), 1);
        assert_eq!(result.chunks[0].records[0].header.record_id, 42);
        assert_eq!(result.chunks[0].records[0].integrity, Integrity::Valid);
        assert_eq!(result.stats.records_recovered, 1);
    }

    #[test]
    fn file_header_found_when_elffile_magic_present() {
        let mut data = vec![0u8; 0x1000 + 0x10000]; // 4KiB file header + one chunk
        data[0..8].copy_from_slice(b"ElfFile\0");
        // chunk at 0x1000
        let chunk = make_minimal_chunk();
        data[0x1000..0x1000 + 0x10000].copy_from_slice(&chunk);
        let result = carve_from_bytes(&data);
        assert!(result.file_header.is_some());
    }

    // ---- US-01: integrity indicator integration tests ----

    /// Build a minimal chunk with explicit first/last record numbers and IDs, with correct checksum.
    fn make_chunk_with_record_range(
        first_record_number: u64,
        last_record_number: u64,
        first_record_id: u64,
        last_record_id: u64,
    ) -> Vec<u8> {
        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[8..16].copy_from_slice(&first_record_number.to_le_bytes());
        chunk[16..24].copy_from_slice(&last_record_number.to_le_bytes());
        chunk[24..32].copy_from_slice(&first_record_id.to_le_bytes());
        chunk[32..40].copy_from_slice(&last_record_id.to_le_bytes());
        chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes());
        chunk[44..48].copy_from_slice(&0x200u32.to_le_bytes());
        chunk[48..52].copy_from_slice(&0x200u32.to_le_bytes());
        chunk[52..56].copy_from_slice(&0u32.to_le_bytes());
        let crc = crc32fast::hash(&chunk[0..0x78]);
        chunk[0x78..0x7C].copy_from_slice(&crc.to_le_bytes());
        chunk
    }

    /// Build a valid file header (128 bytes at offset 0) with given next_record_id.
    fn make_file_header(next_record_id: u64) -> Vec<u8> {
        let mut hdr = vec![0u8; 0x1000];
        hdr[0..8].copy_from_slice(b"ElfFile\0");
        hdr[8..16].copy_from_slice(&0u64.to_le_bytes()); // first_chunk_number
        hdr[16..24].copy_from_slice(&0u64.to_le_bytes()); // last_chunk_number
        hdr[24..32].copy_from_slice(&next_record_id.to_le_bytes()); // next_record_id
        hdr[36..38].copy_from_slice(&1u16.to_le_bytes()); // minor_version
        hdr[38..40].copy_from_slice(&3u16.to_le_bytes()); // major_version
        hdr[40..42].copy_from_slice(&0u16.to_le_bytes()); // HeaderBlockSize padding
        hdr[42..44].copy_from_slice(&1u16.to_le_bytes()); // chunk_count
                                                          // File header checksum covers bytes 0x00..0x78; stored at 0x7C.
        let crc = crc32fast::hash(&hdr[0..0x78]);
        hdr[0x7C..0x80].copy_from_slice(&crc.to_le_bytes());
        hdr
    }

    #[test]
    fn record_id_gap_between_chunks_populates_indicators() {
        // chunk 1: records 1..10, chunk 2: records 15..20 — gap at 11-14
        let mut data = make_chunk_with_record_range(1, 10, 1, 10);
        data.extend(make_chunk_with_record_range(15, 20, 15, 20));
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 2, "expected two chunks");
        let has_gap = result.indicators.iter().any(|ind| {
            matches!(ind, IntegrityAnomaly::RecordIdGap { expected, found, .. }
                if *expected == 11 && *found == 15)
        });
        assert!(
            has_gap,
            "expected RecordIdGap(expected=11, found=15) in result.indicators, got: {:?}",
            result.indicators
        );
    }

    #[test]
    fn corrupt_chunk_checksum_populates_chunk_indicators() {
        let mut data = make_minimal_chunk();
        // Corrupt the checksum so it no longer matches
        data[0x78..0x7C].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 1);
        let has_mismatch = result.chunks[0]
            .indicators
            .iter()
            .any(|ind| matches!(ind, IntegrityAnomaly::ChunkChecksumMismatch { .. }));
        assert!(
            has_mismatch,
            "expected ChunkChecksumMismatch in chunk.indicators"
        );
    }

    #[test]
    fn file_header_inconsistency_populates_result_indicators() {
        // File header says next_record_id = 5, but chunk has records up to 100
        let mut data = make_file_header(5);
        data.extend(make_chunk_with_record_range(1, 100, 1, 100));
        let result = carve_from_bytes(&data);
        let has_inconsistency = result.indicators.iter().any(|ind| {
            matches!(ind, IntegrityAnomaly::NextRecordIdInconsistency { header_next, actual_highest }
                if *header_next == 5 && *actual_highest == 100)
        });
        assert!(
            has_inconsistency,
            "expected NextRecordIdInconsistency in result.indicators, got: {:?}",
            result.indicators
        );
    }

    #[test]
    fn clean_data_returns_empty_indicators() {
        // Two contiguous chunks with no gaps and valid checksums
        let mut data = make_chunk_with_record_range(1, 10, 1, 10);
        data.extend(make_chunk_with_record_range(11, 20, 11, 20));
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 2);
        assert!(
            result.indicators.is_empty(),
            "expected empty result.indicators for clean data, got: {:?}",
            result.indicators
        );
        for chunk in &result.chunks {
            assert!(
                chunk.indicators.is_empty(),
                "expected empty chunk.indicators for valid chunk, got: {:?}",
                chunk.indicators
            );
        }
    }

    // ---- US-02: file API tests ----

    fn write_temp_evtx(data: &[u8]) -> std::path::PathBuf {
        use std::io::Write;
        let mut path = std::env::temp_dir();
        path.push(format!(
            "winevt_test_{}.evtx",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(data).expect("write temp file");
        path
    }

    #[test]
    fn carve_from_file_valid_path_returns_ok_with_chunk() {
        // Minimal EVTX: file header (4096 bytes) + one valid chunk
        let mut data = make_file_header(101);
        data.extend(make_chunk_with_record_range(1, 100, 1, 100));
        let path = write_temp_evtx(&data);
        let result = carve_from_file(&path);
        let _ = std::fs::remove_file(&path);
        let result = result.expect("carve_from_file should return Ok for valid EVTX");
        assert!(
            !result.chunks.is_empty(),
            "expected at least one chunk in result"
        );
    }

    #[test]
    fn carve_from_file_nonexistent_path_returns_err() {
        let path = std::path::Path::new("/nonexistent/path/to/test.evtx");
        let result = carve_from_file(path);
        assert!(result.is_err(), "expected Err for nonexistent path");
    }

    #[test]
    fn verify_integrity_valid_evtx_returns_empty_vec() {
        let mut data = make_file_header(101);
        data.extend(make_chunk_with_record_range(1, 100, 1, 100));
        let path = write_temp_evtx(&data);
        let result = verify_integrity(&path);
        let _ = std::fs::remove_file(&path);
        let indicators = result.expect("verify_integrity should return Ok for valid EVTX");
        assert!(
            indicators.is_empty(),
            "expected empty indicators for valid EVTX, got: {indicators:?}"
        );
    }

    #[test]
    fn verify_integrity_tampered_checksum_returns_chunk_checksum_mismatch() {
        let mut data = make_file_header(101);
        let mut chunk = make_chunk_with_record_range(1, 100, 1, 100);
        // Tamper the header checksum
        chunk[0x78..0x7C].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data.extend(chunk);
        let path = write_temp_evtx(&data);
        let result = verify_integrity(&path);
        let _ = std::fs::remove_file(&path);
        let indicators =
            result.expect("verify_integrity should return Ok (not Err) for tampered file");
        let has_mismatch = indicators
            .iter()
            .any(|ind| matches!(ind, IntegrityAnomaly::ChunkChecksumMismatch { .. }));
        assert!(
            has_mismatch,
            "expected ChunkChecksumMismatch for tampered EVTX, got: {indicators:?}"
        );
    }

    #[test]
    fn verify_integrity_nonexistent_path_returns_err() {
        let path = std::path::Path::new("/nonexistent/path/to/test.evtx");
        let result = verify_integrity(path);
        assert!(result.is_err(), "expected Err for nonexistent path");
    }

    #[test]
    fn verify_integrity_detects_danderspritz_on_inflated_record() {
        let path = write_temp_evtx(&make_chunk_with_inflated_record());
        let indicators = verify_integrity(&path).expect("verify_integrity ok");
        let _ = std::fs::remove_file(&path);
        assert!(
            indicators.iter().any(|ind| {
                matches!(
                    ind,
                    IntegrityAnomaly::SurgicalRecordDeletion {
                        absorbing_record_id: 1,
                        ..
                    }
                )
            }),
            "expected SurgicalRecordDeletion in verify_integrity output, got: {indicators:?}"
        );
    }

    #[test]
    fn verify_integrity_detects_export_corruption_on_zero_ts_record() {
        let path = write_temp_evtx(&make_chunk_with_record(7, 0, b"payload"));
        let indicators = verify_integrity(&path).expect("verify_integrity ok");
        let _ = std::fs::remove_file(&path);
        assert!(
            indicators.iter().any(|ind| {
                matches!(
                    ind,
                    IntegrityAnomaly::ExportTimestampCorruption { record_id: 7, .. }
                )
            }),
            "expected ExportTimestampCorruption(record_id=7) in verify_integrity output, got: {indicators:?}"
        );
    }

    // ---- E01/EWF forensic image support ----

    #[test]
    fn carve_from_ewf_nonexistent_path_returns_err() {
        let path = std::path::Path::new("/nonexistent/disk.E01");
        let result = carve_from_ewf(path);
        assert!(result.is_err(), "expected Err for nonexistent E01 path");
    }

    #[test]
    fn carve_from_ewf_nonexistent_returns_ewf_error_variant() {
        let path = std::path::Path::new("/nonexistent/disk_ewf.E01");
        let result = carve_from_ewf(path);
        assert!(result.is_err());
        // Either CarveError::Io or CarveError::EwfError is acceptable for a missing file
        let err = result.unwrap_err();
        let is_io_or_ewf = matches!(err, CarveError::Io(_) | CarveError::EwfError(_));
        assert!(is_io_or_ewf, "expected Io or EwfError, got: {err:?}");
    }

    // ---- Feature 14: Offset base parameter ----

    #[test]
    fn carve_with_config_offset_base_zero_same_as_default() {
        let data = make_minimal_chunk();
        let config = CarveConfig { offset_base: 0 };
        let r1 = carve_from_bytes_with_config(&data, &config);
        let r2 = carve_from_bytes(&data);
        assert_eq!(r1.chunks.len(), r2.chunks.len());
        assert_eq!(r1.chunks[0].offset, r2.chunks[0].offset);
    }

    #[test]
    fn carve_with_config_offset_base_shifts_chunk_offsets() {
        let data = make_minimal_chunk();
        let base = 0x1000_0000u64;
        let config = CarveConfig { offset_base: base };
        let result = carve_from_bytes_with_config(&data, &config);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(
            result.chunks[0].offset, base,
            "chunk offset should be shifted by offset_base"
        );
    }

    #[test]
    fn carve_from_bytes_delegates_to_config_with_zero_base() {
        let data = make_minimal_chunk();
        let r1 = carve_from_bytes(&data);
        let r2 = carve_from_bytes_with_config(&data, &CarveConfig::default());
        assert_eq!(r1.chunks[0].offset, r2.chunks[0].offset);
    }

    // ---- Feature 13: Parallel chunk processing ----

    #[test]
    fn parallel_processing_same_results_as_sequential() {
        // Build 4 back-to-back chunks and verify carve_from_bytes returns them in offset order
        let mut data = Vec::new();
        for _ in 0..4 {
            data.extend(make_minimal_chunk());
        }
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 4);
        // All offsets must be in ascending order
        let offsets: Vec<u64> = result.chunks.iter().map(|c| c.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort();
        assert_eq!(
            offsets, sorted,
            "chunk offsets should be in order: {offsets:?}"
        );
    }

    #[test]
    fn parallel_processing_results_deterministic() {
        // Run carve_from_bytes multiple times on same input, results must be identical
        let mut data = Vec::new();
        for _ in 0..3 {
            data.extend(make_minimal_chunk());
        }
        let r1 = carve_from_bytes(&data);
        let r2 = carve_from_bytes(&data);
        assert_eq!(r1.chunks.len(), r2.chunks.len());
        for (c1, c2) in r1.chunks.iter().zip(r2.chunks.iter()) {
            assert_eq!(c1.offset, c2.offset);
            assert_eq!(c1.records.len(), c2.records.len());
        }
    }

    // ---- Feature 11: Adversarial inputs / fuzz regression ----

    #[test]
    fn adversarial_inputs_do_not_panic() {
        // All-zeros
        let _ = carve_from_bytes(&[0u8; 65536]);
        // Magic bytes everywhere
        let mut data = vec![0u8; 65536];
        for i in (0..65536).step_by(8) {
            data[i..i + 8].copy_from_slice(b"ElfChnk\0");
        }
        let _ = carve_from_bytes(&data);
        // Maximum record size field
        let mut data = vec![0u8; 65536];
        data[0..8].copy_from_slice(b"ElfChnk\0");
        data[0x78..0x7C].copy_from_slice(&0xDEADBEEFu32.to_le_bytes()); // corrupt checksum
                                                                        // set record magic at 0x200 with size = max u32
        data[0x200..0x204].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        data[0x204..0x208].copy_from_slice(&u32::MAX.to_le_bytes());
        let _ = carve_from_bytes(&data);
        // Single byte
        let _ = carve_from_bytes(&[0x2A]);
        // Empty
        let _ = carve_from_bytes(&[]);
        // Only a file header magic
        let mut data = vec![0u8; 128];
        data[0..8].copy_from_slice(b"ElfFile\0");
        let _ = carve_from_bytes(&data);
        // File header + partial chunk header
        let mut data = vec![0u8; 200];
        data[0..8].copy_from_slice(b"ElfFile\0");
        data[128..136].copy_from_slice(b"ElfChnk\0");
        let _ = carve_from_bytes(&data);
    }

    // ---- Feature 10: BinXml validity heuristic ----

    #[test]
    fn is_likely_valid_binxml_valid_header_returns_true() {
        let payload = vec![0x0F, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(is_likely_valid_binxml(&payload));
    }

    #[test]
    fn is_likely_valid_binxml_empty_returns_false() {
        assert!(!is_likely_valid_binxml(&[]));
    }

    #[test]
    fn is_likely_valid_binxml_wrong_first_byte_returns_false() {
        let payload = vec![0x00, 0x01, 0x01, 0x00];
        assert!(!is_likely_valid_binxml(&payload));
    }

    #[test]
    fn is_likely_valid_binxml_wrong_version_returns_false() {
        let payload = vec![0x0F, 0x02, 0x01, 0x00]; // major version 2 — invalid
        assert!(!is_likely_valid_binxml(&payload));
    }

    #[test]
    fn is_likely_valid_binxml_null_run_in_first_32_returns_false() {
        let mut payload = vec![0x0F, 0x01, 0x01, 0x00];
        payload.extend(vec![0x00u8; 16]); // 16 consecutive nulls
        assert!(!is_likely_valid_binxml(&payload));
    }

    #[test]
    fn is_likely_valid_binxml_null_run_after_32_bytes_returns_true() {
        // 0x0F 0x01 then non-zero bytes in first 32, then null run after
        let mut payload = vec![0x0F, 0x01, 0x01, 0x00];
        payload.extend(vec![0xAAu8; 28]); // fill out first 32 bytes, no null run
        payload.extend(vec![0x00u8; 20]); // null run after first 32 — should not fail
        assert!(is_likely_valid_binxml(&payload));
    }

    #[test]
    fn aggressive_scan_filters_garbage_binxml_payloads() {
        // Build a corrupt chunk with two records:
        // record 1: valid BinXml payload (0x0F 0x01 ...)
        // record 2: garbage payload (starts with 0x00)
        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[8..16].copy_from_slice(&1u64.to_le_bytes());
        chunk[16..24].copy_from_slice(&2u64.to_le_bytes());
        chunk[24..32].copy_from_slice(&1u64.to_le_bytes());
        chunk[32..40].copy_from_slice(&2u64.to_le_bytes());
        chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes());
        chunk[44..48].copy_from_slice(&0x200u32.to_le_bytes());
        chunk[48..52].copy_from_slice(&0x200u32.to_le_bytes());
        chunk[52..56].copy_from_slice(&0u32.to_le_bytes());
        // CORRUPT header checksum to trigger aggressive scan
        chunk[0x78..0x7C].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

        // Record 1 at 0x200: has valid BinXml payload
        let rec1_payload: Vec<u8> = {
            let mut p = vec![0x0F, 0x01, 0x01, 0x00]; // valid BinXml header
            p.extend(vec![0xAAu8; 4]);
            p
        };
        let rec1_bxml_len = rec1_payload.len();
        let rec1_size = 24 + rec1_bxml_len + 4; // header + payload + copy-of-size
        chunk[0x200..0x204].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        chunk[0x204..0x208].copy_from_slice(&(rec1_size as u32).to_le_bytes());
        chunk[0x208..0x210].copy_from_slice(&1u64.to_le_bytes()); // record_id
        chunk[0x210..0x218].copy_from_slice(&100u64.to_le_bytes()); // timestamp
        chunk[0x218..0x218 + rec1_bxml_len].copy_from_slice(&rec1_payload);
        let end1 = 0x200 + rec1_size;
        chunk[end1 - 4..end1].copy_from_slice(&(rec1_size as u32).to_le_bytes());

        // Record 2 at 0x300: has garbage BinXml payload (starts with 0x00)
        let rec2_payload = vec![0x00u8; 8]; // garbage — all zeros
        let rec2_bxml_len = rec2_payload.len();
        let rec2_size = 24 + rec2_bxml_len + 4;
        chunk[0x300..0x304].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        chunk[0x304..0x308].copy_from_slice(&(rec2_size as u32).to_le_bytes());
        chunk[0x308..0x310].copy_from_slice(&2u64.to_le_bytes()); // record_id
        chunk[0x310..0x318].copy_from_slice(&200u64.to_le_bytes()); // timestamp
        chunk[0x318..0x318 + rec2_bxml_len].copy_from_slice(&rec2_payload);
        let end2 = 0x300 + rec2_size;
        chunk[end2 - 4..end2].copy_from_slice(&(rec2_size as u32).to_le_bytes());

        let result = carve_from_bytes(&chunk);
        assert_eq!(result.chunks.len(), 1);
        let records = &result.chunks[0].records;
        let ids: Vec<u64> = records.iter().map(|r| r.header.record_id).collect();
        // Record 1 (valid BinXml) should be present, record 2 (garbage) filtered out
        assert!(
            ids.contains(&1),
            "record 1 with valid BinXml should be kept, got ids: {ids:?}"
        );
        assert!(
            !ids.contains(&2),
            "record 2 with garbage payload should be filtered, got ids: {ids:?}"
        );
    }

    // ---- Feature 8: memmap2 ----

    #[test]
    fn carve_from_file_mmap_same_result_as_bytes() {
        let data = make_chunk_with_one_record();
        let path = write_temp_evtx(&data);
        let file_result = carve_from_file(&path).expect("carve_from_file");
        let _ = std::fs::remove_file(&path);
        let bytes_result = carve_from_bytes(&data);
        assert_eq!(file_result.chunks.len(), bytes_result.chunks.len());
        assert_eq!(
            file_result.stats.chunks_found,
            bytes_result.stats.chunks_found
        );
        assert_eq!(
            file_result.stats.records_recovered,
            bytes_result.stats.records_recovered
        );
        // source_hash must be Some for file path
        assert!(file_result.source_hash.is_some());
        // bytes result must be None
        assert!(bytes_result.source_hash.is_none());
    }

    #[test]
    fn carve_from_file_empty_file_returns_ok_empty_result() {
        use std::io::Write;
        let mut path = std::env::temp_dir();
        path.push("winevt_mmap_empty_test.evtx");
        let mut f = std::fs::File::create(&path).expect("create temp");
        f.write_all(&[]).expect("write empty");
        drop(f);
        let result = carve_from_file(&path).expect("empty file should return Ok");
        let _ = std::fs::remove_file(&path);
        assert!(result.chunks.is_empty());
    }

    #[test]
    fn carve_from_file_three_chunk_file_recovers_all_chunks() {
        let mut data = make_minimal_chunk();
        data.extend(make_minimal_chunk());
        data.extend(make_minimal_chunk());
        let path = write_temp_evtx(&data);
        let result = carve_from_file(&path).expect("carve_from_file");
        let _ = std::fs::remove_file(&path);
        assert_eq!(result.chunks.len(), 3, "expected 3 chunks via mmap path");
    }

    // ---- Feature 6: SHA-256 source hash ----

    #[test]
    fn carve_from_bytes_source_hash_is_none() {
        let data = vec![0u8; 64];
        let result = carve_from_bytes(&data);
        assert!(
            result.source_hash.is_none(),
            "carve_from_bytes should set source_hash to None"
        );
    }

    #[test]
    fn carve_from_file_source_hash_is_some_64_char_hex() {
        let mut data = make_file_header(101);
        data.extend(make_chunk_with_record_range(1, 100, 1, 100));
        let path = write_temp_evtx(&data);
        let result = carve_from_file(&path).expect("carve_from_file should succeed");
        let _ = std::fs::remove_file(&path);
        let hash = result.source_hash.expect("source_hash should be Some");
        assert_eq!(
            hash.len(),
            64,
            "SHA-256 hex should be 64 chars, got: {hash}"
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "SHA-256 should be hex, got: {hash}"
        );
    }

    #[test]
    fn carve_from_file_source_hash_matches_known_sha256() {
        // SHA-256 of empty bytes is known
        use std::io::Write;
        let path = {
            let mut p = std::env::temp_dir();
            p.push("winevt_sha256_test_empty.evtx");
            p
        };
        let mut f = std::fs::File::create(&path).expect("create temp");
        f.write_all(&[]).expect("write empty");
        drop(f);
        let result = carve_from_file(&path).expect("ok");
        let _ = std::fs::remove_file(&path);
        let hash = result.source_hash.expect("Some");
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ---- Feature 1: thiserror / CarveError ----

    #[test]
    fn carve_from_file_nonexistent_returns_carve_error_io() {
        let path = std::path::Path::new("/nonexistent/path/to/feature1.evtx");
        let result = carve_from_file(path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, CarveError::Io(_)),
            "expected CarveError::Io, got: {err:?}"
        );
    }

    #[test]
    fn verify_integrity_nonexistent_returns_carve_error_io() {
        let path = std::path::Path::new("/nonexistent/path/to/feature1b.evtx");
        let result = verify_integrity(path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, CarveError::Io(_)),
            "expected CarveError::Io, got: {err:?}"
        );
    }

    // ---- US-03: aggressive scan for corrupt chunks ----

    /// Build a corrupt chunk (bad header checksum) with two records placed at
    /// non-sequential positions — a gap of zeroes exists between them so the
    /// sequential walker would miss the second one.
    fn make_corrupt_chunk_with_scattered_records() -> Vec<u8> {
        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[8..16].copy_from_slice(&1u64.to_le_bytes());
        chunk[16..24].copy_from_slice(&2u64.to_le_bytes());
        chunk[24..32].copy_from_slice(&1u64.to_le_bytes());
        chunk[32..40].copy_from_slice(&2u64.to_le_bytes());
        chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes());
        chunk[44..48].copy_from_slice(&0x200u32.to_le_bytes());
        chunk[48..52].copy_from_slice(&0x200u32.to_le_bytes());
        chunk[52..56].copy_from_slice(&0u32.to_le_bytes());
        // CORRUPT the header checksum intentionally
        chunk[0x78..0x7C].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

        // Valid BinXml payload to pass the heuristic
        let binxml: [u8; 8] = [0x0F, 0x01, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];

        // Record 1 at offset 0x200 (standard position)
        let rec_size: u32 = 24 + 8 + 4; // header + binxml payload + copy-of-size
        chunk[0x200..0x204].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        chunk[0x204..0x208].copy_from_slice(&rec_size.to_le_bytes());
        chunk[0x208..0x210].copy_from_slice(&1u64.to_le_bytes()); // record_id = 1
        chunk[0x210..0x218].copy_from_slice(&100u64.to_le_bytes()); // timestamp
        chunk[0x218..0x220].copy_from_slice(&binxml);
        let end1 = 0x200 + rec_size as usize;
        chunk[end1 - 4..end1].copy_from_slice(&rec_size.to_le_bytes());

        // Record 2 at a non-sequential offset (0x300 instead of immediately after rec1)
        // This means there's a gap from 0x21C to 0x300 filled with zeros
        chunk[0x300..0x304].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        chunk[0x304..0x308].copy_from_slice(&rec_size.to_le_bytes());
        chunk[0x308..0x310].copy_from_slice(&2u64.to_le_bytes()); // record_id = 2
        chunk[0x310..0x318].copy_from_slice(&200u64.to_le_bytes()); // timestamp
        chunk[0x318..0x320].copy_from_slice(&binxml);
        let end2 = 0x300 + rec_size as usize;
        chunk[end2 - 4..end2].copy_from_slice(&rec_size.to_le_bytes());

        chunk
    }

    #[test]
    fn aggressive_scan_finds_records_at_non_sequential_offsets() {
        let data = make_corrupt_chunk_with_scattered_records();
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 1, "expected one chunk");
        let chunk = &result.chunks[0];
        assert_eq!(
            chunk.integrity,
            Integrity::HeaderCorrupt,
            "chunk should be HeaderCorrupt"
        );
        assert_eq!(
            chunk.records.len(),
            2,
            "aggressive scan should find both records, got: {:?}",
            chunk
                .records
                .iter()
                .map(|r| (r.header.record_id, r.integrity))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn aggressive_scan_marks_records_carved() {
        let data = make_corrupt_chunk_with_scattered_records();
        let result = carve_from_bytes(&data);
        let chunk = &result.chunks[0];
        for rec in &chunk.records {
            assert_eq!(
                rec.integrity,
                Integrity::Carved,
                "records from aggressive scan should be marked Carved, got {:?} for record_id={}",
                rec.integrity,
                rec.header.record_id
            );
        }
    }

    #[test]
    fn aggressive_scan_records_have_valid_ids_and_timestamps() {
        let data = make_corrupt_chunk_with_scattered_records();
        let result = carve_from_bytes(&data);
        let chunk = &result.chunks[0];
        let ids: Vec<u64> = chunk.records.iter().map(|r| r.header.record_id).collect();
        assert!(ids.contains(&1), "expected record_id=1, got {ids:?}");
        assert!(ids.contains(&2), "expected record_id=2, got {ids:?}");
        let ts: Vec<u64> = chunk.records.iter().map(|r| r.header.timestamp).collect();
        assert!(ts.contains(&100), "expected timestamp=100, got {ts:?}");
        assert!(ts.contains(&200), "expected timestamp=200, got {ts:?}");
    }

    #[test]
    fn aggressive_scan_increments_records_corrupt() {
        let data = make_corrupt_chunk_with_scattered_records();
        let result = carve_from_bytes(&data);
        // The two records from the corrupt chunk should increment records_corrupt
        assert!(
            result.stats.records_corrupt >= 2,
            "expected records_corrupt >= 2, got {}",
            result.stats.records_corrupt
        );
    }

    #[test]
    fn aggressive_scan_does_not_duplicate_records_from_sequential_walk() {
        // A corrupt chunk where record 1 IS at offset 0x200 (sequential position)
        // The aggressive scan should not add it twice.
        let data = make_corrupt_chunk_with_scattered_records();
        let result = carve_from_bytes(&data);
        let chunk = &result.chunks[0];
        // Record IDs should be unique
        let mut ids: Vec<u64> = chunk.records.iter().map(|r| r.header.record_id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids.len(),
            chunk.records.len(),
            "duplicate records found: {:?}",
            chunk
                .records
                .iter()
                .map(|r| r.header.record_id)
                .collect::<Vec<_>>()
        );
    }

    // ── Feature 18: export timestamp corruption wired into carve_from_bytes ──

    /// Build a full valid chunk with one record at 0x200 with given id/ts/payload.
    fn make_chunk_with_record(record_id: u64, timestamp: u64, payload: &[u8]) -> Vec<u8> {
        let rec_size = (4 + 4 + 8 + 8 + payload.len() + 4) as u32;
        let free_off = 0x200u32 + rec_size;
        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[8..16].copy_from_slice(&record_id.to_le_bytes());
        chunk[16..24].copy_from_slice(&record_id.to_le_bytes());
        chunk[24..32].copy_from_slice(&record_id.to_le_bytes());
        chunk[32..40].copy_from_slice(&record_id.to_le_bytes());
        chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes());
        chunk[44..48].copy_from_slice(&0x200u32.to_le_bytes());
        chunk[48..52].copy_from_slice(&free_off.to_le_bytes());
        // records area checksum
        let records_area_crc = crc32fast::hash(&chunk[0x200..free_off as usize]);
        chunk[52..56].copy_from_slice(&records_area_crc.to_le_bytes());
        // record at 0x200
        chunk[0x200..0x204].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        chunk[0x204..0x208].copy_from_slice(&rec_size.to_le_bytes());
        chunk[0x208..0x210].copy_from_slice(&record_id.to_le_bytes());
        chunk[0x210..0x218].copy_from_slice(&timestamp.to_le_bytes());
        let pl_end = 0x218 + payload.len();
        chunk[0x218..pl_end].copy_from_slice(payload);
        chunk[pl_end..pl_end + 4].copy_from_slice(&rec_size.to_le_bytes());
        // recompute records area checksum now that record bytes are in place
        let records_area_crc = crc32fast::hash(&chunk[0x200..free_off as usize]);
        chunk[52..56].copy_from_slice(&records_area_crc.to_le_bytes());
        // header checksum
        let hdr_crc = crc32fast::hash(&chunk[0..0x78]);
        chunk[0x78..0x7C].copy_from_slice(&hdr_crc.to_le_bytes());
        chunk
    }

    #[test]
    fn export_timestamp_corruption_zero_ts_record_populates_result_indicators() {
        // Record with timestamp = 0 should trigger ExportTimestampCorruption
        let data = make_chunk_with_record(7, 0, b"payload");
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(
            result.chunks[0].records.len(),
            1,
            "should recover one record"
        );
        let has_indicator = result.indicators.iter().any(|ind| {
            matches!(
                ind,
                IntegrityAnomaly::ExportTimestampCorruption { record_id: 7, .. }
            )
        });
        assert!(
            has_indicator,
            "expected ExportTimestampCorruption(record_id=7) in result.indicators, got: {:?}",
            result.indicators
        );
    }

    #[test]
    fn export_timestamp_corruption_nonzero_ts_returns_no_indicator() {
        let data = make_chunk_with_record(1, 133_297_085_160_000_000, b"");
        let result = carve_from_bytes(&data);
        let has_export = result
            .indicators
            .iter()
            .any(|ind| matches!(ind, IntegrityAnomaly::ExportTimestampCorruption { .. }));
        assert!(
            !has_export,
            "non-zero ts should not produce ExportTimestampCorruption, got: {:?}",
            result.indicators
        );
    }

    // ── Feature 18: DanderSpritz surgical deletion wired into carve_from_bytes ─

    fn make_chunk_with_inflated_record() -> Vec<u8> {
        // Record 1 at 0x200 with size inflated to absorb record 2 (ghost).
        // Record 1 payload = "absorber" (8 bytes), record 2 payload = "ghost" (5 bytes).
        let sz1 = (4 + 4 + 8 + 8 + 8usize + 4) as u32; // 36
        let sz2 = (4 + 4 + 8 + 8 + 5usize + 4) as u32; // 33
        let inflated = sz1 + sz2;
        let free_off = 0x200u32 + inflated;

        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[8..16].copy_from_slice(&1u64.to_le_bytes());
        chunk[16..24].copy_from_slice(&1u64.to_le_bytes());
        chunk[24..32].copy_from_slice(&1u64.to_le_bytes());
        chunk[32..40].copy_from_slice(&1u64.to_le_bytes());
        chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes());
        chunk[44..48].copy_from_slice(&0x200u32.to_le_bytes());
        chunk[48..52].copy_from_slice(&free_off.to_le_bytes());

        // Record 1 (absorbing)
        chunk[0x200..0x204].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        chunk[0x204..0x208].copy_from_slice(&inflated.to_le_bytes()); // inflated size
        chunk[0x208..0x210].copy_from_slice(&1u64.to_le_bytes()); // record_id = 1
        chunk[0x210..0x218].copy_from_slice(&100u64.to_le_bytes()); // timestamp
        chunk[0x218..0x220].copy_from_slice(b"absorber"); // 8-byte payload
                                                          // Record 2 (ghost) at 0x200 + sz1 = 0x224
        let ghost_off = 0x200usize + sz1 as usize;
        chunk[ghost_off..ghost_off + 4].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        chunk[ghost_off + 4..ghost_off + 8].copy_from_slice(&sz2.to_le_bytes());
        chunk[ghost_off + 8..ghost_off + 16].copy_from_slice(&2u64.to_le_bytes());
        chunk[ghost_off + 16..ghost_off + 24].copy_from_slice(&200u64.to_le_bytes());
        chunk[ghost_off + 24..ghost_off + 29].copy_from_slice(b"ghost");
        // Trailing size for inflated record 1
        let trail = 0x200usize + inflated as usize - 4;
        chunk[trail..trail + 4].copy_from_slice(&inflated.to_le_bytes());

        // records area checksum
        let recs_crc = crc32fast::hash(&chunk[0x200..free_off as usize]);
        chunk[52..56].copy_from_slice(&recs_crc.to_le_bytes());
        // header checksum
        let hdr_crc = crc32fast::hash(&chunk[0..0x78]);
        chunk[0x78..0x7C].copy_from_slice(&hdr_crc.to_le_bytes());
        chunk
    }

    #[test]
    fn danderspritz_inflated_record_populates_result_indicators() {
        let data = make_chunk_with_inflated_record();
        let result = carve_from_bytes(&data);
        assert_eq!(result.chunks.len(), 1);
        let has_surgical = result.indicators.iter().any(|ind| {
            matches!(
                ind,
                IntegrityAnomaly::SurgicalRecordDeletion {
                    absorbing_record_id: 1,
                    ..
                }
            )
        });
        assert!(
            has_surgical,
            "expected SurgicalRecordDeletion(absorbing_record_id=1) in result.indicators, got: {:?}",
            result.indicators
        );
    }

    #[test]
    fn danderspritz_normal_chunk_returns_no_surgical_deletion() {
        let data = make_chunk_with_record(3, 133_297_085_160_000_000, b"normal");
        let result = carve_from_bytes(&data);
        let has_surgical = result
            .indicators
            .iter()
            .any(|ind| matches!(ind, IntegrityAnomaly::SurgicalRecordDeletion { .. }));
        assert!(
            !has_surgical,
            "normal chunk should not produce SurgicalRecordDeletion, got: {:?}",
            result.indicators
        );
    }

    // ── §1: free-space slack carving ─────────────────────────────────────────

    fn chunk_with_live_record_and_free_space_record(
        live_payload: &[u8],
        free_payload: &[u8],
    ) -> Vec<u8> {
        // Build a chunk where one live record is at 0x200, and a "deleted" record
        // sits in free space after free_space_offset.
        let live_size = (24 + live_payload.len() + 4) as u32;
        let free_space_offset = 0x200u32 + live_size;

        let mut chunk = vec![0u8; 0x10000];
        chunk[0..8].copy_from_slice(b"ElfChnk\0");
        chunk[8..16].copy_from_slice(&1u64.to_le_bytes());
        chunk[16..24].copy_from_slice(&1u64.to_le_bytes());
        chunk[24..32].copy_from_slice(&1u64.to_le_bytes());
        chunk[32..40].copy_from_slice(&1u64.to_le_bytes());
        chunk[40..44].copy_from_slice(&0x80u32.to_le_bytes());
        chunk[44..48].copy_from_slice(&(0x200u32 + live_size - 4).to_le_bytes());
        chunk[48..52].copy_from_slice(&free_space_offset.to_le_bytes());

        // Live record at 0x200
        chunk[0x200..0x204].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        chunk[0x204..0x208].copy_from_slice(&live_size.to_le_bytes());
        chunk[0x208..0x210].copy_from_slice(&1u64.to_le_bytes());
        chunk[0x210..0x218].copy_from_slice(&100u64.to_le_bytes());
        chunk[0x218..0x218 + live_payload.len()].copy_from_slice(live_payload);
        let live_trail = 0x200 + live_size as usize - 4;
        chunk[live_trail..live_trail + 4].copy_from_slice(&live_size.to_le_bytes());

        // Free-space record placed right after free_space_offset
        let free_off = free_space_offset as usize;
        let free_size = (24 + free_payload.len() + 4) as u32;
        chunk[free_off..free_off + 4].copy_from_slice(&[0x2A, 0x2A, 0x00, 0x00]);
        chunk[free_off + 4..free_off + 8].copy_from_slice(&free_size.to_le_bytes());
        chunk[free_off + 8..free_off + 16].copy_from_slice(&2u64.to_le_bytes());
        chunk[free_off + 16..free_off + 24].copy_from_slice(&99u64.to_le_bytes());
        chunk[free_off + 24..free_off + 24 + free_payload.len()].copy_from_slice(free_payload);
        let free_trail = free_off + free_size as usize - 4;
        chunk[free_trail..free_trail + 4].copy_from_slice(&free_size.to_le_bytes());

        // Compute checksums
        let recs_crc = crc32fast::hash(&chunk[0x200..free_space_offset as usize]);
        chunk[52..56].copy_from_slice(&recs_crc.to_le_bytes());
        let hdr_crc = crc32fast::hash(&chunk[0..0x78]);
        chunk[0x78..0x7C].copy_from_slice(&hdr_crc.to_le_bytes());
        chunk
    }

    #[test]
    fn carve_free_space_empty_slice_returns_empty() {
        let records = carve_chunk_free_space(&[], 0);
        assert!(records.is_empty(), "empty slice must return no records");
    }

    #[test]
    fn carve_free_space_no_free_records_returns_empty() {
        let data = make_chunk_with_record(1, 100, b"payload");
        let records = carve_chunk_free_space(&data, 0);
        assert!(records.is_empty(), "no deleted records should return empty");
    }

    #[test]
    fn carve_free_space_single_deleted_record_recovers_it() {
        let data = chunk_with_live_record_and_free_space_record(b"live", b"deleted");
        let records = carve_chunk_free_space(&data, 0x4000);
        assert_eq!(
            records.len(),
            1,
            "expected 1 carved record; got {:?} records",
            records.len()
        );
        assert_eq!(records[0].chunk_offset, 0x4000);
        // record in free space should be identified
        assert!(
            matches!(
                records[0].confidence,
                CarveConfidence::Definite | CarveConfidence::Probable
            ),
            "confidence must be Definite or Probable"
        );
    }

    #[test]
    fn carve_free_space_does_not_return_live_records() {
        let data = chunk_with_live_record_and_free_space_record(b"live", b"deleted");
        let records = carve_chunk_free_space(&data, 0);
        // Should return the free-space record but NOT the live record
        assert!(
            records.len() <= 1,
            "must not return live records; got {} records",
            records.len()
        );
        // Verify the returned record's offset is beyond the live record
        for r in &records {
            assert!(
                r.record_offset_within_chunk >= 0x200 + 4 + 4,
                "carved record at offset {} is in the live area",
                r.record_offset_within_chunk
            );
        }
    }

    #[test]
    fn carve_free_space_invalid_binxml_demotes_to_probable() {
        // payload is random bytes that are not valid BinXML
        let garbage_payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, 0xFF, 0xFF];
        let data = chunk_with_live_record_and_free_space_record(b"live", &garbage_payload);
        let records = carve_chunk_free_space(&data, 0);
        // If the garbage payload doesn't look like BinXML, confidence should be Probable
        for r in &records {
            assert_ne!(
                r.confidence,
                CarveConfidence::Definite,
                "garbage BinXML should not be Definite"
            );
        }
    }
}
