//! MBR partition table parser — pure, no I/O.

/// Partition table starts at offset 0x1BE; 4 entries × 16 bytes each.
/// Entry layout: status(1) + chs_first(3) + type(1) + chs_last(3) + lba_start(4) + sectors(4).
const TABLE_OFFSET: usize = 0x1BE;
const ENTRY_SIZE: usize = 16;
const TYPE_OFFSET: usize = 4;
const LBA_OFFSET: usize = 8;

const NTFS_TYPES: &[u8] = &[0x07, 0x17, 0x27];

/// Return the LBA start sector of the first NTFS partition, or `None`.
pub(crate) fn parse_ntfs_offset(sector: &[u8; 512]) -> Option<u64> {
    for i in 0..4usize {
        let base = TABLE_OFFSET + i * ENTRY_SIZE;
        let part_type = sector[base + TYPE_OFFSET];
        if NTFS_TYPES.contains(&part_type) {
            let lba = u32::from_le_bytes([
                sector[base + LBA_OFFSET],
                sector[base + LBA_OFFSET + 1],
                sector[base + LBA_OFFSET + 2],
                sector[base + LBA_OFFSET + 3],
            ]);
            return Some(u64::from(lba));
        }
    }
    None
}
