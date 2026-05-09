//! `PartitionReader` — offsets all `SeekFrom::Start` seeks by a base byte
//! offset, presenting a disk partition as a standalone volume to the `ntfs` crate.

use std::io::{Read, Result, Seek, SeekFrom};

pub(crate) struct PartitionReader<R> {
    inner: R,
    base: u64,
}

impl<R: Read + Seek> PartitionReader<R> {
    /// Seek `inner` to `base_offset` bytes and wrap it.
    pub(crate) fn new(mut inner: R, base_offset: u64) -> Result<Self> {
        inner.seek(SeekFrom::Start(base_offset))?;
        Ok(Self { inner, base: base_offset })
    }
}

impl<R: Read + Seek> Read for PartitionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek> Seek for PartitionReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let abs = match pos {
            // Translate volume-relative start seeks to disk-absolute.
            SeekFrom::Start(n) => self.inner.seek(SeekFrom::Start(self.base + n))?,
            // Current/End are already correct in disk terms.
            SeekFrom::Current(n) => self.inner.seek(SeekFrom::Current(n))?,
            SeekFrom::End(n) => self.inner.seek(SeekFrom::End(n))?,
        };
        Ok(abs.saturating_sub(self.base))
    }
}
