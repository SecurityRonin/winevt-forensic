use forensicnomicon::evtx::CHUNK_SIZE;
use winevt_core::binary::{EvtxChunkHeader, EvtxRecordHeader, ELFCHNK_MAGIC, RECORD_MAGIC};

fn make_record_buf(size: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 24];
    buf[0..4].copy_from_slice(&RECORD_MAGIC);
    buf[4..8].copy_from_slice(&size.to_le_bytes());
    buf
}

fn make_chunk_buf(last_record_offset: u32, free_space_offset: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 0x7C];
    buf[0..8].copy_from_slice(&ELFCHNK_MAGIC);
    buf[44..48].copy_from_slice(&last_record_offset.to_le_bytes());
    buf[48..52].copy_from_slice(&free_space_offset.to_le_bytes());
    buf
}

#[test]
fn record_with_zero_size_rejected() {
    assert!(EvtxRecordHeader::parse(&make_record_buf(0)).is_none());
}

#[test]
fn record_with_undersized_size_rejected() {
    assert!(EvtxRecordHeader::parse(&make_record_buf(10)).is_none());
}

#[test]
fn record_with_min_valid_size_accepted() {
    assert!(EvtxRecordHeader::parse(&make_record_buf(24)).is_some());
}

#[test]
fn record_with_oversized_size_rejected() {
    assert!(EvtxRecordHeader::parse(&make_record_buf(CHUNK_SIZE as u32 + 1)).is_none());
}

#[test]
fn chunk_with_overflow_last_record_offset_rejected() {
    assert!(EvtxChunkHeader::parse(&make_chunk_buf(0xFFFF_FFFFu32, 0)).is_none());
}

#[test]
fn chunk_with_overflow_free_space_offset_rejected() {
    assert!(EvtxChunkHeader::parse(&make_chunk_buf(0, 0xFFFF_FFFFu32)).is_none());
}

#[test]
fn chunk_with_valid_offsets_accepted() {
    assert!(EvtxChunkHeader::parse(&make_chunk_buf(512, 1024)).is_some());
}
