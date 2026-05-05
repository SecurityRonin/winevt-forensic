#![no_main]
use libfuzzer_sys::fuzz_target;
use winevt_core::binary::EvtxChunkHeader;

fuzz_target!(|data: &[u8]| {
    let _ = EvtxChunkHeader::parse(data);
});
