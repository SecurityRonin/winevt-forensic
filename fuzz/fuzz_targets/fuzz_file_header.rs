#![no_main]
use libfuzzer_sys::fuzz_target;
use winevt_core::binary::EvtxFileHeader;

fuzz_target!(|data: &[u8]| {
    let _ = EvtxFileHeader::parse(data);
});
