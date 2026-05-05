#![no_main]
use libfuzzer_sys::fuzz_target;
use winevt_core::binary::EvtxRecordHeader;

fuzz_target!(|data: &[u8]| {
    let _ = EvtxRecordHeader::parse(data);
});
