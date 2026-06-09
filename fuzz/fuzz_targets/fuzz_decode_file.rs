#![no_main]
//! Fuzz the full container→record→BinXml pipeline. Invariant: never panic on
//! arbitrary bytes (the input is treated as a whole EVTX file).
use libfuzzer_sys::fuzz_target;
use winevt_binxml::reader::decode_file;

fuzz_target!(|data: &[u8]| {
    let _ = decode_file(data);
});
