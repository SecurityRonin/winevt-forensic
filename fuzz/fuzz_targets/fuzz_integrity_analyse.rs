#![no_main]
use libfuzzer_sys::fuzz_target;
use winevt_integrity::WinevtIntegrity;

fuzz_target!(|data: &[u8]| {
    let _ = WinevtIntegrity::analyse(data);
});
