#![no_main]
use libfuzzer_sys::fuzz_target;
use winevt_binxml::validate_binxml;

fuzz_target!(|data: &[u8]| {
    let _ = validate_binxml(data);
});
