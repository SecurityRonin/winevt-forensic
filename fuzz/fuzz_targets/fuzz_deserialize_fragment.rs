#![no_main]
//! Fuzz the BinXml token-loop deserializer (cursor + value + name + tokens +
//! templates + substitutions). The input is both the chunk addressing base and
//! the cursor stream. Invariant: never panic on arbitrary bytes.
use libfuzzer_sys::fuzz_target;
use winevt_binxml::cursor::Cursor;
use winevt_binxml::deserializer::deserialize_fragment;
use winevt_binxml::name::NameCache;

fuzz_target!(|data: &[u8]| {
    let mut names = NameCache::new();
    let mut cur = Cursor::new(data);
    let _ = deserialize_fragment(&mut cur, data, &mut names);
});
