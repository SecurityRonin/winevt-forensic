# 5. `memmap2` zero-copy file carving — the single bounded `unsafe` site

Date: 2026-07-24
Status: Accepted

## Context

`ev4n6` carves EVTX structure out of whole disk images and large `.evtx` files.
Reading a multi-gigabyte file into a `Vec<u8>` to scan it for `ElfChnk\0` magic
would double memory and stall on the read. A memory map gives the scan zero-copy,
page-cache-backed access to the file bytes.

`memmap2::Mmap::map` is `unsafe`: the borrow is unsound if another process
truncates the file underneath the map. That is the standard, well-understood
memory-mapped-file caveat, not a novel hazard — the constitution's *unsafe*
policy treats a bounded `mmap` as pure-Rust, auditable, far cheaper than a C-FFI
liability, and explicitly the kind of avoidable-perf-`unsafe` the fleet accepts
for readers (ewf-forensic does the same for its mmap sites).

Evidence: `crates/winevt-carver/src/lib.rs:310`
(`let mmap = unsafe { memmap2::Mmap::map(&file)? };`), the only `unsafe` in the
workspace (`grep -rn "unsafe " crates/*/src/*.rs` returns one hit);
`crates/winevt-carver/Cargo.toml` (`memmap2 = "0.9"`). Constitution: "`unsafe` Is
an Avoidable Cost-Benefit Exception" and the Paranoid-Gatekeeper mmap exception.

## Decision

1. Use `memmap2` for the file-carving fast path (`carve_from_file`), mapping the
   file for zero-copy access and delegating the byte scan to `carve_from_bytes`.

2. Confine `unsafe` to that one `Mmap::map` call site — the single `unsafe` in
   the entire workspace. Every other crate stays `unsafe`-free.

3. All parsing over the mapped bytes remains bounds-checked and panic-free; the
   map only supplies the `&[u8]`, it does not relax any read discipline.

## Consequences

- Large images and files are carved without loading them wholesale into memory;
  the scan runs against page-cache-backed bytes.
- The suite cannot wear a blanket "unsafe-forbidden" badge; it is honestly one
  bounded, pure-Rust `mmap` site (a `deny` + single-allow posture), matching how
  the fleet's other mmap readers are represented.
- `rg 'unsafe'` over `crates/*/src` is the complete audit surface — one line.
- The standard mmap unsoundness (concurrent truncation of the evidence file)
  applies; in the forensic workflow the image is read-only and not being written
  by another process, so the window is not a practical concern.
