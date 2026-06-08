# Architecture — native BinXML decoder (`winevt-binxml`)

Status: BUILD. Author: Claude (Opus 4.8), 2026-06-08.
Reference: omerbenamram `evtx` 0.11.2 (Apache-2.0/MIT — ported with attribution)
+ libevtx public spec (Metz). Hayabusa: knowledge-only, no code.

## Goal & non-goals

Decode an EVTX **record payload** (BinXML token stream) into a structured tree,
then project to a `serde_json::Value` whose shape is **identical** to
omerbenamram's default output (named-attribute `Data` array + flat Sysmon
object), so `winevt_extract::flatten_event_data` is a drop-in consumer and all
of issen is untouched. Container layer (file/chunk/record headers, CRC) already
exists in `winevt-core::binary` — reuse it.

Non-goal (now): WEVT manifest templates, raw XML rendering, zero-copy/arena perf.
Correctness + robustness first; optimize later.

## Modules (all in `winevt-binxml`, panic-free, no `unsafe`)

| Module | Responsibility |
|---|---|
| `cursor.rs` | `Cursor<'a>` over `&[u8]`. Bounds-checked reads: u8/i8/u16/u32/u64/i16/i32/i64/f32/f64, UTF-16LE (sized + len-prefixed), take(n), seek/set_pos (bounded). Every read returns `Result`; OOB → `Err`, never panic. |
| `value.rs` | `BinXmlValue` enum + `read_value(cur, type_id, sized_len) -> Result<BinXmlValue>` + `render() -> String`. Full value-type table incl. SID/FILETIME/SYSTEMTIME/GUID/Hex + 0x80 array variants. |
| `name.rs` | `NameRef` (chunk offset) + per-chunk `StringCache` (offset → name), populated by linked-list walk (`next u32`, `hash u16`, len-prefixed UTF-16). |
| `tokens.rs` | Token ID constants (0x00–0x0f, 0x40 attr-flag mask) + readers: open-start-element, attribute, substitution descriptor, template-instance header, fragment header. |
| `template.rs` | Template definition parse + per-chunk `TemplateCache` (keyed by chunk offset/GUID). |
| `deserializer.rs` | The token loop → `Ir` tree. Resolves Normal/Optional substitutions against the instance's value array; array values expand the containing element N×. Depth + iteration caps. |
| `ir.rs` | Owned IR: `Node::Element { name, attributes: Vec<(String,String)>, children }`, `Node::Text(String)`. |
| `json.rs` | `Ir -> serde_json::Value` matching omerbenamram default shape. |
| `lib.rs` | Public API + the existing validator (kept). |

## Token IDs (from reference, verified)

`0x00 EndOfStream, 0x01 OpenStartElement, 0x02 CloseStartElement,
0x03 CloseEmptyElement, 0x04 EndElement, 0x05 Value, 0x06 Attribute,
0x07 CDATA, 0x08 CharRef, 0x09 EntityRef, 0x0a PITarget, 0x0b PIData,
0x0c TemplateInstance, 0x0d NormalSubstitution, 0x0e OptionalSubstitution,
0x0f FragmentHeader`. The `0x40` bit on element/value/attr tokens = "has more /
attributes"; mask it off to get the action ID.

## Value-type IDs (from reference, verified)

Scalars: `00 Null, 01 String(u16-sized UTF-16 or len-prefixed), 02 AnsiString,
03 Int8, 04 UInt8, 05 Int16, 06 UInt16, 07 Int32, 08 UInt32, 09 Int64,
0a UInt64, 0b Real32, 0c Real64, 0d Bool(4 bytes), 0e Binary(u16-sized→hex),
0f Guid(16), 10 SizeT(4|8), 11 FileTime(8), 12 SysTime(16), 13 Sid(8+subs×4),
14 HexInt32(4), 15 HexInt64(8), 21 BinXml(embedded fragment)`. Array variants =
`0x80 | base`, always u16-sized; expand container element per element.

## Substitution-array format (the crux)

TemplateInstance(0x0c): `unused u8, template_id u32, def_offset u32`; if def not
yet cached and `cursor == def_offset`: inline def header `next u32, guid[16],
data_size u32`, then `data_size` BinXML bytes (the template body, parsed once
with substitutions as `Placeholder{index, optional}`). Then the value array:
`count u32`, then `count × (size u16, type u8, unused u8)` descriptors, then the
raw values back-to-back (each `size` bytes, decoded by `type`). Substitution
tokens reference values by index; optional + Null type ⇒ omit.

## Robustness (Paranoid Gatekeeper — mandatory)

- Every cursor read bounds-checked → `Err`, never panic/index.
- **Depth cap** on element + template-instance nesting (e.g. 256) → `Err`.
- **Iteration cap** on the token loop per record → `Err`.
- **Allocation caps**: reject absurd `substitution_count`, string/array sizes,
  data_size beyond chunk bounds.
- Substitution index + all chunk offsets bounds-checked.
- Mismatched declared-vs-consumed value size → reposition to declared end
  (graceful), mirroring the reference, but never read OOB.
- `unwrap_used`/`expect_used` = deny; no slice indexing in production.

## Validation (Doer-Checker)

**Differential parity** against omerbenamram on the real fixture corpus
(`tests/data/`: fox-it Security, Sysmon, hayabusa-samples): decode the same
records with both, assert field-map parity via `flatten_event_data`. Oracle is a
dev-dependency only. Plus per-structure **fuzz targets** (cursor, value, name,
template, record): invariant = never panic.

## TDD phase order (RED/GREEN per unit, 100% line coverage)

1. `cursor.rs` — bounded primitive reads. ← start here
2. `value.rs` — each value type, one RED test per type.
3. `name.rs` — string cache + name resolution.
4. `tokens.rs` — token + descriptor readers.
5. `ir.rs` + `deserializer.rs` — token loop, no templates (template-free fragment).
6. `template.rs` + substitution resolution.
7. `json.rs` — IR → JSON shape parity.
8. container glue + **differential parity test** vs omerbenamram on real corpus.
9. fuzz targets + caps hardening.

Realistically multi-session; this session targets 1–5 (the decode spine) with
full TDD + first fuzz target, honestly reporting the long-tail remainder.

## Corrections from adversarial review (Codex, 2026-06-08)

Cleared to build `cursor` + `value` now. Before the deserializer/template path,
these are binding:

- **Chunk-relative API (BLOCKER).** Public decode takes the **full chunk bytes**
  plus the record's BinXML offset/range — never the payload slice alone. Name
  and template-definition offsets are relative to chunk start; the cursor's base
  is the chunk. `decode_record(chunk: &[u8], binxml_offset: usize, len: usize)`.
- **Template cache by GUID, not template_id.** Split two concerns: (a) when the
  instance carries an *inline* definition (`cursor.position()==def_offset`), skip
  its `24 + data_size` bytes; (b) resolve/parse the definition from the
  chunk-relative `def_offset`, cache the parsed IR keyed by the 16-byte **GUID**,
  and instantiate (deep-clone + resolve) per record.
- **Cycle + budget defense (BLOCKER).** String/template linked-list walks keep a
  **visited-offset set** + max-entries cap (the reference only breaks on
  `next==pos`, missing multi-node cycles). A single shared **budget** bounds:
  recursion depth (embedded BinXml 0x21, substitution fragments, template
  clone), token-loop iterations, substitution_count, decoded value bytes, array
  element count, repeated-element expansion, and total output nodes. Prefer an
  explicit work-stack over native recursion for element nesting.
- **Exact value semantics** (`value.rs`): `String` has two modes — *sized*
  (descriptor size = byte length, no prefix) vs *len-prefixed* (read `u16` char
  count); `SizeT` renders **hex** (`0x…`, 4→hex32 / 8→hex64); `Bool` = 4 bytes,
  nonzero=true; `Sid` = `8 + sub_count*4` bytes → `S-1-…`; FileTime/SysTime →
  UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ`; arrays `0x80|base` are u16-sized and expand
  the container — `AnsiStringArray/BinaryArray/SizeTArray` are **unsupported →
  Err**; embedded `BinXml(0x21)` recurses in **element** context only. All
  `len*2`, `offset+size`, `count*desc_size` use **checked arithmetic**.
- **JSON contract first.** `flatten_event_data` consumes: `Event.EventData` /
  `Event.UserData` as either the `{"Data":[{"@Name","#text"}]}` array shape or a
  flat `{key:val}` object (UserData may nest); `@`-prefixed and `#text` keys are
  meta. `json.rs` need only satisfy *that* contract — but a **differential
  parity test vs omerbenamram is created early** (phase 5, not 8) to prove it on
  real records. JSON parity is the highest hidden-effort risk.
- **Scope.** A template-free milestone is not useful (real records enter via
  TemplateInstance). This session: `cursor` + `value` + `name` fully TDD'd; the
  first real-record integration necessarily brings template + chunk context.

## Attribution

Port informed by omerbenamram `evtx` (Apache-2.0/MIT); retain its LICENSE
reference in `NOTICE`. Format facts cross-checked against libevtx (Metz).
