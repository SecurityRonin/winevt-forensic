# 8. Relicense the suite to Apache-2.0

Date: 2026-07-24
Status: Accepted

## Context

The suite originally shipped under MIT. The fleet standardized on Apache-2.0 for
its **explicit patent grant** — MIT is silent on patents, which matters for
tools published for broad reuse in a domain where patent exposure is a real
concern. Standardizing one license across the fleet also removes per-repo license
friction and keeps the crates.io metadata uniform.

Evidence: commit `234159f` (`chore(license): migrate MIT -> Apache-2.0 (fleet
standard)`), commit `9586697` (README Apache-2.0 badge), commit `91bb302`
(verbatim Apache-2.0 license text); `LICENSE` (11.1K, full Apache-2.0 text);
workspace `Cargo.toml` `license = "Apache-2.0"` inherited by every member;
`deny.toml` `[licenses] allow` includes `Apache-2.0`. Constitution: "the fleet
standardized on Apache-2.0 for its explicit patent grant — migrate any residual
MIT repos".

## Decision

1. License the entire workspace under **Apache-2.0**; declare it once at
   `[workspace.package]` and inherit it in every member (`license.workspace =
   true` / `license = "Apache-2.0"`).

2. Ship the full verbatim Apache-2.0 text as `LICENSE`, which the README badge
   links to as the single source of truth. No `## License` prose section in the
   README.

3. Keep `Apache-2.0` in the `cargo deny` license allowlist alongside the other
   permissive licenses the dependency graph pulls.

## Consequences

- Downstream users receive an explicit patent grant, not just copyright
  permission.
- The suite matches the rest of the fleet's licensing; a consumer mixing several
  fleet crates sees one consistent license.
- The BinXML port from the omerbenamram `evtx` crate (ADR 0004), itself
  Apache-2.0/MIT, is compatible with the Apache-2.0 relicense with attribution
  preserved.
