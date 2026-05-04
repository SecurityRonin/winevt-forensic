# Ralph Agent Task — winevt-forensic

Implement features from user stories using strict TDD (Red-Green-Refactor) until all stories pass.

## Project Context

`winevt-forensic` is a deep EVTX forensic library workspace (NO CLI binary). Three crates:

- `winevt-core` — binary format types, domain types (`EvtxEvent`, `LogonSession`), lookup tables, `AntiForensicIndicator` enum
- `winevt-antiforensic` — detection algorithms (record ID gaps, checksum mismatches, timestamp anomalies)
- `winevt-carver` — EVTX chunk/record recovery from raw bytes, corrupt files, disk images

Pending addition: `winevt-memory` (ETW/EVTX types for memory forensics — no binary I/O).

See `PLAN.md` for full architectural spec and file inventory.

## Workflow Per Iteration

1. Read `scripts/ralph/log.md` to understand what previous iterations completed.

2. Search `docs/user-stories/` for features with `"passes": false`.

3. If no features remain with `"passes": false`:
   - Output: <promise>FINISHED</promise>

4. Pick ONE feature — highest priority, respecting dependencies in PLAN.md section 8.

   **Dependency order:**
   - Stories 01-03 (carver improvements) depend on existing `winevt-carver` and `winevt-antiforensic`
   - Stories 04-05 (winevt-memory) require creating the `winevt-memory` crate first
   - Do story 01 before 02, 02 before 03; stories 04 and 05 can be sequential

5. Implement the feature using **strict TDD — no exceptions**:

   ### RED commit (MANDATORY FIRST)
   - Write failing tests in the appropriate crate
   - Run `cargo test --workspace` — confirm tests FAIL
   - Commit with prefix `test(red): ` — e.g. `test(red): carver anti-forensic wiring — 3 failing tests`
   - Do NOT write any implementation yet

   ### GREEN commit (MANDATORY SECOND)
   - Write the minimal implementation to make the tests pass
   - Run `cargo test --workspace` — confirm ALL tests PASS
   - Run `cargo clippy --workspace -- -D warnings` — fix any warnings
   - Run `cargo fmt --all` — format code
   - Commit with prefix `feat: GREEN — ` — e.g. `feat: GREEN — carver anti-forensic wiring`

   Each feature MUST produce exactly two commits: RED then GREEN.
   Never combine them into one commit.

6. Mark the feature as passing: set `"passes": true` in the JSON file.

7. Append to `scripts/ralph/log.md`:
   ```
   ## Iteration N — YYYY-MM-DD
   - Completed: <feature name>
   - RED commit: <hash>
   - GREEN commit: <hash>
   - Tests added: <count>
   ```

8. Loop — return to step 2.

## Creating a New Crate (winevt-memory)

When implementing story 04 (winevt-memory crate):

1. `cargo new --lib crates/winevt-memory`
2. Add to `Cargo.toml` workspace members: `"crates/winevt-memory"`
3. Add to `[workspace.dependencies]`: `winevt-memory = { path = "crates/winevt-memory" }`
4. Set `Cargo.toml` deps: `winevt-core`, `winevt-antiforensic`, `serde { features = ["derive"] }`
5. Reference `PLAN.md` section 7 for types and API spec

## Rust Rules

- No `unwrap()` in library code — use `?` with `anyhow::Result` or `thiserror`
- No `#[allow(dead_code)]` — remove unused code instead
- `cargo clippy --workspace -- -D warnings` must pass before GREEN commit
- New crates: add to workspace members AND workspace.dependencies in root `Cargo.toml`
