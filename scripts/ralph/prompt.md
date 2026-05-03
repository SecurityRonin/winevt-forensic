# Ralph Agent Task — winevt-forensic

Implement features from user stories using strict TDD (Red-Green-Refactor) until all stories pass.

## Workflow Per Iteration

1. Read `scripts/ralph/log.md` to understand what previous iterations completed.

2. Search `docs/user-stories/` for features with `"passes": false`.

3. If no features remain with `"passes": false`:
   - Output: <promise>FINISHED</promise>

4. Pick ONE feature — the highest priority non-passing feature based on dependencies and logical order.

5. Implement the feature using **strict TDD — no exceptions**:

   ### RED commit (MANDATORY FIRST)
   - Write failing tests that define the expected behavior
   - Run `cargo test --workspace` — confirm tests FAIL
   - Commit with prefix `test(red): ` — e.g. `test(red): time-range filter — 4 failing tests`
   - Do NOT write any implementation yet

   ### GREEN commit (MANDATORY SECOND)
   - Write the minimal implementation to make the tests pass
   - Run `cargo test --workspace` — confirm ALL tests PASS
   - Run `cargo clippy --workspace -- -D warnings` — fix any warnings
   - Run `cargo fmt --all` — format code
   - Commit with prefix `feat: GREEN — ` — e.g. `feat: GREEN — time-range filter`

   Each feature MUST produce exactly two commits: RED then GREEN.
   Never combine them into one commit.

6. Mark the feature as passing: set `"passes": true` in the corresponding JSON file.

7. Append to `scripts/ralph/log.md`:
   ```
   ## Iteration N — YYYY-MM-DD
   - Completed: <feature name>
   - RED commit: <hash>
   - GREEN commit: <hash>
   - Tests added: <count>
   ```

8. Loop — return to step 2.

## Rust-Specific Rules

- All new code lives in the appropriate crate under `crates/`
- New crates get added to `[workspace.members]` in root `Cargo.toml`
- New subcommands go in `crates/wt-evtx/src/main.rs`
- Library logic (parsing, analysis) goes in `winevt-core`, `winevt-session`, `winevt-analyze`, or a new crate
- No `unwrap()` in library code — use `anyhow::Result` or `thiserror`
- Clippy pedantic is enforced — `cargo clippy --workspace -- -D warnings` must pass

## What NOT To Do

- Do NOT write implementation before tests
- Do NOT skip the RED commit
- Do NOT batch multiple features in one iteration
- Do NOT use `#[allow(dead_code)]` to silence unused warnings — remove the dead code
