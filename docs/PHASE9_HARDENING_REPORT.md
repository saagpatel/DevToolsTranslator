# Phase 9 Hardening Report

Date: 2026-02-22
Last verified: 2026-02-22

## Outcome
- Phase 9 hardening/regression closure is implemented across retention/deletion, diagnostics durability, runtime reliability, and fixture-regression expansion.
- `docs/SPEC_LOCK.md` remained unchanged.
- Remaining manual closeout item: interactive Chrome smoke (human-run) is still required before final release sign-off.

## Implemented Changes

### 1) Retention and deletion cascades
- Added migration `004_retention_hardening_v1.sql`:
  - `app_settings`
  - `retention_runs`
  - `bridge_diagnostics`
  - deterministic indexes for diagnostics and retention run history
- Added storage APIs in `~/Projects/DevToolsTranslator/crates/dtt-storage/src/lib.rs`:
  - `get_retention_policy`
  - `set_retention_policy`
  - `delete_session_with_artifacts`
  - `run_retention`
  - `run_retention_with_results`
  - `append_bridge_diagnostic`
  - `list_bridge_diagnostics`
- Added fail-safe artifact path guards (allowed managed roots only) and typed blocked-path behavior.
- Added running-session delete protection (`delete_blocked_running_session`).

### 2) Runtime hardening (extension + bridge)
- Extension reconnect behavior in `~/Projects/DevToolsTranslator/apps/extension-mv3/src/background.ts`:
  - deterministic reconnect schedule `1s -> 2s -> 5s -> 10s`
  - one `DTT.desktop_disconnect.v1` marker per disconnect episode during active capture
  - idempotent stop path retained
- Added reconnect utility + test:
  - `~/Projects/DevToolsTranslator/apps/extension-mv3/src/reconnect.ts`
  - `~/Projects/DevToolsTranslator/apps/extension-mv3/tests/reconnect.test.mjs`
- Desktop WS diagnostics are now persisted (not only in-memory ring):
  - `~/Projects/DevToolsTranslator/apps/desktop-tauri/src-tauri/src/ws_bridge.rs`

### 3) Desktop command + UI hardening for Phase 9 controls
- Added retention/delete command surface:
  - `~/Projects/DevToolsTranslator/apps/desktop-tauri/src-tauri/src/lib.rs`
  - `~/Projects/DevToolsTranslator/apps/desktop-tauri/src-tauri/src/tauri_commands.rs`
- Added UI client parity and mock support:
  - `~/Projects/DevToolsTranslator/apps/desktop-tauri/ui/src/api/client.ts`
- Added Settings retention controls + run-retention actions and session delete action:
  - `~/Projects/DevToolsTranslator/apps/desktop-tauri/ui/src/router.tsx`

### 4) Phase-wide regression and fixture closure
- Added retention/deletion/diagnostics tests in storage.
- Added Top-20 fixture completeness gate in storage tests.
- Added Top-20 raw/expected placeholder fixtures to satisfy locked catalog presence and deterministic test gating.

## Validation Evidence

Canonical source: `~/Projects/DevToolsTranslator/.codex/verify.commands`

All required canonical commands were run and passed on 2026-02-22:
1. `pnpm -r lint`
2. `pnpm -r typecheck`
3. `pnpm -r test`
4. `pnpm -r build`
5. `pnpm --filter @dtt/extension lint`
6. `pnpm --filter @dtt/extension test`
7. `pnpm --filter @dtt/extension build`
8. `pnpm --filter @dtt/desktop-ui test`
9. `pnpm --filter @dtt/desktop-ui build`
10. `cargo fmt --all -- --check`
11. `cargo clippy --workspace --all-targets -- -D warnings`
12. `cargo test --workspace`
13. `cargo build --workspace`
14. `cargo test -p dtt-desktop-core`
15. `cargo test -p dtt-storage`
16. `cargo build -p dtt-desktop-core`
17. `cargo test -p dtt-detectors`
18. `cargo test -p dtt-correlation`
19. `cargo test -p dtt-export`
20. `cargo test -p dtt-integrity`

Additional Phase 9 gate passed:
- `cargo check -p dtt-desktop-core --features desktop_shell`

Phase 9-specific tests now present and passing in `dtt-storage`:
- retention policy roundtrip + validation
- dry-run/apply retention behavior
- running-session delete block
- artifact path guard block behavior
- persisted diagnostics ordering/query
- Top-20 fixture completeness gate

## Risks / Follow-ups
1. Interactive Chrome smoke checklist is still manual and not executable in this shell-only environment.
- Tracking doc: `~/Projects/DevToolsTranslator/docs/PHASE6_SMOKE_EVIDENCE.md`
- Release sign-off should run that checklist on a workstation session.

2. Top-20 fixture catalog now has required raw/expected artifacts and gating coverage.
- Next hardening step can replace placeholder mapped fixtures with richer scenario-specific captures per fixture id.

## Status
- Phase 9: `in progress` for final release closeout due manual Chrome smoke dependency.
- Engineering gates: complete and passing.
