# Phase 12 Release Promotion Report

Date: 2026-02-22  
Phase: Staged Public Prerelease, Signing Enforcement, OTLP-Optional Telemetry, Endurance Reliability

## Outcome
1. Staged public prerelease promotion flow is implemented with manual-smoke and signing/notarization gates.
2. Reliability telemetry remains local-first with optional OTLP configuration and explicit export run records.
3. Endurance/perf coverage now includes deterministic 6h/24h lane evaluation and CI wiring.
4. Phase 12 scenario fixtures and fidelity checks are present and enforced.
5. `docs/SPEC_LOCK.md` remains unchanged.

## Implemented Deliverables
1. Contracts and DTO parity
- `~/Projects/DevToolsTranslator/crates/dtt-core/src/lib.rs`
- `~/Projects/DevToolsTranslator/packages/shared-types/src/index.ts`

2. Storage migration and APIs
- `~/Projects/DevToolsTranslator/crates/dtt-storage/migrations/007_phase12_release_telemetry_endurance_v1.sql`
- `~/Projects/DevToolsTranslator/crates/dtt-storage/src/lib.rs`

3. Desktop backend and command surface
- `~/Projects/DevToolsTranslator/apps/desktop-tauri/src-tauri/src/lib.rs`
- `~/Projects/DevToolsTranslator/apps/desktop-tauri/src-tauri/src/tauri_commands.rs`

4. UI integration
- `~/Projects/DevToolsTranslator/apps/desktop-tauri/ui/src/api/client.ts`
- `~/Projects/DevToolsTranslator/apps/desktop-tauri/ui/src/router.tsx`
- `~/Projects/DevToolsTranslator/apps/desktop-tauri/ui/src/router.test.tsx`

5. Promotion and endurance automation
- `~/Projects/DevToolsTranslator/.github/workflows/release-staged-public-prerelease.yml`
- `~/Projects/DevToolsTranslator/.github/workflows/perf-reliability-regression.yml`
- `~/Projects/DevToolsTranslator/scripts/perf/run_endurance_suite.mjs`

6. Fixtures and expected snapshots
- `~/Projects/DevToolsTranslator/fixtures/raw/fx_phase12_endurance_6h.ndjson`
- `~/Projects/DevToolsTranslator/fixtures/raw/fx_phase12_endurance_24h.ndjson`
- `~/Projects/DevToolsTranslator/fixtures/expected/fx_phase12_endurance_6h.snapshot.ndjson`
- `~/Projects/DevToolsTranslator/fixtures/expected/fx_phase12_endurance_24h.snapshot.ndjson`

## Verification Snapshot (This Run)
1. Canonical suite from `~/Projects/DevToolsTranslator/.codex/verify.commands`: PASS (completed in this shell run after formatting).
2. Phase 12 command checks:
- `cargo check -p dtt-desktop-core --features desktop_shell`: PASS
- `cargo test -p dtt-desktop-core --features desktop_shell`: PASS
- `cargo test -p dtt-storage reliability -- --nocapture`: PASS
- `cargo test -p dtt-storage perf -- --nocapture`: PASS
- `cargo test -p dtt-storage telemetry_exports -- --nocapture`: PASS
- `cargo test -p dtt-storage release_promotion -- --nocapture`: PASS
- `node ~/Projects/DevToolsTranslator/scripts/release/release_desktop_mac.mjs --dry-run --version 0.1.0-beta.12`: PASS
- `node ~/Projects/DevToolsTranslator/scripts/release/release_desktop_windows.mjs --dry-run --version 0.1.0-beta.12`: PASS
- `node ~/Projects/DevToolsTranslator/scripts/release/release_desktop_linux.mjs --dry-run --version 0.1.0-beta.12`: PASS
- `node ~/Projects/DevToolsTranslator/scripts/release/package_extension_beta.mjs --dry-run --version 0.1.0-beta.12`: PASS
- `node ~/Projects/DevToolsTranslator/scripts/perf/run_perf_gate.mjs`: PASS
- `node ~/Projects/DevToolsTranslator/scripts/perf/run_endurance_suite.mjs --mode ci`: PASS (overall `warn`, no fail threshold breach)

## Release Gate Status
1. Automated promotion eligibility checks are implemented in code and workflow.
2. Human interactive Chrome smoke remains required for non-dry-run staged public publish.
   Marker format:
   `interactive_chrome_manual: pass|date=YYYY-MM-DD|observer=<name>`
3. Current interactive smoke status in this environment: `NOT RUN` (non-interactive shell).

## Follow-ups
1. Next-step closeout executed in this run:
- local staged promotion dry-run command passed:
  `pnpm run release:staged-public:dry-run -- --version 0.1.0-beta.12 --promote-from-internal-run-id internal_0.1.0-beta.12`
- publish path correctly blocks without manual marker:
  `pnpm run release:staged-public -- --version 0.1.0-beta.12 --promote-from-internal-run-id internal_0.1.0-beta.12`
- CI workflow dispatch from this filesystem snapshot is blocked because no `.git` remote context is available in the working directory.
2. Remaining manual closeout:
- append dated human browser smoke pass marker in `~/Projects/DevToolsTranslator/docs/PHASE6_SMOKE_EVIDENCE.md`.
3. Use staged public workflow for promotion only after manual evidence is present:
- `~/Projects/DevToolsTranslator/.github/workflows/release-staged-public-prerelease.yml`
