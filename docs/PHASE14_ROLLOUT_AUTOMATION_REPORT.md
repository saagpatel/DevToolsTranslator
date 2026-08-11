# Phase 14 Rollout Automation Report

Date: 2026-02-22

## Scope Completed
1. Added rollout controller persistence and scorecard schema via migration `009_phase14_rollout_ops_scorecard_v1.sql`.
2. Implemented deterministic rollout decision services and UI facade commands for:
- extension stage evaluate/advance
- updater stage evaluate/advance
- rollout controller tick
- release health scorecard retrieval
3. Implemented compliance evidence pack generation/persistence and UI query paths.
4. Added extension and updater stage controller scripts:
- `scripts/release/evaluate_extension_stage.mjs`
- `scripts/release/advance_extension_stage.mjs`
- `scripts/release/evaluate_updater_rollout.mjs`
- `scripts/release/advance_updater_rollout.mjs`
5. Updated release workflows:
- new scheduled/dispatch controller workflow
- extension public workflow consumes controller approval artifact
- staged public prerelease workflow enforces scorecard pass for non-dry-run
- perf reliability workflow now publishes scorecard input artifact
6. Extended updater feed generation with deterministic stage and evidence-pack metadata.

## Evidence
1. Storage tests include deterministic coverage for:
- release health snapshots
- rollout stage transitions
- compliance evidence pack roundtrip/listing
2. Desktop core tests include:
- rollout controller gate precedence and stage ladder
- compliance pack deterministic generation
- scorecard merge behavior
3. UI tests remain passing with rollout/scorecard/evidence surfaces compiled and routed.

## Blocking Gates
1. Manual interactive Chrome smoke remains required for non-dry-run promotion:
- marker format: `interactive_chrome_manual: pass|date=YYYY-MM-DD|observer=<name>`
- source: `~/Projects/DevToolsTranslator/docs/PHASE6_SMOKE_EVIDENCE.md`
2. `docs/SPEC_LOCK.md` unchanged.

## Follow-up Closeout (2026-02-28)
1. Controller dry-run checks executed:
- `evaluate_extension_stage.mjs` returned `action=block` with `manual_smoke_missing` (expected).
- `evaluate_updater_rollout.mjs` returned `action=block` with `manual_smoke_missing` + `signature_invalid` (expected).
2. Non-dry-run safety gates validated:
- `publish_extension_cws.mjs` failed with `error_code=cws_credentials_missing` when CWS secrets were absent.
- `generate_updater_feed.mjs` failed with `error_code=updater_signature_missing` when `UPDATER_SIGNATURE` was absent.
3. Dry-run artifacts regenerated:
- extension public package manifest and checksums
- staged public updater feed with stage/evidence metadata
4. Perf follow-up:
- `run_perf_gate.mjs`: `overall=pass`
- `run_endurance_suite.mjs --mode ci`: `overall=warn` (within policy; no fail threshold breach)
5. Materialized issue resolved:
- `release_staged_public_prerelease.mjs --dry-run` initially failed because internal desktop manifests for `0.1.0-beta.14` were missing.
- Resolution: generated `mac/windows/linux` internal-beta dry-run desktop manifests first, then reran staged-public dry-run successfully.
6. Added promotion readiness precheck automation:
- script: `~/Projects/DevToolsTranslator/scripts/release/check_promotion_readiness.mjs`
- package command: `pnpm run release:promotion:readiness -- --version <v> --channel staged_public_prerelease`
- current run for `0.1.0-beta.14`: `status=blocked` with blockers:
  - `manual_smoke_missing`
  - `cws_credentials_missing`
  - `updater_signature_missing`
- report artifact:
  - `~/Projects/DevToolsTranslator/dist/releases/readiness/0.1.0-beta.14/promotion-readiness-staged_public_prerelease.v1.json`

## Operator Notes
1. For release advancement use controller scripts first, then publish scripts with generated approval file.
2. For non-dry-run updater promotion, signature verification and scorecard pass are mandatory.
3. For non-dry-run extension promotion, compliance and manual smoke gates are mandatory.
