# Release Runbook (Phase 14)

Date: 2026-02-22  
Channels: `internal_beta`, `staged_public_prerelease`, `chrome_store_public`

## Preconditions
1. `docs/SPEC_LOCK.md` unchanged.
2. Canonical gates in `~/Projects/DevToolsTranslator/.codex/verify.commands` pass.
3. Phase 12 extras pass (desktop shell checks, release dry-runs, perf + endurance scripts).
4. Manual Chrome smoke evidence is present in `~/Projects/DevToolsTranslator/docs/PHASE6_SMOKE_EVIDENCE.md` with dated pass entry before any non-dry-run promotion.
   Required marker:
   `interactive_chrome_manual: pass|date=YYYY-MM-DD|observer=<name>`
5. For staged public prerelease promotion dry-runs, internal-beta desktop manifests must exist for target version:
- `dist/releases/internal-beta/<version>/desktop/release-manifest.v1.json`
- `dist/releases/internal-beta/<version>/desktop-windows/release-manifest.v1.json`
- `dist/releases/internal-beta/<version>/desktop-linux/release-manifest.v1.json`

## Internal Beta Pipeline
1. Local dry-run:
```bash
pnpm run release:desktop:mac:dry-run -- --version 0.1.0-beta.12
pnpm run release:desktop:windows:dry-run -- --version 0.1.0-beta.12
pnpm run release:desktop:linux:dry-run -- --version 0.1.0-beta.12
node ~/Projects/DevToolsTranslator/scripts/release/package_extension_beta.mjs --version 0.1.0-beta.12 --dry-run
```
2. CI workflow dispatch:
- `~/Projects/DevToolsTranslator/.github/workflows/release-internal-beta.yml`
- inputs: `version`, `notes`, `dry_run`
3. Outputs:
- platform manifests + checksums
- combined internal release manifest
- draft prerelease (non-dry-run only)

## Staged Public Prerelease Promotion
1. Promotion workflow:
- `~/Projects/DevToolsTranslator/.github/workflows/release-staged-public-prerelease.yml`
- inputs:
  - `version`
  - `notes`
  - `promote_from_internal_run_id`
  - `dry_run`
2. Enforcement before promotion:
- manual smoke file must contain pass-like evidence.
- provenance artifact generated: `release-provenance.v1.json`.
- promotion run stores deterministic artifact references and signing/notarization snapshot.
3. Non-dry-run behavior:
- creates staged public draft prerelease tag `v<version>-staged`.
4. Local equivalent command (dry-run):
```bash
pnpm run release:staged-public:dry-run -- --version 0.1.0-beta.12 --promote-from-internal-run-id internal_0.1.0-beta.12
```

## Extension Public Rollout (Chrome Web Store)
1. Package extension public artifacts:
```bash
node ~/Projects/DevToolsTranslator/scripts/release/package_extension_public.mjs --dry-run --version 0.1.0-beta.13
```
2. Publish stage (dry-run first):
```bash
node ~/Projects/DevToolsTranslator/scripts/release/publish_extension_cws.mjs --dry-run --version 0.1.0-beta.13 --stage pct_5
```
3. Non-dry-run requirements:
- `CWS_CLIENT_ID`
- `CWS_CLIENT_SECRET`
- `CWS_REFRESH_TOKEN`
- `CWS_EXTENSION_ID`
4. Stage progression policy:
- `pct_5 -> pct_25 -> pct_50 -> pct_100`
- minimum soak 24h between stage promotions
- block promotion when compliance checks fail.

## Rollout Controller Operations (Phase 14)
0. Run promotion readiness precheck before any non-dry-run operation:
```bash
node ~/Projects/DevToolsTranslator/scripts/release/check_promotion_readiness.mjs --version 0.1.0-beta.14 --channel staged_public_prerelease
```
Expected: `status=ready`. If `status=blocked`, clear blockers before proceeding.
1. Evaluate extension stage controller decision:
```bash
node ~/Projects/DevToolsTranslator/scripts/release/evaluate_extension_stage.mjs --dry-run --version 0.1.0-beta.14 --stage pct_5
```
2. Generate stage-advance approval artifact:
```bash
node ~/Projects/DevToolsTranslator/scripts/release/advance_extension_stage.mjs --dry-run --version 0.1.0-beta.14 --from-stage pct_5 --to-stage pct_25
```
3. Evaluate updater rollout stage controller decision:
```bash
node ~/Projects/DevToolsTranslator/scripts/release/evaluate_updater_rollout.mjs --dry-run --version 0.1.0-beta.14 --stage pct_5 --channel public_stable
```
4. Generate updater rollout stage advance artifact:
```bash
node ~/Projects/DevToolsTranslator/scripts/release/advance_updater_rollout.mjs --dry-run --version 0.1.0-beta.14 --from-stage pct_5 --to-stage pct_25 --channel public_stable
```
5. Scheduled controller workflow:
- `~/Projects/DevToolsTranslator/.github/workflows/release-extension-stage-controller.yml`
- dispatch inputs: `version`, `stage`, `dry_run`
- scheduled runs default to dry-run for safe continuous evaluation.
6. Non-dry-run stage advancement hard gates:
- manual smoke marker present
- compliance checks pass
- telemetry audit not failed
- anomaly budget not failed
- updater signature verified (updater flow)

## Compliance Evidence Packs (Phase 14)
1. Evidence packs are generated per stage under:
- `dist/releases/evidence/<kind>/<version>/<stage>/`
2. Evidence pack metadata is persisted and queryable through UI commands:
- `ui_get_compliance_evidence_pack`
- `ui_list_compliance_evidence_packs`
3. Updater feed metadata now carries:
- `rollout_stage`
- `compliance_evidence_pack_path`
- deterministic stage metadata (`policy`, `soak_hours_min`).

## Desktop Auto-Update Feed
1. Generate feed per channel:
```bash
node ~/Projects/DevToolsTranslator/scripts/release/generate_updater_feed.mjs --dry-run --version 0.1.0-beta.13 --channel staged_public_prerelease
```
2. Non-dry-run signature gate:
- requires `UPDATER_SIGNATURE`
- staged promotion workflow verifies `signature_verified=true` in feed JSON.
3. Eligibility policy:
- deterministic install bucket hash
- staged rollout percentages (`5`, `25`, `50`, `100`).

## Signing and Provenance Checks
1. Promotion gate requires desktop artifact signing/notarization status `verified`.
2. Validate with desktop command:
- `ui_get_signing_snapshot`
3. Provenance contract includes:
- `workflow_run_id`
- `source_commit`
- artifact hash list
- signing/notarization status

## Evidence Bundle for Release Decision
1. Manual smoke entry:
- `~/Projects/DevToolsTranslator/docs/PHASE6_SMOKE_EVIDENCE.md`
2. Phase 12 implementation report:
- `~/Projects/DevToolsTranslator/docs/PHASE12_RELEASE_PROMOTION_REPORT.md`
3. Latest promotion provenance:
- `dist/releases/staged-public-prerelease/<version>/release-provenance.v1.json`
4. Internal/manifests and checksums:
- `dist/releases/internal-beta/<version>/**/release-manifest.v1.json`
- `dist/releases/internal-beta/<version>/**/checksums.sha256`

## Rollback
1. Draft release rollback:
- remove draft tag/assets and rerun promotion with corrected source run.
2. Provenance/signing mismatch:
- mark run failed in `release_promotions`.
- do not publish; regenerate from valid internal run.
3. Artifact integrity mismatch:
- rerun packaging dry-run and checksum validation.
- increment beta/prerelease version before reattempt.
