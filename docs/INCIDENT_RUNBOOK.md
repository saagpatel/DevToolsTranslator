# Incident Runbook (Phase 14)

Date: 2026-02-22

## Scope
Operational triage for:
1. Capture bridge disconnect/reconnect instability and command failures.
2. Export/inspect integrity failures.
3. Release promotion gate failures (manual smoke, signing/notarization, provenance).
4. Optional OTLP telemetry export failures.
5. Endurance/perf budget regressions.
6. Extension public rollout and updater staged rollout failures.
7. Rollout controller auto-pause and auto-block actions.
8. Compliance evidence pack generation failures.

## Severity
1. `SEV-1`: privacy leak risk, artifact tampering risk, or irreversible data deletion risk.
2. `SEV-2`: release/capture/export workflows blocked without confirmed leak.
3. `SEV-3`: non-blocking diagnostics drift or degraded telemetry/perf signal.

## Initial Triage
1. Capture diagnostic snapshot from `/diagnostics` (bridge + telemetry + perf trend cards).
2. Query persisted diagnostics/metrics through UI commands:
- `ui_get_diagnostics`
- `ui_get_bridge_diagnostics`
- `ui_get_reliability_snapshot`
- `ui_list_reliability_series`
3. For release issues inspect:
- `ui_list_releases`
- `ui_get_signing_snapshot`
- `ui_start_release_promotion` dry-run result
 - `ui_get_release_health_scorecard`
 - `ui_run_rollout_controller_tick`
 - `ui_get_compliance_evidence_pack`
 - `ui_list_compliance_evidence_packs`
4. For telemetry issues inspect:
- `ui_get_telemetry_settings`
- `ui_list_telemetry_exports`
- `ui_run_telemetry_audit`
- `ui_list_telemetry_audits`
- `ui_list_perf_anomalies`

## Common Failure Signatures and Actions
1. `manual_smoke_missing`
- action: block non-dry-run promotion and append dated pass evidence in `~/Projects/DevToolsTranslator/docs/PHASE6_SMOKE_EVIDENCE.md`.
2. `signing_not_verified` / `notarization_not_verified`
- action: block promotion, rebuild artifacts, validate signing pipeline secrets and provenance.
3. `telemetry_export_failed`
- action: verify OTLP endpoint reachability and timeout, keep `local_only` mode active.
4. `bundle_invalid` / `integrity_failed`
- action: re-run `ui_validate_export`, inspect manifest/index/hash mismatch details.
5. endurance `budget_result=fail`
- action: run `node ~/Projects/DevToolsTranslator/scripts/perf/run_perf_gate.mjs` and `node ~/Projects/DevToolsTranslator/scripts/perf/run_endurance_suite.mjs --mode ci`, open regression triage with offending lane/check.
6. `cws_credentials_missing` / `extension_compliance_failed`
- action: keep rollout in dry-run mode, resolve missing CWS secrets/compliance failures, rerun stage package + publish scripts.
7. `updater_signature_missing` / `blocked_signature`
- action: regenerate updater feed with valid signature and confirm `ui_get_update_rollout_snapshot` shows `signature_verified=true`.
8. `telemetry_audit_failed`
- action: inspect violations via telemetry audits table, keep mode `local_only` until violations are resolved.
9. `soak_incomplete`
- action: keep rollout paused until 24h minimum soak is satisfied for current stage.
10. `compliance_pack_generation_failed`
- action: verify pack output path permissions and retry stage evaluation after pack regeneration.

## Containment
1. Keep telemetry in `local_only` until OTLP export failures are resolved.
2. Stop staged public promotion attempts when manual smoke/signing/provenance gates fail.
3. Hold release draft publication until all fail/warn items are dispositioned.
4. For capture instability, stop active sessions and preserve diagnostics rows for forensics.
5. Pause staged rollouts (`pct_5/25/50/100`) when anomalies or incidents exceed thresholds.
6. Respect controller `block` outcomes; only rerun after remediation evidence is available.

## Recovery
1. Release path:
- rerun internal-beta dry-run scripts
- verify checksums/manifests
- rerun promotion as dry-run
- only then attempt non-dry-run promotion.
2. Telemetry path:
- revert to `local_only`, clear failing endpoint config, rerun bounded telemetry export.
3. Perf path:
- compare current endurance report to previous baseline and revert recent high-impact changes when drift exceeds fail threshold.
4. Controller path:
- run evaluate scripts in dry-run mode to confirm gate reasons have cleared before non-dry-run advancement.
- store/review `rollout_stage_transitions` and `release_health_snapshots` records for audit trail.

## Escalation
1. Security/privacy incident (`SEV-1`): immediate owner escalation and release freeze.
2. Release blocker > 2h: escalate to release owner with report evidence.
3. Repeated bridge/pipeline failures over 24h: escalate to hardening backlog with RCA and mitigation owner.
