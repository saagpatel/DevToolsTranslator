#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/artifacts/glassbox-program-readiness.json}"
RECEIPTS="${2:-$ROOT/artifacts/glassbox-program-readiness-receipts}"
mkdir -p "$RECEIPTS"

# Once a frozen candidate is supplied, no local gate may rebuild, re-sign, or
# repackage dist/. Reuse only the exact current clean source-bound local
# receipts, require the complete Gate 1-6 external set up front, and execute
# verify-only promotion paths against the frozen bytes.
if [[ -n "${GLASSBOX_CANDIDATE_MANIFEST:-}" ]]; then
  REQUIRED_PROMOTION_VARIABLES=(
    GLASSBOX_KEY_PROVISIONING_PROFILE
    GLASSBOX_APPLE_LOGARCHIVE_CORPUS
    GLASSBOX_APPLE_TRACE_CORPUS
    GLASSBOX_APPLE_CORPUS_REVIEW_CMS
    GLASSBOX_APPLE_CORPUS_REVIEWER_CA
    GLASSBOX_ACCESSIBILITY_REVIEW_CMS
    GLASSBOX_ACCESSIBILITY_REVIEWER_CA
    GLASSBOX_BROWSER_FRESH_VM_CMS
    GLASSBOX_BROWSER_REVIEWER_CA
    GLASSBOX_AUXILIARY_FRESH_VM_CMS
    GLASSBOX_AUXILIARY_REVIEWER_CA
    GLASSBOX_LIFECYCLE_LOCAL_RECEIPT
    GLASSBOX_LIFECYCLE_EVIDENCE_CMS
    GLASSBOX_LIFECYCLE_TESTER_CA
    GLASSBOX_BENCHMARK_STUDY_ARTIFACT
    GLASSBOX_BENCHMARK_INDEPENDENT_CMS
    GLASSBOX_BENCHMARK_VERIFIER_CA
  )
  for variable in "${REQUIRED_PROMOTION_VARIABLES[@]}"; do
    if [[ -z "${!variable:-}" ]]; then
      echo "frozen-candidate composition requires complete Gate 1-6 evidence; missing $variable" >&2
      exit 2
    fi
  done

  PREFLIGHT="$(mktemp "${TMPDIR:-/tmp}/glassbox-candidate-preflight.XXXXXX")"
  trap 'rm -f "$PREFLIGHT"' EXIT
  python3 "$ROOT/scripts/glassbox/candidate_manifest.py" \
    --root "$ROOT" --verify "$GLASSBOX_CANDIDATE_MANIFEST" >/dev/null
  python3 "$ROOT/scripts/glassbox/program_readiness.py" \
    --root "$ROOT" --receipts "$RECEIPTS" --receipt "$PREFLIGHT" \
    --candidate-manifest "$GLASSBOX_CANDIDATE_MANIFEST" >/dev/null

  python3 "$ROOT/scripts/glassbox/check_gate0.py" >"$RECEIPTS/gate0.json"
  "$ROOT/scripts/glassbox/run_key_lifecycle_readiness.sh" "$RECEIPTS/key_lifecycle.json" >/dev/null
  "$ROOT/scripts/glassbox/run_apple_import_readiness_gate.sh" "$RECEIPTS/apple_import.json" >/dev/null
  "$ROOT/scripts/glassbox/run_macos_artifact_readiness.sh" "$RECEIPTS/macos_artifact.json" >/dev/null
  "$ROOT/scripts/glassbox/run_browser_artifact_readiness.sh" "$RECEIPTS/browser_artifact.json" >/dev/null
  "$ROOT/scripts/glassbox/run_auxiliary_adapter_artifact_readiness.sh" "$RECEIPTS/auxiliary_adapters.json" >/dev/null
  "$ROOT/scripts/glassbox/run_lifecycle_gate.sh" "$RECEIPTS/lifecycle.json" >/dev/null
  "$ROOT/scripts/glassbox/run_accessibility_gate.sh" >"$RECEIPTS/accessibility.json"
  "$ROOT/scripts/glassbox/run_benchmark_readiness_gate.sh" "$RECEIPTS/benchmark.json" >/dev/null
  "$ROOT/scripts/glassbox/run_retirement_readiness_gate.sh" "$RECEIPTS/retirement.json" >/dev/null

  python3 "$ROOT/scripts/glassbox/program_readiness.py" \
    --root "$ROOT" --receipts "$RECEIPTS" --receipt "$OUT" \
    --candidate-manifest "$GLASSBOX_CANDIDATE_MANIFEST"
  exit $?
fi

set +e
python3 "$ROOT/scripts/glassbox/check_gate0.py" >"$RECEIPTS/gate0.json"
GATE0_STATUS=$?
set -e
if [[ "$GATE0_STATUS" -ne 0 && "$GATE0_STATUS" -ne 1 ]]; then
  echo "Gate 0 did not produce a valid pass or policy-refusal result" >&2
  exit 1
fi
python3 "$ROOT/scripts/glassbox/check_boundaries.py" >"$RECEIPTS/boundary.json"
"$ROOT/scripts/glassbox/verify_storage_sandbox_spike.sh" gate "$RECEIPTS/storage.json" >/dev/null
"$ROOT/scripts/glassbox/run_key_lifecycle_readiness.sh" "$RECEIPTS/key_lifecycle.json" >/dev/null
"$ROOT/scripts/glassbox/run_lifecycle_gate.sh" "$RECEIPTS/lifecycle.json" >/dev/null
"$ROOT/scripts/glassbox/run_hostile_import_gate.sh" "$RECEIPTS/hostile_import.json" >/dev/null
"$ROOT/scripts/glassbox/run_privacy_gate.sh" "$RECEIPTS/privacy.json" >/dev/null
"$ROOT/scripts/glassbox/run_native_import_workflow_gate.sh" "$RECEIPTS/native_import.json" >/dev/null
"$ROOT/scripts/glassbox/run_apple_import_readiness_gate.sh" "$RECEIPTS/apple_import.json" >/dev/null
"$ROOT/scripts/glassbox/run_mystery_acceptance.sh" "$RECEIPTS/mysteries.json" >/dev/null
"$ROOT/scripts/glassbox/run_browser_ipc_gate.sh" >"$RECEIPTS/browser_ipc.json"
"$ROOT/scripts/glassbox/run_browser_artifact_readiness.sh" "$RECEIPTS/browser_artifact.json" >/dev/null
"$ROOT/scripts/glassbox/run_auxiliary_adapter_artifact_readiness.sh" "$RECEIPTS/auxiliary_adapters.json" >/dev/null
"$ROOT/scripts/glassbox/run_live_source_gate.sh" >"$RECEIPTS/live_source.json"
"$ROOT/scripts/glassbox/run_resource_sampler_gate.sh" "$RECEIPTS/resource_sampler.json" >/dev/null
"$ROOT/scripts/glassbox/run_process_context_gate.sh" "$RECEIPTS/process_context.json" >/dev/null
"$ROOT/scripts/glassbox/run_observer_effect_gate.sh" >"$RECEIPTS/observer_effect.json"
"$ROOT/scripts/glassbox/run_network_import_gate.sh" >"$RECEIPTS/network_import.json"
"$ROOT/scripts/glassbox/run_passive_context_gate.sh" "$RECEIPTS/passive_context.json" >/dev/null
"$ROOT/scripts/glassbox/run_accessibility_gate.sh" >"$RECEIPTS/accessibility.json"
"$ROOT/scripts/glassbox/run_performance_gate.sh" "$RECEIPTS/performance.json" >/dev/null
"$ROOT/scripts/glassbox/run_egress_gate.sh" >"$RECEIPTS/egress.json"
"$ROOT/scripts/glassbox/run_macos_artifact_readiness.sh" "$RECEIPTS/macos_artifact.json" >/dev/null
"$ROOT/scripts/glassbox/run_benchmark_readiness_gate.sh" "$RECEIPTS/benchmark.json" >/dev/null
RETIREMENT_ARGS=()
for variable in \
  GLASSBOX_CODEC_RETIREMENT_EVIDENCE \
  GLASSBOX_PULSE_RETIREMENT_EVIDENCE \
  GLASSBOX_ECHOLOCATE_RETIREMENT_EVIDENCE
do
  value="${!variable:-}"
  if [[ -n "$value" ]]; then RETIREMENT_ARGS+=("$value"); fi
done
"$ROOT/scripts/glassbox/run_retirement_readiness_gate.sh" \
  "$RECEIPTS/retirement.json" "${RETIREMENT_ARGS[@]}" >/dev/null

python3 "$ROOT/scripts/glassbox/program_readiness.py" --self-test >/dev/null
PROGRAM_ARGS=(--root "$ROOT" --receipts "$RECEIPTS" --receipt "$OUT")
if [[ -n "${GLASSBOX_CANDIDATE_MANIFEST:-}" ]]; then
  PROGRAM_ARGS+=(--candidate-manifest "$GLASSBOX_CANDIDATE_MANIFEST")
fi
python3 "$ROOT/scripts/glassbox/program_readiness.py" "${PROGRAM_ARGS[@]}"
