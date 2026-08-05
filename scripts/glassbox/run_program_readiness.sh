#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/artifacts/glassbox-program-readiness.json}"
RECEIPTS="${2:-$ROOT/artifacts/glassbox-program-readiness-receipts}"
mkdir -p "$RECEIPTS"

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
