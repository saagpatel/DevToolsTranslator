#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-passive-adapter-lifecycle.json}"
WORKFLOW_RECEIPT="${2:-${TMPDIR:-/tmp}/glassbox-passive-adapter-workflow.json}"
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then
  echo "No Developer ID Application identity is available" >&2
  exit 2
fi
export GLASSBOX_CODESIGN_IDENTITY="$IDENTITY"
"$ROOT/script/build_and_run.sh" --stage-only
"$ROOT/script/build_passive_context_adapter.sh" --stage-only
HELPER="$ROOT/dist/Glassbox Passive Context.app/Contents/Helpers/glassbox-passive-context-broker"
BRIDGE="$ROOT/dist/Glassbox.app/Contents/Helpers/glassbox-native-bridge"
GLASSBOX_PASSIVE_BROKER_PATH="$HELPER" \
GLASSBOX_PASSIVE_FIXTURE_PATH="$ROOT/crates/glassbox-fixtures/corpus/passive-context/valid.txt" \
GLASSBOX_NATIVE_BRIDGE_PATH="$BRIDGE" \
GLASSBOX_PASSIVE_WORKFLOW_RECEIPT="$WORKFLOW_RECEIPT" \
swift test --package-path "$ROOT/apps/glassbox-passive-adapter-macos"
python3 "$ROOT/scripts/glassbox/passive_adapter_lifecycle_gate.py" \
  --root "$ROOT" \
  --adapter-app "$ROOT/dist/Glassbox Passive Context.app" \
  --workflow-receipt "$WORKFLOW_RECEIPT" \
  --core-app "$ROOT/dist/Glassbox.app" \
  --identity "$IDENTITY" \
  --receipt "$RECEIPT"
