#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-process-context-gate.json}"
WORKFLOW_RECEIPT="${2:-${TMPDIR:-/tmp}/glassbox-process-adapter-workflow.json}"
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then
  echo "No Developer ID Application identity is available" >&2
  exit 2
fi
export GLASSBOX_CODESIGN_IDENTITY="$IDENTITY"
"$ROOT/script/build_and_run.sh" --stage-only
"$ROOT/script/build_process_context_adapter.sh" --stage-only
HELPER="$ROOT/dist/Glassbox Process Context.app/Contents/Helpers/glassbox-process-context-broker"
BRIDGE="$ROOT/dist/Glassbox.app/Contents/Helpers/glassbox-native-bridge"
GLASSBOX_PROCESS_BROKER_PATH="$HELPER" \
GLASSBOX_NATIVE_BRIDGE_PATH="$BRIDGE" \
GLASSBOX_PROCESS_WORKFLOW_RECEIPT="$WORKFLOW_RECEIPT" \
swift test --package-path "$ROOT/apps/glassbox-process-adapter-macos"
python3 "$ROOT/scripts/glassbox/process_context_gate.py" \
  --root "$ROOT" \
  --adapter-app "$ROOT/dist/Glassbox Process Context.app" \
  --workflow-receipt "$WORKFLOW_RECEIPT" \
  --core-app "$ROOT/dist/Glassbox.app" \
  --identity "$IDENTITY" \
  --receipt "$RECEIPT"
