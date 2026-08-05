#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-passive-context.json}"
TARGET_DIR="${GLASSBOX_PASSIVE_TARGET_DIR:-${TMPDIR:-/tmp}/glassbox-passive-target}"
BASE_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-passive-base.XXXXXX")"
LIFECYCLE_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-passive-lifecycle.XXXXXX")"
WORKFLOW_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-passive-workflow.XXXXXX")"
trap 'rm -f "$BASE_RECEIPT" "$LIFECYCLE_RECEIPT" "$WORKFLOW_RECEIPT"' EXIT
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then
  echo "No Developer ID Application identity is available" >&2
  exit 2
fi
CARGO_TARGET_DIR="$TARGET_DIR" cargo test --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-passive-context-broker
CARGO_TARGET_DIR="$TARGET_DIR" cargo clippy --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-passive-context-broker --all-targets -- -D warnings
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-passive-context-broker -p glassbox-native-bridge
python3 "$ROOT/scripts/glassbox/passive_context_gate.py" "$ROOT" "$TARGET_DIR/debug/glassbox-passive-context-broker" "$TARGET_DIR/debug/glassbox-native-bridge" "$IDENTITY" "$BASE_RECEIPT" >/dev/null
GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" \
  "$ROOT/scripts/glassbox/run_passive_adapter_lifecycle_gate.sh" "$LIFECYCLE_RECEIPT" "$WORKFLOW_RECEIPT" >/dev/null
python3 - "$BASE_RECEIPT" "$LIFECYCLE_RECEIPT" "$RECEIPT" <<'PY'
import json
import pathlib
import sys

base_path, lifecycle_path, output_path = map(pathlib.Path, sys.argv[1:])
base = json.loads(base_path.read_text())
lifecycle = json.loads(lifecycle_path.read_text())
base["checks"]["native_adapter_lifecycle_gate"] = lifecycle.get("ok") is True
base["ok"] = base.get("ok") is True and lifecycle.get("ok") is True
base["adapter_lifecycle"] = lifecycle
base["errors"] = [name for name, passed in base["checks"].items() if not passed]
base["external_requirements"] = lifecycle.get("external_requirements", [])
output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(base, indent=2, sort_keys=True) + "\n")
print(json.dumps(base, indent=2, sort_keys=True))
raise SystemExit(0 if base["ok"] else 1)
PY
