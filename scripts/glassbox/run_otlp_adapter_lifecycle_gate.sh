#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET_DIR="${GLASSBOX_OTLP_TARGET_DIR:-${TMPDIR:-/tmp}/glassbox-otlp-target}"
SOURCE_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/glassbox-reference-source.XXXXXX")"
trap 'rm -rf "$SOURCE_STAGE"' EXIT
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then
  echo "No Developer ID Application identity is available" >&2
  exit 2
fi
python3 "$ROOT/scripts/glassbox/otlp_adapter_lifecycle_gate.py" --self-test >/dev/null
GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" "$ROOT/script/build_and_run.sh" --stage-only >/dev/null
GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" "$ROOT/script/build_otlp_adapter.sh" --stage-only >/dev/null
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --locked --manifest-path "$ROOT/Cargo.toml" \
  -p glassbox-instrumented-source-probe
SOURCE_APP="$SOURCE_STAGE/Glassbox Reference Instrumented Source.app"
SOURCE_WORKFLOW_RECEIPT="$SOURCE_STAGE/reference-workflow.json"
mkdir -p "$SOURCE_APP/Contents/MacOS"
cp "$TARGET_DIR/debug/glassbox-instrumented-source-probe" \
  "$SOURCE_APP/Contents/MacOS/glassbox-instrumented-source-probe"
cp "$ROOT/scripts/glassbox/instrumented-source-probe/Support/Info.plist" \
  "$SOURCE_APP/Contents/Info.plist"
chmod 755 "$SOURCE_APP/Contents/MacOS/glassbox-instrumented-source-probe"
codesign --force --timestamp --options runtime \
  --entitlements "$ROOT/scripts/glassbox/instrumented-source-probe/Support/ReferenceSource.entitlements" \
  --sign "$IDENTITY" "$SOURCE_APP" >/dev/null
codesign --verify --deep --strict "$SOURCE_APP"
GLASSBOX_OTLP_BROKER_PATH="$ROOT/dist/Glassbox OTLP Adapter.app/Contents/Helpers/glassbox-otlp-broker" \
GLASSBOX_REFERENCE_SOURCE_PATH="$SOURCE_APP/Contents/MacOS/glassbox-instrumented-source-probe" \
GLASSBOX_NATIVE_BRIDGE_PATH="$ROOT/dist/Glassbox.app/Contents/Helpers/glassbox-native-bridge" \
GLASSBOX_REFERENCE_WORKFLOW_RECEIPT="$SOURCE_WORKFLOW_RECEIPT" \
  swift test --package-path "$ROOT/apps/glassbox-otlp-adapter-macos" >&2
test -s "$SOURCE_WORKFLOW_RECEIPT"
python3 "$ROOT/scripts/glassbox/otlp_adapter_lifecycle_gate.py" \
  --root "$ROOT" \
  --adapter-app "$ROOT/dist/Glassbox OTLP Adapter.app" \
  --reference-source-app "$SOURCE_APP" \
  --reference-workflow-receipt "$SOURCE_WORKFLOW_RECEIPT" \
  --core-app "$ROOT/dist/Glassbox.app" \
  --identity "$IDENTITY"
