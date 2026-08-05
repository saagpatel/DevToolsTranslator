#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-macos-artifact-readiness.json}"
USE_EXISTING="${GLASSBOX_MACOS_USE_EXISTING_ARTIFACTS:-0}"
if [[ -n "${GLASSBOX_CANDIDATE_MANIFEST:-}" ]]; then
  USE_EXISTING=1
fi

TEMP="$(mktemp -d "${TMPDIR:-/tmp}/glassbox-macos-artifact.XXXXXX")"
CONTAINER="$HOME/Library/Containers/com.glassbox.desktop"
CONTAINER_EXISTED=0
[[ -e "$CONTAINER" ]] && CONTAINER_EXISTED=1
cleanup() {
  pkill -x Glassbox >/dev/null 2>&1 || true
  if [[ $CONTAINER_EXISTED -eq 0 && -e "$CONTAINER" ]]; then rm -rf "$CONTAINER"; fi
  rm -rf "$TEMP"
}
trap cleanup EXIT

APP="$ROOT/dist/Glassbox.app"
DMG="$ROOT/dist/Glassbox-0.1.0.dmg"
if [[ "$USE_EXISTING" != "1" ]]; then
  IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
  if [[ -z "$IDENTITY" ]]; then echo "No Developer ID Application identity is available" >&2; exit 2; fi
  GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" "$ROOT/script/build_and_run.sh" --stage-only >/dev/null
fi
BIN="$APP/Contents/MacOS/Glassbox"
HELPER="$APP/Contents/Helpers/glassbox-native-bridge"

PRIVACY_RECEIPT="$TEMP/privacy-artifact.json"
python3 "$ROOT/scripts/glassbox/privacy_artifact_audit.py" --self-test >/dev/null
python3 "$ROOT/scripts/glassbox/privacy_artifact_audit.py" \
  --binary "$BIN" \
  --companion-binary "$HELPER" \
  --manifest "$APP/Contents/Resources/PrivacyInfo.xcprivacy" \
  --policy "$ROOT/docs/glassbox/PRIVACY-API-POLICY.json" \
  --receipt "$PRIVACY_RECEIPT" >/dev/null
export GLASSBOX_PRIVACY_AUDIT_RECEIPT="$PRIVACY_RECEIPT"

INTERACTION_RESULT="$TEMP/native-interaction.b64"
INTERACTION_RECEIPT="$TEMP/native-interaction.json"
INTERACTION_PROBE_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
python3 "$ROOT/scripts/glassbox/native_interaction_gate.py" --self-test >/dev/null
pkill -x Glassbox >/dev/null 2>&1 || true
for _ in {1..50}; do
  if ! pgrep -x Glassbox >/dev/null; then break; fi
  sleep 0.1
done
if pgrep -x Glassbox >/dev/null; then
  echo "A prior Glassbox process did not terminate before the interaction probe" >&2
  exit 1
fi
/usr/bin/open -n "$APP" --args --glassbox-interaction-probe "$INTERACTION_PROBE_ID"
INTERACTION_PAYLOAD=""
for _ in {1..600}; do
  WINDOW_TITLE="$(osascript -e 'tell application "System Events" to if exists process "Glassbox" then tell process "Glassbox" to if exists first window then return name of first window as text' 2>/dev/null || true)"
  if [[ "$WINDOW_TITLE" == "Glassbox probe result $INTERACTION_PROBE_ID "* ]]; then
    INTERACTION_PAYLOAD="${WINDOW_TITLE#Glassbox probe result $INTERACTION_PROBE_ID }"
    break
  fi
  sleep 0.1
done
pkill -x Glassbox >/dev/null 2>&1 || true
if [[ -z "$INTERACTION_PAYLOAD" ]]; then
  echo "Glassbox interaction probe did not publish its signed result" >&2
  exit 1
fi
printf '%s' "$INTERACTION_PAYLOAD" >"$INTERACTION_RESULT"
set +e
python3 "$ROOT/scripts/glassbox/native_interaction_gate.py" \
  --root "$ROOT" --binary "$BIN" --result "$INTERACTION_RESULT" \
  --receipt "$INTERACTION_RECEIPT" >/dev/null
INTERACTION_STATUS=$?
set -e
export GLASSBOX_NATIVE_INTERACTION_RECEIPT="$INTERACTION_RECEIPT"

/usr/bin/open -n "$APP"
for _ in {1..30}; do pgrep -x Glassbox >/dev/null && break; sleep 0.1; done
GLASSBOX_SIGNED_RUNTIME_OK=0
pgrep -x Glassbox >/dev/null && GLASSBOX_SIGNED_RUNTIME_OK=1
pkill -x Glassbox >/dev/null 2>&1 || true
GLASSBOX_RUNTIME_RESIDUE_CLEAN=1
if [[ $CONTAINER_EXISTED -eq 0 && -e "$CONTAINER" ]]; then rm -rf "$CONTAINER"; fi
if [[ $CONTAINER_EXISTED -eq 0 && -e "$CONTAINER" ]]; then GLASSBOX_RUNTIME_RESIDUE_CLEAN=0; fi
export GLASSBOX_SIGNED_RUNTIME_OK GLASSBOX_RUNTIME_RESIDUE_CLEAN

# Bind the distributable image to the exact already-signed app and nested helper.
if [[ "$USE_EXISTING" != "1" ]]; then
  mkdir -p "$TEMP/staging"
  ditto "$APP" "$TEMP/staging/Glassbox.app"
  hdiutil create -volname Glassbox -srcfolder "$TEMP/staging" -ov -format UDZO "$DMG" >/dev/null
  codesign --force --timestamp --sign "$IDENTITY" "$DMG" >/dev/null
fi
codesign --verify --strict "$HELPER"
set +e
if [[ "$USE_EXISTING" == "1" ]]; then
  "$ROOT/scripts/glassbox/verify_macos_artifact.sh" "$APP" "$DMG" "$RECEIPT"
else
  "$ROOT/scripts/glassbox/verify_macos_artifact.sh" --readiness "$APP" "$DMG" "$RECEIPT"
fi
VERIFY_STATUS=$?
set -e
if [[ "$INTERACTION_STATUS" -ne 0 ]]; then exit "$INTERACTION_STATUS"; fi
exit "$VERIFY_STATUS"
