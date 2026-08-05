#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-browser-artifact-readiness.json}"
TEMP="$(mktemp -d "${TMPDIR:-/tmp}/glassbox-browser-artifact.XXXXXX")"
trap 'rm -rf "$TEMP"' EXIT
APP="$ROOT/dist/Glassbox Browser Adapter.app"
DMG="$ROOT/dist/Glassbox-Browser-Adapter-0.1.0.dmg"
EXTENSION_ZIP="$ROOT/dist/Glassbox-Selected-Tab-Extension-0.1.0.zip"

# A supplied fresh-VM receipt is bound to the final external artifacts. Never
# rebuild, resign, or repackage them here, because doing so would invalidate
# exactly the hashes the external run attested.
if [[ -n "${GLASSBOX_BROWSER_FRESH_VM_CMS:-}" || -n "${GLASSBOX_BROWSER_REVIEWER_CA:-}" || -n "${GLASSBOX_CANDIDATE_MANIFEST:-}" ]]; then
  if [[ -z "${GLASSBOX_BROWSER_FRESH_VM_CMS:-}" || -z "${GLASSBOX_BROWSER_REVIEWER_CA:-}" || -z "${GLASSBOX_CANDIDATE_MANIFEST:-}" ]]; then
    echo "browser promotion requires fresh-VM CMS, reviewer CA, and candidate manifest" >&2
    exit 2
  fi
  "$ROOT/scripts/glassbox/verify_browser_artifact.sh" \
    "$APP" "$DMG" "$EXTENSION_ZIP" "$RECEIPT"
  exit $?
fi

IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then echo "No Developer ID Application identity is available" >&2; exit 2; fi
GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" "$ROOT/script/build_browser_adapter.sh" --stage-only >/dev/null
EXTENSION="$APP/Contents/Resources/Glassbox Selected Tab Extension"
mkdir -p "$TEMP/staging"
ditto "$APP" "$TEMP/staging/Glassbox Browser Adapter.app"
hdiutil create -volname "Glassbox Browser Adapter" -srcfolder "$TEMP/staging" -ov -format UDZO "$DMG" >/dev/null
codesign --force --timestamp --sign "$IDENTITY" "$DMG" >/dev/null
rm -f "$EXTENSION_ZIP"
(
  cd "$EXTENSION"
  /usr/bin/zip -X -q "$EXTENSION_ZIP" manifest.json devtools.html devtools.js panel.html panel.js panel.css
)
"$ROOT/scripts/glassbox/verify_browser_artifact.sh" --readiness "$APP" "$DMG" "$EXTENSION_ZIP" "$RECEIPT"
