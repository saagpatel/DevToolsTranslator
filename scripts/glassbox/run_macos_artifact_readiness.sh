#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-macos-artifact-readiness.json}"
TARGET_DIR="${GLASSBOX_DESKTOP_TARGET_DIR:-${TMPDIR:-/tmp}/glassbox-desktop-target}"
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then echo "No Developer ID Application identity is available" >&2; exit 2; fi
TEMP="$(mktemp -d "${TMPDIR:-/tmp}/glassbox-macos-artifact.XXXXXX")"; trap 'rm -rf "$TEMP"' EXIT
pnpm --dir "$ROOT/apps/glassbox-ui" build >/dev/null
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --locked --release --manifest-path "$ROOT/apps/glassbox-desktop/src-tauri/Cargo.toml"
APP="$TEMP/staging/Glassbox.app"; BIN="$APP/Contents/MacOS/Glassbox"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$TARGET_DIR/release/glassbox-desktop-shell" "$BIN"; cp "$ROOT/apps/glassbox-desktop/src-tauri/PrivacyInfo.xcprivacy" "$APP/Contents/Resources/PrivacyInfo.xcprivacy"; cp "$ROOT/apps/glassbox-desktop/src-tauri/icons/icon.png" "$APP/Contents/Resources/icon.png"
cat >"$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>Glassbox</string><key>CFBundleIdentifier</key><string>com.glassbox.desktop</string><key>CFBundleName</key><string>Glassbox</string><key>CFBundleDisplayName</key><string>Glassbox</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleShortVersionString</key><string>0.1.0</string><key>CFBundleVersion</key><string>1</string><key>LSMinimumSystemVersion</key><string>13.0</string><key>NSHighResolutionCapable</key><true/></dict></plist>
PLIST
codesign --force --timestamp --options runtime --entitlements "$ROOT/apps/glassbox-desktop/src-tauri/entitlements.plist" --sign "$IDENTITY" "$APP" >/dev/null
PRIVACY_RECEIPT="$TEMP/privacy-artifact.json"
python3 "$ROOT/scripts/glassbox/privacy_artifact_audit.py" --self-test >/dev/null
python3 "$ROOT/scripts/glassbox/privacy_artifact_audit.py" --binary "$BIN" --manifest "$APP/Contents/Resources/PrivacyInfo.xcprivacy" --policy "$ROOT/docs/glassbox/PRIVACY-API-POLICY.json" --receipt "$PRIVACY_RECEIPT" >/dev/null
export GLASSBOX_PRIVACY_AUDIT_RECEIPT="$PRIVACY_RECEIPT"
CONTAINER="$HOME/Library/Containers/com.glassbox.desktop"; CONTAINER_EXISTED=0; [[ -e "$CONTAINER" ]] && CONTAINER_EXISTED=1
mkdir -p "$TEMP/runtime-home"; HOME="$TEMP/runtime-home" CFFIXED_USER_HOME="$TEMP/runtime-home" "$BIN" >"$TEMP/runtime.stdout" 2>"$TEMP/runtime.stderr" & RUNTIME_PID=$!
sleep 2
GLASSBOX_SIGNED_RUNTIME_OK=0
if kill -0 "$RUNTIME_PID" 2>/dev/null; then GLASSBOX_SIGNED_RUNTIME_OK=1; kill "$RUNTIME_PID" 2>/dev/null || true; wait "$RUNTIME_PID" 2>/dev/null || true; fi
GLASSBOX_RUNTIME_RESIDUE_CLEAN=1
if [[ $CONTAINER_EXISTED -eq 0 && -e "$CONTAINER" ]]; then rm -rf "$CONTAINER"; fi
if [[ $CONTAINER_EXISTED -eq 0 && -e "$CONTAINER" ]]; then GLASSBOX_RUNTIME_RESIDUE_CLEAN=0; fi
export GLASSBOX_SIGNED_RUNTIME_OK GLASSBOX_RUNTIME_RESIDUE_CLEAN
DMG="$TEMP/Glassbox-0.1.0.dmg"; hdiutil create -volname Glassbox -srcfolder "$TEMP/staging" -ov -format UDZO "$DMG" >/dev/null; codesign --force --timestamp --sign "$IDENTITY" "$DMG" >/dev/null
"$ROOT/scripts/glassbox/verify_macos_artifact.sh" --readiness "$APP" "$DMG" "$RECEIPT"
