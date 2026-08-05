#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="GlassboxInstrumentsAdapter"
PACKAGE="$ROOT/apps/glassbox-instruments-adapter-macos"
APP="$ROOT/dist/Glassbox Instruments Adapter.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
SIGN_IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:--}"

pkill -x "$APP_NAME" >/dev/null 2>&1 || true
swift build --package-path "$PACKAGE" --configuration release
SWIFT_BIN="$(swift build --package-path "$PACKAGE" --configuration release --show-bin-path)/$APP_NAME"
rm -rf "$APP"
mkdir -p "$MACOS" "$RESOURCES"
cp "$SWIFT_BIN" "$MACOS/$APP_NAME"
cp "$PACKAGE/Support/Info.plist" "$CONTENTS/Info.plist"
cp "$PACKAGE/Support/PrivacyInfo.xcprivacy" "$RESOURCES/PrivacyInfo.xcprivacy"
chmod 755 "$MACOS/$APP_NAME"
/usr/bin/xattr -cr "$APP"
SIGN_ARGS=(--force --options runtime --sign "$SIGN_IDENTITY")
[[ "$SIGN_IDENTITY" != "-" ]] && SIGN_ARGS+=(--timestamp)
# This separately distributed developer-tool adapter deliberately has no
# entitlements. The App-Sandboxed core never embeds or launches it.
codesign "${SIGN_ARGS[@]}" "$APP" >/dev/null

open_app() { /usr/bin/open -n "$APP"; }
case "$MODE" in
  --stage-only|stage) exit 0 ;;
  run) open_app ;;
  --debug|debug) lldb -- "$MACOS/$APP_NAME" ;;
  --verify|verify)
    open_app
    for _ in {1..30}; do pgrep -x "$APP_NAME" >/dev/null && exit 0; sleep 0.1; done
    echo "Glassbox Instruments Adapter did not remain running" >&2
    exit 1
    ;;
  *) echo "usage: $0 [run|--stage-only|--debug|--verify]" >&2; exit 2 ;;
esac
