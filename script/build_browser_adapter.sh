#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="GlassboxBrowserAdapter"
PACKAGE="$ROOT/apps/glassbox-browser-adapter-macos"
APP="$ROOT/dist/Glassbox Browser Adapter.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
HELPERS="$CONTENTS/Helpers"
RESOURCES="$CONTENTS/Resources"
EXTENSION="$RESOURCES/Glassbox Selected Tab Extension"
TARGET_DIR="${GLASSBOX_BROWSER_TARGET_DIR:-${TMPDIR:-/tmp}/glassbox-browser-target}"
SIGN_IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:--}"

pkill -x "$APP_NAME" >/dev/null 2>&1 || true
swift build --package-path "$PACKAGE" --configuration release
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --locked --release \
  --manifest-path "$ROOT/Cargo.toml" -p glassbox-browser-host

SWIFT_BIN="$(swift build --package-path "$PACKAGE" --configuration release --show-bin-path)/$APP_NAME"
RUST_BIN="$TARGET_DIR/release/glassbox-browser-host"
rm -rf "$APP"
mkdir -p "$MACOS" "$HELPERS" "$RESOURCES"
cp "$SWIFT_BIN" "$MACOS/$APP_NAME"
cp "$RUST_BIN" "$HELPERS/glassbox-browser-host"
cp "$PACKAGE/Support/Info.plist" "$CONTENTS/Info.plist"
cp "$PACKAGE/Support/PrivacyInfo.xcprivacy" "$RESOURCES/PrivacyInfo.xcprivacy"
mkdir -p "$EXTENSION"
for file in manifest.json devtools.html devtools.js panel.html panel.js panel.css; do
  cp "$ROOT/apps/glassbox-browser-extension/$file" "$EXTENSION/$file"
done
chmod 755 "$MACOS/$APP_NAME" "$HELPERS/glassbox-browser-host"
SIGN_ARGS=(--force --options runtime --sign "$SIGN_IDENTITY")
[[ "$SIGN_IDENTITY" != "-" ]] && SIGN_ARGS+=(--timestamp)
codesign --remove-signature "$HELPERS/glassbox-browser-host" >/dev/null 2>&1 || true
codesign "${SIGN_ARGS[@]}" "$HELPERS/glassbox-browser-host" >/dev/null
# This source-specific adapter and host are separately distributed and have no
# entitlements. The App-Sandboxed Glassbox core never embeds or launches them.
codesign "${SIGN_ARGS[@]}" "$APP" >/dev/null

open_app() { /usr/bin/open -n "$APP"; }
case "$MODE" in
  --stage-only|stage) exit 0 ;;
  run) open_app ;;
  --debug|debug) lldb -- "$MACOS/$APP_NAME" ;;
  --logs|logs) open_app; /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\"" ;;
  --verify|verify)
    open_app
    for _ in {1..30}; do pgrep -x "$APP_NAME" >/dev/null && exit 0; sleep 0.1; done
    echo "Glassbox Browser Adapter did not remain running" >&2
    exit 1
    ;;
  *) echo "usage: $0 [run|--stage-only|--debug|--logs|--verify]" >&2; exit 2 ;;
esac
