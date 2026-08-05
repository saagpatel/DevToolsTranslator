#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="GlassboxPassiveAdapter"
PACKAGE="$ROOT/apps/glassbox-passive-adapter-macos"
APP="$ROOT/dist/Glassbox Passive Context.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
HELPERS="$CONTENTS/Helpers"
RESOURCES="$CONTENTS/Resources"
TARGET_DIR="${GLASSBOX_PASSIVE_TARGET_DIR:-${TMPDIR:-/tmp}/glassbox-passive-target}"
SIGN_IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:--}"

pkill -x "$APP_NAME" >/dev/null 2>&1 || true
swift build --package-path "$PACKAGE" --configuration release
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --locked --release --manifest-path "$ROOT/Cargo.toml" -p glassbox-passive-context-broker

SWIFT_BIN="$(swift build --package-path "$PACKAGE" --configuration release --show-bin-path)/$APP_NAME"
RUST_BIN="$TARGET_DIR/release/glassbox-passive-context-broker"
rm -rf "$APP"
mkdir -p "$MACOS" "$HELPERS" "$RESOURCES"
cp "$SWIFT_BIN" "$MACOS/$APP_NAME"
cp "$RUST_BIN" "$HELPERS/glassbox-passive-context-broker"
cp "$PACKAGE/Support/Info.plist" "$CONTENTS/Info.plist"
cp "$PACKAGE/Support/PrivacyInfo.xcprivacy" "$RESOURCES/PrivacyInfo.xcprivacy"
chmod 755 "$MACOS/$APP_NAME" "$HELPERS/glassbox-passive-context-broker"
SIGN_ARGS=(--force --options runtime --sign "$SIGN_IDENTITY")
[[ "$SIGN_IDENTITY" != "-" ]] && SIGN_ARGS+=(--timestamp)
codesign --remove-signature "$HELPERS/glassbox-passive-context-broker" >/dev/null 2>&1 || true
codesign "${SIGN_ARGS[@]}" "$HELPERS/glassbox-passive-context-broker" >/dev/null
codesign "${SIGN_ARGS[@]}" --entitlements "$PACKAGE/Support/GlassboxPassiveAdapter.entitlements" "$APP" >/dev/null

open_app() { /usr/bin/open -n "$APP"; }
case "$MODE" in
  --stage-only|stage) exit 0 ;;
  run) open_app ;;
  --debug|debug) lldb -- "$MACOS/$APP_NAME" ;;
  --logs|logs) open_app; /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\"" ;;
  --telemetry|telemetry) open_app; /usr/bin/log stream --info --style compact --predicate 'subsystem == "com.glassbox.passive-adapter"' ;;
  --verify|verify)
    open_app
    for _ in {1..30}; do pgrep -x "$APP_NAME" >/dev/null && exit 0; sleep 0.1; done
    echo "Glassbox Passive Context did not remain running" >&2
    exit 1
    ;;
  *) echo "usage: $0 [run|--stage-only|--debug|--logs|--telemetry|--verify]" >&2; exit 2 ;;
esac
