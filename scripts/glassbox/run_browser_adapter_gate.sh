#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-browser-adapter.json}"
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then echo "No Developer ID Application identity is available" >&2; exit 2; fi
cargo test --manifest-path "$ROOT/Cargo.toml" -p glassbox-browser-ipc -p glassbox-browser-host
cargo clippy --manifest-path "$ROOT/Cargo.toml" -p glassbox-browser-ipc -p glassbox-browser-host --all-targets -- -D warnings
swift test --package-path "$ROOT/apps/glassbox-browser-adapter-macos"
node --check "$ROOT/apps/glassbox-browser-extension/devtools.js"
node --check "$ROOT/apps/glassbox-browser-extension/panel.js"
GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" "$ROOT/script/build_and_run.sh" --stage-only
GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" "$ROOT/script/build_browser_adapter.sh" --stage-only
python3 "$ROOT/scripts/glassbox/browser_adapter_gate.py" \
  --root "$ROOT" \
  --adapter-app "$ROOT/dist/Glassbox Browser Adapter.app" \
  --core-app "$ROOT/dist/Glassbox.app" \
  --identity "$IDENTITY" \
  --receipt "$RECEIPT"
