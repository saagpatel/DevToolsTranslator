#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-lifecycle.json}"
TARGET_DIR="${GLASSBOX_DESKTOP_TARGET_DIR:-${TMPDIR:-/tmp}/glassbox-desktop-target}"
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then echo "No Developer ID Application identity is available" >&2; exit 2; fi

python3 "$ROOT/scripts/glassbox/lifecycle_gate.py" --self-test >/dev/null
pnpm --dir "$ROOT/apps/glassbox-ui" build >/dev/null
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --locked --release --manifest-path "$ROOT/apps/glassbox-desktop/src-tauri/Cargo.toml"
python3 "$ROOT/scripts/glassbox/lifecycle_gate.py" \
  --root "$ROOT" \
  --binary "$TARGET_DIR/release/glassbox-desktop-shell" \
  --identity "$IDENTITY" \
  --receipt "$RECEIPT"
