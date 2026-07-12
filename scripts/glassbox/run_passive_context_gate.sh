#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-passive-context.json}"
TARGET_DIR="${GLASSBOX_PASSIVE_TARGET_DIR:-${TMPDIR:-/tmp}/glassbox-passive-target}"
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then
  echo "No Developer ID Application identity is available" >&2
  exit 2
fi
CARGO_TARGET_DIR="$TARGET_DIR" cargo test --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-passive-context-broker
CARGO_TARGET_DIR="$TARGET_DIR" cargo clippy --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-passive-context-broker --all-targets -- -D warnings
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-passive-context-broker
python3 "$ROOT/scripts/glassbox/passive_context_gate.py" "$ROOT" "$TARGET_DIR/debug/glassbox-passive-context-broker" "$IDENTITY" "$RECEIPT"
