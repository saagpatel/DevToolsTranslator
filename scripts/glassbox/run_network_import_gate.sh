#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET_DIR="${GLASSBOX_WORKER_TARGET_DIR:-${TMPDIR:-/tmp}/glassbox-worker-target}"
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then echo "No Developer ID Application identity is available" >&2; exit 2; fi
cargo test --manifest-path "$ROOT/Cargo.toml" -p glassbox-network-import -p glassbox-import-worker >&2
cargo clippy --manifest-path "$ROOT/Cargo.toml" -p glassbox-network-import -p glassbox-import-worker --all-targets -- -D warnings >&2
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-import-worker
python3 "$ROOT/scripts/glassbox/network_import_gate.py" "$ROOT" "$TARGET_DIR/debug/glassbox-import-worker" "$IDENTITY"
