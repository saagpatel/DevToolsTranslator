#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-performance.json}"
TARGET_DIR="${GLASSBOX_PERF_TARGET_DIR:-${TMPDIR:-/tmp}/glassbox-performance-target}"
OUTPUT="$(mktemp "${TMPDIR:-/tmp}/glassbox-performance-output.XXXXXX")"
TIME_LOG="$(mktemp "${TMPDIR:-/tmp}/glassbox-performance-time.XXXXXX")"
trap 'rm -f "$OUTPUT" "$TIME_LOG"' EXIT

CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --release --manifest-path "$ROOT/glassbox-runtime/Cargo.toml" -p glassbox-storage-sqlite --example performance_probe
pnpm --dir "$ROOT/apps/glassbox-ui" test >/dev/null
pnpm --dir "$ROOT/apps/glassbox-ui" build >/dev/null
/usr/bin/time -l "$TARGET_DIR/release/examples/performance_probe" 1000000 >"$OUTPUT" 2>"$TIME_LOG"
python3 "$ROOT/scripts/glassbox/performance_gate.py" "$ROOT" "$OUTPUT" "$TIME_LOG" "$TARGET_DIR/release/examples/performance_probe" "$RECEIPT"
