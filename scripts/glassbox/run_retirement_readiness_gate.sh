#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-retirement-readiness.json}"
shift $(( $# > 0 ? 1 : 0 ))
python3 "$ROOT/scripts/glassbox/check_retirement_readiness.py" --self-test >/dev/null
python3 "$ROOT/scripts/glassbox/check_retirement_readiness.py" --readiness --receipt "$RECEIPT" "$@"
