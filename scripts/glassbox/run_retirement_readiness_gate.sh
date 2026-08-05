#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-retirement-readiness.json}"
shift $(( $# > 0 ? 1 : 0 ))
python3 "$ROOT/scripts/glassbox/check_retirement_readiness.py" --self-test >/dev/null
ARGS=(--readiness --receipt "$RECEIPT")
if [[ -n "${GLASSBOX_CANDIDATE_MANIFEST:-}" ]]; then
  ARGS+=(--candidate-manifest "$GLASSBOX_CANDIDATE_MANIFEST")
fi
python3 "$ROOT/scripts/glassbox/check_retirement_readiness.py" "${ARGS[@]}" "$@"
