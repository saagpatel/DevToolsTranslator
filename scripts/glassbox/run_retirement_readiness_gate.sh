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
if [[ "$#" -gt 0 || -n "${GLASSBOX_RETIREMENT_AUTHORITY_CA:-}" ]]; then
  if [[ "$#" -ne 3 || -z "${GLASSBOX_CANDIDATE_MANIFEST:-}" || -z "${GLASSBOX_RETIREMENT_AUTHORITY_CA:-}" ]]; then
    echo "retirement promotion requires exactly three CMS evidence artifacts, candidate manifest, and product-authority CA" >&2
    exit 2
  fi
  ARGS+=(--authority-ca "$GLASSBOX_RETIREMENT_AUTHORITY_CA")
fi
python3 "$ROOT/scripts/glassbox/check_retirement_readiness.py" "${ARGS[@]}" "$@"
