#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-lifecycle.json}"
if [[ -n "${GLASSBOX_LIFECYCLE_EVIDENCE_CMS:-}" || -n "${GLASSBOX_LIFECYCLE_TESTER_CA:-}" || -n "${GLASSBOX_LIFECYCLE_LOCAL_RECEIPT:-}" || -n "${GLASSBOX_CANDIDATE_MANIFEST:-}" ]]; then
  if [[ -z "${GLASSBOX_LIFECYCLE_EVIDENCE_CMS:-}" || -z "${GLASSBOX_LIFECYCLE_TESTER_CA:-}" || -z "${GLASSBOX_LIFECYCLE_LOCAL_RECEIPT:-}" || -z "${GLASSBOX_CANDIDATE_MANIFEST:-}" ]]; then
    echo "lifecycle promotion requires evidence CMS, tester CA, local receipt, and candidate manifest" >&2
    exit 2
  fi
  python3 "$ROOT/scripts/glassbox/lifecycle_evidence.py" \
    --root "$ROOT" \
    --candidate-manifest "$GLASSBOX_CANDIDATE_MANIFEST" \
    --local-receipt "$GLASSBOX_LIFECYCLE_LOCAL_RECEIPT" \
    --evidence-cms "$GLASSBOX_LIFECYCLE_EVIDENCE_CMS" \
    --tester-ca "$GLASSBOX_LIFECYCLE_TESTER_CA" \
    --app "$ROOT/dist/Glassbox.app" \
    --dmg "$ROOT/dist/Glassbox-0.1.0.dmg" \
    --receipt "$RECEIPT"
  exit $?
fi
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then echo "No Developer ID Application identity is available" >&2; exit 2; fi

python3 "$ROOT/scripts/glassbox/lifecycle_gate.py" --self-test >/dev/null
if [[ "${GLASSBOX_LIFECYCLE_USE_EXISTING_ARTIFACTS:-0}" != "1" ]]; then
  GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" "$ROOT/script/build_and_run.sh" --stage-only >/dev/null
fi
python3 "$ROOT/scripts/glassbox/lifecycle_gate.py" \
  --root "$ROOT" \
  --binary "$ROOT/dist/Glassbox.app/Contents/MacOS/Glassbox" \
  --helper "$ROOT/dist/Glassbox.app/Contents/Helpers/glassbox-native-bridge" \
  --identity "$IDENTITY" \
  --receipt "$RECEIPT"
