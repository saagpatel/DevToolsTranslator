#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/apps/glassbox-macos"

swift test --package-path "$APP" >/dev/null
swift build --package-path "$APP" --configuration release >/dev/null

require() {
  local file="$1" pattern="$2" label="$3"
  if ! grep -Eq "$pattern" "$file"; then
    printf 'accessibility gate failed: %s\n' "$label" >&2
    exit 1
  fi
}

WORKSPACE="$APP/Sources/Glassbox/Views/EvidenceWorkspaceView.swift"
INSPECTOR="$APP/Sources/Glassbox/Views/EvidenceInspectorView.swift"
EXPORT="$APP/Sources/Glassbox/Views/ExportReviewView.swift"
COMMANDS="$APP/Sources/Glassbox/App/GlassboxApp.swift"
CONTENT="$APP/Sources/Glassbox/Views/ContentView.swift"
require "$WORKSPACE" 'Picker\("Evidence view"' 'evidence modes lack a labeled native control'
require "$WORKSPACE" 'Complete tabular equivalent' 'missing complete table equivalent label'
require "$WORKSPACE" 'accessibilityLabel\("Actor-lane evidence timeline"\)' 'timeline lacks an accessible name'
require "$INSPECTOR" 'accessibilityLabel\("Evidence relationship inspector"\)' 'inspector lacks an accessible name'
require "$EXPORT" 'accessibilityIdentifier\("glassbox-export-review-sheet"\)' 'export review lacks stable accessibility identity'
require "$COMMANDS" 'keyboardShortcut' 'investigation action lacks a keyboard command'
require "$CONTENT" 'accessibilityIdentifier\("glassbox-import-evidence"\)' 'import action lacks stable accessibility identity'
require "$CONTENT" 'accessibilityLabel\("Importing evidence"\)' 'import progress lacks an accessible label'
require "$CONTENT" 'accessibilityIdentifier\("glassbox-resource-sampler"\)' 'resource sampler action lacks stable accessibility identity'
require "$CONTENT" 'No process identities or network activity are collected; context is not cause' 'resource sampler scope is not disclosed at the action'

python3 "$ROOT/scripts/glassbox/accessibility_evidence.py" --self-test >/dev/null
ARGS=(
  --app "$ROOT/dist/Glassbox.app"
  --dmg "$ROOT/dist/Glassbox-0.1.0.dmg"
)
if [[ -n "${GLASSBOX_ACCESSIBILITY_REVIEW_CMS:-}" || -n "${GLASSBOX_ACCESSIBILITY_REVIEWER_CA:-}" || -n "${GLASSBOX_CANDIDATE_MANIFEST:-}" ]]; then
  if [[ -z "${GLASSBOX_ACCESSIBILITY_REVIEW_CMS:-}" || -z "${GLASSBOX_ACCESSIBILITY_REVIEWER_CA:-}" || -z "${GLASSBOX_CANDIDATE_MANIFEST:-}" ]]; then
    echo "accessibility promotion requires review CMS, reviewer CA, and candidate manifest" >&2
    exit 2
  fi
  ARGS+=(
    --root "$ROOT"
    --candidate-manifest "$GLASSBOX_CANDIDATE_MANIFEST"
    --review-cms "$GLASSBOX_ACCESSIBILITY_REVIEW_CMS"
    --reviewer-ca "$GLASSBOX_ACCESSIBILITY_REVIEWER_CA"
  )
fi
python3 "$ROOT/scripts/glassbox/accessibility_evidence.py" "${ARGS[@]}"
