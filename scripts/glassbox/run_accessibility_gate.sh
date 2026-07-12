#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/apps/glassbox-ui"

pnpm --dir "$ROOT" --filter @glassbox/investigation-ui test
pnpm --dir "$ROOT" --filter @glassbox/investigation-ui build

APP_TSX="$APP/src/App.tsx"
CSS="$APP/src/styles.css"

require() {
  local file="$1" pattern="$2" label="$3"
  if ! grep -Eq "$pattern" "$file"; then
    printf 'accessibility gate failed: %s\n' "$label" >&2
    exit 1
  fi
}

require "$APP_TSX" 'className="skip-link"' 'missing skip link'
require "$APP_TSX" 'role="tab"' 'evidence modes are not exposed as tabs'
require "$APP_TSX" '<caption className="sr-only">Complete tabular equivalent' 'missing complete table equivalent'
require "$APP_TSX" 'role="dialog" aria-modal="true"' 'export review is not a modal dialog'
require "$APP_TSX" 'aria-label="Evidence relationship inspector"' 'inspector lacks an accessible name'
require "$CSS" ':focus-visible' 'focus visibility is not defined'
require "$CSS" '@media \(prefers-reduced-motion: reduce\)' 'reduced-motion behavior is not defined'
require "$CSS" '@media \(max-width: 900px\)' 'compact responsive mode is not defined'

printf '{"schema_version":"glassbox-accessibility/v1","ok":true,"automated_scope":["semantic landmarks","keyboard-visible focus","modal semantics","complete table equivalent","reduced motion","responsive breakpoint","unit tests","production build"],"manual_scope_remaining":["VoiceOver task flow","macOS 200%% zoom visual review"]}\n'
