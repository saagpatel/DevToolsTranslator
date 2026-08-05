#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-auxiliary-adapters-readiness.json}"
TEMP="$(mktemp -d "${TMPDIR:-/tmp}/glassbox-auxiliary-artifacts.XXXXXX")"
trap 'rm -rf "$TEMP"' EXIT

PROMOTION_CONFIGURED=0
for variable in GLASSBOX_AUXILIARY_FRESH_VM_CMS GLASSBOX_AUXILIARY_REVIEWER_CA GLASSBOX_CANDIDATE_MANIFEST; do
  [[ -n "${!variable:-}" ]] && PROMOTION_CONFIGURED=1
done
if [[ "$PROMOTION_CONFIGURED" -eq 1 ]]; then
  for variable in GLASSBOX_AUXILIARY_FRESH_VM_CMS GLASSBOX_AUXILIARY_REVIEWER_CA GLASSBOX_CANDIDATE_MANIFEST; do
    if [[ -z "${!variable:-}" ]]; then
      echo "auxiliary adapter promotion requires fresh-VM CMS, reviewer CA, and candidate manifest" >&2
      exit 2
    fi
  done
  python3 "$ROOT/scripts/glassbox/verify_auxiliary_adapters.py" \
    --root "$ROOT" --receipt "$RECEIPT" --mode strict
  exit $?
fi

IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then
  echo "No Developer ID Application identity is available" >&2
  exit 2
fi

GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" "$ROOT/script/build_otlp_adapter.sh" --stage-only >/dev/null
GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" "$ROOT/script/build_passive_context_adapter.sh" --stage-only >/dev/null
GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" "$ROOT/script/build_process_context_adapter.sh" --stage-only >/dev/null
GLASSBOX_CODESIGN_IDENTITY="$IDENTITY" "$ROOT/script/build_instruments_adapter.sh" --stage-only >/dev/null

package_dmg() {
  local app_name="$1"
  local volume_name="$2"
  local dmg_name="$3"
  local staging="$TEMP/$dmg_name"
  mkdir -p "$staging"
  ditto "$ROOT/dist/$app_name" "$staging/$app_name"
  hdiutil create -volname "$volume_name" -srcfolder "$staging" -ov -format UDZO "$ROOT/dist/$dmg_name" >/dev/null
  codesign --force --timestamp --sign "$IDENTITY" "$ROOT/dist/$dmg_name" >/dev/null
}

package_dmg "Glassbox OTLP Adapter.app" "Glassbox OTLP Adapter" "Glassbox-OTLP-Adapter-0.1.0.dmg"
package_dmg "Glassbox Passive Context.app" "Glassbox Passive Context" "Glassbox-Passive-Context-0.1.0.dmg"
package_dmg "Glassbox Process Context.app" "Glassbox Process Context" "Glassbox-Process-Context-0.1.0.dmg"
package_dmg "Glassbox Instruments Adapter.app" "Glassbox Instruments Adapter" "Glassbox-Instruments-Adapter-0.1.0.dmg"

python3 "$ROOT/scripts/glassbox/verify_auxiliary_adapters.py" \
  --root "$ROOT" --receipt "$RECEIPT" --mode readiness
