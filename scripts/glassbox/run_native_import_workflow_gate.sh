#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-native-import-workflow.json}"
TEMP="$(mktemp -d "${TMPDIR:-/tmp}/glassbox-native-import.XXXXXX")"
trap 'pkill -x Glassbox >/dev/null 2>&1 || true; rm -rf "$TEMP"' EXIT

HAR="$ROOT/crates/glassbox-fixtures/corpus/hostile-import/har/valid.har"
OTLP="$ROOT/crates/glassbox-fixtures/corpus/hostile-import/otlp/valid-traces.jsonl"
HAR_SHA="$(shasum -a 256 "$HAR" | awk '{print $1}')"
OTLP_SHA="$(shasum -a 256 "$OTLP" | awk '{print $1}')"

swift test --package-path "$ROOT/apps/glassbox-macos" >"$TEMP/swift-test.log" 2>&1
if grep -q 'warning:' "$TEMP/swift-test.log"; then
  echo "Swift import workflow build emitted warnings" >&2
  exit 1
fi
"$ROOT/script/build_and_run.sh" --stage-only >/dev/null
APP="$ROOT/dist/Glassbox.app"
BIN="$APP/Contents/MacOS/Glassbox"
HELPER="$APP/Contents/Helpers/glassbox-native-bridge"

"$HELPER" --import har "$HAR_SHA" session_001 <"$HAR" \
  >"$TEMP/har-payload.json" 2>"$TEMP/har-error.log"
set +e
"$HELPER" --import har "$(printf '0%.0s' {1..64})" session_002 <"$HAR" \
  >"$TEMP/mismatch-output" 2>"$TEMP/mismatch-error"
MISMATCH_STATUS=$?
set -e

pkill -x Glassbox >/dev/null 2>&1 || true
env -i HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" \
  GLASSBOX_IMPORT_FORMAT=otlp-jsonl GLASSBOX_SOURCE_SHA256="$OTLP_SHA" \
  "$BIN" --glassbox-import-probe --glassbox-interaction-probe <"$OTLP" \
  >"$TEMP/app-output" 2>"$TEMP/app-error" &
APP_PID=$!
INTERACTION_PAYLOAD=""
for _ in {1..600}; do
  WINDOW_TITLE="$(osascript -e 'tell application "System Events" to if exists process "Glassbox" then tell process "Glassbox" to if exists first window then return name of first window as text' 2>/dev/null || true)"
  if [[ "$WINDOW_TITLE" == "Glassbox probe result "* ]]; then
    INTERACTION_PAYLOAD="${WINDOW_TITLE#Glassbox probe result }"
    break
  fi
  kill -0 "$APP_PID" 2>/dev/null || break
  sleep 0.1
done
kill "$APP_PID" >/dev/null 2>&1 || true
wait "$APP_PID" >/dev/null 2>&1 || true
if [[ -z "$INTERACTION_PAYLOAD" ]]; then
  echo "signed imported-evidence interaction probe did not publish a result" >&2
  exit 1
fi
printf '%s' "$INTERACTION_PAYLOAD" >"$TEMP/interaction.b64"
python3 "$ROOT/scripts/glassbox/native_interaction_gate.py" \
  --root "$ROOT" --binary "$BIN" --result "$TEMP/interaction.b64" \
  --receipt "$TEMP/interaction.json" >/dev/null

python3 - "$ROOT" "$APP" "$BIN" "$HELPER" "$HAR" "$OTLP" "$TEMP" \
  "$MISMATCH_STATUS" "$RECEIPT" <<'PY'
import hashlib
import json
import os
import plistlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

root, app, binary, helper, har, otlp, temp = map(Path, sys.argv[1:8])
mismatch_status = int(sys.argv[8])
receipt = Path(sys.argv[9])

def run(args):
    return subprocess.run(args, text=True, capture_output=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args):
    result = run(["git", *args])
    return result.stdout.strip() if result.returncode == 0 else "unknown"

entitlements_result = run(["codesign", "-d", "--entitlements", ":-", str(app)])
entitlements_text = entitlements_result.stdout + entitlements_result.stderr
xml_start = entitlements_text.index("<?xml")
xml_end = entitlements_text.index("</plist>", xml_start) + len("</plist>")
entitlements = plistlib.loads(entitlements_text[xml_start:xml_end].encode())
helper_entitlements_result = run(["codesign", "-d", "--entitlements", ":-", str(helper)])
helper_entitlements_text = helper_entitlements_result.stdout + helper_entitlements_result.stderr

payload_text = (temp / "har-payload.json").read_text()
payload = json.loads(payload_text)
interaction = json.loads((temp / "interaction.json").read_text())
mismatch_output = (temp / "mismatch-output").read_bytes()
mismatch_error = (temp / "mismatch-error").read_bytes()
app_error = (temp / "app-error").read_bytes()
swift_log = (temp / "swift-test.log").read_text()
store_source = (root / "apps/glassbox-macos/Sources/Glassbox/Stores/InvestigationStore.swift").read_text()
service_source = (root / "apps/glassbox-macos/Sources/Glassbox/Services/RustEvidenceService.swift").read_text()
secrets = [
    "seed-host.example", "seed-query", "seed-cookie", "seed-header",
    "seed-request-body", "seed-response-body",
]
checks = {
    "swift_contract_tests_pass_without_warnings": "warning:" not in swift_log,
    "signed_app_entitlements_are_minimal_and_user_selected_read_only": entitlements == {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.files.user-selected.read-only": True,
    },
    "isolated_helper_has_no_entitlements": "<key>" not in helper_entitlements_text,
    "signed_har_import_is_kernel_validated_unknown_metadata": (
        payload.get("schema_version") == "glassbox-native-shell/v1"
        and payload.get("total_count") == 1
        and payload.get("kernel", {}).get("inserted") == 1
        and payload.get("view", {}).get("conclusion") == "unknown"
        and payload.get("unmarked_drop_count") == 0
    ),
    "signed_har_import_excludes_seeded_secrets_and_user_path": (
        all(secret not in payload_text for secret in secrets)
        and str(har) not in payload_text
    ),
    "digest_mismatch_has_no_payload_and_sanitized_error": (
        mismatch_status == 2
        and not mismatch_output
        and mismatch_error == b"glassbox-native-bridge: request rejected\n"
        and str(har).encode() not in mismatch_error
    ),
    "signed_imported_workspace_renders_complete_interaction_set": interaction.get("ok") is True,
    "signed_imported_workspace_emits_no_stderr_or_user_path": (
        not app_error and str(otlp).encode() not in app_error
    ),
    "supported_file_allowlist_is_exact": all(
        token in store_source for token in (
            '"har"', '"jsonl"', '"ndjson"', '"pcap"', '"pcapng"', '"glassbox"'
        )
    ) and '"logarchive"' not in store_source and '"trace"' not in store_source,
    "helper_execution_is_bounded_and_preserve_on_failure": all(
        token in service_source for token in (
            "maximumImportBytes", "maximumPayloadBytes", ".seconds(120)",
            "helperTimedOut", "helperOutputTooLarge",
        )
    ) and "payload = loaded" in store_source,
}
result = {
    "schema_version": "glassbox-native-import-workflow/v1",
    "ok": all(checks.values()),
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "git_head": git("-C", str(root), "rev-parse", "HEAD"),
    "git_tree": git("-C", str(root), "rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(git("-C", str(root), "status", "--porcelain")),
    "checks": checks,
    "app_sha256": sha(binary),
    "helper_sha256": sha(helper),
    "fixture_sha256": {"har": sha(har), "otlp_jsonl": sha(otlp)},
    "interaction_measurements": interaction.get("measurements"),
    "explicit_limits": {
        "maximum_selected_file_bytes": 4 * 1024 * 1024 * 1024,
        "maximum_helper_payload_bytes": 8 * 1024 * 1024,
        "helper_timeout_seconds": 120,
        "maximum_projected_rows": 200,
    },
    "enabled_formats": ["har", "otlp-jsonl", "pcap", "pcapng", "glassbox"],
    "disabled_raw_formats": ["logarchive", "trace"],
    "errors": [name for name, passed in checks.items() if not passed],
}
receipt.parent.mkdir(parents=True, exist_ok=True)
receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if result["ok"] else 1)
PY
