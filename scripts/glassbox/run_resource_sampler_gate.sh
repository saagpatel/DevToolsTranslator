#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-resource-sampler.json}"
TEMP="$(mktemp -d "${TMPDIR:-/tmp}/glassbox-resource-sampler.XXXXXX")"
trap 'pkill -x Glassbox >/dev/null 2>&1 || true; rm -rf "$TEMP"' EXIT

cargo test -p glassbox-native-bridge -q
cargo clippy -p glassbox-native-bridge --all-targets -- -D warnings
swift test --package-path "$ROOT/apps/glassbox-macos" >"$TEMP/swift-test.log" 2>&1
if grep -q 'warning:' "$TEMP/swift-test.log"; then
  echo "Swift resource sampler build emitted warnings" >&2
  exit 1
fi
"$ROOT/script/build_and_run.sh" --stage-only >/dev/null

APP="$ROOT/dist/Glassbox.app"
BIN="$APP/Contents/MacOS/Glassbox"
HELPER="$APP/Contents/Helpers/glassbox-native-bridge"

printf '' | "$HELPER" --sample-system gate_maximum 100 1 \
  >"$TEMP/maximum.json" 2>"$TEMP/maximum.err"
{ sleep 0.15; printf 'stop\n'; } | "$HELPER" --sample-system gate_stop 100 20 \
  >"$TEMP/stop.json" 2>"$TEMP/stop.err"
set +e
printf '' | "$HELPER" --sample-system 'bad/session' 99 0 \
  >"$TEMP/invalid.out" 2>"$TEMP/invalid.err"
INVALID_STATUS=$?
printf '' | "$HELPER" --sample-system too_long 5000 7 \
  >"$TEMP/too-long.out" 2>"$TEMP/too-long.err"
TOO_LONG_STATUS=$?
set -e

pkill -x Glassbox >/dev/null 2>&1 || true
for _ in {1..50}; do
  if ! pgrep -x Glassbox >/dev/null; then break; fi
  sleep 0.1
done
if pgrep -x Glassbox >/dev/null; then
  echo "A prior Glassbox process did not terminate before the resource-sampler probe" >&2
  exit 1
fi
INTERACTION_PROBE_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
env -i HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" \
  "$BIN" --glassbox-resource-sampler-probe --glassbox-interaction-probe "$INTERACTION_PROBE_ID" </dev/null \
  >"$TEMP/app.out" 2>"$TEMP/app.err" &
APP_PID=$!
INTERACTION_PAYLOAD=""
for _ in {1..600}; do
  WINDOW_TITLE="$(osascript -e 'tell application "System Events" to if exists process "Glassbox" then tell process "Glassbox" to if exists first window then return name of first window as text' 2>/dev/null || true)"
  if [[ "$WINDOW_TITLE" == "Glassbox probe result $INTERACTION_PROBE_ID "* ]]; then
    INTERACTION_PAYLOAD="${WINDOW_TITLE#Glassbox probe result $INTERACTION_PROBE_ID }"
    break
  fi
  kill -0 "$APP_PID" 2>/dev/null || break
  sleep 0.1
done
kill "$APP_PID" >/dev/null 2>&1 || true
wait "$APP_PID" >/dev/null 2>&1 || true
if [[ -z "$INTERACTION_PAYLOAD" ]]; then
  echo "signed resource-sampler interaction probe did not publish a result" >&2
  exit 1
fi
printf '%s' "$INTERACTION_PAYLOAD" >"$TEMP/interaction.b64"
python3 "$ROOT/scripts/glassbox/native_interaction_gate.py" \
  --root "$ROOT" --binary "$BIN" --result "$TEMP/interaction.b64" \
  --receipt "$TEMP/interaction.json" >/dev/null

python3 - "$ROOT" "$APP" "$HELPER" "$TEMP" "$INVALID_STATUS" "$TOO_LONG_STATUS" "$RECEIPT" <<'PY'
import json
import plistlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

root, app, helper, temp = map(Path, sys.argv[1:5])
invalid_status = int(sys.argv[5])
too_long_status = int(sys.argv[6])
receipt = Path(sys.argv[7])

def run(args):
    return subprocess.run(args, text=True, capture_output=True)

def git(*args):
    result = run(["git", *args])
    return result.stdout.strip() if result.returncode == 0 else "unknown"

def entitlements(path):
    result = run(["codesign", "-d", "--entitlements", ":-", str(path)])
    text = result.stdout + result.stderr
    if "<?xml" not in text:
        return {}, text
    start = text.index("<?xml")
    end = text.index("</plist>", start) + len("</plist>")
    return plistlib.loads(text[start:end].encode()), text

maximum = json.loads((temp / "maximum.json").read_text())
stopped = json.loads((temp / "stop.json").read_text())
interaction = json.loads((temp / "interaction.json").read_text())
app_entitlements, _ = entitlements(app)
_, helper_entitlements = entitlements(helper)
maximum_labels = [row["label"] for row in maximum["view"]["evidence_table"]]
stop_labels = [row["label"] for row in stopped["view"]["evidence_table"]]
bridge_source = (root / "apps/glassbox-native-bridge/src/main.rs").read_text()
swift_log = (temp / "swift-test.log").read_text()

checks = {
    "bounded_maximum_session_is_kernel_backed_and_terminal": (
        maximum["schema_version"] == "glassbox-native-shell/v1"
        and maximum["kernel"]["inserted"] == 2
        and maximum["kernel"]["relation_count"] == 0
        and maximum["view"]["scenario_id"] == "resource-sampler-session"
        and maximum["view"]["conclusion"] == "unknown"
        and any("system_sample" in label and "load_milli=" in label and "memory_estimate_bytes=" in label for label in maximum_labels)
        and any("session_end" in label and "reason=maximum_samples" in label and "sample_count=1" in label for label in maximum_labels)
    ),
    "visible_stop_produces_explicit_terminal_coverage": (
        stopped["kernel"]["relation_count"] == 0
        and stopped["view"]["conclusion"] == "unknown"
        and any("session_end" in label and "reason=user_stop" in label for label in stop_labels)
    ),
    "invalid_configuration_fails_closed_without_payload": (
        invalid_status == 2
        and not (temp / "invalid.out").read_bytes()
        and (temp / "invalid.err").read_bytes() == b"glassbox-native-bridge: request rejected\n"
        and too_long_status == 2
        and not (temp / "too-long.out").read_bytes()
        and (temp / "too-long.err").read_bytes() == b"glassbox-native-bridge: request rejected\n"
    ),
    "ordinary_aggregate_system_apis_only": (
        all(token in bridge_source for token in ("host_statistics64", "getloadavg", "sysctlbyname"))
        and all(token not in bridge_source for token in ("Command::new", "proc_pid", "netstat", "tcpdump", "nmap"))
        and "SourceTrust::SourceDeclared" in bridge_source
    ),
    "signed_native_workspace_renders_complete_interaction_set": interaction.get("ok") is True,
    "sampler_runtime_emits_no_stderr": not (temp / "maximum.err").read_bytes()
        and not (temp / "stop.err").read_bytes() and not (temp / "app.err").read_bytes(),
    "swift_contract_tests_pass_without_warnings": "warning:" not in swift_log,
    "core_app_entitlements_remain_minimal": app_entitlements == {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.files.user-selected.read-only": True,
    },
    "isolated_helper_has_no_entitlements": "<key>" not in helper_entitlements,
}

result = {
    "schema_version": "glassbox-resource-sampler/v1",
    "ok": all(checks.values()),
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "git_head": git("-C", str(root), "rev-parse", "HEAD"),
    "git_tree": git("-C", str(root), "rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(git("-C", str(root), "status", "--porcelain")),
    "checks": checks,
    "limits": {"interval_ms": [100, 5000], "maximum_samples": [1, 600], "maximum_configured_duration_ms": 30000, "native_default_ms": 500, "native_default_samples": 60},
    "fields": ["load_1m_milli", "load_5m_milli", "load_15m_milli", "memory_used_estimate_bytes", "memory_total_bytes", "memory_pressure"],
    "excluded": ["process_identity", "process_arguments", "network_activity", "filesystem_paths", "privileged_capture"],
    "trust": "source_declared",
    "interaction": interaction,
}
receipt.parent.mkdir(parents=True, exist_ok=True)
receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
if not result["ok"]:
    print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)
print(json.dumps(result, sort_keys=True))
PY
