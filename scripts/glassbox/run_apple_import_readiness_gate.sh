#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-apple-import-readiness.json}"
TEMP="$(mktemp -d "${TMPDIR:-/tmp}/glassbox-apple-import.XXXXXX")"
trap 'rm -rf "$TEMP"' EXIT

swift test --package-path "$ROOT/apps/glassbox-macos" >"$TEMP/swift-test.log" 2>&1
swift test --package-path "$ROOT/apps/glassbox-instruments-adapter-macos" \
  >"$TEMP/instruments-swift-test.log" 2>&1
if grep -q 'warning:' "$TEMP/swift-test.log" "$TEMP/instruments-swift-test.log"; then
  echo "Swift Apple import build emitted warnings" >&2
  exit 1
fi
if [[ -z "${GLASSBOX_CANDIDATE_MANIFEST:-}" ]]; then
  "$ROOT/script/build_and_run.sh" --stage-only >/dev/null
  "$ROOT/script/build_instruments_adapter.sh" --stage-only >/dev/null
fi
APP="$ROOT/dist/Glassbox.app"
BIN="$APP/Contents/MacOS/Glassbox"
INSTRUMENTS_APP="$ROOT/dist/Glassbox Instruments Adapter.app"
INSTRUMENTS_BIN="$INSTRUMENTS_APP/Contents/MacOS/GlassboxInstrumentsAdapter"
mkdir "$TEMP/invalid.logarchive"

python3 - "$ROOT" "$APP" "$BIN" "$INSTRUMENTS_APP" "$INSTRUMENTS_BIN" \
  "$TEMP/invalid.logarchive" "$RECEIPT" <<'PY'
import hashlib
import json
import os
import plistlib
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

root, app, binary, instruments_app, instruments_binary, invalid_archive, receipt = map(Path, sys.argv[1:])
bridge = app / "Contents/Helpers/glassbox-native-bridge"

def run(args, timeout=10, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, **kwargs)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args):
    result = run(["git", *args], cwd=root)
    return result.stdout.strip() if result.returncode == 0 else "unknown"

descriptor = os.open(invalid_archive, os.O_RDONLY)
started = time.monotonic()
try:
    child = subprocess.run(
        [str(binary), "--glassbox-apple-log-project"],
        stdin=descriptor,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"GLASSBOX_SOURCE_ARTIFACT_SHA256": "a" * 64},
        timeout=10,
    )
finally:
    os.close(descriptor)
child_elapsed_ms = round((time.monotonic() - started) * 1000, 3)
entitlements_run = run(["codesign", "-d", "--entitlements", ":-", str(app)])
entitlements_text = entitlements_run.stdout + entitlements_run.stderr
try:
    xml_start = entitlements_text.index("<?xml")
    xml_end = entitlements_text.index("</plist>", xml_start) + len("</plist>")
    entitlements = plistlib.loads(entitlements_text[xml_start:xml_end].encode())
except (ValueError, plistlib.InvalidFileException):
    entitlements = {}
instruments_entitlements_run = run([
    "codesign", "-d", "--entitlements", ":-", str(instruments_app),
])
instruments_entitlements_text = (
    instruments_entitlements_run.stdout + instruments_entitlements_run.stderr
)
try:
    xml_start = instruments_entitlements_text.index("<?xml")
    xml_end = instruments_entitlements_text.index("</plist>", xml_start) + len("</plist>")
    instruments_entitlements = plistlib.loads(
        instruments_entitlements_text[xml_start:xml_end].encode()
    )
except (ValueError, plistlib.InvalidFileException):
    instruments_entitlements = {}
nm = run(["nm", "-u", str(binary)])
projector_source = (root / "apps/glassbox-macos/Sources/Glassbox/Services/AppleLogArchiveProjector.swift").read_text()
stager_source = (root / "apps/glassbox-macos/Sources/Glassbox/Services/SelectedArtifactStager.swift").read_text()
instruments_source = (root / "apps/glassbox-instruments-adapter-macos/Sources/GlassboxInstrumentsAdapter/Services/InstrumentsConversionService.swift").read_text()
instruments_app_source = (root / "apps/glassbox-instruments-adapter-macos/Sources/GlassboxInstrumentsAdapter/App/GlassboxInstrumentsAdapterApp.swift").read_text()
app_source = (root / "apps/glassbox-macos/Sources/Glassbox/App/GlassboxApp.swift").read_text()
projection_bytes = (root / "crates/glassbox-fixtures/corpus/hostile-import/apple-log/valid.ndjson").read_bytes()
projection_digest = hashlib.sha256(projection_bytes).hexdigest()
bridge_projection = subprocess.run(
    [str(bridge), "--import", "apple-log-projection", projection_digest, "apple_log_readiness"],
    input=projection_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
)
try:
    bridge_payload = json.loads(bridge_projection.stdout)
except json.JSONDecodeError:
    bridge_payload = {}

try:
    discovered = run(["/usr/bin/xcrun", "--find", "xctrace"], timeout=5)
    xctrace_path = discovered.stdout.strip() if discovered.returncode == 0 else ""
    version = run([xctrace_path, "version"], timeout=5) if xctrace_path else None
    help_result = run([xctrace_path, "help", "export"], timeout=5) if xctrace_path else None
except subprocess.TimeoutExpired:
    discovered = None
    xctrace_path = ""
    version = None
    help_result = None

executables = []
for path in app.rglob("*"):
    if path.is_file() and os.access(path, os.X_OK):
        executables.append(str(path.relative_to(app)))
instruments_executables = []
for path in instruments_app.rglob("*"):
    if path.is_file() and os.access(path, os.X_OK):
        instruments_executables.append(str(path.relative_to(instruments_app)))

checks = {
    "swift_contract_tests_pass": True,
    "signed_app_has_exactly_two_executables": sorted(executables) == [
        "Contents/Helpers/glassbox-native-bridge", "Contents/MacOS/Glassbox"
    ],
    "signed_app_is_app_sandbox_only": entitlements == {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.files.user-selected.read-only": True,
    },
    "signed_app_has_no_network_or_privileged_entitlements": all(
        key not in entitlements for key in (
            "com.apple.security.network.client", "com.apple.security.network.server",
            "com.apple.security.device.audio-input", "com.apple.security.device.camera",
            "com.apple.security.personal-information.location",
        )
    ),
    "oslogstore_public_api_linked": "_OBJC_CLASS_$_OSLogStore" in nm.stdout,
    "composed_message_not_accessed": ".composedMessage" not in projector_source,
    "invalid_archive_fails_fast_without_path_or_output": (
        child.returncode == 2 and not child.stdout and child_elapsed_ms < 10_000
        and bytes(str(invalid_archive), "utf-8") not in child.stderr
        and child.stderr == b"apple-log-projector: archive rejected\n"
    ),
    "trace_stager_is_link_free_bounded_and_atomic": all(token in stager_source for token in (
        "O_NOFOLLOW", "O_EXCL", "maximumFiles", "maximumBytes",
        "caseCollision", "removeItem(at: destination)", "realpath(path, nil)",
    )),
    "core_does_not_embed_or_launch_instruments_adapter": (
        "--glassbox-instruments-har-project" not in app_source
        and "xctrace" not in app_source
        and "Glassbox Instruments Adapter" not in app_source
    ),
    "signed_instruments_adapter_is_separate_entitlement_free_and_single_executable": (
        instruments_entitlements == {}
        and instruments_executables == ["Contents/MacOS/GlassboxInstrumentsAdapter"]
        and app.resolve() not in instruments_app.resolve().parents
        and instruments_app.resolve() not in app.resolve().parents
    ),
    "signed_instruments_adapter_is_handle_in_har_out_and_sanitized": (
        "--glassbox-instruments-har-project" in instruments_app_source
        and all(token in instruments_source for token in (
            "InstrumentsTraceStager.stage", "expectedSourceHash",
            "GLASSBOX_SOURCE_ARTIFACT_SHA256", "discoverXCTrace()",
            "--har", "to: .standardOutput", "instruments-adapter: trace rejected",
        ))
        and all(token in (
            root / "apps/glassbox-instruments-adapter-macos/Sources/GlassboxInstrumentsAdapter/Services/InstrumentsTraceStager.swift"
        ).read_text() for token in (
            "openat", "fstatat", "AT_SYMLINK_NOFOLLOW", "O_NOFOLLOW", "O_EXCL",
            "maximumEntries", "maximumBytes", "stable(", "glassbox-selected-directory-v1",
        ))
        and "CommandLine.arguments" not in instruments_source
    ),
    "completed_projection_reimports_through_offline_kernel_unknown": (
        bridge_projection.returncode == 0 and not bridge_projection.stderr
        and bridge_payload.get("schema_version") == "glassbox-native-shell/v1"
        and bridge_payload.get("total_count") == 2
        and bridge_payload.get("kernel", {}).get("inserted") == 2
        and bridge_payload.get("kernel", {}).get("relation_count") == 0
        and bridge_payload.get("view", {}).get("conclusion") == "unknown"
        and bridge_payload.get("unmarked_drop_count") == 0
    ),
    "xctrace_discovery_is_bounded": discovered is not None,
    "xctrace_export_surface_detected": (
        version is not None and version.returncode == 0 and len(version.stdout) <= 4_096
        and help_result is not None and help_result.returncode == 0
        and "--input <file>" in help_result.stdout and "--har" in help_result.stdout
    ),
}

result = {
    "schema_version": "glassbox-apple-import-readiness/v1",
    "ok": all(checks.values()),
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "git_head": git("rev-parse", "HEAD"),
    "git_tree": git("rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(git("status", "--porcelain")),
    "checks": checks,
    "signed_app_sha256": sha(binary),
    "instruments_adapter_sha256": sha(instruments_binary),
    "xctrace_version": version.stdout.strip() if version and version.returncode == 0 else None,
    "logarchive_import_enabled": False,
    "instruments_import_enabled": False,
    "gate2_promotable": False,
    "remaining": [
        "reviewed valid logarchive corpus and signed OSLogStore end-to-end projection",
        "reviewed valid Instruments trace corpus and noninteractive xctrace conversion",
    ],
    "errors": [] if all(checks.values()) else [name for name, passed in checks.items() if not passed],
}
receipt.parent.mkdir(parents=True, exist_ok=True)
receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if result["ok"] else 1)
PY

provided=0
for variable in GLASSBOX_APPLE_LOGARCHIVE_CORPUS GLASSBOX_APPLE_TRACE_CORPUS GLASSBOX_APPLE_CORPUS_REVIEW_CMS GLASSBOX_APPLE_CORPUS_REVIEWER_CA GLASSBOX_CANDIDATE_MANIFEST; do
  if [[ -n "${!variable:-}" ]]; then provided=$((provided + 1)); fi
done
if [[ "$provided" -ne 0 && "$provided" -ne 5 ]]; then
  echo "Apple promotion requires logarchive, trace, review CMS, reviewer CA, and candidate manifest together" >&2
  exit 2
fi
if [[ "$provided" -eq 5 ]]; then
  cp "$RECEIPT" "$TEMP/local-readiness.json"
  python3 "$ROOT/scripts/glassbox/apple_import_promotion.py" \
    --root "$ROOT" --candidate-manifest "$GLASSBOX_CANDIDATE_MANIFEST" \
    --app "$APP" --instruments-adapter "$INSTRUMENTS_APP" \
    --local-receipt "$TEMP/local-readiness.json" \
    --logarchive "$GLASSBOX_APPLE_LOGARCHIVE_CORPUS" --trace "$GLASSBOX_APPLE_TRACE_CORPUS" \
    --review-cms "$GLASSBOX_APPLE_CORPUS_REVIEW_CMS" --reviewer-ca "$GLASSBOX_APPLE_CORPUS_REVIEWER_CA" \
    --receipt "$RECEIPT" >/dev/null
fi
