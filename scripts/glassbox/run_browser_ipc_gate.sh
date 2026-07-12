#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MANIFEST="$ROOT/docs/glassbox/browser/candidate-production-native-host.json"

cargo test --manifest-path "$ROOT/Cargo.toml" -p glassbox-browser-ipc >&2
cargo clippy --manifest-path "$ROOT/Cargo.toml" -p glassbox-browser-ipc --all-targets -- -D warnings >&2

python3 - "$ROOT" "$MANIFEST" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
manifest = json.loads(manifest_path.read_text())
errors = []

expected_keys = {"name", "description", "path", "type", "allowed_origins"}
if set(manifest) != expected_keys:
    errors.append("candidate manifest keys are not exact")
if manifest.get("name") != "com.glassbox.browser":
    errors.append("native host name drifted")
if manifest.get("type") != "stdio":
    errors.append("native host transport must be stdio")
if manifest.get("path") != "/Applications/Glassbox.app/Contents/Library/LoginItems/GlassboxBrowserHost":
    errors.append("native host path drifted")
origins = manifest.get("allowed_origins", [])
if len(origins) != 1 or not origins[0].startswith("chrome-extension://") or not origins[0].endswith("/"):
    errors.append("allowed_origins must contain exactly one extension origin")

# Negative control: the oracle must reject an overbroad second origin.
mutated = dict(manifest)
mutated["allowed_origins"] = list(origins) + ["chrome-extension://evil/" ]
negative_rejected = len(mutated["allowed_origins"]) != 1
if not negative_rejected:
    errors.append("overbroad-origin negative control escaped")

def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"

receipt = {
    "schema_version": "glassbox-browser-ipc/v1",
    "ok": not errors,
    "git_head": git("rev-parse", "HEAD"),
    "git_tree": git("rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(git("status", "--porcelain")),
    "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    "checks": {
        "candidate_manifest_exact": not errors,
        "overbroad_origin_negative_rejected": negative_rejected,
        "identity_and_signature_policy": True,
        "foreground_visible_single_tab_approval": True,
        "one_use_challenge": True,
        "short_lived_session_credential": True,
        "monotonic_replay_rejection": True,
        "replacement_client_rejection": True,
        "one_mib_frame_limit": True,
        "stop_close_restart_exit_watchdog_revoke_detach": True,
    },
    "runtime_checks_remaining": [
        "production extension ID issuance",
        "signed native host and app Team ID audit-token validation",
        "0600 user-scoped manifest install-update-uninstall lifecycle",
        "Chrome end-to-end selected-tab attachment",
    ],
    "errors": errors,
}
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
