#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-}"
ADAPTER_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-browser-adapter.XXXXXX")"
trap 'rm -f "$ADAPTER_RECEIPT"' EXIT
"$ROOT/scripts/glassbox/run_browser_adapter_gate.sh" "$ADAPTER_RECEIPT" >/dev/null
python3 - "$ROOT" "$ADAPTER_RECEIPT" "$RECEIPT" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
adapter_path = pathlib.Path(sys.argv[2])
output_path = pathlib.Path(sys.argv[3]) if sys.argv[3] else None
adapter = json.loads(adapter_path.read_text())
manifest_path = root / "docs/glassbox/browser/candidate-production-native-host.json"
manifest = json.loads(manifest_path.read_text())
checks = {
    "separate_signed_adapter_gate": adapter.get("ok") is True,
    "candidate_manifest_exact": adapter.get("checks", {}).get(
        "candidate_manifest_targets_separate_adapter_and_exact_origin") is True,
    "extension_public_key_binds_exact_origin": adapter.get("checks", {}).get(
        "extension_id_is_bound_to_embedded_public_key") is True,
    "extension_permissions_are_native_messaging_only": adapter.get("checks", {}).get(
        "extension_permissions_are_native_messaging_only") is True,
    "signed_host_metadata_only_workflow": adapter.get("checks", {}).get(
        "signed_native_messaging_workflow_publishes_private_kernel_bundle") is True,
    "wrong_origin_replay_duplicate_time_watchdog_unknown_and_disconnect_fail_closed": all(
        adapter.get("checks", {}).get(name) is True
        for name in [
            "wrong_extension_origin_fails_before_input_without_bundle",
            "replay_fails_closed_without_bundle",
            "duplicate_request_fails_closed_without_bundle",
            "repeat_response_fails_closed_without_bundle",
            "backward_time_fails_closed_without_bundle",
            "authenticated_idle_session_watchdog_fails_closed_without_bundle",
            "unknown_fails_closed_without_bundle",
            "disconnect_fails_closed_without_bundle",
        ]
    ),
    "manifest_reset_preserves_evidence_and_user_export": adapter.get("checks", {}).get(
        "manifest_install_reset_is_private_and_preserves_inbox_and_user_export") is True,
    "offline_core_remains_two_executables": adapter.get("checks", {}).get(
        "sandboxed_core_remains_exactly_two_executables_without_browser_host") is True,
}
def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"
receipt = {
    "schema_version": "glassbox-browser-ipc/v1",
    "ok": all(checks.values()),
    "git_head": git("rev-parse", "HEAD"),
    "git_tree": git("rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(git("status", "--porcelain")),
    "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    "checks": checks,
    "adapter": adapter,
    "runtime_checks_remaining": adapter.get("external_requirements", []),
    "errors": [name for name, passed in checks.items() if not passed],
}
encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
if output_path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(encoded)
print(encoded, end="")
raise SystemExit(0 if receipt["ok"] else 1)
PY
