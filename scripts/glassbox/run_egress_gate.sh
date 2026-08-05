#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HOSTILE_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-hostile-egress.XXXXXX")"
BROKER_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-broker-egress.XXXXXX")"
PASSIVE_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-passive-egress.XXXXXX")"
PROCESS_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-process-egress.XXXXXX")"
MACOS_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-macos-egress.XXXXXX")"
NETWORK_RUNTIME_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-network-runtime-egress.XXXXXX")"
BROWSER_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-browser-egress.XXXXXX")"
trap 'rm -f "$HOSTILE_RECEIPT" "$BROKER_RECEIPT" "$PASSIVE_RECEIPT" "$PROCESS_RECEIPT" "$MACOS_RECEIPT" "$NETWORK_RUNTIME_RECEIPT" "$BROWSER_RECEIPT"' EXIT

python3 "$ROOT/scripts/glassbox/check_boundaries.py" --self-test >/dev/null
python3 "$ROOT/scripts/glassbox/check_boundaries.py" >/dev/null
"$ROOT/scripts/glassbox/run_hostile_import_gate.sh" "$HOSTILE_RECEIPT" >/dev/null
"$ROOT/scripts/glassbox/run_otlp_broker_gate.sh" >"$BROKER_RECEIPT"
"$ROOT/scripts/glassbox/run_passive_context_gate.sh" "$PASSIVE_RECEIPT" >/dev/null
"$ROOT/scripts/glassbox/run_process_context_gate.sh" "$PROCESS_RECEIPT" >/dev/null
"$ROOT/scripts/glassbox/run_macos_artifact_readiness.sh" "$MACOS_RECEIPT" >/dev/null
"$ROOT/scripts/glassbox/run_network_runtime_gate.sh" "$NETWORK_RUNTIME_RECEIPT" >/dev/null
"$ROOT/scripts/glassbox/run_browser_ipc_gate.sh" "$BROWSER_RECEIPT" >/dev/null

python3 - "$ROOT" "$HOSTILE_RECEIPT" "$BROKER_RECEIPT" "$PASSIVE_RECEIPT" "$PROCESS_RECEIPT" "$MACOS_RECEIPT" "$NETWORK_RUNTIME_RECEIPT" "$BROWSER_RECEIPT" <<'PY'
import json
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
hostile = json.loads(pathlib.Path(sys.argv[2]).read_text())
broker = json.loads(pathlib.Path(sys.argv[3]).read_text())
passive = json.loads(pathlib.Path(sys.argv[4]).read_text())
process_context = json.loads(pathlib.Path(sys.argv[5]).read_text())
macos = json.loads(pathlib.Path(sys.argv[6]).read_text())
network_runtime = json.loads(pathlib.Path(sys.argv[7]).read_text())
browser = json.loads(pathlib.Path(sys.argv[8]).read_text())
manifest = json.loads((root / "docs/glassbox/COMPONENT-MANIFEST.json").read_text())
components = {item.get("path"): item for item in manifest.get("components", [])}
protected = [
    root / "crates/glassbox-contracts",
    root / "crates/glassbox-kernel",
    root / "crates/glassbox-import",
    root / "crates/glassbox-investigation",
    root / "crates/glassbox-privacy",
    root / "apps/glassbox-import-worker",
    root / "apps/glassbox-macos",
    root / "apps/glassbox-native-bridge",
    root / "apps/glassbox-otlp-adapter-macos/Sources",
    root / "apps/glassbox-passive-adapter-macos/Sources",
    root / "apps/glassbox-process-adapter-macos/Sources",
    root / "apps/glassbox-process-context-broker",
    root / "crates/glassbox-browser-ipc",
    root / "apps/glassbox-browser-host",
    root / "apps/glassbox-browser-adapter-macos/Sources",
    root / "apps/glassbox-browser-extension",
    root / "crates/glassbox-live-source",
    root / "crates/glassbox-har-import",
    root / "crates/glassbox-network-import",
    root / "crates/glassbox-otlp-import",
    root / "crates/glassbox-evidence-bundle",
    root / "crates/glassbox-apple-log-import",
    root / "scripts/glassbox/workflow-probe",
]
forbidden_source = re.compile(r"\b(?:TcpStream|TcpListener|UdpSocket|reqwest|tokio_tungstenite|URLSession|NWConnection|NWListener)\b|\b(?:fetch|socket)\s*\(")
hits = []
for base in protected:
    for path in base.rglob("*"):
        if not path.is_file() or any(part in {"dist", "target", "node_modules"} for part in path.parts):
            continue
        if path.suffix not in {".rs", ".swift", ".ts", ".tsx", ".js", ".mjs"}:
            continue
        if path == root / "apps/glassbox-import-worker/src/main.rs":
            # This is the deliberate, sandbox-denied socket negative control proven above.
            continue
        for line_no, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if forbidden_source.search(line):
                hits.append(f"{path.relative_to(root)}:{line_no}")

checks = {
    "core_worker_ui_dependency_denylist": not hits,
    "core_worker_ui_socket_source_absent": not hits,
    "sandboxed_worker_socket_negative_test": hostile.get("checks", {}).get("worker_no_network_self_test") is True,
    "sandboxed_worker_network_entitlements_absent": hostile.get("checks", {}).get("network_entitlements_absent") is True,
    "loopback_broker_separately_accounted": broker.get("checks", {}).get("ipv4_loopback_runtime") is True and broker.get("checks", {}).get("ipv6_loopback_runtime") is True,
    "loopback_broker_outbound_denied": broker.get("checks", {}).get("outbound_denied_by_sandbox") is True,
    "passive_context_broker_separately_accounted": passive.get("checks", {}).get("descriptor_authorized_live_capture_passes") is True,
    "passive_context_has_no_network_or_privileged_entitlements": passive.get("checks", {}).get("no_network_or_privileged_entitlements") is True,
    "passive_context_active_scan_rejected": passive.get("checks", {}).get("active_scan_operation_rejected") is True,
    "passive_native_adapter_is_sandboxed_without_network_or_privileged_entitlements": (
        passive.get("checks", {}).get("native_adapter_lifecycle_gate") is True
        and passive.get("adapter_lifecycle", {}).get("checks", {}).get(
            "adapter_entitlements_are_exactly_sandbox_and_user_selected_file"
        ) is True
    ),
    "passive_native_adapter_preserves_two_executable_offline_core": (
        passive.get("adapter_lifecycle", {}).get("checks", {}).get(
            "core_remains_exactly_native_app_and_rust_bridge_without_passive_helper"
        ) is True
    ),
    "process_context_adapter_is_separate_zero_entitlement_and_network_free": (
        process_context.get("ok") is True
        and process_context.get("checks", {}).get(
            "native_controller_and_rust_helper_have_exactly_zero_entitlements"
        ) is True
        and process_context.get("checks", {}).get(
            "process_adapter_sources_have_no_network_client_or_server_api"
        ) is True
    ),
    "process_context_preserves_sandboxed_two_executable_offline_core": (
        process_context.get("checks", {}).get(
            "sandboxed_core_remains_exactly_native_app_and_rust_bridge"
        ) is True
        and process_context.get("checks", {}).get(
            "sandboxed_negative_control_denies_cross_process_sampling_and_publishes_zero_bytes"
        ) is True
    ),
    "signed_core_app_sandbox_only": macos.get("local_checks", {}).get("app_sandbox_only_entitlement") is True,
    "signed_core_app_network_entitlements_absent": macos.get("local_checks", {}).get("network_and_privileged_entitlements_absent") is True,
    "complete_workflow_os_socket_monitor": network_runtime.get("ok") is True
        and network_runtime.get("checks", {}).get("observer_positive_control_detected_socket") is True
        and network_runtime.get("checks", {}).get("workflow_os_socket_rows_absent") is True
        and network_runtime.get("phases") == ["fixture", "import", "browse", "compare", "export"],
    "browser_adapter_is_separate_signed_zero_entitlement_artifact": (
        browser.get("ok") is True
        and browser.get("adapter", {}).get("checks", {}).get(
            "adapter_and_host_have_exactly_zero_entitlements"
        ) is True
        and browser.get("adapter", {}).get("checks", {}).get(
            "host_has_no_network_client_server_or_arbitrary_destination_api"
        ) is True
    ),
    "browser_adapter_preserves_sandboxed_two_executable_offline_core": (
        browser.get("adapter", {}).get("checks", {}).get(
            "sandboxed_core_remains_exactly_two_executables_without_browser_host"
        ) is True
        and browser.get("adapter", {}).get("checks", {}).get(
            "browser_gate_does_not_mutate_core_bundle"
        ) is True
    ),
    "reference_instrumented_source_network_client_is_test_only_and_outside_core": (
        components.get("scripts/glassbox/instrumented-source-probe", {}).get("class")
        == "glassbox_test"
        and components.get("scripts/glassbox/instrumented-source-probe", {}).get("disposition")
        == "test_only"
    ),
}
def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"
receipt = {
    "schema_version": "glassbox-egress/v1",
    "ok": all(checks.values()),
    "git_head": git("rev-parse", "HEAD"),
    "git_tree": git("rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(git("status", "--porcelain")),
    "checks": checks,
    "unexpected_source_hits": hits,
    "broker_binary_sha256": broker.get("binary_sha256"),
    "passive_context_binary_sha256": passive.get("binary_sha256"),
    "process_context_helper_sha256": process_context.get("adapter_helper_sha256"),
    "signed_core_app_sha256": macos.get("app_sha256"),
    "network_runtime_binary_sha256": network_runtime.get("workflow_binary_sha256"),
    "network_runtime_monitor_sha256": network_runtime.get("monitor_sha256"),
    "browser_host_sha256": browser.get("adapter", {}).get("host_sha256"),
    "runtime_checks_remaining": [],
}
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
