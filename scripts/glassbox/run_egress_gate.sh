#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HOSTILE_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-hostile-egress.XXXXXX")"
BROKER_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-broker-egress.XXXXXX")"
PASSIVE_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-passive-egress.XXXXXX")"
MACOS_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-macos-egress.XXXXXX")"
trap 'rm -f "$HOSTILE_RECEIPT" "$BROKER_RECEIPT" "$PASSIVE_RECEIPT" "$MACOS_RECEIPT"' EXIT

python3 "$ROOT/scripts/glassbox/check_boundaries.py" --self-test >/dev/null
python3 "$ROOT/scripts/glassbox/check_boundaries.py" >/dev/null
"$ROOT/scripts/glassbox/run_hostile_import_gate.sh" "$HOSTILE_RECEIPT" >/dev/null
"$ROOT/scripts/glassbox/run_otlp_broker_gate.sh" >"$BROKER_RECEIPT"
"$ROOT/scripts/glassbox/run_passive_context_gate.sh" "$PASSIVE_RECEIPT" >/dev/null
"$ROOT/scripts/glassbox/run_macos_artifact_readiness.sh" "$MACOS_RECEIPT" >/dev/null

python3 - "$ROOT" "$HOSTILE_RECEIPT" "$BROKER_RECEIPT" "$PASSIVE_RECEIPT" "$MACOS_RECEIPT" <<'PY'
import json
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
hostile = json.loads(pathlib.Path(sys.argv[2]).read_text())
broker = json.loads(pathlib.Path(sys.argv[3]).read_text())
passive = json.loads(pathlib.Path(sys.argv[4]).read_text())
macos = json.loads(pathlib.Path(sys.argv[5]).read_text())
protected = [
    root / "crates/glassbox-contracts",
    root / "crates/glassbox-kernel",
    root / "crates/glassbox-import",
    root / "crates/glassbox-investigation",
    root / "crates/glassbox-privacy",
    root / "apps/glassbox-import-worker",
    root / "apps/glassbox-ui",
    root / "crates/glassbox-browser-ipc",
    root / "crates/glassbox-live-source",
    root / "apps/glassbox-desktop/src-tauri",
]
forbidden_source = re.compile(r"\b(?:TcpStream|TcpListener|UdpSocket|reqwest|tokio_tungstenite)\b|\bfetch\s*\(")
hits = []
for base in protected:
    for path in base.rglob("*"):
        if not path.is_file() or any(part in {"dist", "target", "node_modules"} for part in path.parts):
            continue
        if path.suffix not in {".rs", ".ts", ".tsx", ".js", ".mjs"}:
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
    "passive_context_broker_separately_accounted": passive.get("checks", {}).get("ordinary_live_snapshot_passes") is True,
    "passive_context_has_no_network_or_privileged_entitlements": passive.get("checks", {}).get("no_network_or_privileged_entitlements") is True,
    "passive_context_active_scan_rejected": passive.get("checks", {}).get("active_scan_operation_rejected") is True,
    "signed_core_app_sandbox_only": macos.get("local_checks", {}).get("app_sandbox_only_entitlement") is True,
    "signed_core_app_network_entitlements_absent": macos.get("local_checks", {}).get("network_and_privileged_entitlements_absent") is True,
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
    "signed_core_app_sha256": macos.get("app_sha256"),
    "runtime_checks_remaining": [
        "OS network-syscall monitoring across fixture/import/browse/compare/export workflows",
    ],
}
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
