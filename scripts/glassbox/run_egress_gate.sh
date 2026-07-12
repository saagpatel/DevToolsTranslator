#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HOSTILE_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-hostile-egress.XXXXXX")"
trap 'rm -f "$HOSTILE_RECEIPT"' EXIT

python3 "$ROOT/scripts/glassbox/check_boundaries.py" --self-test >/dev/null
python3 "$ROOT/scripts/glassbox/check_boundaries.py" >/dev/null
"$ROOT/scripts/glassbox/run_hostile_import_gate.sh" "$HOSTILE_RECEIPT" >/dev/null

python3 - "$ROOT" "$HOSTILE_RECEIPT" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
hostile = json.loads(pathlib.Path(sys.argv[2]).read_text())
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
}
receipt = {
    "schema_version": "glassbox-egress/v1",
    "ok": all(checks.values()),
    "checks": checks,
    "unexpected_source_hits": hits,
    "runtime_checks_remaining": [
        "signed core app entitlement inspection",
        "OS network-syscall monitoring across fixture/import/browse/compare/export workflows",
        "separate accounting for loopback and passive-context brokers",
    ],
}
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
