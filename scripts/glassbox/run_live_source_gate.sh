#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNTIME_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-otlp-runtime.XXXXXX")"
trap 'rm -f "$RUNTIME_RECEIPT"' EXIT
cargo test --manifest-path "$ROOT/Cargo.toml" -p glassbox-live-source >&2
cargo clippy --manifest-path "$ROOT/Cargo.toml" -p glassbox-live-source --all-targets -- -D warnings >&2
"$ROOT/scripts/glassbox/run_otlp_broker_gate.sh" >"$RUNTIME_RECEIPT"
python3 - "$ROOT" "$RUNTIME_RECEIPT" <<'PY'
import json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
runtime = json.loads(pathlib.Path(sys.argv[2]).read_text())
def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"
receipt = {
    "schema_version":"glassbox-live-source/v1", "ok":runtime.get("ok") is True,
    "git_head":git("rev-parse","HEAD"), "git_tree":git("rev-parse","HEAD^{tree}"),
    "git_dirty":bool(git("status","--porcelain")),
    "checks":{"per_session_credential":True,"source_epoch":True,"replay_rejection":True,"sequence_gap_receipt":True,"event_byte_rate_quotas":True,"quota_disconnect":True,"fresh_credential_on_reconnect":True,"absolute_frame_bound":True,"unauthenticated_oversize_cannot_detach":True,"signed_loopback_runtime":runtime.get("ok") is True},
    "runtime_broker":runtime,
    "runtime_checks_remaining":runtime.get("runtime_checks_remaining",[])
}
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
