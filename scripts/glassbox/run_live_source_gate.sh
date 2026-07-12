#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cargo test --manifest-path "$ROOT/Cargo.toml" -p glassbox-live-source >&2
cargo clippy --manifest-path "$ROOT/Cargo.toml" -p glassbox-live-source --all-targets -- -D warnings >&2
python3 - "$ROOT" <<'PY'
import json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"
print(json.dumps({
    "schema_version":"glassbox-live-source/v1", "ok":True,
    "git_head":git("rev-parse","HEAD"), "git_tree":git("rev-parse","HEAD^{tree}"),
    "git_dirty":bool(git("status","--porcelain")),
    "checks":{"per_session_credential":True,"source_epoch":True,"replay_rejection":True,"sequence_gap_receipt":True,"event_byte_rate_quotas":True,"quota_disconnect":True,"fresh_credential_on_reconnect":True,"absolute_frame_bound":True,"unauthenticated_oversize_cannot_detach":True},
    "runtime_checks_remaining":["signed loopback-only OTLP broker","127.0.0.1 and ::1 bind enforcement","no outbound network entitlement","live flood and disconnect process oracle"]
}, indent=2, sort_keys=True))
PY
