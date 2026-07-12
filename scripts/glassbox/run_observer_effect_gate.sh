#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNTIME_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-observer-runtime.XXXXXX")"
trap 'rm -f "$RUNTIME_RECEIPT"' EXIT
"$ROOT/scripts/glassbox/run_otlp_broker_gate.sh" >"$RUNTIME_RECEIPT"
python3 - "$RUNTIME_RECEIPT" <<'PY'
import json, pathlib, sys
runtime = json.loads(pathlib.Path(sys.argv[1]).read_text())
observer = runtime.get("observer", {})
checks = {
    "runtime_broker_passed": runtime.get("ok") is True,
    "rss_under_128_mib": runtime.get("checks", {}).get("observer_rss_under_128_mib") is True,
    "1000_events_under_5_seconds": runtime.get("checks", {}).get("observer_1000_events_under_5_seconds") is True,
    "audit_output_excludes_secret": runtime.get("checks", {}).get("audit_output_excludes_secret") is True,
}
receipt = {
    "schema_version":"glassbox-observer-effect/v1", "ok":all(checks.values()),
    "git_head":runtime.get("git_head"), "git_tree":runtime.get("git_tree"), "git_dirty":runtime.get("git_dirty"),
    "checks":checks, "observer":observer,
    "runtime_checks_remaining":["sustained representative production-load study","resource-sampler observer-effect study","full UI workflow observer-effect study"],
    "errors":[name for name,value in checks.items() if not value],
}
print(json.dumps(receipt,indent=2,sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
