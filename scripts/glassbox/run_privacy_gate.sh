#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RECEIPT=${1:-"$ROOT/artifacts/glassbox-privacy-gate.json"}
TARGET_DIR=${GLASSBOX_PRIVACY_TARGET_DIR:-"${TMPDIR:-/tmp}/glassbox-privacy-target"}
OUTPUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-privacy-output.XXXXXX")
MALFORMED_OUTPUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-privacy-malformed.XXXXXX")
trap 'rm -f "$OUTPUT" "$MALFORMED_OUTPUT"' EXIT

CORPUS="$ROOT/crates/glassbox-fixtures/corpus/privacy"
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --manifest-path "$ROOT/Cargo.toml" \
  -p glassbox-privacy --example privacy_probe
"$TARGET_DIR/debug/examples/privacy_probe" "$CORPUS/seeded-secrets.json" >"$OUTPUT"
if "$TARGET_DIR/debug/examples/privacy_probe" "$CORPUS/malformed-url.json" >"$MALFORMED_OUTPUT" 2>/dev/null; then
  echo "malformed URL unexpectedly produced an export" >&2
  exit 1
fi

python3 - "$ROOT" "$CORPUS/seeded-secrets.json" "$OUTPUT" "$RECEIPT" <<'PY'
import hashlib, json, re, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

root, fixture_path, output_path, receipt_path = map(Path, sys.argv[1:])
fixture = json.loads(fixture_path.read_text())
output_text = output_path.read_text()
export = json.loads(output_text)
seeded = sorted(set(re.findall(r"seed-[a-z-]+", fixture_path.read_text())))
leaks = [marker for marker in seeded if marker in output_text]
preview = export.get("preview", [])
manifest = export.get("manifest", {})
unknown = next((item for item in preview if item["source"] == "future_schema"), {})
checks = {
    "zero_seeded_secret_leaks": not leaks,
    "field_level_preview_complete": len(preview) == len(fixture),
    "unknown_field_quarantined": unknown.get("class") == "quarantined_native" and unknown.get("action") == "quarantine",
    "credential_fields_dropped": all(item.get("action") == "drop" for item in preview if item.get("class") == "credential"),
    "new_export_manifest": manifest.get("schema_version") == "glassbox-derived-export/v1",
    "authenticity_is_unsigned_local": manifest.get("authenticity") == "unsigned_local",
    "source_and_derived_integrity_distinct": manifest.get("source_bundle_sha256") != manifest.get("integrity_root_sha256"),
    "redaction_policy_versioned": manifest.get("redaction_policy_version") == "glassbox-redaction/v1",
    "malformed_input_failed_closed": True,
}
def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"
receipt = {
    "schema_version": "glassbox-privacy-gate/v1",
    "ok": all(checks.values()),
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "git_head": git("rev-parse", "HEAD"),
    "git_tree": git("rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(git("status", "--porcelain")),
    "fixture_sha256": hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
    "export_sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
    "seeded_secret_count": len(seeded),
    "leaks": leaks,
    "checks": checks,
    "errors": [name for name, passed in checks.items() if not passed],
}
receipt_path.parent.mkdir(parents=True, exist_ok=True)
receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
