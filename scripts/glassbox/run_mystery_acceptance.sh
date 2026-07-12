#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RECEIPT=${1:-"$ROOT/artifacts/glassbox-mystery-gate.json"}
TARGET_DIR=${GLASSBOX_MYSTERY_TARGET_DIR:-"${TMPDIR:-/tmp}/glassbox-mystery-target"}
OUTPUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-mystery-output.XXXXXX")
trap 'rm -f "$OUTPUT"' EXIT

FIXTURE="$ROOT/crates/glassbox-fixtures/corpus/mysteries/mystery-families.json"
CARGO_TARGET_DIR="$TARGET_DIR" cargo run --quiet --manifest-path "$ROOT/Cargo.toml" \
  -p glassbox-investigation --example mystery_probe -- "$FIXTURE" >"$OUTPUT"

python3 - "$ROOT" "$FIXTURE" "$OUTPUT" "$RECEIPT" <<'PY'
import hashlib, json, subprocess, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

root, fixture_path, output_path, receipt_path = map(Path, sys.argv[1:])
views = json.loads(output_path.read_text())["views"]
families = defaultdict(set)
for view in views:
    families[view["family"]].add(view["variant"])
statuses = Counter(view["conclusion"] for view in views)
limitation_kinds = {item["kind"] for view in views for item in view["limitations"]}
checks = {
    "five_mystery_families": len(families) == 5,
    "counterfactual_and_negative_controls": all(variants == {"base", "counterfactual", "negative_control"} for variants in families.values()),
    "timeline_table_equivalence": all({item["id"] for lane in view["actor_lanes"].values() for item in lane} == {row["id"] for row in view["evidence_table"]} for view in views),
    "native_drilldown_addressable": all(all(row["native_locator"] for row in view["evidence_table"]) for view in views),
    "why_link_explanations_complete": all(all(rel["basis"] and rel["rule_version"] and rel["uncertainty"] and rel["supporting_evidence"] for rel in view["relation_explanations"]) for view in views),
    "temporal_links_make_no_causal_assertion": all(not rel["causal_assertion"] for view in views for rel in view["relation_explanations"] if rel["basis"] == "temporal_candidate"),
    "competing_hypotheses_present": all(len(view["hypotheses"]) >= 2 for view in views),
    "healthy_run_comparison_on_base": all(view["comparison"] is not None for view in views if view["variant"] == "base"),
    "unknown_names_next_safe_source": all(view["smallest_safe_next_source"] for view in views if view["conclusion"] == "unknown"),
    "limitations_visible": {"clock", "gap", "drop", "redaction", "opaque", "sampling"}.issubset(limitation_kinds),
    "field_level_export_preview": all(view["export_preview"] for view in views),
    "unknown_cases_exercised": statuses["unknown"] >= 5,
}
def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"
receipt = {
    "schema_version": "glassbox-mystery-gate/v1", "ok": all(checks.values()),
    "generated_at": datetime.now(timezone.utc).isoformat(), "git_head": git("rev-parse", "HEAD"),
    "git_tree": git("rev-parse", "HEAD^{tree}"), "git_dirty": bool(git("status", "--porcelain")),
    "fixture_sha256": hashlib.sha256(fixture_path.read_bytes()).hexdigest(), "scenario_count": len(views),
    "family_variants": {key: sorted(value) for key, value in sorted(families.items())},
    "conclusion_counts": dict(statuses), "checks": checks,
    "errors": [name for name, passed in checks.items() if not passed],
}
receipt_path.parent.mkdir(parents=True, exist_ok=True)
receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
