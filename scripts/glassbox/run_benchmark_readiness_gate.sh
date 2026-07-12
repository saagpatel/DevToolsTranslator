#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-benchmark-readiness.json}"
MYSTERY="$(mktemp "${TMPDIR:-/tmp}/glassbox-benchmark-mystery.XXXXXX")"
SELF_TEST="$(mktemp "${TMPDIR:-/tmp}/glassbox-benchmark-validator.XXXXXX")"
TEMPLATE_OUT="$(mktemp "${TMPDIR:-/tmp}/glassbox-benchmark-template.XXXXXX")"
trap 'rm -f "$MYSTERY" "$SELF_TEST" "$TEMPLATE_OUT"' EXIT
"$ROOT/scripts/glassbox/run_mystery_acceptance.sh" "$MYSTERY" >/dev/null
python3 "$ROOT/scripts/glassbox/validate_benchmark_results.py" --self-test >"$SELF_TEST"
if python3 "$ROOT/scripts/glassbox/validate_benchmark_results.py" "$ROOT/docs/glassbox/BENCHMARK-STUDY-ARTIFACT.template.json" >"$TEMPLATE_OUT"; then
  echo "incomplete external-study template unexpectedly passed" >&2; exit 1
fi
python3 - "$ROOT" "$MYSTERY" "$SELF_TEST" "$TEMPLATE_OUT" "$RECEIPT" <<'PY'
import json, pathlib, subprocess, sys
root,mystery_path,self_path,template_path,receipt_path=map(pathlib.Path,sys.argv[1:])
mystery=json.loads(mystery_path.read_text()); self_test=json.loads(self_path.read_text()); template=json.loads(template_path.read_text())
def git(*args):
 r=subprocess.run(["git",*args],cwd=root,text=True,capture_output=True); return r.stdout.strip() if r.returncode==0 else "unknown"
checks={"sixty_public_rehearsal_scenarios":mystery.get("scenario_count")==60,"public_corpus_not_mislabeled_held_out":mystery.get("checks",{}).get("public_corpus_explicitly_not_held_out") is True,"validator_self_tests_pass":self_test.get("ok") is True,"incomplete_external_template_fails_closed":template.get("ok") is False and bool(template.get("errors"))}
receipt={"schema_version":"glassbox-benchmark-readiness/v1","ok":all(checks.values()),"benchmark_passed":False,"gate6_promotable":False,"formal_benchmark_status":"external_artifacts_required","git_head":git("rev-parse","HEAD"),"git_tree":git("rev-parse","HEAD^{tree}"),"git_dirty":bool(git("status","--porcelain")),"checks":checks,"external_requirements":["10-12 engineer randomized counterbalanced pilot","pilot-derived power analysis","preregistration before formal collection","powered held-out human study","independent scoring and blinded adjudication","independent verification of participant and study records"],"errors":[k for k,v in checks.items() if not v]}
receipt_path.parent.mkdir(parents=True,exist_ok=True); receipt_path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n"); print(json.dumps(receipt,indent=2,sort_keys=True)); raise SystemExit(0 if receipt["ok"] else 1)
PY
