#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-benchmark-readiness.json}"
MYSTERY="$(mktemp "${TMPDIR:-/tmp}/glassbox-benchmark-mystery.XXXXXX")"
SELF_TEST="$(mktemp "${TMPDIR:-/tmp}/glassbox-benchmark-validator.XXXXXX")"
PROMOTION_SELF_TEST="$(mktemp "${TMPDIR:-/tmp}/glassbox-benchmark-promotion.XXXXXX")"
TEMPLATE_OUT="$(mktemp "${TMPDIR:-/tmp}/glassbox-benchmark-template.XXXXXX")"
trap 'rm -f "$MYSTERY" "$SELF_TEST" "$PROMOTION_SELF_TEST" "$TEMPLATE_OUT"' EXIT
"$ROOT/scripts/glassbox/run_mystery_acceptance.sh" "$MYSTERY" >/dev/null
python3 "$ROOT/scripts/glassbox/validate_benchmark_results.py" --self-test >"$SELF_TEST"
python3 "$ROOT/scripts/glassbox/verify_benchmark_promotion.py" --self-test >"$PROMOTION_SELF_TEST"
if python3 "$ROOT/scripts/glassbox/validate_benchmark_results.py" "$ROOT/docs/glassbox/BENCHMARK-STUDY-ARTIFACT.template.json" >"$TEMPLATE_OUT"; then
  echo "incomplete external-study template unexpectedly passed" >&2; exit 1
fi
python3 - "$ROOT" "$MYSTERY" "$SELF_TEST" "$PROMOTION_SELF_TEST" "$TEMPLATE_OUT" "$RECEIPT" <<'PY'
import json, pathlib, subprocess, sys
root,mystery_path,self_path,promotion_self_path,template_path,receipt_path=map(pathlib.Path,sys.argv[1:])
mystery=json.loads(mystery_path.read_text()); self_test=json.loads(self_path.read_text()); promotion_self_test=json.loads(promotion_self_path.read_text()); template=json.loads(template_path.read_text())
def git(*args):
 r=subprocess.run(["git",*args],cwd=root,text=True,capture_output=True); return r.stdout.strip() if r.returncode==0 else "unknown"
checks={"sixty_public_rehearsal_scenarios":mystery.get("scenario_count")==60,"public_corpus_not_mislabeled_held_out":mystery.get("checks",{}).get("public_corpus_explicitly_not_held_out") is True,"validator_self_tests_pass":self_test.get("ok") is True,"promotion_verifier_self_tests_pass":promotion_self_test.get("ok") is True,"incomplete_external_template_fails_closed":template.get("ok") is False and bool(template.get("errors"))}
receipt={"schema_version":"glassbox-benchmark-readiness/v1","ok":all(checks.values()),"benchmark_passed":False,"gate6_promotable":False,"formal_benchmark_status":"external_artifacts_required","git_head":git("rev-parse","HEAD"),"git_tree":git("rev-parse","HEAD^{tree}"),"git_dirty":bool(git("status","--porcelain")),"checks":checks,"external_requirements":["10-12 engineer randomized counterbalanced pilot","pilot-derived power analysis","preregistration before formal collection","powered held-out human study","independent scoring and blinded adjudication","independent verification of participant and study records"],"errors":[k for k,v in checks.items() if not v]}
receipt_path.parent.mkdir(parents=True,exist_ok=True); receipt_path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n"); print(json.dumps(receipt,indent=2,sort_keys=True)); raise SystemExit(0 if receipt["ok"] else 1)
PY

provided=0
for variable in GLASSBOX_BENCHMARK_STUDY_ARTIFACT GLASSBOX_BENCHMARK_INDEPENDENT_CMS GLASSBOX_BENCHMARK_VERIFIER_CA GLASSBOX_CANDIDATE_MANIFEST; do
  if [[ -n "${!variable:-}" ]]; then provided=$((provided + 1)); fi
done
if [[ "$provided" -ne 0 && "$provided" -ne 4 ]]; then
  echo "benchmark promotion requires study artifact, independent CMS, verifier CA, and candidate manifest together" >&2
  exit 2
fi
if [[ "$provided" -eq 4 ]]; then
  python3 "$ROOT/scripts/glassbox/verify_benchmark_promotion.py" \
    --root "$ROOT" \
    --candidate-manifest "$GLASSBOX_CANDIDATE_MANIFEST" \
    --local-receipt "$RECEIPT" \
    --study "$GLASSBOX_BENCHMARK_STUDY_ARTIFACT" \
    --independent-cms "$GLASSBOX_BENCHMARK_INDEPENDENT_CMS" \
    --verifier-ca "$GLASSBOX_BENCHMARK_VERIFIER_CA" \
    --receipt "$RECEIPT" >/dev/null
fi
