#!/usr/bin/env python3
"""Require a valid human study plus CA-verified independent CMS attestation."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from external_evidence import validate_timestamp
from candidate_manifest import load_and_validate

CHECKS = {
    "participant_registry_verified", "study_records_verified", "scoring_export_verified",
    "adjudication_log_verified", "preregistration_verified",
    "held_out_corpus_separation_verified", "reported_metrics_recomputed",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--candidate-manifest", required=True, type=Path)
    parser.add_argument("--local-receipt", required=True, type=Path)
    parser.add_argument("--study", required=True, type=Path)
    parser.add_argument("--independent-cms", required=True, type=Path)
    parser.add_argument("--verifier-ca", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    errors: list[str] = []
    _, candidate_digest, candidate_errors = load_and_validate(
        args.root.resolve(), args.candidate_manifest.resolve(),
    )
    errors.extend(candidate_errors)
    try:
        local = json.loads(args.local_receipt.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        local = {}
        errors.append(f"local readiness unreadable: {exc}")
    if not (
        local.get("schema_version") == "glassbox-benchmark-readiness/v1"
        and local.get("ok") is True
        and local.get("benchmark_passed") is False
        and local.get("gate6_promotable") is False
        and isinstance(local.get("checks"), dict)
        and all(value is True for value in local["checks"].values())
    ):
        errors.append("local_readiness")

    with tempfile.TemporaryDirectory(prefix="glassbox-benchmark-promotion.") as temp_name:
        temp = Path(temp_name)
        study_receipt = temp / "study.json"
        validation = run(
            "python3", str(args.root / "scripts/glassbox/validate_benchmark_results.py"),
            str(args.study), "--receipt", str(study_receipt),
        )
        try:
            study = json.loads(study_receipt.read_text())
        except (OSError, json.JSONDecodeError):
            study = {}
        if validation.returncode != 0 or study.get("ok") is not True or study.get("benchmark_passed") is not True:
            errors.append("human_study")

        payload_path = temp / "independent.json"
        cms = run(
            "/usr/bin/openssl", "cms", "-verify", "-inform", "DER",
            "-in", str(args.independent_cms), "-CAfile", str(args.verifier_ca),
            "-purpose", "any", "-out", str(payload_path),
        )
        try:
            independent = json.loads(payload_path.read_text())
        except (OSError, json.JSONDecodeError):
            independent = {}
        if cms.returncode != 0:
            errors.append("independent_cms_signature")

    root_keys = {"schema_version", "ok", "benchmark_artifact_sha256", "candidate_manifest_sha256", "verifier", "checks"}
    if not isinstance(independent, dict) or set(independent) != root_keys:
        errors.append("independent_root_keys")
    else:
        if independent.get("schema_version") != "glassbox-benchmark-independent-verification/v1": errors.append("independent_schema")
        if independent.get("ok") is not True: errors.append("independent_ok")
        if independent.get("benchmark_artifact_sha256") != sha(args.study): errors.append("independent_study_hash")
        if independent.get("candidate_manifest_sha256") != candidate_digest: errors.append("independent_candidate_manifest_hash")
        if study.get("candidate_manifest_sha256") != candidate_digest: errors.append("study_candidate_manifest_hash")
        verifier = independent.get("verifier")
        if not isinstance(verifier, dict) or set(verifier) != {"identity", "role", "verified_at"}:
            errors.append("independent_verifier")
        else:
            if verifier.get("role") != "independent_benchmark_verifier": errors.append("independent_verifier_role")
            if not isinstance(verifier.get("identity"), str) or not verifier["identity"].strip(): errors.append("independent_verifier_identity")
            errors.extend(validate_timestamp(
                verifier.get("verified_at"), field="independent_verifier_time"
            ))
        checks = independent.get("checks")
        if not isinstance(checks, dict) or set(checks) != CHECKS or not all(checks.get(name) is True for name in CHECKS):
            errors.append("independent_checks")

    promoted = not errors
    result = dict(local)
    result.update({
        "schema_version": "glassbox-benchmark-readiness/v1",
        "ok": promoted,
        "benchmark_passed": promoted,
        "gate6_promotable": promoted,
        "formal_benchmark_status": "independently_verified" if promoted else "promotion_rejected",
        "study_receipt": study if promoted else None,
        "independent_verification": independent if promoted else None,
        "independent_cms_sha256": sha(args.independent_cms) if args.independent_cms.is_file() else None,
        "verifier_ca_sha256": sha(args.verifier_ca) if args.verifier_ca.is_file() else None,
        "candidate_manifest_sha256": candidate_digest if promoted else None,
        "external_requirements": [] if promoted else ["valid held-out human study and CA-verified independent CMS attestation"],
        "errors": sorted(set(errors)),
    })
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if promoted else 1


if __name__ == "__main__":
    raise SystemExit(main())
