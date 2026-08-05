#!/usr/bin/env python3
"""Require a valid human study plus CA-verified independent CMS attestation."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from external_evidence import sha256, validate_attachments, validate_timestamp, verify_cms_json
from candidate_manifest import load_and_validate

CHECKS = {
    "participant_registry_verified", "study_records_verified", "scoring_export_verified",
    "adjudication_log_verified", "preregistration_verified",
    "held_out_corpus_separation_verified", "reported_metrics_recomputed",
}

EVIDENCE_HASHES = {
    "participant_registry": ("integrity", "participant_registry_sha256"),
    "study_records": ("integrity", "study_records_sha256"),
    "scoring_export": ("integrity", "scoring_export_sha256"),
    "adjudication_log": ("integrity", "adjudication_log_sha256"),
    "preregistration_record": ("integrity", "preregistration_record_sha256"),
    "held_out_corpus_manifest": ("corpus_manifest", "sha256"),
    "metric_recomputation": ("integrity", "metric_recomputation_sha256"),
}


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True)


def validate_independent(
    independent: object,
    *,
    study_data: object,
    study_artifact_sha256: str,
    candidate_digest: str,
    cms_path: Path,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    root_keys = {
        "schema_version", "ok", "benchmark_artifact_sha256",
        "candidate_manifest_sha256", "verifier", "evidence_files", "checks",
    }
    if not isinstance(independent, dict) or set(independent) != root_keys:
        return ["independent_root_keys"]
    if independent.get("schema_version") != "glassbox-benchmark-independent-verification/v1":
        errors.append("independent_schema")
    if independent.get("ok") is not True:
        errors.append("independent_ok")
    if independent.get("benchmark_artifact_sha256") != study_artifact_sha256:
        errors.append("independent_study_hash")
    if independent.get("candidate_manifest_sha256") != candidate_digest:
        errors.append("independent_candidate_manifest_hash")
    if not isinstance(study_data, dict) or study_data.get("candidate_manifest_sha256") != candidate_digest:
        errors.append("study_candidate_manifest_hash")
    verifier = independent.get("verifier")
    if not isinstance(verifier, dict) or set(verifier) != {"identity", "role", "verified_at"}:
        errors.append("independent_verifier")
    else:
        if verifier.get("role") != "independent_benchmark_verifier":
            errors.append("independent_verifier_role")
        if not isinstance(verifier.get("identity"), str) or not verifier["identity"].strip():
            errors.append("independent_verifier_identity")
        errors.extend(validate_timestamp(
            verifier.get("verified_at"), field="independent_verifier_time", now=now,
        ))
    checks = independent.get("checks")
    if (
        not isinstance(checks, dict)
        or set(checks) != CHECKS
        or not all(checks.get(name) is True for name in CHECKS)
    ):
        errors.append("independent_checks")

    evidence_files = independent.get("evidence_files")
    errors.extend(validate_attachments(
        evidence_files, cms_path=cms_path, required_kinds=set(EVIDENCE_HASHES),
    ))
    by_kind = {
        item.get("kind"): item.get("sha256")
        for item in evidence_files if isinstance(item, dict)
    } if isinstance(evidence_files, list) else {}
    for kind, (section_name, field_name) in EVIDENCE_HASHES.items():
        section = study_data.get(section_name) if isinstance(study_data, dict) else None
        expected = section.get(field_name) if isinstance(section, dict) else None
        if by_kind.get(kind) != expected:
            errors.append(f"evidence_hash_{kind}")
    return sorted(set(errors))


def self_test() -> bool:
    now = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix="glassbox-benchmark-promotion-self-test.") as temp_name:
        root = Path(temp_name)
        cms = root / "review.cms"
        cms.write_bytes(b"self-test-placeholder")
        files = {}
        evidence_files = []
        for kind in EVIDENCE_HASHES:
            path = root / f"{kind}.json"
            path.write_text(json.dumps({"kind": kind}), encoding="utf-8")
            digest = sha256(path)
            files[kind] = digest
            evidence_files.append({"kind": kind, "path": path.name, "sha256": digest})
        candidate_digest = "a" * 64
        study_data = {
            "candidate_manifest_sha256": candidate_digest,
            "corpus_manifest": {"sha256": files["held_out_corpus_manifest"]},
            "integrity": {
                field: files[kind]
                for kind, (section, field) in EVIDENCE_HASHES.items()
                if section == "integrity"
            },
        }
        independent = {
            "schema_version": "glassbox-benchmark-independent-verification/v1",
            "ok": True,
            "benchmark_artifact_sha256": "b" * 64,
            "candidate_manifest_sha256": candidate_digest,
            "verifier": {
                "identity": "independent-self-test",
                "role": "independent_benchmark_verifier",
                "verified_at": now.isoformat(),
            },
            "evidence_files": evidence_files,
            "checks": {name: True for name in CHECKS},
        }
        valid = not validate_independent(
            independent, study_data=study_data, study_artifact_sha256="b" * 64,
            candidate_digest=candidate_digest, cms_path=cms, now=now,
        )

        mismatched = json.loads(json.dumps(study_data))
        mismatched["integrity"]["participant_registry_sha256"] = "c" * 64
        hash_mismatch_rejected = "evidence_hash_participant_registry" in validate_independent(
            independent, study_data=mismatched, study_artifact_sha256="b" * 64,
            candidate_digest=candidate_digest, cms_path=cms, now=now,
        )

        escaped = json.loads(json.dumps(independent))
        escaped["evidence_files"][0]["path"] = "../escape.json"
        path_escape_rejected = bool(validate_independent(
            escaped, study_data=study_data, study_artifact_sha256="b" * 64,
            candidate_digest=candidate_digest, cms_path=cms, now=now,
        ))

        future = json.loads(json.dumps(independent))
        future["verifier"]["verified_at"] = (now + timedelta(minutes=6)).isoformat()
        future_time_rejected = "independent_verifier_time_future" in validate_independent(
            future, study_data=study_data, study_artifact_sha256="b" * 64,
            candidate_digest=candidate_digest, cms_path=cms, now=now,
        )
        return all([valid, hash_mismatch_rejected, path_escape_rejected, future_time_rejected])


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

        try:
            study_data = json.loads(args.study.read_text())
        except (OSError, json.JSONDecodeError):
            study_data = {}
            errors.append("human_study_payload")
        independent, cms_errors = verify_cms_json(
            args.independent_cms.resolve(), args.verifier_ca.resolve(),
        )
        errors.extend(f"independent_{error}" for error in cms_errors)

    errors.extend(validate_independent(
        independent,
        study_data=study_data,
        study_artifact_sha256=sha256(args.study) if args.study.is_file() else "",
        candidate_digest=candidate_digest,
        cms_path=args.independent_cms.resolve(),
    ))

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
        "independent_cms_sha256": sha256(args.independent_cms) if args.independent_cms.is_file() else None,
        "verifier_ca_sha256": sha256(args.verifier_ca) if args.verifier_ca.is_file() else None,
        "candidate_manifest_sha256": candidate_digest if promoted else None,
        "external_requirements": [] if promoted else ["valid held-out human study and CA-verified independent CMS attestation"],
        "errors": sorted(set(errors)),
    })
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if promoted else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        passed = self_test()
        print(json.dumps({
            "schema_version": "glassbox-benchmark-promotion-self-test/v1",
            "ok": passed,
        }))
        raise SystemExit(0 if passed else 1)
    raise SystemExit(main())
