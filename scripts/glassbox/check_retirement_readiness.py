#!/usr/bin/env python3
"""Fail-closed donor-retirement readiness validator."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from candidate_manifest import load_and_validate

ROOT = Path(__file__).resolve().parents[2]
CANDIDATES = ("Codec", "Pulse Orbit", "Echolocate")
SHA = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
TOP_KEYS = {
    "schema_version", "candidate", "candidate_manifest_sha256", "as_of", "parity", "glassbox_releases", "benchmark", "soak",
    "open_critical_defects", "defect_scan", "expert_workflow", "donor_final_release",
    "rollback", "archive", "approval",
}


def timestamp(value: object, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field} must be an RFC3339 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{field} must be an RFC3339 timestamp")
        return None
    if parsed.tzinfo is None:
        errors.append(f"{field} must include a timezone")
        return None
    return parsed.astimezone(timezone.utc)


def exact_keys(value: object, keys: set[str], field: str, errors: list[str]) -> dict:
    if not isinstance(value, dict):
        errors.append(f"{field} must be an object")
        return {}
    if set(value) != keys:
        errors.append(f"{field} keys must be exact")
    return value


def valid_sha(value: object) -> bool:
    return isinstance(value, str) and bool(SHA.fullmatch(value))


def evidence_ref(value: object, base: Path, field: str, errors: list[str]) -> bool:
    item = exact_keys(value, {"path", "sha256"}, field, errors)
    rel = item.get("path")
    expected = item.get("sha256")
    if not isinstance(rel, str) or not rel.strip() or not valid_sha(expected):
        errors.append(f"{field} must contain a relative path and SHA-256")
        return False
    path = base / rel
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(base.resolve())
    except (OSError, ValueError):
        errors.append(f"{field} path is missing or escapes its evidence directory")
        return False
    if path.is_symlink() or not resolved.is_file():
        errors.append(f"{field} must reference a regular non-symlink file")
        return False
    actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if actual != expected:
        errors.append(f"{field} SHA-256 mismatch")
        return False
    return True


def validate(payload: object, source: str, base: Path) -> dict:
    errors: list[str] = []
    data = exact_keys(payload, TOP_KEYS, "root", errors)
    if data.get("schema_version") != "glassbox-retirement-evidence/v1": errors.append("unsupported schema_version")
    if not valid_sha(data.get("candidate_manifest_sha256")): errors.append("candidate_manifest_sha256 is invalid")
    candidate = data.get("candidate")
    if candidate not in CANDIDATES: errors.append("candidate is not retirement-eligible")
    as_of = timestamp(data.get("as_of"), "as_of", errors)

    parity = exact_keys(data.get("parity"), {"workflows", "migration_instructions", "import_compatibility", "export_compatibility"}, "parity", errors)
    workflows = parity.get("workflows")
    if not isinstance(workflows, list) or not workflows: errors.append("parity.workflows must be non-empty")
    else:
        for index, item in enumerate(workflows):
            row = exact_keys(item, {"workflow", "glassbox_test", "passed"}, f"parity.workflows[{index}]", errors)
            if not all(isinstance(row.get(key), str) and row[key].strip() for key in ("workflow", "glassbox_test")) or row.get("passed") is not True:
                errors.append(f"parity.workflows[{index}] is not addressably passed")
    if not isinstance(parity.get("migration_instructions"), str) or len(parity["migration_instructions"].strip()) < 20:
        errors.append("migration instructions are missing or too weak")
    for direction in ("import_compatibility", "export_compatibility"):
        item = exact_keys(parity.get(direction), {"passed", "evidence"}, f"parity.{direction}", errors)
        if item.get("passed") is not True or not evidence_ref(item.get("evidence"), base, f"parity.{direction}.evidence", errors):
            errors.append(f"parity.{direction} lacks passing hashed evidence")

    releases = data.get("glassbox_releases")
    release_dates: list[datetime] = []
    if not isinstance(releases, list) or len(releases) < 2: errors.append("at least two Glassbox releases are required")
    else:
        versions: set[str] = set()
        for index, item in enumerate(releases):
            row = exact_keys(item, {"version", "released_at", "successful", "replacement_included", "artifact"}, f"glassbox_releases[{index}]", errors)
            version = row.get("version")
            if not isinstance(version, str) or not version.strip() or version in versions: errors.append(f"glassbox_releases[{index}] version is invalid or duplicate")
            else: versions.add(version)
            date = timestamp(row.get("released_at"), f"glassbox_releases[{index}].released_at", errors)
            if date: release_dates.append(date)
            if row.get("successful") is not True or row.get("replacement_included") is not True or not evidence_ref(row.get("artifact"), base, f"glassbox_releases[{index}].artifact", errors):
                errors.append(f"glassbox_releases[{index}] is not qualifying")

    benchmark = exact_keys(data.get("benchmark"), {"benchmark_passed", "gate6_promotable", "evidence"}, "benchmark", errors)
    if benchmark.get("benchmark_passed") is not True or benchmark.get("gate6_promotable") is not True or not evidence_ref(benchmark.get("evidence"), base, "benchmark.evidence", errors):
        errors.append("verified held-out benchmark and Gate 6 promotion evidence are required")

    soak = exact_keys(data.get("soak"), {"started_at", "ended_at", "incident_count"}, "soak", errors)
    soak_start = timestamp(soak.get("started_at"), "soak.started_at", errors)
    soak_end = timestamp(soak.get("ended_at"), "soak.ended_at", errors)
    if soak_start and soak_end and (soak_end - soak_start).total_seconds() < 30 * 86400: errors.append("soak is shorter than 30 days")
    if release_dates and soak_start and soak_start < max(release_dates): errors.append("soak starts before the second/latest qualifying release")
    if as_of and soak_end and as_of < soak_end: errors.append("as_of precedes soak completion")
    if not isinstance(soak.get("incident_count"), int) or soak["incident_count"] < 0: errors.append("soak.incident_count must be non-negative")

    defects = data.get("open_critical_defects")
    if defects != []: errors.append("open P0/P1 retirement-blocking defects must be empty")
    defect_scan = exact_keys(data.get("defect_scan"), {"checked_at", "evidence"}, "defect_scan", errors)
    defect_date = timestamp(defect_scan.get("checked_at"), "defect_scan.checked_at", errors)
    if not evidence_ref(defect_scan.get("evidence"), base, "defect_scan.evidence", errors): errors.append("defect scan requires verified evidence")
    if soak_end and defect_date and defect_date < soak_end: errors.append("defect scan predates soak completion")

    expert = exact_keys(data.get("expert_workflow"), {"verified", "surface", "evidence"}, "expert_workflow", errors)
    if expert.get("verified") is not True or not isinstance(expert.get("surface"), str) or not expert["surface"].strip() or not evidence_ref(expert.get("evidence"), base, "expert_workflow.evidence", errors):
        errors.append("expert workflow is not verified")
    donor = exact_keys(data.get("donor_final_release"), {"tag", "commit", "clean", "dependency_posture", "security_posture"}, "donor_final_release", errors)
    if not isinstance(donor.get("tag"), str) or not donor["tag"].strip() or donor.get("clean") is not True or not isinstance(donor.get("commit"), str) or not COMMIT.fullmatch(donor["commit"]):
        errors.append("final donor release is not clean, tagged, and commit-bound")
    if not evidence_ref(donor.get("dependency_posture"), base, "donor_final_release.dependency_posture", errors) or not evidence_ref(donor.get("security_posture"), base, "donor_final_release.security_posture", errors): errors.append("donor posture evidence is incomplete")

    rollback = exact_keys(data.get("rollback"), {"instructions", "artifact", "post_retirement_path"}, "rollback", errors)
    if not isinstance(rollback.get("instructions"), str) or len(rollback["instructions"].strip()) < 20 or not evidence_ref(rollback.get("artifact"), base, "rollback.artifact", errors) or not isinstance(rollback.get("post_retirement_path"), str) or len(rollback["post_retirement_path"].strip()) < 10:
        errors.append("rollback evidence and post-retirement path are incomplete")
    archive = exact_keys(data.get("archive"), {"read_only", "remote_verified", "preserve_tags", "preserve_releases", "preserve_source", "preserve_issues_and_decisions", "final_readme"}, "archive", errors)
    for key in ("read_only", "remote_verified", "preserve_tags", "preserve_releases", "preserve_source", "preserve_issues_and_decisions"):
        if archive.get(key) is not True: errors.append(f"archive.{key} must be true")
    if not evidence_ref(archive.get("final_readme"), base, "archive.final_readme", errors): errors.append("archive final README requires verified evidence")

    approval = exact_keys(data.get("approval"), {"approved", "role", "signer", "approved_at", "artifact"}, "approval", errors)
    approval_date = timestamp(approval.get("approved_at"), "approval.approved_at", errors)
    if approval.get("approved") is not True or approval.get("role") != "product_authority" or not isinstance(approval.get("signer"), str) or not approval["signer"].strip() or not evidence_ref(approval.get("artifact"), base, "approval.artifact", errors):
        errors.append("explicit product-authority approval is missing")
    latest_evidence = [date for date in (soak_end, defect_date) if date]
    if approval_date and latest_evidence and approval_date < max(latest_evidence): errors.append("approval predates final evidence")

    return {"candidate": candidate if isinstance(candidate, str) else source, "source": source, "ready": not errors, "errors": errors}


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="glassbox-retirement-self-test.") as temp_name:
        base = Path(temp_name)
        proof = base / "proof.json"
        proof.write_text('{"verified":true}\n', encoding="utf-8")
        ref = {"path": "proof.json", "sha256": hashlib.sha256(proof.read_bytes()).hexdigest()}
        payload = {
            "schema_version": "glassbox-retirement-evidence/v1", "candidate": "Codec", "candidate_manifest_sha256": "b" * 64, "as_of": "2026-03-05T00:00:00Z",
            "parity": {"workflows": [{"workflow": "device projection", "glassbox_test": "test://codec/device-projection", "passed": True}],
                       "migration_instructions": "Import the final Codec export and verify every projected device.",
                       "import_compatibility": {"passed": True, "evidence": ref}, "export_compatibility": {"passed": True, "evidence": ref}},
            "glassbox_releases": [
                {"version": "1.0.0", "released_at": "2026-01-01T00:00:00Z", "successful": True, "replacement_included": True, "artifact": ref},
                {"version": "1.1.0", "released_at": "2026-02-01T00:00:00Z", "successful": True, "replacement_included": True, "artifact": ref}],
            "benchmark": {"benchmark_passed": True, "gate6_promotable": True, "evidence": ref},
            "soak": {"started_at": "2026-02-01T00:00:00Z", "ended_at": "2026-03-03T00:00:00Z", "incident_count": 0},
            "open_critical_defects": [], "defect_scan": {"checked_at": "2026-03-03T01:00:00Z", "evidence": ref},
            "expert_workflow": {"verified": True, "surface": "Glassbox device projection", "evidence": ref},
            "donor_final_release": {"tag": "v1.0.0", "commit": "a" * 40, "clean": True, "dependency_posture": ref, "security_posture": ref},
            "rollback": {"instructions": "Restore the tagged Codec release and redirect affected users.", "artifact": ref, "post_retirement_path": "Unarchive Codec and publish the tagged build."},
            "archive": {"read_only": True, "remote_verified": True, "preserve_tags": True, "preserve_releases": True, "preserve_source": True, "preserve_issues_and_decisions": True, "final_readme": ref},
            "approval": {"approved": True, "role": "product_authority", "signer": "test-authority", "approved_at": "2026-03-04T00:00:00Z", "artifact": ref},
        }
        valid = validate(payload, "valid", base)["ready"]
        payload["approval"]["approved"] = False
        approval_rejected = "explicit product-authority approval is missing" in validate(payload, "approval", base)["errors"]
        payload["approval"]["approved"] = True
        payload["soak"]["ended_at"] = "2026-03-02T00:00:00Z"
        short_soak_rejected = "soak is shorter than 30 days" in validate(payload, "soak", base)["errors"]
        payload["soak"]["ended_at"] = "2026-03-03T00:00:00Z"
        payload["parity"]["import_compatibility"]["evidence"] = {"path": "../escape", "sha256": "0" * 64}
        escaped_evidence_rejected = any("escapes its evidence directory" in error for error in validate(payload, "escape", base)["errors"])
        return valid and approval_rejected and short_soak_rejected and escaped_evidence_rejected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", nargs="*", type=Path)
    parser.add_argument("--readiness", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--candidate-manifest", type=Path)
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps({"fail_closed_incomplete_fixture": self_test()}))
        return 0 if self_test() else 1
    results = []
    candidate_digest = None
    candidate_errors = ["candidate manifest is required for retirement promotion"]
    if args.candidate_manifest is not None:
        _, candidate_digest, manifest_errors = load_and_validate(ROOT, args.candidate_manifest.resolve())
        candidate_errors = [f"candidate manifest: {error}" for error in manifest_errors]
    supplied: dict[str, Path] = {}
    for path in args.artifacts:
        try: payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            results.append({"candidate": str(path), "source": str(path), "ready": False, "errors": [f"unreadable artifact: {exc}"]}); continue
        result = validate(payload, str(path), path.resolve().parent)
        if candidate_errors:
            result["errors"].extend(candidate_errors)
            result["ready"] = False
        elif payload.get("candidate_manifest_sha256") != candidate_digest:
            result["errors"].append("retirement evidence targets a different candidate manifest")
            result["ready"] = False
        if result["candidate"] in supplied: result["errors"].append("duplicate candidate artifact"); result["ready"] = False
        elif result["candidate"] in CANDIDATES: supplied[result["candidate"]] = path
        results.append(result)
    for candidate in CANDIDATES:
        if candidate not in supplied: results.append({"candidate": candidate, "source": None, "ready": False, "errors": ["retirement evidence artifact is missing"]})
    passed = len(results) == len(CANDIDATES) and all(result["ready"] for result in results)
    readiness_ok = args.readiness and not args.artifacts and not passed and all(
        result["errors"] == ["retirement evidence artifact is missing"] for result in results
    )
    receipt = {
        "schema_version": "glassbox-retirement/v1", "ok": passed, "retirement_passed": passed,
        "gate7_promotable": passed, "readiness_ok": readiness_ok,
        "git_head": git("rev-parse", "HEAD"), "git_tree": git("rev-parse", "HEAD^{tree}"),
        "git_dirty": bool(git("status", "--porcelain")), "candidates": results,
        "candidate_manifest_sha256": candidate_digest if passed else None,
        "candidate_manifest_errors": candidate_errors if args.artifacts else [],
        "non_candidates": {"retained_expert_tools": ["Grotto", "NetworkDecoder"], "separate_manual_only": ["NetworkMapper"]},
    }
    output = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.receipt: args.receipt.parent.mkdir(parents=True, exist_ok=True); args.receipt.write_text(output, encoding="utf-8")
    print(output, end="")
    if passed or receipt["readiness_ok"]: return 0
    return 1


if __name__ == "__main__": raise SystemExit(main())
