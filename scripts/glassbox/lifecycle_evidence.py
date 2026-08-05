#!/usr/bin/env python3
"""Verify fresh-VM lifecycle evidence against local oracle and final artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from external_evidence import (
    sha256,
    validate_actor,
    validate_attachments,
    verify_cms_json,
)
from candidate_manifest import load_and_validate

SCHEMA = "glassbox-lifecycle-fresh-vm/v1"
CHECKS = {
    "fresh_vm_confirmed", "gatekeeper_before_first_launch", "install",
    "first_launch_permission_denial", "update_preserves_investigations",
    "downgrade_rejected", "credential_revoke", "reset_owned_state_only",
    "uninstall", "reinstall", "keychain_restart_and_delete",
    "security_scoped_bookmark_revoke", "user_exports_preserved", "no_owned_residue",
    "sandbox_and_entitlements_unchanged",
}


ATTACHMENT_KINDS = {
    "install_update",
    "permission_denial",
    "credential_lifecycle",
    "uninstall_residue",
    "user_work_preservation",
}


def validate(
    local: dict,
    evidence: object,
    evidence_path: Path,
    app: Path,
    dmg: Path,
    *,
    authenticated: bool,
    candidate_digest: str,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    if not authenticated:
        errors.append("tester_cms_signature")
    binary = app / "Contents/MacOS/Glassbox"
    helper = app / "Contents/Helpers/glassbox-native-bridge"
    if not (
        local.get("schema_version") == "glassbox-lifecycle/v1"
        and local.get("ok") is True
        and local.get("lifecycle_passed") is True
        and local.get("binary_sha256") == sha256(binary)
        and local.get("helper_sha256") == sha256(helper)
        and isinstance(local.get("checks"), dict)
        and local["checks"]
        and all(value is True for value in local["checks"].values())
    ):
        errors.append("local_receipt")
    root_keys = {
        "schema_version", "ok", "app_binary_sha256", "helper_sha256", "dmg_sha256",
        "candidate_manifest_sha256", "macos_version", "tester", "checks", "evidence_files",
    }
    if not isinstance(evidence, dict) or set(evidence) != root_keys:
        return sorted(set(errors + ["root keys must be exact"]))
    if evidence.get("schema_version") != SCHEMA: errors.append("schema_version")
    if evidence.get("ok") is not True: errors.append("ok")
    if evidence.get("candidate_manifest_sha256") != candidate_digest: errors.append("candidate_manifest_sha256")
    if evidence.get("app_binary_sha256") != sha256(binary): errors.append("app_binary_sha256")
    if evidence.get("helper_sha256") != sha256(helper): errors.append("helper_sha256")
    if evidence.get("dmg_sha256") != sha256(dmg): errors.append("dmg_sha256")
    if not isinstance(evidence.get("macos_version"), str) or not evidence["macos_version"].strip(): errors.append("macos_version")
    errors.extend(validate_actor(
        evidence.get("tester"), role="independent_fresh_vm_tester",
        timestamp_field="tested_at", actor_field="tester", now=now,
    ))
    checks = evidence.get("checks")
    if not isinstance(checks, dict) or set(checks) != CHECKS or not all(checks.get(name) is True for name in CHECKS):
        errors.append("checks")
    errors.extend(validate_attachments(
        evidence.get("evidence_files"), cms_path=evidence_path,
        required_kinds=ATTACHMENT_KINDS,
    ))
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-receipt", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--candidate-manifest", required=True, type=Path)
    parser.add_argument("--evidence-cms", required=True, type=Path)
    parser.add_argument("--tester-ca", required=True, type=Path)
    parser.add_argument("--app", required=True, type=Path)
    parser.add_argument("--dmg", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    candidate_digest: str | None = None
    try:
        local = json.loads(args.local_receipt.read_text())
        _, candidate_digest, candidate_errors = load_and_validate(
            args.root.resolve(), args.candidate_manifest.resolve(),
        )
        evidence, cms_errors = verify_cms_json(args.evidence_cms.resolve(), args.tester_ca.resolve())
        errors = candidate_errors + [f"tester_{code}" for code in cms_errors]
        errors.extend(validate(
            local, evidence, args.evidence_cms.resolve(), args.app.resolve(), args.dmg.resolve(),
            authenticated=not cms_errors, candidate_digest=candidate_digest or "",
        ))
    except (OSError, json.JSONDecodeError) as exc:
        local, evidence, errors = {}, {}, [f"unreadable evidence: {exc}"]
    promoted = not errors
    result = dict(local)
    result.update({
        "schema_version": "glassbox-lifecycle/v1",
        "ok": promoted,
        "lifecycle_passed": promoted,
        "gate6_promotable": promoted,
        "fresh_vm_evidence": evidence if promoted else None,
        "evidence_cms_sha256": sha256(args.evidence_cms) if args.evidence_cms.is_file() else None,
        "tester_ca_sha256": sha256(args.tester_ca) if args.tester_ca.is_file() else None,
        "candidate_manifest_sha256": candidate_digest if promoted else None,
        "external_requirements": [] if promoted else ["valid hash-bound fresh-VM lifecycle evidence"],
        "errors": errors,
    })
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if promoted else 1


if __name__ == "__main__":
    raise SystemExit(main())
