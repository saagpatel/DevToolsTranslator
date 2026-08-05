#!/usr/bin/env python3
"""Bind manual accessibility review to the exact final Glassbox artifact."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from external_evidence import (
    sha256,
    validate_actor,
    validate_attachments,
    verify_cms_json,
)
from candidate_manifest import load_and_validate

SCHEMA = "glassbox-accessibility-manual/v1"
CHECKS = {
    "full_keyboard_traversal",
    "visible_focus",
    "voiceover_task_flow",
    "reduce_motion",
    "zoom_200_percent",
    "non_color_evidence_states",
    "pauseable_live_updates",
    "semantic_tabular_alternatives",
}
ROOT_KEYS = {
    "schema_version", "ok", "app_binary_sha256", "dmg_sha256", "reviewer",
    "candidate_manifest_sha256", "checks", "evidence_files",
}


ATTACHMENT_KINDS = {"keyboard", "voiceover", "zoom", "reduce_motion"}


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def validate(
    data: object,
    source: Path,
    app: Path,
    dmg: Path,
    *,
    authenticated: bool,
    candidate_digest: str,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    if not authenticated:
        errors.append("review_cms_signature")
    if not isinstance(data, dict) or set(data) != ROOT_KEYS:
        return sorted(set(errors + ["root keys must be exact"]))
    if data.get("schema_version") != SCHEMA: errors.append("schema_version")
    if data.get("ok") is not True: errors.append("ok")
    if data.get("candidate_manifest_sha256") != candidate_digest: errors.append("candidate_manifest_sha256")
    binary = app / "Contents/MacOS/Glassbox"
    if not binary.is_file() or data.get("app_binary_sha256") != sha256(binary): errors.append("app_binary_sha256")
    if not dmg.is_file() or data.get("dmg_sha256") != sha256(dmg): errors.append("dmg_sha256")
    errors.extend(validate_actor(
        data.get("reviewer"), role="independent_accessibility_reviewer",
        timestamp_field="reviewed_at", actor_field="reviewer", now=now,
    ))
    checks = data.get("checks")
    if not isinstance(checks, dict) or set(checks) != CHECKS or not all(checks.get(name) is True for name in CHECKS):
        errors.append("checks")
    errors.extend(validate_attachments(
        data.get("evidence_files"), cms_path=source, required_kinds=ATTACHMENT_KINDS,
    ))
    return sorted(set(errors))


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="glassbox-accessibility-self-test.") as temp_name:
        root = Path(temp_name)
        app = root / "Glassbox.app/Contents/MacOS"
        app.mkdir(parents=True)
        binary = app / "Glassbox"
        binary.write_bytes(b"app")
        dmg = root / "Glassbox.dmg"
        dmg.write_bytes(b"dmg")
        refs = []
        for kind in sorted(ATTACHMENT_KINDS):
            proof = root / f"{kind}.txt"
            proof.write_bytes(kind.encode())
            refs.append({"kind": kind, "path": proof.name, "sha256": sha256(proof)})
        now = datetime.now(timezone.utc)
        payload = {
            "schema_version": SCHEMA, "ok": True,
            "candidate_manifest_sha256": "a" * 64,
            "app_binary_sha256": sha256(binary), "dmg_sha256": sha256(dmg),
            "reviewer": {"role": "independent_accessibility_reviewer", "identity": "test", "reviewed_at": now.isoformat()},
            "checks": {name: True for name in CHECKS},
            "evidence_files": refs,
        }
        source = root / "evidence.cms"
        valid = not validate(payload, source, root / "Glassbox.app", dmg, authenticated=True, candidate_digest="a" * 64, now=now)
        unsigned_rejected = "review_cms_signature" in validate(
            payload, source, root / "Glassbox.app", dmg, authenticated=False, candidate_digest="a" * 64, now=now,
        )
        payload["reviewer"]["reviewed_at"] = "2001-01-01T00:00:00Z"
        stale_rejected = "reviewer.reviewed_at_stale" in validate(
            payload, source, root / "Glassbox.app", dmg, authenticated=True, candidate_digest="a" * 64, now=now,
        )
        payload["reviewer"]["reviewed_at"] = now.isoformat()
        payload["checks"]["visible_focus"] = "yes"
        non_boolean_rejected = "checks" in validate(
            payload, source, root / "Glassbox.app", dmg, authenticated=True, candidate_digest="a" * 64, now=now,
        )
        payload["checks"]["visible_focus"] = True
        payload["evidence_files"][1]["path"] = payload["evidence_files"][0]["path"]
        payload["evidence_files"][1]["sha256"] = payload["evidence_files"][0]["sha256"]
        duplicate_rejected = "evidence_files[1]" in validate(
            payload, source, root / "Glassbox.app", dmg, authenticated=True, candidate_digest="a" * 64, now=now,
        )
        return valid and unsigned_rejected and stale_rejected and non_boolean_rejected and duplicate_rejected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--review-cms", type=Path)
    parser.add_argument("--reviewer-ca", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument("--app", type=Path)
    parser.add_argument("--dmg", type=Path)
    args = parser.parse_args()
    if args.self_test:
        passed = self_test()
        print(json.dumps({"ok": passed}))
        return 0 if passed else 1
    supplied = any(
        value is not None
        for value in (args.review_cms, args.reviewer_ca, args.root, args.candidate_manifest)
    )
    errors: list[str] = []
    evidence: dict[str, object] = {}
    candidate_digest: str | None = None
    if supplied:
        if None in (args.review_cms, args.reviewer_ca, args.root, args.candidate_manifest):
            errors = ["review_cms_reviewer_ca_root_and_candidate_manifest_required"]
        else:
            _, candidate_digest, candidate_errors = load_and_validate(
                args.root.resolve(), args.candidate_manifest.resolve(),
            )
            errors.extend(candidate_errors)
            evidence, cms_errors = verify_cms_json(args.review_cms.resolve(), args.reviewer_ca.resolve())
            errors.extend(f"review_{code}" for code in cms_errors)
            errors.extend(validate(
                evidence, args.review_cms.resolve(), args.app.resolve(), args.dmg.resolve(),
                authenticated=not cms_errors, candidate_digest=candidate_digest or "",
            ))
    manual_passed = supplied and not errors
    source_root = args.root.resolve() if args.root is not None else Path(__file__).resolve().parents[2]
    result = {
        "schema_version": "glassbox-accessibility/v1",
        "ok": not errors,
        "readiness_ok": True,
        "git_head": git(source_root, "rev-parse", "HEAD"),
        "git_tree": git(source_root, "rev-parse", "HEAD^{tree}"),
        "git_dirty": bool(git(source_root, "status", "--porcelain")),
        "manual_accessibility_passed": manual_passed,
        "gate6_promotable": manual_passed,
        "automated_scope": [
            "native labeled controls", "keyboard command", "import action and progress identity",
            "export sheet identity", "complete table equivalent", "Swift tests", "release build",
        ],
        "manual_scope_remaining": [] if manual_passed else [
            "VoiceOver task flow", "full keyboard traversal", "macOS 200% zoom visual review",
            "Reduce Motion visual review",
        ],
        "manual_evidence": evidence if manual_passed else None,
        "review_cms_sha256": sha256(args.review_cms) if manual_passed else None,
        "reviewer_ca_sha256": sha256(args.reviewer_ca) if manual_passed else None,
        "candidate_manifest_sha256": candidate_digest if manual_passed else None,
        "errors": errors,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
