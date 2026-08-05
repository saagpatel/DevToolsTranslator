#!/usr/bin/env python3
"""Verify every separately distributed non-browser Glassbox adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import subprocess
import tempfile
from pathlib import Path

from candidate_manifest import load_and_validate
from external_evidence import validate_actor, validate_attachments, verify_cms_json


SCHEMA = "glassbox-auxiliary-adapters/v1"
EVIDENCE_SCHEMA = "glassbox-auxiliary-adapters-fresh-vm/v1"
TEAM_ID = "3TGZFKFNA4"
ADAPTERS = {
    "otlp": {
        "app": "dist/Glassbox OTLP Adapter.app",
        "dmg": "dist/Glassbox-OTLP-Adapter-0.1.0.dmg",
        "bundle_id": "com.glassbox.otlp-adapter",
        "binary": "GlassboxOTLPAdapter",
        "helper": "glassbox-otlp-broker",
        "entitlements": {
            "com.apple.security.app-sandbox": True,
            "com.apple.security.files.user-selected.read-write": True,
            "com.apple.security.network.server": True,
        },
    },
    "passive": {
        "app": "dist/Glassbox Passive Context.app",
        "dmg": "dist/Glassbox-Passive-Context-0.1.0.dmg",
        "bundle_id": "com.glassbox.passive-adapter",
        "binary": "GlassboxPassiveAdapter",
        "helper": "glassbox-passive-context-broker",
        "entitlements": {
            "com.apple.security.app-sandbox": True,
            "com.apple.security.files.user-selected.read-write": True,
        },
    },
    "process": {
        "app": "dist/Glassbox Process Context.app",
        "dmg": "dist/Glassbox-Process-Context-0.1.0.dmg",
        "bundle_id": "com.glassbox.process-adapter",
        "binary": "GlassboxProcessAdapter",
        "helper": "glassbox-process-context-broker",
        "entitlements": {},
    },
}
CHECKS = {"fresh_vm_confirmed"} | {
    f"{name}_{check}"
    for name in ADAPTERS
    for check in (
        "gatekeeper_install",
        "explicit_consent",
        "capture_and_stop",
        "revoke_reset",
        "uninstall_no_residue",
        "keyboard_voiceover_disclosure",
    )
}
ATTACHMENTS = {
    "artifact_identity",
    "otlp_workflow",
    "passive_workflow",
    "process_workflow",
    "reset_uninstall_accessibility",
}


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def signing(target: Path) -> tuple[dict[str, object], str]:
    result = run("codesign", "-dvvv", "--entitlements", ":-", str(target))
    text = result.stdout + result.stderr
    start, end = text.find("<?xml"), text.find("</plist>")
    if start < 0 or end < 0:
        return {}, text
    try:
        return plistlib.loads(text[start : end + len("</plist>")].encode()), text
    except plistlib.InvalidFileException:
        return {}, text


def validate_external(
    evidence: object,
    *,
    cms_path: Path,
    candidate_digest: str,
    dmg_hashes: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    root_keys = {
        "schema_version", "ok", "candidate_manifest_sha256", "macos_version",
        "reviewer", "artifacts", "checks", "evidence_files",
    }
    if not isinstance(evidence, dict) or set(evidence) != root_keys:
        return ["fresh_vm_root_keys"]
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        errors.append("fresh_vm_schema")
    if evidence.get("ok") is not True:
        errors.append("fresh_vm_ok")
    if evidence.get("candidate_manifest_sha256") != candidate_digest:
        errors.append("fresh_vm_candidate_manifest_sha256")
    if not isinstance(evidence.get("macos_version"), str) or not evidence["macos_version"].strip():
        errors.append("fresh_vm_macos_version")
    if evidence.get("artifacts") != dmg_hashes:
        errors.append("fresh_vm_artifact_hashes")
    checks = evidence.get("checks")
    if not isinstance(checks, dict) or set(checks) != CHECKS or not all(
        checks.get(name) is True for name in CHECKS
    ):
        errors.append("fresh_vm_checks")
    errors.extend(validate_actor(
        evidence.get("reviewer"),
        role="independent_auxiliary_adapter_fresh_vm_reviewer",
        timestamp_field="reviewed_at",
        actor_field="reviewer",
    ))
    errors.extend(validate_attachments(
        evidence.get("evidence_files"), cms_path=cms_path, required_kinds=ATTACHMENTS,
    ))
    return sorted(set(errors))


def external_evidence(root: Path, dmg_hashes: dict[str, str]) -> tuple[bool, dict, str | None, list[str]]:
    cms_value = os.environ.get("GLASSBOX_AUXILIARY_FRESH_VM_CMS", "")
    ca_value = os.environ.get("GLASSBOX_AUXILIARY_REVIEWER_CA", "")
    candidate_value = os.environ.get("GLASSBOX_CANDIDATE_MANIFEST", "")
    if not cms_value and not ca_value and not candidate_value:
        return False, {}, None, []
    if not cms_value or not ca_value or not candidate_value:
        return False, {}, None, ["fresh_vm_cms_reviewer_ca_and_candidate_manifest_required"]
    cms_path = Path(cms_value).resolve()
    _, candidate_digest, candidate_errors = load_and_validate(root, Path(candidate_value).resolve())
    evidence, cms_errors = verify_cms_json(cms_path, Path(ca_value).resolve())
    errors = candidate_errors + [f"fresh_vm_{error}" for error in cms_errors]
    errors.extend(validate_external(
        evidence,
        cms_path=cms_path,
        candidate_digest=candidate_digest or "",
        dmg_hashes=dmg_hashes,
    ))
    errors = sorted(set(errors))
    return not errors, evidence, candidate_digest, errors


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="glassbox-auxiliary-self-test.") as temp_name:
        root = Path(temp_name)
        files = []
        for kind in sorted(ATTACHMENTS):
            path = root / f"{kind}.txt"
            path.write_text(kind, encoding="utf-8")
            files.append({"kind": kind, "path": path.name, "sha256": sha256(path)})
        cms = root / "evidence.cms"
        cms.write_bytes(b"fixture")
        hashes = {f"{name}_dmg_sha256": "a" * 64 for name in ADAPTERS}
        evidence = {
            "schema_version": EVIDENCE_SCHEMA,
            "ok": True,
            "candidate_manifest_sha256": "b" * 64,
            "macos_version": "15.0",
            "reviewer": {
                "identity": "fixture reviewer",
                "role": "independent_auxiliary_adapter_fresh_vm_reviewer",
                "reviewed_at": "2099-01-01T00:00:00Z",
            },
            "artifacts": dict(hashes),
            "checks": {name: True for name in CHECKS},
            "evidence_files": files,
        }
        # Give timestamp validation a current value without weakening production validation.
        from datetime import datetime, timezone
        evidence["reviewer"]["reviewed_at"] = datetime.now(timezone.utc).isoformat()
        valid = not validate_external(
            evidence, cms_path=cms, candidate_digest="b" * 64, dmg_hashes=hashes,
        )
        evidence["checks"]["otlp_gatekeeper_install"] = False
        false_check_rejected = "fresh_vm_checks" in validate_external(
            evidence, cms_path=cms, candidate_digest="b" * 64, dmg_hashes=hashes,
        )
        evidence["checks"]["otlp_gatekeeper_install"] = True
        evidence["artifacts"]["otlp_dmg_sha256"] = "c" * 64
        drift_rejected = "fresh_vm_artifact_hashes" in validate_external(
            evidence, cms_path=cms, candidate_digest="b" * 64, dmg_hashes=hashes,
        )
        return valid and false_check_rejected and drift_rejected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--mode", choices=("readiness", "strict"), default="strict")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        passed = self_test()
        print(json.dumps({"schema_version": "glassbox-auxiliary-adapters-self-test/v1", "ok": passed}))
        return 0 if passed else 1
    if args.root is None or args.receipt is None:
        parser.error("--root and --receipt are required")
    root = args.root.resolve()
    local_checks: dict[str, bool] = {}
    release_checks: dict[str, bool] = {}
    artifacts: dict[str, dict[str, str | None]] = {}
    gatekeeper_output: dict[str, str] = {}
    stapler_output: dict[str, dict[str, str]] = {}
    dmg_hashes: dict[str, str] = {}

    for name, spec in ADAPTERS.items():
        app = root / str(spec["app"])
        dmg = root / str(spec["dmg"])
        info_path = app / "Contents/Info.plist"
        privacy_path = app / "Contents/Resources/PrivacyInfo.xcprivacy"
        info = plistlib.loads(info_path.read_bytes()) if info_path.is_file() else {}
        privacy = plistlib.loads(privacy_path.read_bytes()) if privacy_path.is_file() else {}
        binary = app / "Contents/MacOS" / str(spec["binary"])
        helper = app / "Contents/Helpers" / str(spec["helper"])
        app_entitlements, app_signing = signing(app)
        helper_entitlements, helper_signing = signing(helper)
        app_verify = run("codesign", "--verify", "--deep", "--strict", str(app))
        helper_verify = run("codesign", "--verify", "--strict", str(helper))
        dmg_sign = run("codesign", "--verify", "--strict", str(dmg))
        dmg_verify = run("hdiutil", "verify", str(dmg))
        app_staple = run("xcrun", "stapler", "validate", str(app))
        dmg_staple = run("xcrun", "stapler", "validate", str(dmg))
        gatekeeper = run("spctl", "-a", "-vvv", "--type", "execute", str(app))
        executables = sorted(
            path.relative_to(app).as_posix() for path in app.rglob("*")
            if path.is_file() and path.stat().st_mode & 0o111
        ) if app.is_dir() else []
        expected_executables = sorted([
            f"Contents/MacOS/{spec['binary']}", f"Contents/Helpers/{spec['helper']}",
        ])
        local_checks.update({
            f"{name}_artifacts_exist": app.is_dir() and dmg.is_file(),
            f"{name}_bundle_identity_exact": (
                info.get("CFBundleIdentifier") == spec["bundle_id"]
                and info.get("CFBundleExecutable") == spec["binary"]
                and info.get("CFBundleShortVersionString") == "0.1.0"
            ),
            f"{name}_developer_id_runtime_signatures": (
                app_verify.returncode == 0 and helper_verify.returncode == 0
                and f"TeamIdentifier={TEAM_ID}" in app_signing
                and f"TeamIdentifier={TEAM_ID}" in helper_signing
                and "Authority=Developer ID Application:" in app_signing
                and "Authority=Developer ID Application:" in helper_signing
                and "flags=0x10000(runtime)" in app_signing
                and "flags=0x10000(runtime)" in helper_signing
            ),
            f"{name}_entitlements_exact": app_entitlements == spec["entitlements"] and helper_entitlements == {},
            f"{name}_two_executable_closure": executables == expected_executables,
            f"{name}_privacy_no_collection": (
                privacy.get("NSPrivacyTracking") is False
                and privacy.get("NSPrivacyTrackingDomains") == []
                and privacy.get("NSPrivacyCollectedDataTypes") == []
                and privacy.get("NSPrivacyAccessedAPITypes") == []
            ),
            f"{name}_dmg_signature_and_filesystem": dmg_sign.returncode == 0 and dmg_verify.returncode == 0,
        })
        release_checks.update({
            f"{name}_app_stapled": app_staple.returncode == 0,
            f"{name}_dmg_stapled": dmg_staple.returncode == 0,
            f"{name}_gatekeeper_accepts": gatekeeper.returncode == 0,
        })
        if dmg.is_file():
            dmg_hashes[f"{name}_dmg_sha256"] = sha256(dmg)
        artifacts[name] = {
            "app_binary_sha256": sha256(binary) if binary.is_file() else None,
            "helper_sha256": sha256(helper) if helper.is_file() else None,
            "dmg_sha256": sha256(dmg) if dmg.is_file() else None,
        }
        gatekeeper_output[name] = (gatekeeper.stdout + gatekeeper.stderr).strip()
        stapler_output[name] = {
            "app": (app_staple.stdout + app_staple.stderr).strip(),
            "dmg": (dmg_staple.stdout + dmg_staple.stderr).strip(),
        }

    external_ok, evidence, candidate_digest, evidence_errors = external_evidence(root, dmg_hashes)
    release_checks["fresh_vm_workflows_accessibility_and_residue"] = external_ok
    readiness_ok = all(local_checks.values())
    promoted = readiness_ok and all(release_checks.values())
    receipt = {
        "schema_version": SCHEMA,
        "ok": promoted,
        "readiness_ok": readiness_ok,
        "artifact_passed": promoted,
        "gate6_promotable": promoted,
        "git_head": git(root, "rev-parse", "HEAD"),
        "git_tree": git(root, "rev-parse", "HEAD^{tree}"),
        "git_dirty": bool(git(root, "status", "--porcelain")),
        "artifacts": artifacts,
        "local_checks": local_checks,
        "release_checks": release_checks,
        "fresh_vm_evidence": evidence if external_ok else None,
        "candidate_manifest_sha256": candidate_digest if external_ok else None,
        "fresh_vm_evidence_errors": evidence_errors,
        "gatekeeper_output": gatekeeper_output,
        "stapler_output": stapler_output,
        "errors": [name for name, value in {**local_checks, **release_checks}.items() if not value],
        "external_requirements": [] if promoted else [
            "notarize and staple the exact OTLP, passive-context, and process-context app bundles and DMGs",
            "run Gatekeeper and fresh-VM consent, capture, stop, revoke, reset, uninstall, residue, keyboard, VoiceOver, and disclosure review for all three adapters",
            "rerun strict verification with the frozen candidate manifest and CA-verified reviewer CMS",
        ],
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if (readiness_ok if args.mode == "readiness" else promoted) else 1


if __name__ == "__main__":
    raise SystemExit(main())
