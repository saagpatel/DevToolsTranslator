#!/usr/bin/env python3
"""Verify the native Glassbox app and its Rust evidence helper as one artifact."""

import hashlib
import json
import os
import pathlib
import plistlib
import subprocess
import sys

from candidate_manifest import load_and_validate


mode, root, app, dmg, receipt_path = (
    sys.argv[1],
    pathlib.Path(sys.argv[2]),
    pathlib.Path(sys.argv[3]),
    pathlib.Path(sys.argv[4]),
    pathlib.Path(sys.argv[5]),
)


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True)


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    result = run("git", *args)
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def load_receipt(environment_key: str) -> dict:
    path = pathlib.Path(os.environ.get(environment_key, ""))
    return json.loads(path.read_text()) if path.is_file() else {}


def entitlement_dict(target: pathlib.Path) -> tuple[dict, str]:
    details = run("codesign", "-dvvv", "--entitlements", ":-", str(target))
    text = details.stdout + details.stderr
    try:
        start = text.index("<?xml")
        end = text.index("</plist>", start) + len("</plist>")
        return plistlib.loads(text[start:end].encode()), text
    except (ValueError, plistlib.InvalidFileException):
        return {}, text


info_path = app / "Contents/Info.plist"
privacy_path = app / "Contents/Resources/PrivacyInfo.xcprivacy"
entitlements_path = root / "apps/glassbox-macos/Support/Glassbox.entitlements"
package_path = root / "apps/glassbox-macos/Package.swift"
interaction_oracle_path = root / "scripts/glassbox/native_interaction_gate.py"
info = plistlib.loads(info_path.read_bytes()) if info_path.is_file() else {}
privacy = plistlib.loads(privacy_path.read_bytes()) if privacy_path.is_file() else {}
executable_name = info.get("CFBundleExecutable")
binary = app / "Contents/MacOS" / executable_name if isinstance(executable_name, str) else app / "Contents/MacOS/__missing__"
helper = app / "Contents/Helpers/glassbox-native-bridge"

app_verify = run("codesign", "--verify", "--deep", "--strict", str(app))
helper_verify = run("codesign", "--verify", "--strict", str(helper))
entitlements, sign_text = entitlement_dict(app)
helper_entitlements, helper_sign_text = entitlement_dict(helper)
linked = run("otool", "-L", str(binary))
binary_strings = run("strings", str(binary))
dmg_sign = run("codesign", "--verify", "--strict", str(dmg))
dmg_verify = run("hdiutil", "verify", str(dmg))
app_staple = run("xcrun", "stapler", "validate", str(app))
dmg_staple = run("xcrun", "stapler", "validate", str(dmg))
gatekeeper = run("spctl", "-a", "-vvv", "--type", "execute", str(app))
privacy_audit = load_receipt("GLASSBOX_PRIVACY_AUDIT_RECEIPT")
interaction = load_receipt("GLASSBOX_NATIVE_INTERACTION_RECEIPT")
candidate_manifest_path = pathlib.Path(os.environ.get("GLASSBOX_CANDIDATE_MANIFEST", ""))
candidate_manifest_digest = None
candidate_manifest_errors = ["candidate_manifest_required"]
if candidate_manifest_path.is_file():
    _, candidate_manifest_digest, candidate_manifest_errors = load_and_validate(
        root, candidate_manifest_path.resolve(),
    )

executable_files = sorted(
    path.relative_to(app).as_posix()
    for path in app.rglob("*")
    if path.is_file() and path.stat().st_mode & 0o111
)
expected_executables = ["Contents/Helpers/glassbox-native-bridge", "Contents/MacOS/Glassbox"]
forbidden_runtime_tokens = ("WKWebView", "WebKit.framework", "tauri://", "__TAURI__")
native_runtime_text = linked.stdout + binary_strings.stdout

local_checks = {
    "app_and_dmg_exist": app.is_dir() and dmg.is_file(),
    "bundle_identifier_is_glassbox": info.get("CFBundleIdentifier") == "com.glassbox.desktop"
    and executable_name == "Glassbox",
    "developer_id_signature_valid": app_verify.returncode == 0
    and "Authority=Developer ID Application:" in sign_text
    and "TeamIdentifier=3TGZFKFNA4" in sign_text,
    "nested_rust_helper_signature_valid": helper_verify.returncode == 0
    and "Authority=Developer ID Application:" in helper_sign_text
    and "TeamIdentifier=3TGZFKFNA4" in helper_sign_text,
    "hardened_runtime_enabled": "flags=0x10000(runtime)" in sign_text
    and "flags=0x10000(runtime)" in helper_sign_text,
    "app_sandbox_only_entitlement": entitlements == {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.files.user-selected.read-only": True,
    },
    "helper_has_no_entitlements": helper_entitlements == {},
    "network_and_privileged_entitlements_absent": not any(
        key.startswith("com.apple.security.network") or key.startswith("com.apple.developer")
        for key in entitlements
    ),
    "native_two_executable_closure": executable_files == expected_executables,
    "native_runtime_has_no_webview_or_tauri_surface": linked.returncode == 0
    and binary_strings.returncode == 0
    and not any(token in native_runtime_text for token in forbidden_runtime_tokens),
    "privacy_manifest_present_and_no_collection": privacy.get("NSPrivacyTracking") is False
    and privacy.get("NSPrivacyTrackingDomains") == []
    and privacy.get("NSPrivacyCollectedDataTypes") == [],
    "privacy_artifact_inventory_matches_reviewed_policy": privacy_audit.get("ok") is True
    and binary.is_file()
    and privacy_audit.get("binary_sha256") == sha(binary)
    and helper.is_file()
    and privacy_audit.get("companion_binary_sha256") == sha(helper),
    "signed_native_interaction_p95": interaction.get("ok") is True
    and binary.is_file()
    and interaction.get("binary_sha256") == sha(binary)
    and interaction.get("oracle_sha256") == sha(interaction_oracle_path)
    and isinstance(interaction.get("sample_sha256"), str)
    and len(interaction["sample_sha256"]) == 64,
    "dmg_signature_valid": dmg_sign.returncode == 0,
    "dmg_filesystem_valid": dmg_verify.returncode == 0,
    "signed_app_runtime_launch": os.environ.get("GLASSBOX_SIGNED_RUNTIME_OK") == "1",
    "runtime_test_residue_clean": os.environ.get("GLASSBOX_RUNTIME_RESIDUE_CLEAN") == "1",
}
distribution_checks = {
    "candidate_manifest_valid": not candidate_manifest_errors,
    "app_stapled": app_staple.returncode == 0,
    "dmg_stapled": dmg_staple.returncode == 0,
    "gatekeeper_accepts": gatekeeper.returncode == 0,
}
readiness_ok = all(local_checks.values())
artifact_passed = all(local_checks.values()) and all(distribution_checks.values())
receipt = {
    "schema_version": "glassbox-macos-artifact/v1",
    "ok": artifact_passed,
    "artifact_passed": artifact_passed,
    "readiness_ok": readiness_ok,
    "gate6_promotable": artifact_passed,
    "git_head": git("rev-parse", "HEAD"),
    "git_tree": git("rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(git("status", "--porcelain")),
    "app_sha256": sha(binary) if binary.is_file() else None,
    "helper_sha256": sha(helper) if helper.is_file() else None,
    "dmg_sha256": sha(dmg) if dmg.is_file() else None,
    "candidate_manifest_sha256": candidate_manifest_digest if not candidate_manifest_errors else None,
    "candidate_manifest_errors": candidate_manifest_errors,
    "native_boundary_sha256": {
        "package": sha(package_path),
        "entitlements": sha(entitlements_path),
    },
    "codesign_identity_line": next(
        (line for line in sign_text.splitlines() if line.startswith("Authority=")), None
    ),
    "team_identifier": "3TGZFKFNA4" if "TeamIdentifier=3TGZFKFNA4" in sign_text else None,
    "local_checks": local_checks,
    "privacy_artifact": privacy_audit,
    "native_interaction": interaction,
    "distribution_checks": distribution_checks,
    "gatekeeper_output": (gatekeeper.stdout + gatekeeper.stderr).strip(),
    "stapler_output": {
        "app": (app_staple.stdout + app_staple.stderr).strip(),
        "dmg": (dmg_staple.stdout + dmg_staple.stderr).strip(),
    },
    "errors": [name for name, value in {**local_checks, **distribution_checks}.items() if not value],
    "external_requirements": []
    if artifact_passed
    else [
        "submit exact app and DMG to Apple notary service",
        "wait for Accepted status and retain notary log",
        "staple and validate tickets on app and DMG",
        "rerun Gatekeeper assessment",
    ],
}
receipt_path.parent.mkdir(parents=True, exist_ok=True)
receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if (readiness_ok if mode == "readiness" else artifact_passed) else 1)
