#!/usr/bin/env python3
"""Verify the separate Browser Adapter release without upgrading missing external proof."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import plistlib
import subprocess
import sys
import zipfile

from external_evidence import validate_actor, validate_attachments, verify_cms_json
from candidate_manifest import load_and_validate


mode, root, app, dmg, extension_zip, receipt_path = (
    sys.argv[1],
    pathlib.Path(sys.argv[2]),
    pathlib.Path(sys.argv[3]),
    pathlib.Path(sys.argv[4]),
    pathlib.Path(sys.argv[5]),
    pathlib.Path(sys.argv[6]),
)
team_id = "3TGZFKFNA4"
extension_id = "giffhfldblangaphoeeeelcapcmedjbd"
shipping_files = {
    "manifest.json", "devtools.html", "devtools.js", "panel.html", "panel.js", "panel.css"
}


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True)


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    result = run("git", *args)
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def signing(target: pathlib.Path) -> tuple[dict[str, object], str]:
    result = run("codesign", "-dvvv", "--entitlements", ":-", str(target))
    text = result.stdout + result.stderr
    start, end = text.find("<?xml"), text.find("</plist>")
    entitlements = {}
    if start >= 0 and end >= 0:
        entitlements = plistlib.loads(text[start : end + len("</plist>")].encode())
    return entitlements, text


def derived_extension_id(public_key: str) -> str:
    first = hashlib.sha256(base64.b64decode(public_key)).hexdigest()[:32]
    return first.translate(str.maketrans("0123456789abcdef", "abcdefghijklmnop"))


def external_evidence() -> tuple[bool, dict[str, object], str | None, list[str]]:
    configured_cms = os.environ.get("GLASSBOX_BROWSER_FRESH_VM_CMS", "")
    configured_ca = os.environ.get("GLASSBOX_BROWSER_REVIEWER_CA", "")
    configured_candidate = os.environ.get("GLASSBOX_CANDIDATE_MANIFEST", "")
    if not configured_cms and not configured_ca and not configured_candidate:
        return False, {}, None, []
    if not configured_cms or not configured_ca or not configured_candidate:
        return False, {}, None, ["fresh_vm_cms_reviewer_ca_and_candidate_manifest_required"]
    path = pathlib.Path(configured_cms).resolve()
    _, candidate_digest, candidate_errors = load_and_validate(
        root, pathlib.Path(configured_candidate).resolve(),
    )
    evidence, cms_errors = verify_cms_json(path, pathlib.Path(configured_ca).resolve())
    errors = candidate_errors + [f"fresh_vm_{code}" for code in cms_errors]
    required = {
        "fresh_vm_confirmed",
        "production_extension_identity_confirmed",
        "chrome_extension_install_passed",
        "native_manifest_install_passed",
        "selected_tab_only_capture_passed",
        "persistent_capture_indicator_passed",
        "explicit_stop_and_private_bundle_passed",
        "offline_core_import_passed",
        "revoke_reset_passed",
        "uninstall_residue_passed",
        "keyboard_and_visible_focus_passed",
        "voiceover_and_disclosure_passed",
    }
    checks = evidence.get("checks", {})
    attachments = evidence.get("evidence_files", [])
    root_keys_exact = set(evidence) == {
        "schema_version", "ok", "adapter_dmg_sha256", "extension_zip_sha256",
        "candidate_manifest_sha256", "extension_id", "chrome_version", "reviewer",
        "checks", "evidence_files",
    }
    errors.extend(validate_actor(
        evidence.get("reviewer"), role="independent_browser_fresh_vm_reviewer",
        timestamp_field="reviewed_at", actor_field="reviewer",
    ))
    errors.extend(validate_attachments(
        attachments,
        cms_path=path,
        required_kinds={"chrome_flow", "accessibility", "reset_uninstall", "artifact_identity"},
    ))
    if evidence.get("candidate_manifest_sha256") != candidate_digest:
        errors.append("fresh_vm_candidate_manifest_sha256")
    ok = all([
        evidence.get("schema_version") == "glassbox-browser-fresh-vm/v1",
        root_keys_exact,
        evidence.get("ok") is True,
        evidence.get("candidate_manifest_sha256") == candidate_digest,
        evidence.get("adapter_dmg_sha256") == sha(dmg),
        evidence.get("extension_zip_sha256") == sha(extension_zip),
        evidence.get("extension_id") == extension_id,
        isinstance(evidence.get("chrome_version"), str) and bool(evidence.get("chrome_version")),
        isinstance(checks, dict)
        and set(checks) == required
        and all(checks.get(name) is True for name in required),
        not errors,
    ])
    return ok, evidence, candidate_digest, sorted(set(errors))


info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
privacy = plistlib.loads((app / "Contents/Resources/PrivacyInfo.xcprivacy").read_bytes())
binary = app / "Contents/MacOS/GlassboxBrowserAdapter"
host = app / "Contents/Helpers/glassbox-browser-host"
extension = app / "Contents/Resources/Glassbox Selected Tab Extension"
manifest = json.loads((extension / "manifest.json").read_text())
candidate = json.loads((root / "docs/glassbox/browser/candidate-production-native-host.json").read_text())
app_entitlements, app_signing = signing(app)
host_entitlements, host_signing = signing(host)
app_verify = run("codesign", "--verify", "--deep", "--strict", str(app))
host_verify = run("codesign", "--verify", "--strict", str(host))
dmg_sign = run("codesign", "--verify", "--strict", str(dmg))
dmg_verify = run("hdiutil", "verify", str(dmg))
app_staple = run("xcrun", "stapler", "validate", str(app))
dmg_staple = run("xcrun", "stapler", "validate", str(dmg))
gatekeeper = run("spctl", "-a", "-vvv", "--type", "execute", str(app))
external_ok, external, candidate_manifest_digest, external_errors = external_evidence()
executables = sorted(
    path.relative_to(app).as_posix() for path in app.rglob("*")
    if path.is_file() and path.stat().st_mode & 0o111
)
extension_files = {path.name for path in extension.iterdir() if path.is_file()}
with zipfile.ZipFile(extension_zip) as archive:
    zip_names = archive.namelist()
    zip_files = set(zip_names)
    zip_safe = all(
        name and not name.startswith("/") and ".." not in pathlib.PurePosixPath(name).parts
        for name in zip_names
    )

local_checks = {
    "release_artifacts_exist": app.is_dir() and dmg.is_file() and extension_zip.is_file(),
    "bundle_identity_and_version_are_exact": (
        info.get("CFBundleIdentifier") == "com.glassbox.browser-adapter"
        and info.get("CFBundleExecutable") == "GlassboxBrowserAdapter"
        and info.get("CFBundleShortVersionString") == "0.1.0"
    ),
    "developer_id_signatures_and_hardened_runtime_are_valid": (
        app_verify.returncode == 0 and host_verify.returncode == 0
        and f"TeamIdentifier={team_id}" in app_signing and f"TeamIdentifier={team_id}" in host_signing
        and "Authority=Developer ID Application:" in app_signing
        and "Authority=Developer ID Application:" in host_signing
        and "flags=0x10000(runtime)" in app_signing and "flags=0x10000(runtime)" in host_signing
    ),
    "adapter_and_host_have_zero_entitlements": app_entitlements == {} and host_entitlements == {},
    "executable_closure_is_native_controller_and_rust_host": executables == [
        "Contents/Helpers/glassbox-browser-host", "Contents/MacOS/GlassboxBrowserAdapter"
    ],
    "privacy_manifest_declares_no_collection": (
        privacy.get("NSPrivacyTracking") is False
        and privacy.get("NSPrivacyTrackingDomains") == []
        and privacy.get("NSPrivacyCollectedDataTypes") == []
        and privacy.get("NSPrivacyAccessedAPITypes") == []
    ),
    "embedded_extension_is_exact_shipping_allowlist": extension_files == shipping_files,
    "extension_zip_is_safe_exact_shipping_allowlist": zip_safe and zip_files == shipping_files,
    "extension_identity_and_permissions_are_exact": (
        derived_extension_id(manifest.get("key", "")) == extension_id
        and manifest.get("permissions") == ["nativeMessaging"]
        and all(key not in manifest for key in ["host_permissions", "content_scripts", "background", "externally_connectable"])
    ),
    "candidate_manifest_targets_separate_adapter_and_exact_origin": candidate == {
        "name": "com.glassbox.browser",
        "description": "Glassbox selected-tab evidence broker",
        "path": "/Applications/Glassbox Browser Adapter.app/Contents/Helpers/glassbox-browser-host",
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{extension_id}/"],
    },
    "dmg_signature_and_filesystem_are_valid": dmg_sign.returncode == 0 and dmg_verify.returncode == 0,
}
release_checks = {
    "app_stapled": app_staple.returncode == 0,
    "dmg_stapled": dmg_staple.returncode == 0,
    "gatekeeper_accepts": gatekeeper.returncode == 0,
    "fresh_vm_chrome_accessibility_and_residue_evidence": external_ok,
}
readiness_ok = all(local_checks.values())
artifact_passed = readiness_ok and all(release_checks.values())
receipt = {
    "schema_version": "glassbox-browser-artifact/v1",
    "ok": artifact_passed,
    "artifact_passed": artifact_passed,
    "readiness_ok": readiness_ok,
    "gate6_promotable": artifact_passed,
    "git_head": git("rev-parse", "HEAD"),
    "git_tree": git("rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(git("status", "--porcelain")),
    "adapter_binary_sha256": sha(binary),
    "host_sha256": sha(host),
    "dmg_sha256": sha(dmg),
    "extension_zip_sha256": sha(extension_zip),
    "extension_id": extension_id,
    "local_checks": local_checks,
    "release_checks": release_checks,
    "fresh_vm_evidence": external,
    "candidate_manifest_sha256": candidate_manifest_digest if external_ok else None,
    "fresh_vm_evidence_errors": external_errors,
    "gatekeeper_output": (gatekeeper.stdout + gatekeeper.stderr).strip(),
    "stapler_output": {
        "app": (app_staple.stdout + app_staple.stderr).strip(),
        "dmg": (dmg_staple.stdout + dmg_staple.stderr).strip(),
    },
    "errors": [name for name, value in {**local_checks, **release_checks}.items() if not value],
    "external_requirements": [] if artifact_passed else [
        "submit the exact Browser Adapter app and DMG to Apple notarization and staple both tickets",
        "publish or independently issue the exact extension ZIP identity",
        "run the hash-bound fresh-VM Chrome, accessibility, reset, and uninstall evidence protocol",
        "rerun this strict verifier with GLASSBOX_BROWSER_FRESH_VM_CMS and GLASSBOX_BROWSER_REVIEWER_CA set",
    ],
}
receipt_path.parent.mkdir(parents=True, exist_ok=True)
receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if (readiness_ok if mode == "readiness" else artifact_passed) else 1)
