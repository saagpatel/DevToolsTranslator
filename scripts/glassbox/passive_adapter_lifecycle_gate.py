#!/usr/bin/env python3
"""Lifecycle and signed-runtime oracle for the separate passive-context adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import tempfile
from pathlib import Path

TEAM_ID = "3TGZFKFNA4"


def run(*args: str, check: bool = True, input_bytes: bytes | None = None, pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(args, input=input_bytes, capture_output=True, pass_fds=pass_fds)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout).decode(errors="replace").strip() or "command failed")
    return result


def text_run(*args: str, check: bool = True) -> str:
    result = subprocess.run(args, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result.stdout + result.stderr


def entitlements(path: Path) -> dict[str, object]:
    result = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", str(path)], capture_output=True
    )
    payload = result.stdout + result.stderr
    start = payload.find(b"<?xml")
    end = payload.find(b"</plist>", start)
    if start < 0 or end < 0:
        return {}
    return plistlib.loads(payload[start : end + len(b"</plist>")])


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def executables(app: Path) -> list[str]:
    return sorted(
        str(path.relative_to(app))
        for path in app.rglob("*")
        if path.is_file() and os.access(path, os.X_OK)
    )


def numeric_version(value: str) -> tuple[int, ...]:
    parts = value.split(".")
    if not parts or any(not item.isdigit() for item in parts):
        raise ValueError(f"invalid version: {value}")
    return tuple(int(item) for item in parts)


def install(candidate: Path, destination: Path, installed_version: str | None) -> bool:
    version = plistlib.loads((candidate / "Contents/Info.plist").read_bytes())["CFBundleShortVersionString"]
    if installed_version is not None and numeric_version(version) < numeric_version(installed_version):
        return False
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(candidate, destination, symlinks=True)
    return True


def versioned_copy(template: Path, staging: Path, version: str, identity: str) -> Path:
    app = staging / f"Glassbox Passive Context-{version}.app"
    shutil.copytree(template, app, symlinks=True)
    info_path = app / "Contents/Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    info["CFBundleShortVersionString"] = version
    info["CFBundleVersion"] = version.replace(".", "")
    info_path.write_bytes(plistlib.dumps(info, sort_keys=True))
    entitlements = staging / "adapter-entitlements.plist"
    entitlements.write_bytes(plistlib.dumps({
        "com.apple.security.app-sandbox": True,
        "com.apple.security.files.user-selected.read-write": True,
    }, sort_keys=True))
    helper = app / "Contents/Helpers/glassbox-passive-context-broker"
    text_run("codesign", "--force", "--timestamp=none", "--options", "runtime", "--sign", identity, str(helper))
    text_run(
        "codesign", "--force", "--timestamp=none", "--options", "runtime",
        "--entitlements", str(entitlements), "--sign", identity, str(app),
    )
    text_run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app))
    return app


def signed_sandbox_snapshot(helper: Path, staging: Path, identity: str) -> tuple[bool, int]:
    app = staging / "SandboxedPassiveProbe.app"
    executable = app / "Contents/MacOS/glassbox-passive-context-broker"
    executable.parent.mkdir(parents=True)
    shutil.copy2(helper, executable)
    executable.chmod(0o755)
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleExecutable": executable.name,
        "CFBundleIdentifier": "com.glassbox.passive-context-sandbox-probe",
        "CFBundleName": "Glassbox Passive Context Sandbox Probe",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "1.0.0",
        "CFBundleVersion": "1",
    }, sort_keys=True))
    entitlements = staging / "sandbox-probe-entitlements.plist"
    entitlements.write_bytes(plistlib.dumps({"com.apple.security.app-sandbox": True}, sort_keys=True))
    text_run(
        "codesign", "--force", "--timestamp=none", "--options", "runtime",
        "--entitlements", str(entitlements), "--sign", identity, str(app),
    )
    evidence = staging / "sandbox-live.glassbox"
    evidence_fd = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    consent_read, consent_write = os.pipe()
    capability = b"sandbox-descriptor-capability-000001\n"
    os.write(consent_write, capability)
    os.close(consent_write)
    request = b'{"capture_session":"sandbox_live_001","protocol_version":1}\n'
    try:
        result = run(
            str(executable), "--snapshot-evidence", f"--evidence-fd={evidence_fd}",
            f"--consent-fd={consent_read}", check=False, input_bytes=request,
            pass_fds=(evidence_fd, consent_read),
        )
    finally:
        os.close(evidence_fd)
        os.close(consent_read)
    outputs = [json.loads(line) for line in result.stdout.splitlines() if line.startswith(b"{")]
    receipt = outputs[0].get("evidence", {}) if outputs else {}
    bundle = evidence.read_bytes()
    ok = (
        result.returncode == 0
        and not result.stderr
        and receipt.get("schema_version") == "glassbox-passive-evidence/v1"
        and receipt.get("relations") == 0
        and receipt.get("observations", 0) >= 1
        and receipt.get("published_to_inherited_descriptor") is True
        and bundle.startswith(b"GLSBX001")
        and capability.strip() not in result.stdout
        and capability.strip() not in bundle
    )
    return ok, receipt.get("observations", 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--adapter-app", required=True, type=Path)
    parser.add_argument("--workflow-receipt", required=True, type=Path)
    parser.add_argument("--core-app", required=True, type=Path)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    adapter = args.adapter_app.resolve()
    core = args.core_app.resolve()
    workflow = json.loads(args.workflow_receipt.read_text(encoding="utf-8"))
    checks: dict[str, bool] = {}
    core_before = sorted((str(path.relative_to(core)), digest(path)) for path in core.rglob("*") if path.is_file())
    with tempfile.TemporaryDirectory(prefix="glassbox-passive-adapter-lifecycle.") as temp_name:
        temp = Path(temp_name)
        staging = temp / "staging"
        applications = temp / "home/Applications"
        staging.mkdir()
        applications.mkdir(parents=True)
        v1 = versioned_copy(adapter, staging, "1.0.0", args.identity)
        v2 = versioned_copy(adapter, staging, "2.0.0", args.identity)
        helper = v2 / "Contents/Helpers/glassbox-passive-context-broker"
        app_signing = text_run("codesign", "-dvvv", "--entitlements", ":-", str(v2), check=False)
        helper_signing = text_run("codesign", "-dvvv", "--entitlements", ":-", str(helper), check=False)
        required_entitlements = {
            "com.apple.security.app-sandbox": True,
            "com.apple.security.files.user-selected.read-write": True,
        }

        checks["adapter_is_separately_signed_hardened_developer_id_artifact"] = (
            f"TeamIdentifier={TEAM_ID}" in app_signing
            and "Authority=Developer ID Application:" in app_signing
            and "flags=0x10000(runtime)" in app_signing
        )
        checks["adapter_entitlements_are_exactly_sandbox_and_user_selected_file"] = (
            entitlements(adapter) == required_entitlements
            and entitlements(v2) == required_entitlements
        )
        checks["helper_is_hardened_entitlement_free_and_inherits_controller_sandbox"] = (
            f"TeamIdentifier={TEAM_ID}" in helper_signing
            and "flags=0x10000(runtime)" in helper_signing
            and entitlements(helper) == {}
        )
        checks["adapter_contains_exactly_native_controller_and_rust_helper"] = executables(v2) == [
            "Contents/Helpers/glassbox-passive-context-broker",
            "Contents/MacOS/GlassboxPassiveAdapter",
        ]
        checks["swift_descriptor_workflow_publishes_and_core_reimports_private_safe_evidence"] = (
            workflow.get("schema_version") == "glassbox-passive-adapter-workflow/v1"
            and workflow.get("ok") is True
            and workflow.get("consent_transport") == "inherited_descriptor"
            and workflow.get("request_omits_consent_capability") is True
            and workflow.get("evidence_schema_version") == "glassbox-passive-evidence/v1"
            and workflow.get("observations") == 3
            and workflow.get("relations") == 0
            and workflow.get("published_to_inherited_descriptor") is True
            and workflow.get("addresses_link_ids_and_interfaces_excluded") is True
            and workflow.get("consent_capability_excluded") is True
            and workflow.get("core_reimport_schema_version") == "glassbox-native-shell/v1"
            and workflow.get("core_reimport_total_count") == 3
            and workflow.get("core_reimport_inserted") == 3
            and workflow.get("core_reimport_relation_count") == 0
            and workflow.get("core_reimport_unmarked_drop_count") == 0
            and workflow.get("core_conclusion") == "unknown"
        )
        sandbox_ok, live_observations = signed_sandbox_snapshot(helper, staging, args.identity)
        checks["fixed_ordinary_snapshot_succeeds_inside_app_sandbox_with_descriptor_consent"] = sandbox_ok

        installed = applications / "Glassbox Passive Context.app"
        checks["fresh_install"] = install(v1, installed, None)
        export = temp / "home/Documents/user-owned-passive.glassbox"
        export.parent.mkdir(parents=True)
        export.write_bytes(b"user-owned-export")
        checks["update_installs_newer_adapter"] = install(v2, installed, "1.0.0")
        checks["update_preserves_user_export"] = export.read_bytes() == b"user-owned-export"
        checks["downgrade_is_rejected"] = not install(v1, installed, "2.0.0")
        shutil.rmtree(installed)
        checks["uninstall_removes_adapter_and_preserves_user_export"] = (
            not installed.exists() and export.read_bytes() == b"user-owned-export"
        )
        forbidden_residue_names = {
            "Launch" + "Agents",
            "Launch" + "Daemons",
            "Privileged" + "HelperTools",
        }
        checks["no_launch_agent_daemon_or_privileged_helper_residue"] = not any(
            path.name in forbidden_residue_names
            for path in (temp / "home").rglob("*")
        )

    core_after = sorted((str(path.relative_to(core)), digest(path)) for path in core.rglob("*") if path.is_file())
    checks["adapter_lifecycle_does_not_mutate_core_bundle"] = core_before == core_after
    checks["core_remains_exactly_native_app_and_rust_bridge_without_passive_helper"] = (
        executables(core) == ["Contents/Helpers/glassbox-native-bridge", "Contents/MacOS/Glassbox"]
        and not any("passive" in path.lower() for path in executables(core))
    )
    errors = [name for name, passed in checks.items() if not passed]
    receipt = {
        "schema_version": "glassbox-passive-adapter-lifecycle/v1",
        "ok": not errors,
        "checks": checks,
        "live_sandbox_observations": live_observations,
        "adapter_main_sha256": digest(adapter / "Contents/MacOS/GlassboxPassiveAdapter"),
        "adapter_helper_sha256": digest(adapter / "Contents/Helpers/glassbox-passive-context-broker"),
        "workflow_receipt_sha256": digest(args.workflow_receipt),
        "core_executables": executables(core),
        "git_head": text_run("git", "-C", str(root), "rev-parse", "HEAD").strip(),
        "git_dirty": bool(text_run("git", "-C", str(root), "status", "--porcelain").strip()),
        "external_requirements": [
            "repeat install, update, downgrade, visible consent, export, core import, and uninstall on a fresh macOS VM",
            "verify the final Developer ID artifact is notarized and stapled",
            "complete manual keyboard, VoiceOver, and disclosure review",
        ],
        "errors": errors,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
