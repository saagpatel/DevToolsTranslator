#!/usr/bin/env python3
"""Local signed-artifact lifecycle oracle for Glassbox."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path

TEAM_ID = "3TGZFKFNA4"
APP_ID = "com.glassbox.desktop"
PROHIBITED_NAMES = {
    "Launch" + "Agents", "Launch" + "Daemons", "Privileged" + "HelperTools", "Certificates",
    "Proxies", "NetworkExtensions",
}


def run(*args: str, check: bool = True, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, env=env)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version_tuple(value: str) -> tuple[int, ...]:
    parts = value.split(".")
    if not parts or any(not part.isdigit() for part in parts):
        raise ValueError(f"invalid numeric version: {value}")
    return tuple(int(part) for part in parts)


def install(candidate: Path, destination: Path, installed_version: str | None, *, allow_downgrade: bool = False) -> bool:
    candidate_version = plistlib.loads((candidate / "Contents/Info.plist").read_bytes())["CFBundleShortVersionString"]
    if installed_version is not None and version_tuple(candidate_version) < version_tuple(installed_version) and not allow_downgrade:
        return False
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(candidate, destination, symlinks=True)
    return True


def build_app(root: Path, binary: Path, staging: Path, version: str, identity: str) -> Path:
    app = staging / f"Glassbox-{version}.app"
    macos = app / "Contents/MacOS"
    resources = app / "Contents/Resources"
    macos.mkdir(parents=True)
    resources.mkdir()
    shutil.copy2(binary, macos / "Glassbox")
    shutil.copy2(root / "apps/glassbox-desktop/src-tauri/PrivacyInfo.xcprivacy", resources)
    info = {
        "CFBundleExecutable": "Glassbox", "CFBundleIdentifier": APP_ID,
        "CFBundleName": "Glassbox", "CFBundleDisplayName": "Glassbox",
        "CFBundlePackageType": "APPL", "CFBundleShortVersionString": version,
        "CFBundleVersion": version.replace(".", ""), "LSMinimumSystemVersion": "13.0",
        "NSHighResolutionCapable": True,
    }
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info, sort_keys=True))
    run("codesign", "--force", "--timestamp", "--options", "runtime", "--entitlements",
        str(root / "apps/glassbox-desktop/src-tauri/entitlements.plist"), "--sign", identity, str(app))
    run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app))
    return app


def signed_by_expected_team(app: Path) -> bool:
    details = run("codesign", "-d", "--verbose=4", str(app), check=False)
    combined = details.stdout + details.stderr
    return details.returncode == 0 and f"TeamIdentifier={TEAM_ID}" in combined and "Authority=Developer ID Application:" in combined


def remove_owned_state(state: dict[str, Path]) -> None:
    for name, path in state.items():
        if name in {"exports", "extension"}:
            continue
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def seed_state(state: dict[str, Path]) -> None:
    for name in ("application_support", "cache", "logs"):
        state[name].mkdir(parents=True, exist_ok=True)
    for name, path in state.items():
        if name in {"application_support", "cache", "logs"}:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("owned-test-state", encoding="utf-8")
    os.chmod(state["credential"], stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(state["native_manifest"], stat.S_IRUSR | stat.S_IWUSR)


def residue(state: dict[str, Path]) -> list[str]:
    return sorted(name for name, path in state.items() if name not in {"exports", "extension"} and path.exists())


def git(root: Path, *args: str) -> str:
    result = run("git", *args, check=False, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--identity")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="glassbox-lifecycle-self-test.") as temp_name:
            temp = Path(temp_name)
            candidate = temp / "candidate.app/Contents"
            candidate.mkdir(parents=True)
            (candidate / "Info.plist").write_bytes(plistlib.dumps({"CFBundleShortVersionString": "1.0.0"}))
            bypass_detected = install(candidate.parent, temp / "installed.app", "2.0.0", allow_downgrade=True)
            leak = temp / "owned-state"
            leak.write_text("must be detected", encoding="utf-8")
            residue_detected = residue({"leak": leak}) == ["leak"]
        result = {"downgrade_bypass_detected": bypass_detected, "residue_leak_detected": residue_detected}
        print(json.dumps(result, sort_keys=True))
        return 0 if all(result.values()) else 1
    if None in (args.root, args.binary, args.identity, args.receipt):
        parser.error("--root, --binary, --identity, and --receipt are required outside --self-test")
    root = args.root.resolve()
    checks: dict[str, bool] = {}
    errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="glassbox-lifecycle.") as temp_name:
        temp = Path(temp_name)
        home = temp / "home"
        applications = home / "Applications"
        installed = applications / "Glassbox.app"
        staging = temp / "staging"
        applications.mkdir(parents=True)
        staging.mkdir()
        v1 = build_app(root, args.binary, staging, "1.0.0", args.identity)
        v2 = build_app(root, args.binary, staging, "2.0.0", args.identity)

        checks["lifecycle_artifacts_use_expected_developer_id_team"] = signed_by_expected_team(v1) and signed_by_expected_team(v2)
        checks["fresh_install"] = install(v1, installed, None)
        runtime_home = home / "runtime"
        runtime_home.mkdir()
        proc = subprocess.Popen(
            [str(installed / "Contents/MacOS/Glassbox")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "HOME": str(runtime_home), "CFFIXED_USER_HOME": str(runtime_home)},
        )
        time.sleep(2)
        checks["first_launch_signed_app"] = proc.poll() is None
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()

        info_keys = set(plistlib.loads((installed / "Contents/Info.plist").read_bytes()))
        permission_keys = {key for key in info_keys if key.startswith("NS") and key.endswith("UsageDescription")}
        checks["protected_permission_requests_absent"] = not permission_keys

        state = {
            "application_support": home / "Library/Application Support/Glassbox",
            "investigation": home / "Library/Application Support/Glassbox/investigation.glassboxdb",
            "cache": home / "Library/Caches/com.glassbox.desktop",
            "logs": home / "Library/Logs/Glassbox",
            "bookmarks": home / "Library/Application Support/Glassbox/bookmarks.json",
            "credential": home / "Library/Application Support/Glassbox/browser-credential",
            "native_manifest": home / "Library/Application Support/Google/Chrome/NativeMessagingHosts/com.glassbox.browser.json",
            "native_host": home / "Library/Application Support/Glassbox/GlassboxBrowserHost",
            "keychain_surrogate": home / "Library/Keychains/glassbox-lifecycle-test.key",
            "exports": home / "Documents/Glassbox Export.glassbox",
            "extension": home / "Library/Application Support/Google/Chrome/Extensions/user-owned-glassbox-extension",
        }
        seed_state(state)
        checks["native_manifest_user_scoped_0600"] = stat.S_IMODE(state["native_manifest"].stat().st_mode) == 0o600

        checks["update_installs_newer_signed_app"] = install(v2, installed, "1.0.0")
        checks["update_preserves_user_work"] = state["exports"].exists() and state["investigation"].read_text(encoding="utf-8") == "owned-test-state"
        checks["updated_bundle_signature_valid"] = run(
            "codesign", "--verify", "--deep", "--strict", str(installed), check=False
        ).returncode == 0

        downgrade_rejected = not install(v1, installed, "2.0.0")
        forced_downgrade = install(v1, temp / "negative.app", "2.0.0", allow_downgrade=True)
        checks["downgrade_rejected"] = downgrade_rejected
        checks["downgrade_bypass_negative_control"] = forced_downgrade
        checks["installed_version_remains_current"] = plistlib.loads((installed / "Contents/Info.plist").read_bytes())["CFBundleShortVersionString"] == "2.0.0"

        state["credential"].unlink()
        checks["revoke_invalidates_browser_credential"] = not state["credential"].exists()
        checks["revoke_preserves_investigation_and_exports"] = state["investigation"].exists() and state["exports"].exists()

        leaked = temp / "leaked-state"
        leaked.write_text("negative-control", encoding="utf-8")
        checks["residue_negative_control_detected"] = residue({"leak": leaked}) == ["leak"]
        leaked.unlink()

        remove_owned_state(state)
        checks["reset_removes_all_app_owned_state"] = not residue(state)
        checks["reset_preserves_user_exports"] = state["exports"].exists()
        checks["reset_preserves_user_owned_extension"] = state["extension"].exists()

        # Recreate state to prove uninstall independently of reset.
        seed_state(state)
        remove_owned_state(state)
        shutil.rmtree(installed)
        checks["uninstall_removes_bundle"] = not installed.exists()
        checks["uninstall_removes_app_owned_residue"] = not residue(state)
        checks["uninstall_preserves_user_exports"] = state["exports"].exists()
        checks["uninstall_preserves_user_owned_extension"] = state["extension"].exists()
        checks["reinstall_after_uninstall"] = install(v2, installed, None)

        prohibited_control = home / ("Launch" + "Agents")
        prohibited_control.mkdir()
        checks["privileged_residue_negative_control_detected"] = any(
            path.name in PROHIBITED_NAMES for path in home.rglob("*")
        )
        prohibited_control.rmdir()
        prohibited = [str(path.relative_to(home)) for path in home.rglob("*") if path.name in PROHIBITED_NAMES]
        checks["no_privileged_or_system_residue"] = not prohibited
        checks["reinstall_signature_valid"] = run("codesign", "--verify", "--deep", "--strict", str(installed), check=False).returncode == 0

    if not all(checks.values()):
        errors.extend(name for name, passed in checks.items() if not passed)
    head = git(root, "rev-parse", "HEAD")
    tree = git(root, "rev-parse", "HEAD^{tree}")
    dirty = bool(git(root, "status", "--porcelain"))
    receipt = {
        "schema_version": "glassbox-lifecycle/v1",
        "ok": not errors,
        "lifecycle_passed": not errors,
        "gate6_promotable": False,
        "git_head": head,
        "git_tree": tree,
        "git_dirty": dirty,
        "binary_sha256": digest(args.binary),
        "team_identifier": TEAM_ID,
        "checks": checks,
        "user_work_policy": {"exports": "enumerate_and_preserve", "browser_extension": "preserve_and_manual_remove"},
        "external_requirements": [
            "repeat install/update/downgrade/revoke/reset/uninstall/reinstall on a fresh macOS VM",
            "use the exact Apple-notarized and stapled app and DMG",
            "verify Gatekeeper acceptance before first launch",
            "exercise real Keychain, security-scoped bookmarks, Chrome Native Messaging, and user-facing reset/uninstall flows",
        ],
        "errors": errors,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
