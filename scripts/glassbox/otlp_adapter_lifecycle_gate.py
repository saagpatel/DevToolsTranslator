#!/usr/bin/env python3
"""Local lifecycle oracle for the separately distributed Glassbox OTLP adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

TEAM_ID = "3TGZFKFNA4"
ADAPTER_ID = "com.glassbox.otlp-adapter"


def run(*args: str, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, input=input_text, capture_output=True)
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


def install(candidate: Path, destination: Path, installed_version: str | None) -> bool:
    candidate_version = plistlib.loads((candidate / "Contents/Info.plist").read_bytes())[
        "CFBundleShortVersionString"
    ]
    if installed_version is not None and version_tuple(candidate_version) < version_tuple(installed_version):
        return False
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(candidate, destination, symlinks=True)
    return True


def build_adapter(template: Path, staging: Path, version: str, identity: str) -> Path:
    app = staging / f"Glassbox OTLP Adapter-{version}.app"
    shutil.copytree(template, app, symlinks=True)
    info_path = app / "Contents/Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    info["CFBundleShortVersionString"] = version
    info["CFBundleVersion"] = version.replace(".", "")
    info_path.write_bytes(plistlib.dumps(info, sort_keys=True))
    entitlements = staging / "otlp-adapter-entitlements.plist"
    entitlements.write_bytes(
        plistlib.dumps(
            {
                "com.apple.security.app-sandbox": True,
                "com.apple.security.files.user-selected.read-write": True,
                "com.apple.security.network.server": True,
            },
            sort_keys=True,
        )
    )
    helper = app / "Contents/Helpers/glassbox-otlp-broker"
    run("codesign", "--force", "--timestamp=none", "--options", "runtime", "--sign", identity, str(helper))
    run(
        "codesign", "--force", "--timestamp=none", "--options", "runtime",
        "--entitlements", str(entitlements), "--sign", identity, str(app),
    )
    run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app))
    return app


def signing_text(app: Path) -> str:
    result = run("codesign", "-dvvv", "--entitlements", ":-", str(app), check=False)
    return result.stdout + result.stderr


def entitlement_text(executable: Path) -> str:
    result = run("codesign", "-d", "--entitlements", ":-", str(executable), check=False)
    return result.stdout + result.stderr


def executable_paths(app: Path) -> list[str]:
    paths: list[str] = []
    for path in app.rglob("*"):
        if path.is_file() and os.access(path, os.X_OK):
            paths.append(str(path.relative_to(app)))
    return sorted(paths)


def remove_adapter_state(state: dict[str, Path]) -> None:
    for name, path in state.items():
        if name == "exports":
            continue
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def seed_adapter_state(state: dict[str, Path]) -> None:
    state["support"].mkdir(parents=True, exist_ok=True)
    state["config"].write_text('{"enabled":true}\n', encoding="utf-8")
    state["credential"].write_text("test-only-credential", encoding="utf-8")
    state["exports"].parent.mkdir(parents=True, exist_ok=True)
    state["exports"].write_text("user-owned-export", encoding="utf-8")
    os.chmod(state["config"], stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(state["credential"], stat.S_IRUSR | stat.S_IWUSR)


def broker_watchdog_probe(binary: Path) -> bool:
    config = {
        "protocol_version": 1,
        "bind": "127.0.0.1:0",
        "session_id": "adapter_lifecycle_001",
        "source_id": "adapter_lifecycle_source_001",
        "source_epoch": 1,
        "credential": "adapter-lifecycle-credential-0001",
        "max_frame_bytes": 65536,
        "max_events": 100,
        "max_total_bytes": 1048576,
        "max_events_per_second": 100,
        "watchdog_timeout_ms": 100,
    }
    result = run(str(binary), check=False, input_text=json.dumps(config, separators=(",", ":")) + "\n")
    outputs = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    return (
        result.returncode == 0
        and any(item.get("type") == "ready" for item in outputs)
        and any(
            item.get("type") == "complete"
            and any(gap.get("reason") == "watchdog_timeout" for gap in item.get("gaps", []))
            for item in outputs
        )
        and "adapter-lifecycle-credential-0001" not in result.stdout
        and "adapter-lifecycle-credential-0001" not in result.stderr
    )


def reference_source_negative_probe(binary: Path) -> bool:
    secret = "reference-negative-control-secret-0001"
    invalid_config = {
        "protocol_version": 1,
        "endpoint": "192.0.2.1:4317",
        "session_id": "reference_session_001",
        "source_id": "reference_source_001",
        "source_epoch": 1,
        "credential": secret,
        "event_count": 1,
    }
    non_loopback = run(
        str(binary),
        check=False,
        input_text=json.dumps(invalid_config, separators=(",", ":")) + "\n",
    )
    argument = run(str(binary), f"--credential={secret}", check=False)
    combined = non_loopback.stdout + non_loopback.stderr + argument.stdout + argument.stderr
    return (
        non_loopback.returncode != 0
        and argument.returncode != 0
        and secret not in combined
        and not non_loopback.stdout.strip()
        and not argument.stdout.strip()
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--adapter-app", type=Path)
    parser.add_argument("--reference-source-app", type=Path)
    parser.add_argument("--reference-workflow-receipt", type=Path)
    parser.add_argument("--core-app", type=Path)
    parser.add_argument("--identity")
    args = parser.parse_args()
    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="glassbox-otlp-adapter-self-test.") as temp_name:
            temp = Path(temp_name)
            candidate = temp / "candidate.app/Contents"
            candidate.mkdir(parents=True)
            (candidate / "Info.plist").write_bytes(
                plistlib.dumps({"CFBundleShortVersionString": "1.0.0"})
            )
            downgrade_rejected = not install(candidate.parent, temp / "installed.app", "2.0.0")
            credential = temp / "credential"
            credential.write_text("secret", encoding="utf-8")
            credential.unlink()
        receipt = {
            "downgrade_negative_control": downgrade_rejected,
            "revocation_negative_control": not credential.exists(),
        }
        print(json.dumps(receipt, sort_keys=True))
        return 0 if all(receipt.values()) else 1
    if None in (
        args.root,
        args.adapter_app,
        args.reference_source_app,
        args.reference_workflow_receipt,
        args.core_app,
        args.identity,
    ):
        parser.error("all artifact, workflow receipt, core app, and identity arguments are required")

    root = args.root.resolve()
    adapter_app = args.adapter_app.resolve()
    reference_source_app = args.reference_source_app.resolve()
    reference_workflow = json.loads(args.reference_workflow_receipt.read_text(encoding="utf-8"))
    core_app = args.core_app.resolve()
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="glassbox-otlp-adapter-lifecycle.") as temp_name:
        temp = Path(temp_name)
        home = temp / "home"
        applications = home / "Applications"
        installed = applications / "Glassbox OTLP Adapter.app"
        staging = temp / "staging"
        applications.mkdir(parents=True)
        staging.mkdir()
        v1 = build_adapter(adapter_app, staging, "1.0.0", args.identity)
        v2 = build_adapter(adapter_app, staging, "2.0.0", args.identity)
        signed = signing_text(v2)
        helper = v2 / "Contents/Helpers/glassbox-otlp-broker"
        helper_entitlements = entitlement_text(helper)
        reference_source_signing = signing_text(reference_source_app)
        core_before = sorted((path.relative_to(core_app), digest(path)) for path in core_app.rglob("*") if path.is_file())

        checks["adapter_is_separately_signed_developer_id_artifact"] = (
            f"TeamIdentifier={TEAM_ID}" in signed
            and "Authority=Developer ID Application:" in signed
            and "flags=0x10000(runtime)" in signed
        )
        checks["adapter_controller_entitlements_are_exactly_sandbox_server_and_user_selected_file"] = (
            "com.apple.security.app-sandbox" in signed
            and "com.apple.security.network.server" in signed
            and "com.apple.security.files.user-selected.read-write" in signed
            and "com.apple.security.network.client" not in signed
            and "com.apple.security.inherit" not in signed
        )
        checks["adapter_helper_is_separately_signed_hardened_and_entitlement_free"] = (
            f"TeamIdentifier={TEAM_ID}" in signing_text(helper)
            and "flags=0x10000(runtime)" in signing_text(helper)
            and "com.apple.security" not in helper_entitlements
        )
        checks["adapter_bundle_contains_exactly_controller_and_broker_executables"] = executable_paths(v2) == [
            "Contents/Helpers/glassbox-otlp-broker",
            "Contents/MacOS/GlassboxOTLPAdapter",
        ]
        checks["reference_instrumented_source_is_signed_sandboxed_client_only"] = (
            f"TeamIdentifier={TEAM_ID}" in reference_source_signing
            and "flags=0x10000(runtime)" in reference_source_signing
            and "com.apple.security.app-sandbox" in reference_source_signing
            and "com.apple.security.network.client" in reference_source_signing
            and "com.apple.security.network.server" not in reference_source_signing
            and executable_paths(reference_source_app)
            == ["Contents/MacOS/glassbox-instrumented-source-probe"]
        )
        checks["reference_instrumented_source_rejects_arguments_and_non_loopback_without_secret_output"] = (
            reference_source_negative_probe(
                reference_source_app / "Contents/MacOS/glassbox-instrumented-source-probe"
            )
        )
        checks["signed_reference_source_controller_workflow_publishes_private_safe_evidence"] = (
            reference_workflow.get("schema_version")
            == "glassbox-reference-instrumented-workflow/v1"
            and reference_workflow.get("ok") is True
            and reference_workflow.get("source_schema_version")
            == "glassbox-reference-instrumented-source/v1"
            and reference_workflow.get("frames_sent") == 1
            and reference_workflow.get("source_bytes_sent", 0) > 0
            and reference_workflow.get("endpoint_was_loopback") is True
            and reference_workflow.get("credential_exposed") is False
            and reference_workflow.get("evidence_schema_version")
            == "glassbox-live-evidence/v1"
            and reference_workflow.get("observations") == 2
            and reference_workflow.get("relations") == 0
            and reference_workflow.get("published_to_inherited_descriptor") is True
            and reference_workflow.get("raw_private_content_excluded") is True
            and reference_workflow.get("core_reimport_schema_version")
            == "glassbox-native-shell/v1"
            and reference_workflow.get("core_reimport_total_count") == 2
            and reference_workflow.get("core_reimport_inserted") == 2
            and reference_workflow.get("core_reimport_unmarked_drop_count") == 0
        )
        checks["fresh_install"] = install(v1, installed, None)
        checks["installed_broker_launches_and_fails_closed_on_watchdog"] = broker_watchdog_probe(
            installed / "Contents/Helpers/glassbox-otlp-broker"
        )

        state = {
            "support": home / "Library/Application Support/Glassbox OTLP Adapter",
            "config": home / "Library/Application Support/Glassbox OTLP Adapter/config.json",
            "credential": home / "Library/Application Support/Glassbox OTLP Adapter/credential",
            "exports": home / "Documents/Glassbox Live Evidence.glassbox",
        }
        seed_adapter_state(state)
        checks["adapter_config_and_credential_are_user_only"] = all(
            stat.S_IMODE(state[name].stat().st_mode) == 0o600 for name in ("config", "credential")
        )
        checks["update_installs_newer_adapter"] = install(v2, installed, "1.0.0")
        checks["update_preserves_state_and_user_export"] = all(path.exists() for path in state.values())
        checks["downgrade_rejected"] = not install(v1, installed, "2.0.0")
        checks["installed_version_remains_current"] = (
            plistlib.loads((installed / "Contents/Info.plist").read_bytes())[
                "CFBundleShortVersionString"
            ]
            == "2.0.0"
        )
        state["credential"].unlink()
        checks["revoke_removes_credential_without_deleting_export"] = (
            not state["credential"].exists() and state["exports"].exists()
        )
        remove_adapter_state(state)
        shutil.rmtree(installed)
        checks["uninstall_removes_adapter_and_owned_state"] = (
            not installed.exists()
            and not state["support"].exists()
            and not state["config"].exists()
            and not state["credential"].exists()
        )
        checks["uninstall_preserves_user_export"] = state["exports"].exists()
        forbidden_residue_names = {"Launch" + "Agents", "Launch" + "Daemons", "Privileged" + "HelperTools"}
        checks["no_launch_agent_daemon_or_privileged_residue"] = not any(
            path.name in forbidden_residue_names
            for path in home.rglob("*")
        )

        core_after = sorted((path.relative_to(core_app), digest(path)) for path in core_app.rglob("*") if path.is_file())
        checks["adapter_lifecycle_does_not_mutate_core_bundle"] = core_before == core_after
        checks["core_bundle_still_contains_exactly_two_executables_and_no_broker"] = (
            executable_paths(core_app)
            == ["Contents/Helpers/glassbox-native-bridge", "Contents/MacOS/Glassbox"]
            and not any("otlp" in str(path).lower() for path in executable_paths(core_app))
        )

    errors = [name for name, passed in checks.items() if not passed]
    receipt = {
        "schema_version": "glassbox-otlp-adapter-lifecycle/v1",
        "ok": not errors,
        "checks": checks,
        "adapter_main_sha256": digest(adapter_app / "Contents/MacOS/GlassboxOTLPAdapter"),
        "adapter_helper_sha256": digest(adapter_app / "Contents/Helpers/glassbox-otlp-broker"),
        "reference_source_sha256": digest(reference_source_app / "Contents/MacOS/glassbox-instrumented-source-probe"),
        "reference_workflow_receipt_sha256": digest(args.reference_workflow_receipt),
        "core_executables": executable_paths(core_app),
        "git_head": run("git", "-C", str(root), "rev-parse", "HEAD").stdout.strip(),
        "git_tree": run("git", "-C", str(root), "rev-parse", "HEAD^{tree}").stdout.strip(),
        "git_dirty": bool(run("git", "-C", str(root), "status", "--porcelain").stdout.strip()),
        "external_requirements": [
            "repeat install/update/downgrade/revoke/uninstall on a fresh macOS VM",
            "exercise the signed and notarized adapter artifact with an independently instrumented third-party app",
            "repeat the visible consent, endpoint disclosure, stop, export, and core import workflow on the fresh VM",
        ],
        "errors": errors,
    }
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
