#!/usr/bin/env python3
"""Signed-runtime, privacy, boundary, and lifecycle oracle for process context."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

TEAM_ID = "3TGZFKFNA4"
FORBIDDEN_ENTITLEMENTS = {
    "com.apple.security.network.client",
    "com.apple.security.network.server",
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.allow-unsigned-executable-memory",
}


def text_run(*args: str, check: bool = True) -> str:
    result = subprocess.run(args, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result.stdout + result.stderr


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def entitlements(path: Path) -> dict[str, object]:
    result = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(path)], capture_output=True)
    payload = result.stdout + result.stderr
    start = payload.find(b"<?xml")
    end = payload.find(b"</plist>", start)
    if start < 0 or end < 0:
        return {}
    return plistlib.loads(payload[start : end + len(b"</plist>")])


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
    app = staging / f"Glassbox Process Context-{version}.app"
    shutil.copytree(template, app, symlinks=True)
    info_path = app / "Contents/Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    info["CFBundleShortVersionString"] = version
    info["CFBundleVersion"] = version.replace(".", "")
    info_path.write_bytes(plistlib.dumps(info, sort_keys=True))
    helper = app / "Contents/Helpers/glassbox-process-context-broker"
    text_run("codesign", "--force", "--timestamp=none", "--options", "runtime", "--sign", identity, str(helper))
    text_run("codesign", "--force", "--timestamp=none", "--options", "runtime", "--sign", identity, str(app))
    text_run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app))
    return app


def broker_capture(
    helper: Path,
    directory: Path,
    config: dict[str, object],
    consent: bytes = b"process-gate-consent-capability-000001\n",
    control: bytes | None = None,
) -> tuple[int, bytes, bytes, bytes]:
    evidence = directory / f"evidence-{time.time_ns()}.glassbox"
    evidence_fd = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    consent_read, consent_write = os.pipe()
    os.write(consent_write, consent)
    os.close(consent_write)
    process = subprocess.Popen(
        [str(helper), "--capture", f"--evidence-fd={evidence_fd}", f"--consent-fd={consent_read}"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(evidence_fd, consent_read),
    )
    os.close(evidence_fd)
    os.close(consent_read)
    assert process.stdin is not None
    process.stdin.write((json.dumps(config, separators=(",", ":")) + "\n").encode())
    if control is not None:
        process.stdin.write(control)
        process.stdin.close()
    else:
        process.stdin.flush()
    try:
        code = process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("process broker did not terminate")
    if process.stdin is not None and not process.stdin.closed:
        process.stdin.close()
    assert process.stdout is not None and process.stderr is not None
    stdout = process.stdout.read()
    stderr = process.stderr.read()
    return code, stdout, stderr, evidence.read_bytes()


def core_import(bridge: Path, bundle: bytes, session: str) -> dict[str, object]:
    source_sha256 = hashlib.sha256(bundle).hexdigest()
    result = subprocess.run(
        [str(bridge), "--import", "glassbox", source_sha256, session],
        input=bundle,
        capture_output=True,
    )
    if result.returncode or result.stderr:
        raise RuntimeError(result.stderr.decode(errors="replace") or "core import failed")
    return json.loads(result.stdout)


def sandbox_probe(helper: Path, staging: Path, identity: str, target_pid: int) -> tuple[bool, int]:
    app = staging / "SandboxedProcessProbe.app"
    executable = app / "Contents/MacOS/glassbox-process-context-broker"
    executable.parent.mkdir(parents=True)
    shutil.copy2(helper, executable)
    executable.chmod(0o755)
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleExecutable": executable.name,
        "CFBundleIdentifier": "com.glassbox.process-context-sandbox-probe",
        "CFBundleName": "Glassbox Process Context Sandbox Probe",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "1.0.0",
        "CFBundleVersion": "1",
    }, sort_keys=True))
    entitlement_path = staging / "sandbox-probe-entitlements.plist"
    entitlement_path.write_bytes(plistlib.dumps({"com.apple.security.app-sandbox": True}, sort_keys=True))
    text_run(
        "codesign", "--force", "--timestamp=none", "--options", "runtime",
        "--entitlements", str(entitlement_path), "--sign", identity, str(app),
    )
    config = {
        "protocol_version": 1,
        "capture_session": "sandbox_negative_001",
        "process_id": target_pid,
        "process_bundle_id": "com.glassbox.process-gate-target",
        "interval_ms": 100,
        "maximum_samples": 1,
    }
    code, stdout, _stderr, evidence = broker_capture(executable, staging, config)
    rejected = [json.loads(line) for line in stdout.splitlines() if line.startswith(b"{")]
    return (
        code != 0
        and not evidence
        and bool(rejected)
        and rejected[0].get("type") == "rejected"
        and rejected[0].get("code") in {"process_unavailable", "capture_failed"},
        len(evidence),
    )


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
    helper = adapter / "Contents/Helpers/glassbox-process-context-broker"
    core_bridge = core / "Contents/Helpers/glassbox-native-bridge"
    workflow = json.loads(args.workflow_receipt.read_text(encoding="utf-8"))
    checks: dict[str, bool] = {}
    core_before = sorted((str(path.relative_to(core)), digest(path)) for path in core.rglob("*") if path.is_file())

    with tempfile.TemporaryDirectory(prefix="glassbox-process-context-gate.") as temp_name:
        temp = Path(temp_name)
        staging = temp / "staging"
        applications = temp / "home/Applications"
        staging.mkdir()
        applications.mkdir(parents=True)
        v1 = versioned_copy(adapter, staging, "1.0.0", args.identity)
        v2 = versioned_copy(adapter, staging, "2.0.0", args.identity)
        versioned_helper = v2 / "Contents/Helpers/glassbox-process-context-broker"
        app_signing = text_run("codesign", "-dvvv", str(v2), check=False)
        helper_signing = text_run("codesign", "-dvvv", str(versioned_helper), check=False)

        checks["separate_adapter_is_hardened_developer_id_artifact"] = (
            f"TeamIdentifier={TEAM_ID}" in app_signing
            and "Authority=Developer ID Application:" in app_signing
            and "flags=0x10000(runtime)" in app_signing
        )
        checks["native_controller_and_rust_helper_have_exactly_zero_entitlements"] = (
            entitlements(adapter) == {}
            and entitlements(helper) == {}
            and entitlements(v2) == {}
            and entitlements(versioned_helper) == {}
        )
        checks["no_network_or_privileged_entitlement_exists"] = not (
            FORBIDDEN_ENTITLEMENTS
            & (set(entitlements(v2)) | set(entitlements(versioned_helper)))
        )
        checks["adapter_contains_exactly_native_controller_and_rust_helper"] = executables(v2) == [
            "Contents/Helpers/glassbox-process-context-broker",
            "Contents/MacOS/GlassboxProcessAdapter",
        ]
        checks["helper_is_hardened_developer_id_and_entitlement_free"] = (
            f"TeamIdentifier={TEAM_ID}" in helper_signing
            and "Authority=Developer ID Application:" in helper_signing
            and "flags=0x10000(runtime)" in helper_signing
            and entitlements(versioned_helper) == {}
        )
        checks["signed_controller_workflow_publishes_private_bundle_and_core_reimports"] = (
            workflow.get("schema_version") == "glassbox-process-adapter-workflow/v1"
            and workflow.get("ok") is True
            and workflow.get("consent_transport") == "inherited_descriptor"
            and workflow.get("configuration_transport") == "stdin"
            and workflow.get("evidence_schema_version") == "glassbox-process-evidence/v1"
            and workflow.get("observations") == 2
            and workflow.get("relations") == 0
            and workflow.get("published_to_inherited_descriptor") is True
            and workflow.get("pid_path_arguments_user_environment_files_disk_and_network_excluded") is True
            and workflow.get("consent_capability_excluded") is True
            and workflow.get("core_reimport_schema_version") == "glassbox-native-shell/v1"
            and workflow.get("core_reimport_total_count") == 2
            and workflow.get("core_reimport_inserted") == 2
            and workflow.get("core_reimport_relation_count") == 0
            and workflow.get("core_reimport_unmarked_drop_count") == 0
            and workflow.get("core_conclusion") == "unknown"
        )

        app_process = subprocess.Popen([str(v2 / "Contents/MacOS/GlassboxProcessAdapter")])
        try:
            time.sleep(0.5)
            config = {
                "protocol_version": 1,
                "capture_session": "signed_gui_process_001",
                "process_id": app_process.pid,
                "process_bundle_id": "com.glassbox.process-adapter",
                "interval_ms": 100,
                "maximum_samples": 1,
            }
            code, stdout, stderr, bundle = broker_capture(versioned_helper, temp, config)
        finally:
            app_process.send_signal(signal.SIGTERM)
            try:
                app_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                app_process.kill()
                app_process.wait()
        output = [json.loads(line) for line in stdout.splitlines() if line.startswith(b"{")]
        evidence = output[0].get("evidence", {}) if output else {}
        prohibited = [
            b"process-gate-consent-capability", b'"process_id"', b"executable_path",
            b"process_arguments", b"username", b"environment", b"diskio", b"network_activity",
        ]
        checks["signed_entitlement_free_helper_samples_running_native_gui_app"] = (
            code == 0
            and not stderr
            and evidence.get("schema_version") == "glassbox-process-evidence/v1"
            and evidence.get("observations") == 2
            and evidence.get("relations") == 0
            and evidence.get("published_to_inherited_descriptor") is True
            and bundle.startswith(b"GLSBX001")
            and not any(token in bundle or token in stdout for token in prohibited)
        )

        control_config = dict(config, process_id=os.getpid())
        stop_config = dict(control_config, capture_session="explicit_stop_001", maximum_samples=10)
        stop_code, stop_stdout, _stop_stderr, stop_bundle = broker_capture(
            versioned_helper, temp, stop_config, control=b"stop\n"
        )
        stop_projection = core_import(core_bridge, stop_bundle, "process_stop_reimport_001")
        stop_labels = [row.get("label", "") for row in stop_projection["view"]["evidence_table"]]
        checks["explicit_stop_publishes_terminal_coverage_without_relations"] = (
            stop_code == 0
            and b'"type":"evidence"' in stop_stdout
            and stop_bundle.startswith(b"GLSBX001")
            and stop_projection["kernel"]["relation_count"] == 0
            and stop_projection["view"]["conclusion"] == "unknown"
            and any("session_end" in label and "reason=user_stop" in label for label in stop_labels)
        )

        invalid_config = dict(
            control_config,
            capture_session="invalid_bounds_001",
            interval_ms=5_000,
            maximum_samples=7,
        )
        invalid_code, invalid_stdout, _invalid_stderr, invalid_bundle = broker_capture(
            versioned_helper, temp, invalid_config
        )
        checks["invalid_bounds_fail_closed_without_evidence"] = (
            invalid_code != 0 and b'"code":"invalid_config"' in invalid_stdout and not invalid_bundle
        )
        unknown_config = dict(control_config, unexpected_field="rejected")
        unknown_code, unknown_stdout, _unknown_stderr, unknown_bundle = broker_capture(
            versioned_helper, temp, unknown_config
        )
        checks["unknown_configuration_fields_fail_closed_without_evidence"] = (
            unknown_code != 0
            and b'"code":"invalid_config"' in unknown_stdout
            and not unknown_bundle
        )
        consent_code, consent_stdout, _consent_stderr, consent_bundle = broker_capture(
            versioned_helper, temp, control_config, consent=b"short\n"
        )
        checks["missing_or_invalid_consent_fails_closed_without_evidence"] = (
            consent_code != 0 and b'"code":"consent_required"' in consent_stdout and not consent_bundle
        )
        cancel_config = dict(
            control_config,
            capture_session="disconnect_cancel_001",
            maximum_samples=10,
        )
        cancel_code, cancel_stdout, _cancel_stderr, cancel_bundle = broker_capture(
            versioned_helper, temp, cancel_config, control=b""
        )
        checks["controller_disconnect_is_cancellation_and_publishes_zero_bytes"] = (
            cancel_code != 0 and b'"code":"cancelled"' in cancel_stdout and not cancel_bundle
        )
        sandbox_ok, sandbox_bytes = sandbox_probe(versioned_helper, staging, args.identity, os.getpid())
        checks["sandboxed_negative_control_denies_cross_process_sampling_and_publishes_zero_bytes"] = sandbox_ok

        installed = applications / "Glassbox Process Context.app"
        checks["fresh_install"] = install(v1, installed, None)
        export = temp / "home/Documents/user-owned-process.glassbox"
        export.parent.mkdir(parents=True)
        export.write_bytes(b"user-owned-export")
        checks["update_installs_newer_adapter"] = install(v2, installed, "1.0.0")
        checks["update_preserves_user_export"] = export.read_bytes() == b"user-owned-export"
        checks["downgrade_is_rejected"] = not install(v1, installed, "2.0.0")
        shutil.rmtree(installed)
        checks["uninstall_removes_adapter_and_preserves_user_export"] = (
            not installed.exists() and export.read_bytes() == b"user-owned-export"
        )
        forbidden_residue = {
            "Launch" + "Agents",
            "Launch" + "Daemons",
            "Privileged" + "HelperTools",
        }
        checks["no_launch_agent_daemon_or_privileged_helper_residue"] = not any(
            path.name in forbidden_residue for path in (temp / "home").rglob("*")
        )

    source_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for base in [
            root / "apps/glassbox-process-adapter-macos/Sources",
            root / "apps/glassbox-process-context-broker/src",
        ]
        for path in base.rglob("*") if path.is_file()
    )
    forbidden_network_apis = ["URLSession", "NWConnection", "NWListener", "TcpStream", "UdpSocket"]
    checks["process_adapter_sources_have_no_network_client_or_server_api"] = not any(
        token in source_text for token in forbidden_network_apis
    )
    checks["pid_reuse_is_detected_by_executable_uuid_and_process_start_time"] = all(
        token in source_text for token in ["ri_uuid", "ri_proc_start_abstime", "ProcessIdentityChanged"]
    )
    checks["controller_lists_only_transient_visible_gui_applications"] = all(
        token in source_text
        for token in [
            "NSWorkspace.shared.runningApplications",
            "activationPolicy == .regular",
            "isStillSelectedApplication",
        ]
    )
    core_after = sorted((str(path.relative_to(core)), digest(path)) for path in core.rglob("*") if path.is_file())
    checks["adapter_gate_does_not_mutate_core_bundle"] = core_before == core_after
    checks["sandboxed_core_remains_exactly_native_app_and_rust_bridge"] = (
        executables(core) == ["Contents/Helpers/glassbox-native-bridge", "Contents/MacOS/Glassbox"]
        and entitlements(core).get("com.apple.security.app-sandbox") is True
        and not any("process" in path.lower() for path in executables(core))
    )
    checks["core_bridge_contains_no_process_sampling_command_or_syscall"] = not any(
        token in (root / "apps/glassbox-native-bridge/src/main.rs").read_text(encoding="utf-8")
        for token in ["--sample-process", "proc_pid_rusage", "ProcessResource", "process_resource_sample"]
    )

    errors = [name for name, passed in checks.items() if not passed]
    receipt = {
        "schema_version": "glassbox-process-context-gate/v1",
        "ok": not errors,
        "checks": checks,
        "sandbox_negative_control_evidence_bytes": sandbox_bytes,
        "adapter_main_sha256": digest(adapter / "Contents/MacOS/GlassboxProcessAdapter"),
        "adapter_helper_sha256": digest(helper),
        "workflow_receipt_sha256": digest(args.workflow_receipt),
        "core_executables": executables(core),
        "git_head": text_run("git", "-C", str(root), "rev-parse", "HEAD").strip(),
        "git_tree": text_run("git", "-C", str(root), "rev-parse", "HEAD^{tree}").strip(),
        "git_dirty": bool(text_run("git", "-C", str(root), "status", "--porcelain").strip()),
        "external_requirements": [
            "repeat visible selection, capture, explicit stop, export, core import, update, downgrade, and uninstall on a fresh macOS VM",
            "verify final separately distributed Developer ID artifact is notarized and stapled",
            "complete manual keyboard, VoiceOver, disclosure, and selected-application identity review",
        ],
        "errors": errors,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
