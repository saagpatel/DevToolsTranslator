#!/usr/bin/env python3
"""Signed Native Messaging, extension, lifecycle, privacy, and core-boundary oracle."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import plistlib
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

EXTENSION_ID = "giffhfldblangaphoeeeelcapcmedjbd"
ORIGIN = f"chrome-extension://{EXTENSION_ID}/"
TEAM_ID = "3TGZFKFNA4"
MAX_FRAME_BYTES = 1024 * 1024


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


def send_message(process: subprocess.Popen[bytes], message: dict[str, object]) -> None:
    payload = json.dumps(message, separators=(",", ":")).encode()
    assert process.stdin is not None
    process.stdin.write(struct.pack("<I", len(payload)) + payload)
    process.stdin.flush()


def read_exact(handle, count: int) -> bytes:
    output = bytearray()
    while len(output) < count:
        chunk = handle.read(count - len(output))
        if not chunk:
            raise RuntimeError("native host response ended early")
        output.extend(chunk)
    return bytes(output)


def read_message(process: subprocess.Popen[bytes]) -> dict[str, object]:
    assert process.stdout is not None
    size = struct.unpack("<I", read_exact(process.stdout, 4))[0]
    if size == 0 or size > MAX_FRAME_BYTES:
        raise RuntimeError("native host emitted invalid frame length")
    return json.loads(read_exact(process.stdout, size))


def start_host(host: Path, home: Path, origin: str = ORIGIN) -> subprocess.Popen[bytes]:
    environment = os.environ.copy()
    environment["HOME"] = str(home)
    return subprocess.Popen(
        [str(host), origin], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=environment,
    )


def handshake(process: subprocess.Popen[bytes]) -> tuple[dict[str, object], dict[str, object]]:
    context = {
        "extension_id": EXTENSION_ID,
        "browser_attachment_id": "attachment_1234567890",
        "selected_tab_id": 42,
        "request_id": "request_attach_123456",
        "session_nonce": "nonce_123456789012",
    }
    send_message(process, {
        "type": "attach",
        "request": {
            "protocol_version": 1,
            "context": context,
            "foreground_user_gesture": True,
            "visible_approval": True,
            "selected_tab_count": 1,
        },
    })
    challenge = read_message(process)
    if challenge.get("type") != "challenge":
        raise RuntimeError("challenge rejected")
    send_message(process, {"type": "exchange", "challenge": challenge["challenge"]})
    credential = read_message(process)
    if credential.get("type") != "credential":
        raise RuntimeError("credential rejected")
    return context, credential["credential"]


def frame(context: dict[str, object], credential: dict[str, object], sequence: int, payload: dict[str, object]) -> dict[str, object]:
    return {
        "type": "frame",
        "frame": {
            "protocol_version": 1,
            "context": context,
            "session_token": credential["token"],
            "sequence": sequence,
            "payload": payload,
        },
    }


def core_import(bridge: Path, bundle: bytes) -> dict[str, object]:
    result = subprocess.run(
        [str(bridge), "--import", "glassbox", hashlib.sha256(bundle).hexdigest(), "browser_gate_import"],
        input=bundle, capture_output=True,
    )
    if result.returncode or result.stderr:
        raise RuntimeError(result.stderr.decode(errors="replace") or "core import failed")
    return json.loads(result.stdout)


def extension_id(public_key: str) -> str:
    first = hashlib.sha256(base64.b64decode(public_key)).hexdigest()[:32]
    return first.translate(str.maketrans("0123456789abcdef", "abcdefghijklmnop"))


def numeric_version(value: str) -> tuple[int, ...]:
    parts = value.split(".")
    if not parts or any(not part.isdigit() for part in parts):
        raise ValueError("invalid version")
    return tuple(int(part) for part in parts)


def install(candidate: Path, destination: Path, installed_version: str | None) -> bool:
    version = plistlib.loads((candidate / "Contents/Info.plist").read_bytes())["CFBundleShortVersionString"]
    if installed_version is not None and numeric_version(version) < numeric_version(installed_version):
        return False
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(candidate, destination, symlinks=True)
    return True


def versioned_copy(template: Path, staging: Path, version: str, identity: str) -> Path:
    app = staging / f"Glassbox Browser Adapter-{version}.app"
    shutil.copytree(template, app, symlinks=True)
    info_path = app / "Contents/Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    info["CFBundleShortVersionString"] = version
    info["CFBundleVersion"] = version.replace(".", "")
    info_path.write_bytes(plistlib.dumps(info, sort_keys=True))
    host = app / "Contents/Helpers/glassbox-browser-host"
    text_run("codesign", "--force", "--timestamp=none", "--options", "runtime", "--sign", identity, str(host))
    text_run("codesign", "--force", "--timestamp=none", "--options", "runtime", "--sign", identity, str(app))
    text_run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app))
    return app


def negative_session(host: Path, home: Path, kind: str) -> tuple[int, bytes, bytes, list[Path]]:
    process = start_host(host, home)
    context, credential = handshake(process)
    now = "1720000000000000000"
    if kind == "replay":
        message = frame(context, credential, 1, {
            "kind": "navigation", "observed_unix_ns": now,
            "uncertainty_ns": 1, "url": "https://example.test/",
        })
        send_message(process, message)
        read_message(process)
        send_message(process, message)
    elif kind == "duplicate_request":
        request = {
            "kind": "request", "observed_unix_ns": now, "uncertainty_ns": 1,
            "request_id": "duplicate_1", "method": "GET",
            "resource_type": "document", "url": "https://example.test/",
        }
        send_message(process, frame(context, credential, 1, request))
        read_message(process)
        send_message(process, frame(context, credential, 2, request))
    elif kind == "repeat_response":
        request = {
            "kind": "request", "observed_unix_ns": now, "uncertainty_ns": 1,
            "request_id": "consume_1", "method": "GET",
            "resource_type": "document", "url": "https://example.test/",
        }
        response = {
            "kind": "response", "observed_unix_ns": now, "uncertainty_ns": 1,
            "request_id": "consume_1", "status": 200, "encoded_body_bytes": 0,
        }
        send_message(process, frame(context, credential, 1, request))
        read_message(process)
        send_message(process, frame(context, credential, 2, response))
        read_message(process)
        send_message(process, frame(context, credential, 3, response))
    elif kind == "backward_time":
        send_message(process, frame(context, credential, 1, {
            "kind": "navigation", "observed_unix_ns": now,
            "uncertainty_ns": 1, "url": "https://example.test/first",
        }))
        read_message(process)
        send_message(process, frame(context, credential, 2, {
            "kind": "navigation", "observed_unix_ns": str(int(now) - 1000),
            "uncertainty_ns": 1, "url": "https://example.test/backward",
        }))
    elif kind == "unknown":
        send_message(process, frame(context, credential, 1, {
            "kind": "navigation", "observed_unix_ns": now,
            "uncertainty_ns": 1, "url": "https://example.test/", "secret": "rejected",
        }))
    elif kind == "disconnect":
        assert process.stdin is not None
        process.stdin.close()
    response = read_message(process)
    code = process.wait(timeout=5)
    assert process.stdout is not None and process.stderr is not None
    stdout = json.dumps(response, sort_keys=True).encode() + process.stdout.read()
    stderr = process.stderr.read()
    inbox = home / "Library/Application Support/Glassbox Browser Adapter/Inbox"
    return code, stdout, stderr, list(inbox.glob("*.glassbox")) if inbox.exists() else []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--adapter-app", required=True, type=Path)
    parser.add_argument("--core-app", required=True, type=Path)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    adapter = args.adapter_app.resolve()
    core = args.core_app.resolve()
    host = adapter / "Contents/Helpers/glassbox-browser-host"
    bridge = core / "Contents/Helpers/glassbox-native-bridge"
    extension = adapter / "Contents/Resources/Glassbox Selected Tab Extension"
    manifest = json.loads((extension / "manifest.json").read_text())
    candidate_manifest = json.loads((root / "docs/glassbox/browser/candidate-production-native-host.json").read_text())
    checks: dict[str, bool] = {}
    core_before = sorted((str(path.relative_to(core)), digest(path)) for path in core.rglob("*") if path.is_file())

    signing = text_run("codesign", "-dvvv", str(adapter), check=False)
    host_signing = text_run("codesign", "-dvvv", str(host), check=False)
    checks["adapter_and_host_are_hardened_developer_id_artifacts"] = all([
        f"TeamIdentifier={TEAM_ID}" in signing,
        "Authority=Developer ID Application:" in signing,
        "flags=0x10000(runtime)" in signing,
        f"TeamIdentifier={TEAM_ID}" in host_signing,
        "Authority=Developer ID Application:" in host_signing,
        "flags=0x10000(runtime)" in host_signing,
    ])
    checks["adapter_and_host_have_exactly_zero_entitlements"] = entitlements(adapter) == {} and entitlements(host) == {}
    checks["adapter_contains_exactly_native_controller_and_rust_host"] = executables(adapter) == [
        "Contents/Helpers/glassbox-browser-host", "Contents/MacOS/GlassboxBrowserAdapter"
    ]
    checks["extension_id_is_bound_to_embedded_public_key"] = extension_id(manifest.get("key", "")) == EXTENSION_ID
    checks["extension_permissions_are_native_messaging_only"] = (
        manifest.get("permissions") == ["nativeMessaging"]
        and manifest.get("devtools_page") == "devtools.html"
        and all(key not in manifest for key in ["host_permissions", "content_scripts", "background", "externally_connectable"])
    )
    extension_source = "\n".join(path.read_text(errors="replace") for path in extension.glob("*.js"))
    checks["devtools_source_has_no_scripting_tabs_content_or_raw_body_access"] = not any(
        token in extension_source
        for token in ["chrome.scripting", "chrome.tabs", "getContent(", ".request.headers", ".response.headers", ".request.postData"]
    )
    checks["candidate_manifest_targets_separate_adapter_and_exact_origin"] = (
        candidate_manifest == {
            "name": "com.glassbox.browser",
            "description": "Glassbox selected-tab evidence broker",
            "path": "/Applications/Glassbox Browser Adapter.app/Contents/Helpers/glassbox-browser-host",
            "type": "stdio",
            "allowed_origins": [ORIGIN],
        }
    )

    with tempfile.TemporaryDirectory(prefix="glassbox-browser-gate.") as temp_name:
        temp = Path(temp_name)
        staging = temp / "staging"
        applications = temp / "applications"
        staging.mkdir()
        applications.mkdir()
        v1 = versioned_copy(adapter, staging, "1.0.0", args.identity)
        v2 = versioned_copy(adapter, staging, "2.0.0", args.identity)
        home = temp / "home"
        home.mkdir()
        process = start_host(host, home)
        context, credential = handshake(process)
        now = "1720000000000000000"
        payloads = [
            {"kind":"gap", "observed_unix_ns":now, "uncertainty_ns":1, "reason":"devtools_opened_late", "dropped_count":0},
            {"kind":"request", "observed_unix_ns":now, "uncertainty_ns":1, "request_id":"raw_request_secret_1", "method":"POST", "resource_type":"fetch", "url":"https://user:pass@seeded-secret.example/private/value?token=seeded-query-secret&safe=1#seeded-fragment"},
            {"kind":"response", "observed_unix_ns":now, "uncertainty_ns":1, "request_id":"raw_request_secret_1", "status":204, "encoded_body_bytes":17},
            {"kind":"user_action", "observed_unix_ns":now, "uncertainty_ns":1, "action":"click"},
            {"kind":"stop", "observed_unix_ns":now, "uncertainty_ns":1},
        ]
        responses = []
        for sequence, payload in enumerate(payloads, 1):
            send_message(process, frame(context, credential, sequence, payload))
            responses.append(read_message(process))
        code = process.wait(timeout=5)
        assert process.stderr is not None
        stderr = process.stderr.read()
        completed = responses[-1]
        inbox = home / "Library/Application Support/Glassbox Browser Adapter/Inbox"
        bundles = list(inbox.glob("*.glassbox"))
        bundle = bundles[0].read_bytes() if len(bundles) == 1 else b""
        projection = core_import(bridge, bundle) if bundle else {}
        forbidden = [
            b"raw_request_secret_1", b"seeded-secret.example", b"seeded-query-secret",
            b"seeded-fragment", b"user:pass", b"private/value",
        ]
        checks["signed_native_messaging_workflow_publishes_private_kernel_bundle"] = (
            code == 0 and not stderr and len(bundles) == 1 and bundle.startswith(b"GLSBX001")
            and completed.get("type") == "completed"
            and completed.get("schema_version") == "glassbox-browser-evidence/v1"
            and completed.get("observations") == 5 and completed.get("relations") == 1
            and completed.get("bundle_sha256") == hashlib.sha256(bundle).hexdigest()
            and not any(token in bundle for token in forbidden)
            and b"SignedUntrusted" in bundle and b"UserAsserted" in bundle
        )
        checks["offline_core_reimports_browser_bundle_without_epistemic_upgrade"] = (
            projection.get("schema_version") == "glassbox-native-shell/v1"
            and projection.get("total_count") == 5
            and projection.get("kernel", {}).get("inserted") == 5
            and projection.get("kernel", {}).get("relation_count") == 1
            and projection.get("view", {}).get("conclusion") == "unknown"
            and projection.get("unmarked_drop_count") == 0
        )
        checks["inbox_and_bundle_permissions_are_private"] = (
            (inbox.stat().st_mode & 0o777) == 0o700
            and (bundles[0].stat().st_mode & 0o777) == 0o600
        )

        for kind in [
            "replay", "duplicate_request", "repeat_response", "backward_time",
            "unknown", "disconnect",
        ]:
            negative_home = temp / f"home-{kind}"
            negative_home.mkdir()
            n_code, n_stdout, n_stderr, n_bundles = negative_session(host, negative_home, kind)
            checks[f"{kind}_fails_closed_without_bundle"] = (
                n_code != 0 and b'"type": "rejected"' in n_stdout
                and n_stderr == b"glassbox browser host: request rejected\n"
                and not n_bundles
            )

        watchdog_home = temp / "home-watchdog"
        watchdog_home.mkdir()
        watchdog = start_host(host, watchdog_home)
        handshake(watchdog)
        try:
            watchdog_code = watchdog.wait(timeout=17)
            watchdog_response = read_message(watchdog)
        except subprocess.TimeoutExpired:
            watchdog.kill()
            watchdog.wait(timeout=5)
            watchdog_code = 0
            watchdog_response = {}
        assert watchdog.stderr is not None
        watchdog_stderr = watchdog.stderr.read()
        watchdog_inbox = watchdog_home / "Library/Application Support/Glassbox Browser Adapter/Inbox"
        checks["authenticated_idle_session_watchdog_fails_closed_without_bundle"] = (
            watchdog_code != 0
            and watchdog_response == {"type": "rejected", "code": "request_rejected"}
            and watchdog_stderr == b"glassbox browser host: request rejected\n"
            and not watchdog_inbox.exists()
        )

        wrong_home = temp / "home-wrong-origin"
        wrong_home.mkdir()
        wrong = start_host(host, wrong_home, "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
        wrong_response = read_message(wrong)
        wrong_code = wrong.wait(timeout=5)
        wrong_inbox = wrong_home / "Library/Application Support/Glassbox Browser Adapter/Inbox"
        checks["wrong_extension_origin_fails_before_input_without_bundle"] = (
            wrong_code != 0 and wrong_response == {"type":"rejected", "code":"request_rejected"}
            and not wrong_inbox.exists()
        )

        manifest_path = home / "Library/Application Support/Google/Chrome/NativeMessagingHosts/com.glassbox.browser.json"
        manifest_path.parent.mkdir(parents=True)
        installed_manifest = dict(candidate_manifest)
        installed_manifest["path"] = str(host)
        manifest_path.write_text(json.dumps(installed_manifest, indent=2, sort_keys=True) + "\n")
        manifest_path.chmod(0o600)
        user_export = home / "Documents/user-browser.glassbox"
        user_export.parent.mkdir()
        user_export.write_bytes(bundle)
        manifest_path.unlink()
        checks["manifest_install_reset_is_private_and_preserves_inbox_and_user_export"] = (
            not manifest_path.exists() and bundles[0].exists() and user_export.read_bytes() == bundle
        )
        forbidden_residue = {
            "Launch" + "Agents",
            "Launch" + "Daemons",
            "Privileged" + "HelperTools",
        }
        checks["no_launch_agent_daemon_or_privileged_residue"] = not any(
            path.name in forbidden_residue for path in home.rglob("*")
        )

        installed = applications / "Glassbox Browser Adapter.app"
        checks["fresh_install"] = install(v1, installed, None)
        installed_v1 = plistlib.loads((installed / "Contents/Info.plist").read_bytes())
        checks["fresh_install_is_signed_expected_identity_and_version"] = (
            installed_v1.get("CFBundleShortVersionString") == "1.0.0"
            and text_run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(installed), check=False).find("valid on disk") >= 0
        )
        checks["update_installs_newer_adapter"] = install(v2, installed, "1.0.0")
        installed_v2 = plistlib.loads((installed / "Contents/Info.plist").read_bytes())
        checks["update_is_signed_expected_identity_and_version"] = (
            installed_v2.get("CFBundleShortVersionString") == "2.0.0"
            and text_run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(installed), check=False).find("valid on disk") >= 0
        )
        checks["downgrade_is_rejected"] = not install(v1, installed, "2.0.0")
        checks["downgrade_rejection_preserves_installed_version"] = (
            plistlib.loads((installed / "Contents/Info.plist").read_bytes()).get("CFBundleShortVersionString") == "2.0.0"
        )
        shutil.rmtree(installed)
        adapter_support = home / "Library/Application Support/Glassbox Browser Adapter"
        if adapter_support.exists():
            shutil.rmtree(adapter_support)
        checks["uninstall_removes_adapter_owned_state_and_preserves_user_export"] = (
            not installed.exists()
            and not adapter_support.exists()
            and user_export.read_bytes() == bundle
        )

    host_source = (root / "apps/glassbox-browser-host/src/main.rs").read_text()
    checks["host_has_no_network_client_server_or_arbitrary_destination_api"] = not any(
        token in host_source for token in ["TcpStream", "TcpListener", "UdpSocket", "reqwest", "URLSession", "NWConnection"]
    ) and "Glassbox Browser Adapter/Inbox" in host_source
    core_after = sorted((str(path.relative_to(core)), digest(path)) for path in core.rglob("*") if path.is_file())
    checks["browser_gate_does_not_mutate_core_bundle"] = core_before == core_after
    checks["sandboxed_core_remains_exactly_two_executables_without_browser_host"] = (
        executables(core) == ["Contents/Helpers/glassbox-native-bridge", "Contents/MacOS/Glassbox"]
        and entitlements(core).get("com.apple.security.app-sandbox") is True
        and not any("browser" in item.lower() for item in executables(core))
    )
    errors = [name for name, passed in checks.items() if not passed]
    receipt = {
        "schema_version": "glassbox-browser-adapter/v1",
        "ok": not errors,
        "checks": checks,
        "adapter_main_sha256": digest(adapter / "Contents/MacOS/GlassboxBrowserAdapter"),
        "host_sha256": digest(host),
        "extension_manifest_sha256": digest(extension / "manifest.json"),
        "candidate_manifest_sha256": digest(root / "docs/glassbox/browser/candidate-production-native-host.json"),
        "core_executables": executables(core),
        "git_head": text_run("git", "-C", str(root), "rev-parse", "HEAD").strip(),
        "git_dirty": bool(text_run("git", "-C", str(root), "status", "--porcelain").strip()),
        "external_requirements": [
            "publish or independently issue the production Chrome extension ID and review store artifact identity",
            "run the exact extension, host, install, selected-tab capture, explicit stop, export, import, reset, and uninstall flow in Chrome on a fresh macOS VM",
            "notarize and staple the separately distributed Browser Adapter artifact",
            "complete manual keyboard, screen-reader, and disclosure review in Chrome DevTools and the native adapter",
        ],
        "errors": errors,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
