#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

root, source_binary, native_bridge, identity, receipt_path = (
    pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]),
    sys.argv[4], pathlib.Path(sys.argv[5]),
)
corpus = root / "crates/glassbox-fixtures/corpus/passive-context"
CONSENT = b"passive-consent-capability-000001\n"


def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def output_lines(result):
    return [
        json.loads(line) for line in result.stdout.splitlines()
        if line.strip().startswith(b"{")
    ]


def run_legacy(binary, operation, fixture=None):
    env = os.environ.copy()
    env["GLASSBOX_PASSIVE_CONTEXT_ENABLED"] = "1"
    env["GLASSBOX_PASSIVE_CONTEXT_CONSENT_TOKEN"] = CONSENT.strip().decode()
    request = json.dumps({
        "protocol_version": 1,
        "consent_token": CONSENT.strip().decode(),
        "capture_session": "legacy_001",
    }, separators=(",", ":")).encode() + b"\n"
    data = request + (fixture.read_bytes() if fixture else b"")
    result = subprocess.run(
        [str(binary), operation], input=data, capture_output=True, timeout=5, env=env,
    )
    return result, output_lines(result)


def run_evidence(binary, operation, output_path, fixture=None, *, capability=CONSENT, request_extra=None):
    evidence_fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    consent_read, consent_write = os.pipe()
    os.write(consent_write, capability)
    os.close(consent_write)
    request = {"protocol_version": 1, "capture_session": output_path.stem}
    request.update(request_extra or {})
    data = json.dumps(request, separators=(",", ":")).encode() + b"\n"
    if fixture:
        data += fixture.read_bytes()
    env = os.environ.copy()
    # Old ambient controls are deliberately hostile. They must be ignored.
    env["GLASSBOX_PASSIVE_CONTEXT_ENABLED"] = "1"
    env["GLASSBOX_PASSIVE_CONTEXT_CONSENT_TOKEN"] = "ambient-authority-must-not-work"
    try:
        result = subprocess.run(
            [str(binary), operation, f"--evidence-fd={evidence_fd}", f"--consent-fd={consent_read}"],
            input=data, capture_output=True, timeout=5, env=env,
            pass_fds=(evidence_fd, consent_read),
        )
    finally:
        os.close(evidence_fd)
        os.close(consent_read)
    return result, output_lines(result)


def run_missing_consent(binary, output_path, fixture):
    evidence_fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    request = b'{"capture_session":"missing_consent","protocol_version":1}\n'
    try:
        result = subprocess.run(
            [str(binary), "--parse-stdin-evidence", f"--evidence-fd={evidence_fd}"],
            input=request + fixture.read_bytes(), capture_output=True, timeout=5,
            pass_fds=(evidence_fd,),
        )
    finally:
        os.close(evidence_fd)
    return result, output_lines(result)


def rejected(result, lines, code):
    return result.returncode != 0 and bool(lines) and lines[0].get("code") == code


with tempfile.TemporaryDirectory(prefix="glassbox-passive-sign.") as temp_name:
    temp = pathlib.Path(temp_name)
    app = temp / "GlassboxPassiveContextBroker.app"
    binary = app / "Contents/MacOS/glassbox-passive-context-broker"
    binary.parent.mkdir(parents=True)
    shutil.copy2(source_binary, binary)
    binary.chmod(0o755)
    (app / "Contents/Info.plist").write_text('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>glassbox-passive-context-broker</string><key>CFBundleIdentifier</key><string>com.glassbox.passive-context-broker</string><key>CFBundleName</key><string>Glassbox Passive Context Broker</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleShortVersionString</key><string>0.1</string><key>CFBundleVersion</key><string>1</string></dict></plist>''')
    subprocess.run(
        ["codesign", "--force", "--timestamp=none", "--options", "runtime", "--sign", identity, str(app)],
        check=True, capture_output=True,
    )
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True, capture_output=True)
    signing = subprocess.run(["codesign", "-dvvv", "--entitlements", ":-", str(app)], text=True, capture_output=True)
    signing_text = signing.stdout + signing.stderr

    legacy_snapshot, legacy_snapshot_lines = run_legacy(binary, "--snapshot")
    legacy_parse, legacy_parse_lines = run_legacy(binary, "--parse-stdin", corpus / "valid.txt")
    unsupported, unsupported_lines = run_legacy(binary, "--scan")
    missing_path = temp / "missing.glassbox"
    missing, missing_lines = run_missing_consent(binary, missing_path, corpus / "valid.txt")

    token_path = temp / "token.glassbox"
    token, token_lines = run_evidence(
        binary, "--parse-stdin-evidence", token_path, corpus / "valid.txt",
        request_extra={"consent_token": CONSENT.strip().decode()},
    )
    short_path = temp / "short.glassbox"
    short, short_lines = run_evidence(
        binary, "--parse-stdin-evidence", short_path, corpus / "valid.txt", capability=b"too-short\n",
    )

    valid_path = temp / "valid.glassbox"
    valid, valid_lines = run_evidence(binary, "--parse-stdin-evidence", valid_path, corpus / "valid.txt")
    conflict_path = temp / "conflict.glassbox"
    conflict, conflict_lines = run_evidence(binary, "--parse-stdin-evidence", conflict_path, corpus / "conflict.txt")
    malformed_path = temp / "malformed.glassbox"
    malformed, malformed_lines = run_evidence(binary, "--parse-stdin-evidence", malformed_path, corpus / "malformed.txt")
    live_path = temp / "live.glassbox"
    live, live_lines = run_evidence(binary, "--snapshot-evidence", live_path)

    valid_receipt = valid_lines[0].get("evidence", {}) if valid_lines else {}
    conflict_receipt = conflict_lines[0].get("evidence", {}) if conflict_lines else {}
    live_receipt = live_lines[0].get("evidence", {}) if live_lines else {}
    evidence_bytes = valid_path.read_bytes()
    evidence_sha = hashlib.sha256(evidence_bytes).hexdigest()
    native_import = subprocess.run(
        [str(native_bridge), "--import", "glassbox", evidence_sha, "passive_import_001"],
        input=evidence_bytes, capture_output=True, timeout=10,
    )
    native_payload = json.loads(native_import.stdout) if native_import.returncode == 0 else {}
    source_text = (root / "apps/glassbox-passive-context-broker/src/main.rs").read_text()
    forbidden_tokens = (
        b"192.0.2.1", b"192.0.2.2", b"aa:bb:cc:dd:ee:1", b"en0",
    )
    checks = {
        "developer_id_signed_hardened_runtime": (
            "Authority=Developer ID Application:" in signing_text
            and "flags=0x10000(runtime)" in signing_text
        ),
        "no_network_or_privileged_entitlements": (
            "com.apple.security.network" not in signing_text and "com.apple.developer" not in signing_text
        ),
        "descriptor_only_contract_rejects_legacy_raw_operations": (
            rejected(legacy_snapshot, legacy_snapshot_lines, "unsupported_operation")
            and rejected(legacy_parse, legacy_parse_lines, "unsupported_operation")
        ),
        "legacy_environment_cannot_authorize_capture": (
            rejected(legacy_parse, legacy_parse_lines, "unsupported_operation")
            and not missing_path.read_bytes()
        ),
        "both_inherited_descriptors_are_required": rejected(missing, missing_lines, "unsupported_operation"),
        "request_body_consent_is_rejected": token.returncode != 0 and not token_path.read_bytes(),
        "short_descriptor_capability_is_rejected": (
            rejected(short, short_lines, "consent_required") and not short_path.read_bytes()
        ),
        "active_scan_operation_rejected": rejected(unsupported, unsupported_lines, "unsupported_operation"),
        "consent_capability_not_emitted": all(
            CONSENT.strip() not in result.stdout and CONSENT.strip() not in result.stderr
            for result in [legacy_snapshot, legacy_parse, unsupported, missing, token, short, valid, conflict, malformed, live]
        ),
        "fixed_passive_command_only": (
            'const ARP_PATH: &str = "/usr/sbin/arp"' in source_text
            and '.arg("-an")' in source_text
            and all(command not in source_text for command in ["/ping", "/nmap", "/nc", "port_scan", "banner_scan"])
        ),
        "ambient_and_raw_authority_paths_absent_from_source": (
            "GLASSBOX_PASSIVE_CONTEXT_ENABLED" not in source_text
            and "GLASSBOX_PASSIVE_CONTEXT_CONSENT_TOKEN" not in source_text
            and 'operation == "--snapshot"' not in source_text
            and 'operation == "--parse-stdin"' not in source_text
            and "consent_token" not in source_text
        ),
        "valid_fixture_publishes_atomic_digest_bound_evidence": (
            valid.returncode == 0
            and valid_receipt.get("schema_version") == "glassbox-passive-evidence/v1"
            and valid_receipt.get("observations") == 3
            and valid_receipt.get("relations") == 0
            and valid_receipt.get("published_to_inherited_descriptor") is True
            and valid_receipt.get("bundle_bytes") == len(evidence_bytes)
            and valid_receipt.get("bundle_sha256") == evidence_sha
            and evidence_bytes.startswith(b"GLSBX001")
        ),
        "conflicting_fixture_is_preserved_as_distinct_observations": (
            conflict.returncode == 0
            and conflict_receipt.get("observations") == 3
            and conflict_receipt.get("relations") == 0
        ),
        "passive_bundle_excludes_addresses_link_ids_and_interfaces": all(
            token_value not in evidence_bytes for token_value in forbidden_tokens
        ),
        "malformed_passive_input_publishes_no_partial_bundle": (
            malformed.returncode != 0
            and not malformed_path.read_bytes()
            and not any(line.get("type") == "evidence" for line in malformed_lines)
        ),
        "passive_bundle_reimports_through_native_kernel_boundary": (
            native_import.returncode == 0 and not native_import.stderr
            and native_payload.get("kernel", {}).get("inserted") == 3
            and native_payload.get("kernel", {}).get("relation_count") == 0
            and native_payload.get("total_count") == 3
            and native_payload.get("view", {}).get("conclusion") == "unknown"
            and native_payload.get("unmarked_drop_count") == 0
        ),
        "descriptor_authorized_live_capture_passes": (
            live.returncode == 0
            and live_receipt.get("schema_version") == "glassbox-passive-evidence/v1"
            and live_receipt.get("relations") == 0
            and live_receipt.get("published_to_inherited_descriptor") is True
            and live_path.read_bytes().startswith(b"GLSBX001")
        ),
    }
    fixture_hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(corpus.iterdir())
    }
    receipt = {
        "schema_version": "glassbox-passive-context/v1",
        "ok": all(checks.values()),
        "git_head": git("rev-parse", "HEAD"),
        "git_tree": git("rev-parse", "HEAD^{tree}"),
        "git_dirty": bool(git("status", "--porcelain")),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "codesign_identity": identity,
        "checks": checks,
        "fixture_sha256": fixture_hashes,
        "live_observation_count": live_receipt.get("observations", 0),
        "explicit_limitations": [
            "logical untrusted context only", "no active scanning",
            "no physical topology or ownership", "no packet, process, service, or causal attribution",
        ],
        "errors": [name for name, value in checks.items() if not value],
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    raise SystemExit(0 if receipt["ok"] else 1)
