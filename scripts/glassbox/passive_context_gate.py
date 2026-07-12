#!/usr/bin/env python3
import hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile

root, source_binary, identity, receipt_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3], pathlib.Path(sys.argv[4])
corpus = root / "crates/glassbox-fixtures/corpus/passive-context"

def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"

CONSENT = "passive-consent-capability-000001"

def run(binary, args, fixture=None, enabled=True, expected=CONSENT, supplied=CONSENT):
    env = os.environ.copy()
    if enabled:
        env["GLASSBOX_PASSIVE_CONTEXT_ENABLED"] = "1"
        if expected is not None: env["GLASSBOX_PASSIVE_CONTEXT_CONSENT_TOKEN"] = expected
    else: env.pop("GLASSBOX_PASSIVE_CONTEXT_ENABLED", None)
    if expected is None: env.pop("GLASSBOX_PASSIVE_CONTEXT_CONSENT_TOKEN", None)
    request = json.dumps({"protocol_version":1,"consent_token":supplied},separators=(",", ":")).encode()+b"\n"
    data = request + (fixture.read_bytes() if fixture else b"")
    result = subprocess.run([str(binary), *args], input=data, capture_output=True, timeout=5, env=env)
    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip().startswith(b"{")]
    return result, lines

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
    subprocess.run(["codesign","--force","--timestamp=none","--options","runtime","--sign",identity,str(app)],check=True,capture_output=True)
    subprocess.run(["codesign","--verify","--deep","--strict",str(app)],check=True,capture_output=True)
    signing = subprocess.run(["codesign","-dvvv","--entitlements",":-",str(app)],text=True,capture_output=True)
    signing_text = signing.stdout + signing.stderr

    disabled, disabled_lines = run(binary, ["--snapshot"], enabled=False)
    no_consent, no_consent_lines = run(binary, ["--snapshot"], expected=None)
    stale, stale_lines = run(binary, ["--snapshot"], expected="passive-consent-capability-000002")
    unsupported, unsupported_lines = run(binary, ["--scan"])
    valid, valid_lines = run(binary, ["--parse-stdin"], corpus / "valid.txt")
    conflict, conflict_lines = run(binary, ["--parse-stdin"], corpus / "conflict.txt")
    malformed, malformed_lines = run(binary, ["--parse-stdin"], corpus / "malformed.txt")
    live, live_lines = run(binary, ["--snapshot"])

    valid_snapshot = valid_lines[0].get("snapshot", {}) if valid_lines else {}
    conflict_neighbors = conflict_lines[0].get("snapshot", {}).get("neighbors", []) if conflict_lines else []
    live_snapshot = live_lines[0].get("snapshot", {}) if live_lines else {}
    source_text = (root / "apps/glassbox-passive-context-broker/src/main.rs").read_text()
    neighbors = valid_snapshot.get("neighbors", [])
    forbidden_keys = {"owner","ownership","process","process_id","pid","topology","cause","causal","service"}
    def forbidden(value):
        if isinstance(value, dict): return any(key in forbidden_keys or forbidden(item) for key,item in value.items())
        if isinstance(value, list): return any(forbidden(item) for item in value)
        return False
    checks = {
        "developer_id_signed_hardened_runtime": "Authority=Developer ID Application:" in signing_text and "flags=0x10000(runtime)" in signing_text,
        "no_network_or_privileged_entitlements": "com.apple.security.network" not in signing_text and "com.apple.developer" not in signing_text,
        "independent_disable_default": disabled.returncode != 0 and disabled_lines and disabled_lines[0].get("code") == "not_enabled",
        "explicit_consent_required": no_consent.returncode != 0 and no_consent_lines and no_consent_lines[0].get("code") == "consent_required",
        "stale_consent_capability_rejected": stale.returncode != 0 and stale_lines and stale_lines[0].get("code") == "consent_rejected",
        "consent_capability_not_emitted": all(CONSENT.encode() not in result.stdout and CONSENT.encode() not in result.stderr for result in [disabled,no_consent,stale,unsupported,valid,conflict,malformed,live]),
        "active_scan_operation_rejected": unsupported.returncode != 0 and unsupported_lines and unsupported_lines[0].get("code") == "unsupported_operation",
        "fixed_passive_command_only": 'const ARP_PATH: &str = "/usr/sbin/arp"' in source_text and '.arg("-an")' in source_text and all(command not in source_text for command in ["/ping", "/nmap", "/nc", "port_scan", "banner_scan"]),
        "bounded_fixture_snapshot": valid.returncode == 0 and len(neighbors) == 2,
        "logical_untrusted_noncausal_labels": bool(neighbors) and all(item.get("trust") == "untrusted_local_observation" and item.get("role") == "logical_context_only" and "not_causal_evidence" in item.get("limitations",[]) for item in neighbors),
        "active_probe_never_claimed": valid_snapshot.get("active_probe_performed") is False and live_snapshot.get("active_probe_performed") is False,
        "conflicting_neighbors_preserved": conflict.returncode == 0 and len(conflict_neighbors) == 2 and all(item.get("conflict") is True for item in conflict_neighbors),
        "malformed_snapshot_fails_closed": malformed.returncode != 0 and not any(line.get("type") == "snapshot" for line in malformed_lines),
        "no_ownership_process_topology_or_cause_fields": not forbidden(valid_snapshot) and not forbidden(live_snapshot),
        "ordinary_live_snapshot_passes": live.returncode == 0 and live_lines and live_lines[0].get("type") == "snapshot",
    }
    fixture_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(corpus.iterdir())}
    receipt = {"schema_version":"glassbox-passive-context/v1","ok":all(checks.values()),"git_head":git("rev-parse","HEAD"),"git_tree":git("rev-parse","HEAD^{tree}"),"git_dirty":bool(git("status","--porcelain")),"binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"codesign_identity":identity,"checks":checks,"fixture_sha256":fixture_hashes,"live_neighbor_count":len(live_snapshot.get("neighbors",[])),"explicit_limitations":["logical untrusted context only","no active scanning","no physical topology or ownership","no packet, process, service, or causal attribution"],"errors":[name for name,value in checks.items() if not value]}
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    raise SystemExit(0 if receipt["ok"] else 1)
