#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET_DIR="${GLASSBOX_OTLP_TARGET_DIR:-${TMPDIR:-/tmp}/glassbox-otlp-target}"
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then
  echo "No Developer ID Application identity is available" >&2
  exit 2
fi
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-otlp-broker
python3 - "$ROOT" "$TARGET_DIR/debug/glassbox-otlp-broker" "$IDENTITY" <<'PY'
import hashlib, json, os, pathlib, re, resource, shutil, socket, struct, subprocess, sys, tempfile, time

root = pathlib.Path(sys.argv[1])
source_binary = pathlib.Path(sys.argv[2])
identity = sys.argv[3]
credential = "runtime-test-credential-00000001"

def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"

def config(bind="127.0.0.1:0", max_events=5000, max_rate=5000):
    return {"protocol_version":1,"bind":bind,"session_id":"session_runtime_001","source_id":"source_runtime_001","source_epoch":1,"credential":credential,"max_frame_bytes":65536,"max_events":max_events,"max_total_bytes":16*1024*1024,"max_events_per_second":max_rate,"watchdog_timeout_ms":1000}

def frame(sequence, token=credential, epoch=1):
    return json.dumps({"protocol_version":1,"session_id":"session_runtime_001","source_id":"source_runtime_001","source_epoch":epoch,"sequence":sequence,"credential":token,"captured_at_ms":1700000000000+sequence,"payload":{"kind":"span","duration_us":100+sequence%10}}, separators=(",", ":")).encode()

def parse_lines(text):
    return [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]

def run_stream(binary, cfg, frames, timed=False):
    command = ["/usr/bin/time", "-l", str(binary)] if timed else [str(binary)]
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False)
    proc.stdin.write((json.dumps(cfg, separators=(",", ":"))+"\n").encode()); proc.stdin.flush()
    ready_line = proc.stdout.readline().decode()
    ready = json.loads(ready_line)
    if ready.get("type") != "ready":
        proc.kill(); raise RuntimeError(f"broker did not become ready: {ready}")
    host, port = ready["bound"].rsplit(":", 1)
    host = host.strip("[]")
    started = time.perf_counter()
    with socket.create_connection((host, int(port)), timeout=2) as client:
        for payload in frames:
            client.sendall(struct.pack(">I", len(payload)) + payload)
    proc.stdin.close()
    remainder = proc.stdout.read().decode()
    stderr = proc.stderr.read().decode(errors="replace")
    code = proc.wait(timeout=10)
    elapsed = time.perf_counter() - started
    outputs = [ready] + parse_lines(remainder)
    rss_match = re.search(r"\s+(\d+)\s+maximum resident set size", stderr)
    return code, outputs, stderr, elapsed, int(rss_match.group(1)) if rss_match else None

with tempfile.TemporaryDirectory(prefix="glassbox-otlp-sign.") as temp:
    temp = pathlib.Path(temp)
    app = temp / "GlassboxOTLPBroker.app"
    binary = app / "Contents/MacOS/glassbox-otlp-broker"
    binary.parent.mkdir(parents=True)
    shutil.copy2(source_binary, binary)
    binary.chmod(0o755)
    (app / "Contents/Info.plist").write_text('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>glassbox-otlp-broker</string><key>CFBundleIdentifier</key><string>com.glassbox.otlp-broker</string><key>CFBundleName</key><string>Glassbox OTLP Broker</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleShortVersionString</key><string>0.1</string><key>CFBundleVersion</key><string>1</string></dict></plist>''')
    entitlements_path = temp / "entitlements.plist"
    entitlements_path.write_text('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/><key>com.apple.security.network.server</key><true/></dict></plist>''')
    subprocess.run(["codesign","--force","--timestamp=none","--options","runtime","--entitlements",str(entitlements_path),"--sign",identity,str(app)],check=True,capture_output=True)
    subprocess.run(["codesign","--verify","--deep","--strict",str(app)],check=True,capture_output=True)
    signing = subprocess.run(["codesign","-dvvv","--entitlements",":-",str(app)],text=True,capture_output=True)
    signing_text = signing.stdout + signing.stderr

    nonloop = subprocess.run([str(binary)],input=(json.dumps(config("0.0.0.0:0"))+"\n"),text=True,capture_output=True,timeout=3)
    nonloop_outputs = parse_lines(nonloop.stdout)

    valid_frames = [frame(i) for i in range(1000)]
    valid_code, valid_outputs, valid_stderr, elapsed, max_rss = run_stream(binary, config(), valid_frames, timed=True)
    complete = next((item for item in valid_outputs if item.get("type") == "complete"), {})

    wrong_code, wrong_outputs, _, _, _ = run_stream(binary, config(), [frame(0, token="wrong-credential-000000000000000")])
    quota_code, quota_outputs, _, _, _ = run_stream(binary, config(max_events=2), [frame(i) for i in range(3)])
    quota_complete = next((item for item in quota_outputs if item.get("type") == "complete"), {})

    watchdog_proc = subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    watchdog_proc.stdin.write(json.dumps(config())+"\n"); watchdog_proc.stdin.flush()
    watchdog_ready = json.loads(watchdog_proc.stdout.readline())
    watchdog_proc.stdin.close()
    watchdog_lines = parse_lines(watchdog_proc.stdout.read())
    watchdog_code = watchdog_proc.wait(timeout=3)
    watchdog_complete = next((item for item in watchdog_lines if item.get("type") == "complete"), {})

    ipv6_supported = True
    try:
        ipv6_code, ipv6_outputs, _, _, _ = run_stream(binary, config("[::1]:0"), [frame(0)])
    except (OSError, RuntimeError, subprocess.SubprocessError):
        ipv6_supported = False; ipv6_code = None; ipv6_outputs = []

    outbound = subprocess.run([str(binary),"--self-test-outbound-denied"],text=True,capture_output=True,timeout=3)
    outbound_outputs = parse_lines(outbound.stdout)
    outbound_kind = outbound_outputs[0].get("error_kind") if outbound_outputs else None

    gaps = complete.get("gaps", [])
    quota_gaps = quota_complete.get("gaps", [])
    checks = {
        "developer_id_signed_hardened_runtime": "Authority=Developer ID Application:" in signing_text and "flags=0x10000(runtime)" in signing_text,
        "app_sandbox_enabled": "com.apple.security.app-sandbox" in signing_text,
        "network_server_entitlement_only": "com.apple.security.network.server" in signing_text and "com.apple.security.network.client" not in signing_text,
        "non_loopback_bind_rejected": nonloop.returncode != 0 and any(item.get("code") == "non_loopback_bind" for item in nonloop_outputs),
        "ipv4_loopback_runtime": valid_code == 0 and complete.get("accepted_events") == 1000,
        "ipv6_loopback_runtime": ipv6_supported and ipv6_code == 0,
        "wrong_credential_rejected": wrong_code != 0 and any(item.get("code") == "session_rejected" for item in wrong_outputs),
        "quota_disconnect_with_gap": quota_code != 0 and any(gap.get("reason") == "quota_exceeded" for gap in quota_gaps),
        "disconnect_gap_recorded": any(gap.get("reason") == "disconnected" for gap in gaps),
        "watchdog_gap_recorded": watchdog_ready.get("type") == "ready" and watchdog_code == 0 and any(gap.get("reason") == "watchdog_timeout" for gap in watchdog_complete.get("gaps",[])),
        "outbound_denied_by_sandbox": outbound.returncode == 0 and outbound_kind == "PermissionDenied",
        "observer_rss_under_128_mib": max_rss is not None and max_rss <= 128*1024*1024,
        "observer_1000_events_under_5_seconds": elapsed <= 5.0,
        "audit_output_excludes_secret": credential not in json.dumps(valid_outputs) and credential not in valid_stderr,
    }
    receipt = {
        "schema_version":"glassbox-otlp-broker/v1", "ok":all(checks.values()),
        "git_head":git("rev-parse","HEAD"), "git_tree":git("rev-parse","HEAD^{tree}"), "git_dirty":bool(git("status","--porcelain")),
        "binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(), "codesign_identity":identity,
        "checks":checks, "observer":{"events":1000,"elapsed_seconds":elapsed,"events_per_second":1000/elapsed if elapsed else None,"maximum_resident_set_size_bytes":max_rss},
        "outbound_error_kind":outbound_kind, "runtime_checks_remaining":["production bundle nesting and audit-token IPC","sustained production-load observer study"],
        "errors":[name for name,value in checks.items() if not value],
    }
    print(json.dumps(receipt,indent=2,sort_keys=True))
    raise SystemExit(0 if receipt["ok"] else 1)
PY
