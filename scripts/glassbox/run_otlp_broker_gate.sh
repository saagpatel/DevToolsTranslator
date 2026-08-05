#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET_DIR="${GLASSBOX_OTLP_TARGET_DIR:-${TMPDIR:-/tmp}/glassbox-otlp-target}"
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then
  echo "No Developer ID Application identity is available" >&2
  exit 2
fi
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-otlp-broker -p glassbox-native-bridge
python3 - "$ROOT" "$TARGET_DIR/debug/glassbox-otlp-broker" "$TARGET_DIR/debug/glassbox-native-bridge" "$IDENTITY" <<'PY'
import hashlib, json, os, pathlib, re, resource, shutil, socket, struct, subprocess, sys, tempfile, time

root = pathlib.Path(sys.argv[1])
source_binary = pathlib.Path(sys.argv[2])
native_bridge = pathlib.Path(sys.argv[3])
identity = sys.argv[4]
credential = "runtime-test-credential-00000001"

def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"

def config(bind="127.0.0.1:0", max_events=5000, max_rate=5000):
    return {"protocol_version":1,"bind":bind,"session_id":"session_runtime_001","source_id":"source_runtime_001","source_epoch":1,"credential":credential,"max_frame_bytes":65536,"max_events":max_events,"max_total_bytes":16*1024*1024,"max_events_per_second":max_rate,"watchdog_timeout_ms":1000}

def frame(sequence, token=credential, epoch=1, payload=None):
    if payload is None:
        span_id=f"{sequence+1:016x}"
        span={"traceId":"5b8efff798038103d269b633813fc60c","spanId":span_id,
              "name":"seed-live-span-name","kind":2,
              "startTimeUnixNano":str(1581452772000000321+sequence*1000),
              "endTimeUnixNano":str(1581452773000000789+sequence*1000),
              "attributes":[{"key":"http.url","value":{"stringValue":"https://seed-live-host/private?token=seed-live-query","futureValue":"ignored"}}],
              "events":[],"links":[],"futureSpanField":"ignored"}
        if sequence > 0: span["parentSpanId"]=f"{sequence:016x}"
        payload={"resourceSpans":[{"scopeSpans":[{"spans":[span]}]}],"futureRequestField":{"secret":"ignored"}}
    return json.dumps({"protocol_version":1,"session_id":"session_runtime_001","source_id":"source_runtime_001","source_epoch":epoch,"sequence":sequence,"credential":token,"captured_at_ms":1700000000000+sequence,"payload":payload}, separators=(",", ":")).encode()

def parse_lines(text):
    return [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]

def run_stream(binary, cfg, frames, timed=False, evidence_path=None):
    command = [str(binary)]
    pass_fds=()
    evidence_fd=None
    if evidence_path is not None:
        evidence_fd=os.open(evidence_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        command.append(f"--evidence-fd={evidence_fd}")
        pass_fds=(evidence_fd,)
    if timed: command=["/usr/bin/time","-l",*command]
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False, pass_fds=pass_fds)
    if evidence_fd is not None: os.close(evidence_fd)
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

def run_rejected_peer_then_valid(binary):
    proc = subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=False)
    proc.stdin.write((json.dumps(config(),separators=(",",":"))+"\n").encode()); proc.stdin.flush()
    ready = json.loads(proc.stdout.readline())
    host, port = ready["bound"].rsplit(":",1); host = host.strip("[]")
    with socket.create_connection((host,int(port)),timeout=2) as client:
        payload=frame(0,token="wrong-credential-000000000000000")
        client.sendall(struct.pack(">I",len(payload))+payload)
    with socket.create_connection((host,int(port)),timeout=2) as client:
        payload=frame(0)
        client.sendall(struct.pack(">I",len(payload))+payload)
    proc.stdin.close()
    outputs=[ready]+parse_lines(proc.stdout.read().decode())
    stderr=proc.stderr.read().decode(errors="replace")
    return proc.wait(timeout=5),outputs,stderr

def run_explicit_stop(binary):
    proc = subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    proc.stdin.write(json.dumps(config())+"\n"); proc.stdin.flush()
    ready=json.loads(proc.stdout.readline())
    proc.stdin.write("stop\n"); proc.stdin.flush(); proc.stdin.close()
    outputs=[ready]+parse_lines(proc.stdout.read())
    stderr=proc.stderr.read()
    return proc.wait(timeout=5),outputs,stderr

def run_fragmented_frame(binary):
    proc = subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=False)
    proc.stdin.write((json.dumps(config(),separators=(",",":"))+"\n").encode()); proc.stdin.flush()
    ready=json.loads(proc.stdout.readline())
    host,port=ready["bound"].rsplit(":",1); host=host.strip("[]")
    payload=frame(0); encoded=struct.pack(">I",len(payload))+payload
    with socket.create_connection((host,int(port)),timeout=2) as client:
        for offset in range(0,len(encoded),7):
            client.sendall(encoded[offset:offset+7]); time.sleep(0.002)
    proc.stdin.close()
    outputs=[ready]+parse_lines(proc.stdout.read().decode())
    stderr=proc.stderr.read().decode(errors="replace")
    return proc.wait(timeout=5),outputs,stderr

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
    evidence_path=temp/"valid.glassbox"
    valid_code, valid_outputs, valid_stderr, elapsed, max_rss = run_stream(binary, config(), valid_frames, timed=True, evidence_path=evidence_path)
    complete = next((item for item in valid_outputs if item.get("type") == "complete"), {})

    invalid_evidence_path=temp/"invalid.glassbox"
    invalid_payload={"resourceSpans":[],"resourceMetrics":[]}
    invalid_code, invalid_outputs, _, _, _ = run_stream(
        binary,config(),[frame(0,payload=invalid_payload)],evidence_path=invalid_evidence_path)
    invalid_complete=next((item for item in invalid_outputs if item.get("type")=="complete"),{})

    wrong_code, wrong_outputs, wrong_stderr = run_rejected_peer_then_valid(binary)
    wrong_complete = next((item for item in wrong_outputs if item.get("type") == "complete"), {})
    quota_code, quota_outputs, _, _, _ = run_stream(binary, config(max_events=2), [frame(i) for i in range(3)])
    quota_complete = next((item for item in quota_outputs if item.get("type") == "complete"), {})

    watchdog_proc = subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    watchdog_proc.stdin.write(json.dumps(config())+"\n"); watchdog_proc.stdin.flush()
    watchdog_ready = json.loads(watchdog_proc.stdout.readline())
    watchdog_proc.stdin.close()
    watchdog_lines = parse_lines(watchdog_proc.stdout.read())
    watchdog_code = watchdog_proc.wait(timeout=3)
    watchdog_complete = next((item for item in watchdog_lines if item.get("type") == "complete"), {})

    stop_code, stop_outputs, stop_stderr = run_explicit_stop(binary)
    stop_complete = next((item for item in stop_outputs if item.get("type") == "complete"), {})
    fragmented_code, fragmented_outputs, fragmented_stderr = run_fragmented_frame(binary)
    fragmented_complete = next((item for item in fragmented_outputs if item.get("type") == "complete"), {})
    unbounded = subprocess.run(
        [str(binary)], input=(json.dumps(config(max_events=100001))+"\n"),
        text=True, capture_output=True, timeout=3)
    unbounded_outputs = parse_lines(unbounded.stdout)

    ipv6_supported = True
    try:
        ipv6_code, ipv6_outputs, _, _, _ = run_stream(binary, config("[::1]:0"), [frame(0)])
    except (OSError, RuntimeError, subprocess.SubprocessError):
        ipv6_supported = False; ipv6_code = None; ipv6_outputs = []

    outbound = subprocess.run([str(binary),"--self-test-outbound-denied"],text=True,capture_output=True,timeout=3)
    outbound_outputs = parse_lines(outbound.stdout)
    outbound_kind = outbound_outputs[0].get("error_kind") if outbound_outputs else None

    gaps = complete.get("gaps", [])
    evidence = complete.get("evidence") or {}
    evidence_bytes=evidence_path.read_bytes()
    evidence_sha=hashlib.sha256(evidence_bytes).hexdigest()
    native_import=subprocess.run(
        [str(native_bridge),"--import","glassbox",evidence_sha,"live_import_001"],
        input=evidence_bytes,capture_output=True,timeout=10)
    native_payload=json.loads(native_import.stdout) if native_import.returncode==0 else {}
    quota_gaps = quota_complete.get("gaps", [])
    checks = {
        "developer_id_signed_hardened_runtime": "Authority=Developer ID Application:" in signing_text and "flags=0x10000(runtime)" in signing_text,
        "app_sandbox_enabled": "com.apple.security.app-sandbox" in signing_text,
        "network_server_entitlement_only": "com.apple.security.network.server" in signing_text and "com.apple.security.network.client" not in signing_text,
        "non_loopback_bind_rejected": nonloop.returncode != 0 and any(item.get("code") == "non_loopback_bind" for item in nonloop_outputs),
        "ipv4_loopback_runtime": valid_code == 0 and complete.get("accepted_events") == 1000,
        "validated_live_projection_publishes_kernel_checked_bundle": (
            evidence.get("schema_version")=="glassbox-live-evidence/v1"
            and evidence.get("observations")==1001
            and evidence.get("relations")==999
            and evidence.get("published_to_inherited_descriptor") is True
            and evidence.get("bundle_bytes")==len(evidence_bytes)
            and evidence.get("bundle_sha256")==hashlib.sha256(evidence_bytes).hexdigest()
            and evidence_bytes.startswith(b"GLSBX001")
        ),
        "published_bundle_reimports_through_native_kernel_boundary": (
            native_import.returncode==0 and not native_import.stderr
            and native_payload.get("kernel",{}).get("inserted")==1001
            and native_payload.get("kernel",{}).get("relation_count")==999
            and native_payload.get("total_count")==1001
            and native_payload.get("view",{}).get("conclusion")=="unknown"
            and native_payload.get("unmarked_drop_count")==0
        ),
        "live_bundle_excludes_raw_content_and_credentials": all(
            token not in evidence_bytes for token in (
                credential.encode(),b"seed-live-span-name",b"seed-live-host",
                b"seed-live-query",b"futureSpanField",b"futureRequestField"
            )
        ),
        "invalid_live_payload_publishes_no_partial_bundle": (
            invalid_code != 0 and not invalid_evidence_path.read_bytes()
            and invalid_complete.get("evidence") is None
            and any(gap.get("reason")=="invalid_payload" for gap in invalid_complete.get("gaps",[]))
        ),
        "ipv6_loopback_runtime": ipv6_supported and ipv6_code == 0,
        "wrong_credential_peer_rejected_without_terminating_legitimate_session": (
            wrong_code == 0
            and any(item.get("code") == "session_rejected" for item in wrong_outputs)
            and wrong_complete.get("accepted_events") == 1
            and credential not in json.dumps(wrong_outputs)
            and credential not in wrong_stderr
        ),
        "quota_disconnect_with_gap": quota_code != 0 and any(gap.get("reason") == "quota_exceeded" for gap in quota_gaps),
        "disconnect_gap_recorded": any(gap.get("reason") == "disconnected" for gap in gaps),
        "watchdog_gap_recorded": watchdog_ready.get("type") == "ready" and watchdog_code == 0 and any(gap.get("reason") == "watchdog_timeout" for gap in watchdog_complete.get("gaps",[])),
        "explicit_stop_records_revocation_gap": stop_code == 0 and not stop_stderr and any(gap.get("reason") == "revoked" for gap in stop_complete.get("gaps",[])),
        "fragmented_frames_preserve_framing_until_complete": fragmented_code == 0 and not fragmented_stderr and fragmented_complete.get("accepted_events") == 1,
        "absolute_quota_ceiling_cannot_be_relaxed_by_configuration": unbounded.returncode != 0 and not any(item.get("type") == "ready" for item in unbounded_outputs),
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
