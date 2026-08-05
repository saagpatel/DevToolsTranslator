#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-network-runtime.json}"
TARGET_DIR="${GLASSBOX_WORKFLOW_TARGET_DIR:-$ROOT/target}"
IDENTITY="${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}"
if [[ -z "$IDENTITY" ]]; then echo "No Developer ID Application identity is available" >&2; exit 2; fi
TEMP="$(mktemp -d "${TMPDIR:-/tmp}/glassbox-network-runtime.XXXXXX")"
trap 'rm -rf "$TEMP"' EXIT

CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --locked --release -p glassbox-workflow-probe
APP="$TEMP/GlassboxWorkflowProbe.app"
mkdir -p "$APP/Contents/MacOS"
cp "$TARGET_DIR/release/glassbox-workflow-probe" "$APP/Contents/MacOS/GlassboxWorkflowProbe"
cat >"$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>GlassboxWorkflowProbe</string><key>CFBundleIdentifier</key><string>com.glassbox.workflow-probe</string><key>CFBundleName</key><string>GlassboxWorkflowProbe</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>
PLIST
codesign --force --timestamp --options runtime --entitlements "$ROOT/apps/glassbox-macos/Support/Glassbox.entitlements" --sign "$IDENTITY" "$APP" >/dev/null
codesign --verify --deep --strict "$APP"

# Calibrate the observer against a deliberate socket-producing process.
python3 -c 'import socket,time; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); time.sleep(5)' &
CONTROL_PID=$!
nettop -n -x -m tcp -p "$CONTROL_PID" -L 2 -s 1 >"$TEMP/control.csv" 2>"$TEMP/control.err" || true
wait "$CONTROL_PID"

HOME="$TEMP/home" CFFIXED_USER_HOME="$TEMP/home" "$APP/Contents/MacOS/GlassboxWorkflowProbe" >"$TEMP/workflow.jsonl" 2>"$TEMP/workflow.err" &
WORKFLOW_PID=$!
ps -p "$WORKFLOW_PID" -o pid=,comm= >"$TEMP/workflow-process.txt"
nettop -n -x -p "$WORKFLOW_PID" -L 6 -s 1 >"$TEMP/workflow.csv" 2>"$TEMP/workflow-nettop.err" || true
wait "$WORKFLOW_PID"

python3 - "$ROOT" "$APP" "$TEMP/control.csv" "$TEMP/workflow.csv" "$TEMP/workflow.jsonl" "$TEMP/workflow-process.txt" "$WORKFLOW_PID" "$RECEIPT" <<'PY'
import csv, hashlib, json, pathlib, plistlib, re, subprocess, sys
root, app, control_path, workflow_path, phases_path, process_path = map(pathlib.Path, sys.argv[1:7])
workflow_pid=sys.argv[7]; receipt_path=pathlib.Path(sys.argv[8])
socket_row = re.compile(r"^(?:tcp|udp)\d* ")
def observed_rows(path):
    sockets=[]; processes=[]
    for row in csv.reader(path.read_text(errors="replace").splitlines()):
        if len(row) <= 1 or not row[1]: continue
        if socket_row.match(row[1]): sockets.append(row[1])
        elif row[0] != "time": processes.append(row[1])
    return sockets, processes
control_sockets, control_processes=observed_rows(control_path)
workflow_sockets, workflow_processes=observed_rows(workflow_path)
phases=[]; phase_errors=[]
for line in phases_path.read_text().splitlines():
    try: phases.append(json.loads(line))
    except json.JSONDecodeError as exc: phase_errors.append(str(exc))
expected=["fixture","import","browse","compare","export"]
phase_names=[item.get("phase") for item in phases]
entitlements=subprocess.run(["codesign","-d","--entitlements",":-",str(app)],capture_output=True,text=True)
entitlement_text=entitlements.stdout+entitlements.stderr
xml_start=entitlement_text.find("<?xml")
xml_end=entitlement_text.find("</plist>")
entitlement_dict={}
if xml_start >= 0 and xml_end >= 0:
    entitlement_dict=plistlib.loads(entitlement_text[xml_start:xml_end+8].encode())
checks={
 "observer_positive_control_detected_socket": bool(control_sockets),
 "workflow_pid_identity_observed": workflow_pid in process_path.read_text() and "GlassboxWorkflowProbe" in process_path.read_text(),
 "workflow_phases_complete_and_ordered": phase_names == expected and all(item.get("ok") is True for item in phases) and not phase_errors,
 "workflow_os_socket_rows_absent": not workflow_sockets,
 "workflow_app_sandbox_only": entitlement_dict == {
   "com.apple.security.app-sandbox": True,
   "com.apple.security.files.user-selected.read-only": True,
 },
 "workflow_network_entitlements_absent": "com.apple.security.network.client" not in entitlement_dict and "com.apple.security.network.server" not in entitlement_dict,
}
def git(*args):
 r=subprocess.run(["git",*args],cwd=root,text=True,capture_output=True); return r.stdout.strip() if r.returncode==0 else "unknown"
receipt={
 "schema_version":"glassbox-network-runtime/v1","ok":all(checks.values()),"checks":checks,
 "git_head":git("rev-parse","HEAD"),"git_tree":git("rev-parse","HEAD^{tree}"),"git_dirty":bool(git("status","--porcelain")),
 "workflow_binary_sha256":hashlib.sha256((app/"Contents/MacOS/GlassboxWorkflowProbe").read_bytes()).hexdigest(),
 "monitor_sha256":hashlib.sha256(workflow_path.read_bytes()).hexdigest(),"phases":phase_names,
 "positive_control_socket_rows":control_sockets,"unexpected_workflow_socket_rows":workflow_sockets,
 "workflow_process_identity":process_path.read_text().strip(),
 "scope":"process-scoped macOS nettop socket observation of signed App-Sandbox fixture/import/browse/compare/export probe",
 "errors":[name for name,passed in checks.items() if not passed],
}
pathlib.Path(receipt_path).parent.mkdir(parents=True,exist_ok=True); pathlib.Path(receipt_path).write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
print(json.dumps(receipt,indent=2,sort_keys=True)); raise SystemExit(0 if receipt["ok"] else 1)
PY
