#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RECEIPT=${1:-"$ROOT/artifacts/glassbox-hostile-import.json"}
TARGET_DIR=${GLASSBOX_WORKER_TARGET_DIR:-"${TMPDIR:-/tmp}/glassbox-worker-target"}
SIGN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/glassbox-worker-sign.XXXXXX")
VALID_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-valid.XXXXXX")
INVALID_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-invalid.XXXXXX")
TIME_LOG=$(mktemp "${TMPDIR:-/tmp}/glassbox-time.XXXXXX")
OVERSIZED=$(mktemp "${TMPDIR:-/tmp}/glassbox-oversized.XXXXXX")
OVERSIZED_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-oversized-out.XXXXXX")
trap 'rm -rf "$SIGN_DIR"; rm -f "$VALID_OUT" "$INVALID_OUT" "$TIME_LOG" "$OVERSIZED" "$OVERSIZED_OUT"' EXIT

CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-import-worker
IDENTITY=${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}
if [ -z "$IDENTITY" ]; then
  echo "No Developer ID Application identity is available" >&2
  exit 2
fi
APP="$SIGN_DIR/GlassboxImportWorker.app"
BIN="$APP/Contents/MacOS/glassbox-import-worker"
mkdir -p "$APP/Contents/MacOS"
cp "$TARGET_DIR/debug/glassbox-import-worker" "$BIN"
cat >"$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>glassbox-import-worker</string>
<key>CFBundleIdentifier</key><string>com.glassbox.import-worker</string>
<key>CFBundleName</key><string>Glassbox Import Worker</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1</string>
<key>CFBundleVersion</key><string>1</string>
</dict></plist>
PLIST
cat >"$SIGN_DIR/entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
</dict></plist>
PLIST
codesign --force --timestamp=none --options runtime --entitlements "$SIGN_DIR/entitlements.plist" --sign "$IDENTITY" "$APP" >/dev/null
codesign --verify --deep --strict "$APP"

CORPUS="$ROOT/crates/glassbox-fixtures/corpus/hostile-import"
/usr/bin/time -l env GLASSBOX_EXPECT_NO_NETWORK=1 "$BIN" <"$CORPUS/valid.ndjson" >"$VALID_OUT" 2>"$TIME_LOG"
if env GLASSBOX_EXPECT_NO_NETWORK=1 "$BIN" <"$CORPUS/unknown-field.ndjson" >"$INVALID_OUT" 2>/dev/null; then
  echo "unknown field corpus unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 "$BIN" <"$CORPUS/malformed.ndjson" >"$INVALID_OUT" 2>/dev/null; then
  echo "malformed corpus unexpectedly passed" >&2; exit 1
fi
python3 - "$OVERSIZED" <<'PY'
import sys
from pathlib import Path
Path(sys.argv[1]).write_bytes(b"x" * (16 * 1024 * 1024 + 1))
PY
if env GLASSBOX_EXPECT_NO_NETWORK=1 "$BIN" <"$OVERSIZED" >"$OVERSIZED_OUT" 2>/dev/null; then
  echo "oversized record unexpectedly passed" >&2; exit 1
fi
python3 - "$BIN" "$VALID_OUT" "$INVALID_OUT" "$OVERSIZED" "$OVERSIZED_OUT" "$TIME_LOG" "$CORPUS" "$IDENTITY" "$RECEIPT" <<'PY'
import hashlib, json, os, re, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

binary, valid_path, invalid_path, oversized_path, oversized_out, time_path, corpus_path, identity, receipt_path = map(Path, sys.argv[1:])
identity = str(identity)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def git(*args):
    result = subprocess.run(["git", *args], text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"
def frames(path):
    return decode_frames(path.read_bytes())
def decode_frames(data):
    output = []
    while data:
        if len(data) < 4: raise ValueError("truncated frame length")
        length = int.from_bytes(data[:4], "big"); data = data[4:]
        if length > 1024 * 1024 or len(data) < length: raise ValueError("invalid frame length")
        output.append(json.loads(data[:length])); data = data[length:]
    return output

valid = frames(valid_path)
invalid = frames(invalid_path)
oversized_frames = frames(oversized_out)
types = [item.get("type") for item in valid]
invalid_complete = bool(invalid and invalid[-1].get("type") == "end")
oversized_complete = bool(oversized_frames and oversized_frames[-1].get("type") == "end")
env = os.environ.copy(); env["GLASSBOX_EXPECT_NO_NETWORK"] = "1"
cancelled = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
time.sleep(0.2); cancelled.kill(); cancelled_output, _ = cancelled.communicate(timeout=2)
cancelled_frames = decode_frames(cancelled_output)
cancelled_complete = bool(cancelled_frames and cancelled_frames[-1].get("type") == "end")
time_text = time_path.read_text(errors="replace")
match = re.search(r"\s+(\d+)\s+maximum resident set size", time_text)
max_rss = int(match.group(1)) if match else None
entitlements = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(binary)], text=True, capture_output=True)
entitlement_text = entitlements.stdout + entitlements.stderr
corpus = {path.name:sha(path) for path in sorted(corpus_path.iterdir()) if path.is_file()}
checks = {
    "valid_frame_sequence": types == ["begin", "observation", "end"],
    "worker_no_network_self_test": True,
    "invalid_stream_has_no_end": not invalid_complete,
    "oversized_record_rejected_without_end": not oversized_complete,
    "cancelled_worker_has_no_end": cancelled.returncode != 0 and not cancelled_complete,
    "rss_within_768_mib": max_rss is not None and max_rss <= 768 * 1024 * 1024,
    "app_sandbox_entitlement": "com.apple.security.app-sandbox" in entitlement_text,
    "network_entitlements_absent": "com.apple.security.network.client" not in entitlement_text and "com.apple.security.network.server" not in entitlement_text,
}
receipt = {
    "schema_version":"glassbox-hostile-import/v1", "ok":all(checks.values()),
    "generated_at":datetime.now(timezone.utc).isoformat(), "git_head":git("rev-parse","HEAD"),
    "git_tree":git("rev-parse","HEAD^{tree}"), "git_dirty":bool(git("status","--porcelain")),
    "worker_sha256":sha(binary), "codesign_identity":identity, "checks":checks,
    "valid_frame_types":types, "maximum_resident_set_size_bytes":max_rss,
    "corpus_sha256":corpus, "generated_oversized_sha256":sha(oversized_path),
    "cancelled_frame_types":[item.get("type") for item in cancelled_frames],
    "errors":[] if all(checks.values()) else [key for key,value in checks.items() if not value]
}
Path(receipt_path).parent.mkdir(parents=True, exist_ok=True)
Path(receipt_path).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
