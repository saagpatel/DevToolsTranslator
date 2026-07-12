#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
MODE=${1:-gate}
RECEIPT=${2:-"$ROOT/artifacts/glassbox-storage-spike.json"}
TARGET_DIR=${GLASSBOX_SPIKE_TARGET_DIR:-"${TMPDIR:-/tmp}/glassbox-storage-spike-target"}
TECHNICAL=$(mktemp "${TMPDIR:-/tmp}/glassbox-storage-technical.XXXXXX")
SANDBOXED=$(mktemp "${TMPDIR:-/tmp}/glassbox-storage-sandboxed.XXXXXX")
SIGN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/glassbox-storage-sign.XXXXXX")
trap 'rm -f "$TECHNICAL" "$SANDBOXED"; rm -rf "$SIGN_DIR"' EXIT

CARGO_TARGET_DIR="$TARGET_DIR" cargo run --quiet --manifest-path "$ROOT/scripts/glassbox/storage-spike/Cargo.toml" >"$TECHNICAL"
IDENTITY=${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}
if [ -z "$IDENTITY" ]; then
  echo "No Developer ID Application identity is available; set GLASSBOX_CODESIGN_IDENTITY" >&2
  exit 2
fi
APP="$SIGN_DIR/GlassboxStorageSpike.app"
SIGNED_BIN="$APP/Contents/MacOS/glassbox-storage-spike"
mkdir -p "$APP/Contents/MacOS"
cp "$TARGET_DIR/debug/glassbox-storage-spike" "$SIGNED_BIN"
cat >"$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>glassbox-storage-spike</string>
<key>CFBundleIdentifier</key><string>com.glassbox.storage-spike</string>
<key>CFBundleName</key><string>Glassbox Storage Spike</string>
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
codesign --force --timestamp=none --options runtime --entitlements "$SIGN_DIR/entitlements.plist" --sign "$IDENTITY" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
GLASSBOX_EXPECT_SANDBOX=1 GLASSBOX_FORBIDDEN_HOME="$HOME" "$SIGNED_BIN" >"$SANDBOXED"
mkdir -p "$(dirname -- "$RECEIPT")"
python3 - "$MODE" "$TECHNICAL" "$SANDBOXED" "$SIGNED_BIN" "$IDENTITY" "$RECEIPT" <<'PY'
import json, platform, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

mode, technical_path, sandboxed_path, signed_bin, identity, receipt_path = sys.argv[1:]
technical = json.loads(Path(technical_path).read_text())
sandboxed = json.loads(Path(sandboxed_path).read_text())
def command(*args):
    result = subprocess.run(args, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"
details = subprocess.run(["codesign", "-d", "--entitlements", ":-", "--verbose=4", signed_bin], text=True, capture_output=True)
entitlements = details.stdout + details.stderr
sandbox = {
    "status":"passed" if sandboxed.get("technical_ok") and sandboxed.get("sandbox_home_write_denied") and "com.apple.security.app-sandbox" in entitlements else "failed",
    "identity":identity,
    "signed_binary_sha256":command("shasum", "-a", "256", signed_bin).split(" ")[0],
    "app_sandbox_entitlement_present":"com.apple.security.app-sandbox" in entitlements,
    "forbidden_home_write_denied":sandboxed.get("sandbox_home_write_denied", False),
    "sandboxed_technical_ok":sandboxed.get("technical_ok", False)
}
receipt = {
    "schema_version":"glassbox-storage-spike/v1",
    "ok": bool(technical.get("technical_ok")) and sandbox.get("status") == "passed",
    "mode": mode,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "platform": platform.platform(),
    "git_head": command("git", "rev-parse", "HEAD"),
    "git_tree": command("git", "rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(command("git", "status", "--porcelain")),
    "technical": technical,
    "app_sandbox": sandbox,
    "license": {
        "candidate":"SQLCipher Community Edition",
        "status":"acceptable_with_attribution",
        "requirements":["SQLCipher BSD-style license and copyright", "SQLite notice", "OpenSSL Apache-2.0 notice"]
    },
    "promotion_blockers": [] if sandbox.get("status") == "passed" else ["signed App Sandbox harness failed"]
}
Path(receipt_path).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(json.dumps(receipt, indent=2, sort_keys=True))
if mode == "gate" and not receipt["ok"]:
    raise SystemExit(1)
if not technical.get("technical_ok"):
    raise SystemExit(1)
PY
