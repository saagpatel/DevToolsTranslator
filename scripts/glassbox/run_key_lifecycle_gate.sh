#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RECEIPT=${1:-"$ROOT/artifacts/glassbox-key-lifecycle.json"}
TARGET_DIR=${GLASSBOX_KEY_TARGET_DIR:-"${TMPDIR:-/tmp}/glassbox-key-target"}
PROBE=$(mktemp "${TMPDIR:-/tmp}/glassbox-key-probe.XXXXXX")
SIGN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/glassbox-key-sign.XXXXXX")
trap 'rm -f "$PROBE"; rm -rf "$SIGN_DIR"' EXIT

SERVICE="com.project-glassbox.key-gate.$$.${RANDOM:-0}"
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet \
  --manifest-path "$ROOT/glassbox-runtime/Cargo.toml" \
  -p glassbox-key-lifecycle --example key_lifecycle_probe
IDENTITY=${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}
if [ -z "$IDENTITY" ]; then
  echo "No Developer ID Application identity is available" >&2
  exit 2
fi
PROFILE=${GLASSBOX_KEY_PROVISIONING_PROFILE:-}
if [ -z "$PROFILE" ] || [ ! -f "$PROFILE" ]; then
  echo "A Glassbox macOS provisioning profile is required in GLASSBOX_KEY_PROVISIONING_PROFILE" >&2
  echo "The profile must authorize the app identifier and Keychain access group used below" >&2
  exit 2
fi
TEAM_ID=$(printf '%s' "$IDENTITY" | sed -n 's/.*(\([^()]\{10\}\))$/\1/p')
APP="$SIGN_DIR/GlassboxKeyLifecycleGate.app"
BIN="$APP/Contents/MacOS/key_lifecycle_probe"
mkdir -p "$APP/Contents/MacOS"
cp "$TARGET_DIR/debug/examples/key_lifecycle_probe" "$BIN"
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
cat >"$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>key_lifecycle_probe</string>
<key>CFBundleIdentifier</key><string>com.project-glassbox.key-lifecycle-gate</string>
<key>CFBundleName</key><string>Glassbox Key Lifecycle Gate</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1</string>
<key>CFBundleVersion</key><string>1</string>
</dict></plist>
PLIST
cat >"$SIGN_DIR/entitlements.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.application-identifier</key><string>$TEAM_ID.com.project-glassbox.key-lifecycle-gate</string>
<key>com.apple.developer.team-identifier</key><string>$TEAM_ID</string>
<key>keychain-access-groups</key><array><string>$TEAM_ID.com.project-glassbox.key-lifecycle-gate</string></array>
</dict></plist>
PLIST
codesign --force --timestamp=none --options runtime --entitlements "$SIGN_DIR/entitlements.plist" --sign "$IDENTITY" "$APP" >/dev/null
codesign --verify --deep --strict "$APP"
GLASSBOX_KEYCHAIN_SERVICE="$SERVICE" "$BIN" >"$PROBE"

python3 - "$ROOT" "$PROBE" "$RECEIPT" <<'PY'
import json, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

root, probe_path, receipt_path = map(Path, sys.argv[1:])
probe = json.loads(probe_path.read_text())
source = (root / "crates/glassbox-key-lifecycle/src/lib.rs").read_text()
checks = {
    "data_protection_keychain_selected": "use_protected_keychain()" in source,
    "device_only_unlocked_protection_selected": "AccessibleWhenUnlockedThisDeviceOnly" in source,
    "synchronization_explicitly_disabled": "set_access_synchronized(Some(false))" in source,
    "versioned_key_account": "application-wrapping-key-v{version}" in source,
    "keychain_restart_roundtrip": probe["keychain_restart_roundtrip"],
    "wrapped_key_has_no_plaintext": probe["wrapped_key_has_no_plaintext"],
    "database_has_no_plaintext_key": probe["database_has_no_plaintext_key"],
    "key_deleted_before_cleanup": probe["key_deleted_before_cleanup"],
    "crypto_shred_blocks_recovery": probe["retained_database_and_wrapped_key_unrecoverable_after_crypto_shred"],
}
def git(*args):
    p = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return p.stdout.strip() if p.returncode == 0 else "unknown"
receipt = {
    "schema_version": "glassbox-key-lifecycle/v1",
    "ok": all(checks.values()),
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "git_head": git("rev-parse", "HEAD"),
    "git_tree": git("rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(git("status", "--porcelain")),
    "checks": checks,
    "errors": [name for name, passed in checks.items() if not passed],
}
receipt_path.parent.mkdir(parents=True, exist_ok=True)
receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
