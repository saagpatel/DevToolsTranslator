#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
RECEIPT=${1:-"$ROOT/artifacts/glassbox-key-lifecycle.json"}
TARGET_DIR=${GLASSBOX_KEY_TARGET_DIR:-"${TMPDIR:-/tmp}/glassbox-key-target"}
PROBE=$(mktemp "${TMPDIR:-/tmp}/glassbox-key-probe.XXXXXX")
PROFILE_RECEIPT=$(mktemp "${TMPDIR:-/tmp}/glassbox-key-profile.XXXXXX")
VALIDATED_PROFILE=$(mktemp "${TMPDIR:-/tmp}/glassbox-key-validated-profile.XXXXXX")
SIGNED_ENTITLEMENTS=$(mktemp "${TMPDIR:-/tmp}/glassbox-key-entitlements.XXXXXX")
SIGNING_DETAILS=$(mktemp "${TMPDIR:-/tmp}/glassbox-key-signing.XXXXXX")
SIGN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/glassbox-key-sign.XXXXXX")
trap 'rm -f "$PROBE" "$PROFILE_RECEIPT" "$VALIDATED_PROFILE" "$SIGNED_ENTITLEMENTS" "$SIGNING_DETAILS"; rm -rf "$SIGN_DIR"' EXIT

SERVICE="com.project-glassbox.key-gate.$$"
TEAM_ID="3TGZFKFNA4"
BUNDLE_ID="com.project-glassbox.key-lifecycle-gate"
KEYCHAIN_GROUP="$TEAM_ID.$BUNDLE_ID"
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet \
  --manifest-path "$ROOT/glassbox-runtime/Cargo.toml" \
  -p glassbox-key-lifecycle --example key_lifecycle_probe
IDENTITY=${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n '/(3TGZFKFNA4)"$/s/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}
if [ -z "$IDENTITY" ]; then
  echo "No Developer ID Application identity is available for team $TEAM_ID" >&2
  exit 2
fi
PROFILE=${GLASSBOX_KEY_PROVISIONING_PROFILE:-}
if [ -z "$PROFILE" ] || [ ! -f "$PROFILE" ]; then
  echo "A Glassbox macOS provisioning profile is required in GLASSBOX_KEY_PROVISIONING_PROFILE" >&2
  echo "The profile must authorize the app identifier and Keychain access group used below" >&2
  exit 2
fi
IDENTITY_SHA1=$(security find-identity -v -p codesigning | awk -v identity="$IDENTITY" 'index($0, "\"" identity "\"") { print $2; exit }')
if [ -z "$IDENTITY_SHA1" ]; then
  echo "Unable to bind the selected Developer ID identity to its certificate" >&2
  exit 2
fi
if ! python3 "$ROOT/scripts/glassbox/validate_key_provisioning_profile.py" \
  --profile "$PROFILE" --team-id "$TEAM_ID" --bundle-id "$BUNDLE_ID" \
  --keychain-group "$KEYCHAIN_GROUP" --identity-sha1 "$IDENTITY_SHA1" \
  --validated-copy "$VALIDATED_PROFILE" \
  >"$PROFILE_RECEIPT"; then
  cat "$PROFILE_RECEIPT" >&2
  exit 2
fi
APP="$SIGN_DIR/GlassboxKeyLifecycleGate.app"
BIN="$APP/Contents/MacOS/key_lifecycle_probe"
mkdir -p "$APP/Contents/MacOS"
cp "$TARGET_DIR/debug/examples/key_lifecycle_probe" "$BIN"
cp "$VALIDATED_PROFILE" "$APP/Contents/embedded.provisionprofile"
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
<key>com.apple.application-identifier</key><string>$TEAM_ID.$BUNDLE_ID</string>
<key>com.apple.developer.team-identifier</key><string>$TEAM_ID</string>
<key>com.apple.security.app-sandbox</key><true/>
<key>keychain-access-groups</key><array><string>$KEYCHAIN_GROUP</string></array>
</dict></plist>
PLIST
codesign --force --timestamp=none --options runtime --entitlements "$SIGN_DIR/entitlements.plist" --sign "$IDENTITY" "$APP" >/dev/null
codesign --verify --deep --strict "$APP"
codesign --display --entitlements - --xml "$APP" 2>"$SIGNED_ENTITLEMENTS"
codesign --display --verbose=4 "$APP" 2>"$SIGNING_DETAILS"
GLASSBOX_KEYCHAIN_SERVICE="$SERVICE" "$BIN" >"$PROBE"

python3 - "$ROOT" "$PROBE" "$RECEIPT" "$PROFILE_RECEIPT" "$SIGNED_ENTITLEMENTS" "$SIGNING_DETAILS" "$VALIDATED_PROFILE" "$APP/Contents/embedded.provisionprofile" <<'PY'
import hashlib, json, plistlib, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

root, probe_path, receipt_path, profile_receipt_path, signed_entitlements_path, signing_details_path, profile_path, embedded_profile_path = map(Path, sys.argv[1:])
probe = json.loads(probe_path.read_text())
profile = json.loads(profile_receipt_path.read_text())
source = (root / "crates/glassbox-key-lifecycle/src/lib.rs").read_text()
entitlements_text = signed_entitlements_path.read_text()
try:
    xml_start = entitlements_text.index("<?xml")
    xml_end = entitlements_text.index("</plist>", xml_start) + len("</plist>")
    claimed_entitlements = plistlib.loads(entitlements_text[xml_start:xml_end].encode())
except (ValueError, plistlib.InvalidFileException):
    claimed_entitlements = {}
team_id = "3TGZFKFNA4"
bundle_id = "com.project-glassbox.key-lifecycle-gate"
app_id = f"{team_id}.{bundle_id}"
signing_details = signing_details_path.read_text()
profile_checks = profile.get("checks", {}) if isinstance(profile, dict) else {}
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
    "provisioning_profile_validation_passed": (
        profile.get("schema_version") == "glassbox-key-profile-validation/v1"
        and profile.get("ok") is True
        and isinstance(profile_checks, dict)
        and len(profile_checks) == 8
        and all(value is True for value in profile_checks.values())
    ),
    "signed_probe_claims_exact_entitlements": claimed_entitlements == {
        "com.apple.application-identifier": app_id,
        "com.apple.developer.team-identifier": team_id,
        "com.apple.security.app-sandbox": True,
        "keychain-access-groups": [app_id],
    },
    "signed_probe_uses_exact_developer_id_team": (
        f"TeamIdentifier={team_id}" in signing_details
        and f"Authority=Developer ID Application: SAAGAR I PATEL ({team_id})" in signing_details
    ),
    "signed_probe_uses_hardened_runtime": "flags=0x10000(runtime)" in signing_details,
    "embedded_profile_matches_supplied_profile": (
        hashlib.sha256(profile_path.read_bytes()).digest()
        == hashlib.sha256(embedded_profile_path.read_bytes()).digest()
    ),
}
checks.update(profile_checks)
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
    "profile_validation": profile,
    "errors": [name for name, passed in checks.items() if not passed],
}
receipt_path.parent.mkdir(parents=True, exist_ok=True)
receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
