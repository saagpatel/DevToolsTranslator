#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RECEIPT="${1:-$ROOT/artifacts/glassbox-key-lifecycle-readiness.json}"
TARGET_OWNED=0
if [[ -n "${GLASSBOX_KEY_TARGET_DIR:-}" ]]; then
  TARGET_DIR="$GLASSBOX_KEY_TARGET_DIR"
else
  TARGET_DIR="$(mktemp -d "${TMPDIR:-/tmp}/glassbox-key-target.XXXXXX")"
  TARGET_OWNED=1
fi
STRICT_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-key-strict.XXXXXX")"
cleanup() {
  rm -f "$STRICT_RECEIPT"
  if [[ "$TARGET_OWNED" -eq 1 ]]; then rm -rf "$TARGET_DIR"; fi
}
trap cleanup EXIT
python3 "$ROOT/scripts/glassbox/validate_key_provisioning_profile.py" --self-test >/dev/null
CARGO_TARGET_DIR="$TARGET_DIR" cargo test --quiet \
  --manifest-path "$ROOT/glassbox-runtime/Cargo.toml" -p glassbox-key-lifecycle
CARGO_TARGET_DIR="$TARGET_DIR" cargo clippy --quiet \
  --manifest-path "$ROOT/glassbox-runtime/Cargo.toml" -p glassbox-key-lifecycle \
  --all-targets -- -D warnings
if [[ -n "${GLASSBOX_KEY_PROVISIONING_PROFILE:-}" ]]; then
  GLASSBOX_KEY_TARGET_DIR="$TARGET_DIR" \
    "$ROOT/scripts/glassbox/run_key_lifecycle_gate.sh" "$STRICT_RECEIPT" >/dev/null
fi
python3 - "$ROOT" "$RECEIPT" "$STRICT_RECEIPT" "${GLASSBOX_CANDIDATE_MANIFEST:-}" <<'PY'
import json
import pathlib
import subprocess
import sys

root, receipt, strict_path = map(pathlib.Path, sys.argv[1:4])
candidate_path = pathlib.Path(sys.argv[4]) if sys.argv[4] else None
sys.path.insert(0, str(root / "scripts/glassbox"))
from candidate_manifest import load_and_validate
source = (root / "crates/glassbox-key-lifecycle/src/lib.rs").read_text()
strict_gate = (root / "scripts/glassbox/run_key_lifecycle_gate.sh").read_text()
try:
    strict = json.loads(strict_path.read_text()) if strict_path.stat().st_size else {}
except (OSError, json.JSONDecodeError):
    strict = {}
checks = {
    "crypto_unit_tests_and_clippy_pass": True,
    "data_protection_keychain_selected": "use_protected_keychain()" in source,
    "device_only_unlocked_protection_selected": "AccessibleWhenUnlockedThisDeviceOnly" in source,
    "synchronization_explicitly_disabled": "set_access_synchronized(Some(false))" in source,
    "versioned_key_account": "application-wrapping-key-v{version}" in source,
    "strict_gate_requires_explicit_product_provisioning_profile": (
        "GLASSBOX_KEY_PROVISIONING_PROFILE" in strict_gate
        and "embedded.provisionprofile" in strict_gate
        and "keychain-access-groups" in strict_gate
        and "validate_key_provisioning_profile.py" in strict_gate
        and "com.apple.security.app-sandbox" in strict_gate
    ),
}
def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"
strict_checks = strict.get("checks", {})
required_strict_checks = {
    "provisioning_profile_validation_passed",
    "profile_is_macos_developer_id_distribution",
    "profile_team_is_exact",
    "profile_app_identifier_is_exact",
    "profile_authorizes_keychain_group",
    "profile_has_no_unrelated_restricted_entitlements",
    "profile_binds_selected_developer_id_certificate",
    "signed_probe_claims_exact_entitlements",
    "signed_probe_uses_exact_developer_id_team",
    "signed_probe_uses_hardened_runtime",
    "embedded_profile_matches_supplied_profile",
    "keychain_restart_roundtrip",
    "crypto_shred_blocks_recovery",
}
candidate_digest = None
candidate_errors = ["candidate_manifest_required"]
if candidate_path is not None:
    _, candidate_digest, candidate_errors = load_and_validate(root, candidate_path.resolve())
signed_roundtrip = (
    strict.get("schema_version") == "glassbox-key-lifecycle/v1"
    and strict.get("ok") is True
    and strict.get("git_tree") == git("rev-parse", "HEAD^{tree}")
    and isinstance(strict_checks, dict)
    and required_strict_checks.issubset(strict_checks)
    and all(value is True for value in strict_checks.values())
    and not candidate_errors
)
result = {
    "schema_version": "glassbox-key-lifecycle-readiness/v1",
    "ok": all(checks.values()),
    "readiness_ok": all(checks.values()),
    "gate1_promotable": signed_roundtrip,
    "signed_keychain_roundtrip_passed": signed_roundtrip,
    "git_head": git("rev-parse", "HEAD"),
    "git_tree": git("rev-parse", "HEAD^{tree}"),
    "git_dirty": bool(git("status", "--porcelain")),
    "checks": checks,
    "strict_receipt": strict if signed_roundtrip else None,
    "candidate_manifest_sha256": candidate_digest if signed_roundtrip else None,
    "candidate_manifest_errors": candidate_errors if strict else [],
    "external_requirements": [] if signed_roundtrip else [
        "product-authorized macOS provisioning profile for com.project-glassbox.key-lifecycle-gate",
        "profile-backed signed Keychain restart, crypto-shred, and cleanup round-trip",
    ],
    "errors": [name for name, passed in checks.items() if not passed],
}
receipt.parent.mkdir(parents=True, exist_ok=True)
receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if result["ok"] else 1)
PY
