#!/usr/bin/env python3
"""Generate and verify Glassbox's final macOS privacy API inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(binary: Path, policy: dict) -> tuple[dict[str, list[str]], list[str]]:
    nm = run("nm", "-u", str(binary)); strings = run("strings", str(binary)); errors = []
    if nm.returncode: errors.append("nm could not inspect the final executable")
    if strings.returncode: errors.append("strings could not inspect the final executable")
    undefined = {line.strip().split()[-1] for line in nm.stdout.splitlines() if line.strip()}
    observed = {}
    for category, rule in policy.get("categories", {}).items():
        matches = [f"symbol:{symbol}" for symbol in rule.get("undefined_symbols", []) if symbol in undefined]
        matches.extend(f"string:{token}" for token in rule.get("binary_strings", []) if token in strings.stdout)
        observed[category] = sorted(set(matches))
    return observed, errors


def compare(observed: dict[str, list[str]], policy: dict) -> list[str]:
    errors = []; categories = policy.get("categories", {})
    if set(observed) != set(categories): errors.append("covered category inventory is incomplete")
    for category, rule in categories.items():
        if observed.get(category) != sorted(rule.get("reviewed_matches", [])):
            errors.append(f"unreviewed required-reason API surface drift: {category}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--binary", type=Path); parser.add_argument("--manifest", type=Path)
    parser.add_argument("--policy", type=Path); parser.add_argument("--receipt", type=Path); args = parser.parse_args()
    if args.self_test:
        rejected = compare({"boot": ["symbol:_mach_absolute_time"]}, {"categories": {"boot": {"reviewed_matches": []}}})
        print(json.dumps({"unreviewed_symbol_drift_rejected": bool(rejected)})); return 0 if rejected else 1
    if None in (args.binary, args.manifest, args.policy, args.receipt): parser.error("--binary, --manifest, --policy, and --receipt are required")
    errors = []
    try: policy = json.loads(args.policy.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: policy = {}; errors.append(f"invalid policy: {exc}")
    try: manifest = plistlib.loads(args.manifest.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc: manifest = {}; errors.append(f"invalid privacy manifest: {exc}")
    expected_policy_keys = {"schema_version", "platform", "reviewed_at", "max_age_days", "apple_policy", "manifest_accessed_api_types", "categories"}
    if set(policy) != expected_policy_keys or policy.get("schema_version") != "glassbox-privacy-api-policy/v1" or policy.get("platform") != "macos": errors.append("privacy API policy shape or platform is invalid")
    try:
        reviewed_at = datetime.fromisoformat(policy["reviewed_at"].replace("Z", "+00:00")).astimezone(timezone.utc)
        age_days = (datetime.now(timezone.utc) - reviewed_at).total_seconds() / 86400
        if age_days < 0 or age_days > policy["max_age_days"]: errors.append("official Apple privacy API policy review is stale")
    except (KeyError, TypeError, ValueError): age_days = None; errors.append("privacy policy freshness fields are invalid")
    apple = policy.get("apple_policy", {})
    if apple.get("privacy_manifest_required") is not True or apple.get("required_reason_enforcement_applies") is not False or apple.get("required_reason_platforms") != ["ios", "ipados", "tvos", "visionos", "watchos"] or len(apple.get("sources", [])) < 4: errors.append("Apple platform applicability review is incomplete")
    expected_manifest_keys = {"NSPrivacyTracking", "NSPrivacyTrackingDomains", "NSPrivacyCollectedDataTypes", "NSPrivacyAccessedAPITypes"}
    if set(manifest) != expected_manifest_keys: errors.append("privacy manifest keys are not exact")
    if manifest.get("NSPrivacyTracking") is not False or manifest.get("NSPrivacyTrackingDomains") != [] or manifest.get("NSPrivacyCollectedDataTypes") != []: errors.append("privacy manifest claims tracking, domains, or collected data")
    if manifest.get("NSPrivacyAccessedAPITypes") != policy.get("manifest_accessed_api_types"): errors.append("privacy manifest accessed API types drifted from reviewed macOS policy")
    observed, inspection_errors = inventory(args.binary, policy); errors.extend(inspection_errors); errors.extend(compare(observed, policy))
    receipt = {"schema_version": "glassbox-privacy-artifact/v1", "ok": not errors, "binary_sha256": sha256(args.binary) if args.binary.is_file() else None, "manifest_sha256": sha256(args.manifest) if args.manifest.is_file() else None, "policy_sha256": sha256(args.policy) if args.policy.is_file() else None, "platform": "macos", "policy_age_days": age_days, "apple_required_reason_enforcement_applies": apple.get("required_reason_enforcement_applies"), "observed_categories": observed, "manifest_accessed_api_types": manifest.get("NSPrivacyAccessedAPITypes"), "errors": errors}
    args.receipt.parent.mkdir(parents=True, exist_ok=True); args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"); print(json.dumps(receipt, indent=2, sort_keys=True)); return 0 if receipt["ok"] else 1


if __name__ == "__main__": raise SystemExit(main())
