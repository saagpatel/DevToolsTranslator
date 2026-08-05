#!/usr/bin/env python3
"""Fail-closed validation for the Gate 1 Developer ID provisioning profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import stat
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


MAX_PROFILE_BYTES = 10 * 1024 * 1024
MAX_FUTURE_SKEW = timedelta(minutes=5)
STANDARD_PROFILE_ENTITLEMENTS = {
    "com.apple.application-identifier",
    "com.apple.developer.team-identifier",
    "get-task-allow",
    "keychain-access-groups",
    "com.apple.security.app-sandbox",
}


def utc(value: object) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def authorized(pattern: object, expected: str) -> bool:
    if not isinstance(pattern, str):
        return False
    return pattern == expected or (pattern.endswith("*") and expected.startswith(pattern[:-1]))


def validate_payload(
    payload: object,
    *,
    team_id: str,
    bundle_id: str,
    keychain_group: str,
    identity_sha1: str,
    now: datetime | None = None,
) -> dict[str, bool]:
    now = now or datetime.now(timezone.utc)
    if not isinstance(payload, dict):
        payload = {}
    entitlements = payload.get("Entitlements")
    if not isinstance(entitlements, dict):
        entitlements = {}
    certificates = payload.get("DeveloperCertificates")
    if not isinstance(certificates, list):
        certificates = []
    certificate_sha1 = {
        hashlib.sha1(value).hexdigest().upper()
        for value in certificates
        if isinstance(value, bytes) and value
    }
    creation = utc(payload.get("CreationDate"))
    expiration = utc(payload.get("ExpirationDate"))
    expected_app_id = f"{team_id}.{bundle_id}"
    groups = entitlements.get("keychain-access-groups")
    if not isinstance(groups, list):
        groups = []
    return {
        "profile_has_stable_identity": (
            payload.get("Version") == 1
            and isinstance(payload.get("UUID"), str)
            and bool(payload["UUID"].strip())
            and isinstance(payload.get("Name"), str)
            and bool(payload["Name"].strip())
        ),
        "profile_is_current": (
            creation is not None
            and creation <= now + MAX_FUTURE_SKEW
            and expiration is not None
            and expiration > now
        ),
        "profile_is_macos_developer_id_distribution": (
            payload.get("Platform") == ["OSX"]
            and payload.get("ProvisionsAllDevices") is True
            and "ProvisionedDevices" not in payload
            and entitlements.get("get-task-allow") in (None, False)
        ),
        "profile_team_is_exact": (
            payload.get("TeamIdentifier") == [team_id]
            and payload.get("ApplicationIdentifierPrefix") == [team_id]
            and entitlements.get("com.apple.developer.team-identifier") == team_id
        ),
        "profile_app_identifier_is_exact": (
            entitlements.get("com.apple.application-identifier") == expected_app_id
        ),
        "profile_authorizes_keychain_group": any(
            authorized(group, keychain_group) for group in groups
        ),
        "profile_has_no_unrelated_restricted_entitlements": (
            set(entitlements).issubset(STANDARD_PROFILE_ENTITLEMENTS)
            and entitlements.get("com.apple.security.app-sandbox", True) is True
        ),
        "profile_binds_selected_developer_id_certificate": (
            identity_sha1.upper() in certificate_sha1
        ),
    }


def read_profile(path: Path) -> tuple[bytes, list[str]]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        return b"", ["profile_file"]
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_PROFILE_BYTES
        ):
            return b"", ["profile_file"]
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, MAX_PROFILE_BYTES + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_PROFILE_BYTES:
                return b"", ["profile_file"]
        data = b"".join(chunks)
        if len(data) != metadata.st_size:
            return b"", ["profile_changed_during_read"]
        return data, []
    finally:
        os.close(descriptor)


def decode_profile(path: Path) -> tuple[dict[str, object], bytes, list[str]]:
    profile_bytes, errors = read_profile(path)
    if errors:
        return {}, b"", errors
    with tempfile.TemporaryDirectory(prefix="glassbox-key-profile.") as temp_name:
        snapshot = Path(temp_name) / "profile.provisionprofile"
        snapshot.write_bytes(profile_bytes)
        integrity = subprocess.run(
            [
                "/usr/bin/openssl", "cms", "-verify", "-inform", "DER",
                "-in", str(snapshot), "-noverify", "-out", "/dev/null",
            ],
            text=True,
            capture_output=True,
            timeout=15,
        )
        decoded = subprocess.run(
            ["/usr/bin/security", "cms", "-D", "-u", "9", "-i", str(snapshot)],
            capture_output=True,
            timeout=15,
        )
    if integrity.returncode != 0:
        errors.append("profile_cms_integrity")
    if decoded.returncode != 0:
        errors.append("profile_apple_trust")
    try:
        payload = plistlib.loads(decoded.stdout)
    except plistlib.InvalidFileException:
        payload = {}
        errors.append("profile_payload")
    if not isinstance(payload, dict):
        return {}, profile_bytes, sorted(set(errors + ["profile_payload_object"]))
    return payload, profile_bytes, sorted(set(errors))


def self_test() -> bool:
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    team = "3TGZFKFNA4"
    bundle = "com.project-glassbox.key-lifecycle-gate"
    group = f"{team}.{bundle}"
    certificate = b"developer-id-certificate"
    identity_sha1 = hashlib.sha1(certificate).hexdigest().upper()
    valid = {
        "Version": 1,
        "UUID": "00000000-0000-0000-0000-000000000001",
        "Name": "Glassbox Key Lifecycle Gate Developer ID",
        "CreationDate": now - timedelta(days=1),
        "ExpirationDate": now + timedelta(days=365),
        "Platform": ["OSX"],
        "ProvisionsAllDevices": True,
        "TeamIdentifier": [team],
        "ApplicationIdentifierPrefix": [team],
        "DeveloperCertificates": [certificate],
        "Entitlements": {
            "com.apple.application-identifier": group,
            "com.apple.developer.team-identifier": team,
            "keychain-access-groups": [f"{team}.*", "com.apple.token"],
        },
    }
    checks = validate_payload(
        valid, team_id=team, bundle_id=bundle, keychain_group=group,
        identity_sha1=identity_sha1, now=now,
    )
    if not all(checks.values()):
        return False
    mutations = {
        "wrong_platform": ("Platform", ["iOS"]),
        "device_bound": ("ProvisionedDevices", ["device"]),
        "wrong_team": ("TeamIdentifier", ["AAAAAAAAAA"]),
        "expired": ("ExpirationDate", now - timedelta(seconds=1)),
    }
    for key, value in mutations.values():
        candidate = dict(valid)
        candidate[key] = value
        if all(validate_payload(
            candidate, team_id=team, bundle_id=bundle, keychain_group=group,
            identity_sha1=identity_sha1, now=now,
        ).values()):
            return False
    candidate = dict(valid)
    candidate["DeveloperCertificates"] = [b"other"]
    if all(validate_payload(
        candidate, team_id=team, bundle_id=bundle, keychain_group=group,
        identity_sha1=identity_sha1, now=now,
    ).values()):
        return False
    candidate = dict(valid)
    candidate["Entitlements"] = dict(valid["Entitlements"])
    candidate["Entitlements"]["com.apple.security.network.client"] = True
    if all(validate_payload(
        candidate, team_id=team, bundle_id=bundle, keychain_group=group,
        identity_sha1=identity_sha1, now=now,
    ).values()):
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--team-id")
    parser.add_argument("--bundle-id")
    parser.add_argument("--keychain-group")
    parser.add_argument("--identity-sha1")
    parser.add_argument("--validated-copy", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        passed = self_test()
        print(json.dumps({
            "schema_version": "glassbox-key-profile-validator-self-test/v1",
            "ok": passed,
        }, sort_keys=True))
        return 0 if passed else 1
    if not all((args.profile, args.team_id, args.bundle_id, args.keychain_group, args.identity_sha1)):
        parser.error("profile, team, bundle, keychain group, and identity SHA-1 are required")
    profile = args.profile.expanduser().absolute()
    payload, profile_bytes, errors = decode_profile(profile)
    checks = validate_payload(
        payload,
        team_id=args.team_id,
        bundle_id=args.bundle_id,
        keychain_group=args.keychain_group,
        identity_sha1=args.identity_sha1,
    )
    errors.extend(name for name, passed in checks.items() if not passed)
    if not errors and args.validated_copy is not None:
        destination = args.validated_copy.expanduser().absolute()
        try:
            destination_metadata = destination.lstat()
            if not stat.S_ISREG(destination_metadata.st_mode):
                raise OSError("validated destination is not a regular file")
            destination.write_bytes(profile_bytes)
        except OSError:
            errors.append("validated_profile_copy")
    result = {
        "schema_version": "glassbox-key-profile-validation/v1",
        "ok": not errors,
        "profile_sha256": hashlib.sha256(profile_bytes).hexdigest() if not errors else None,
        "profile_name": payload.get("Name") if not errors else None,
        "profile_uuid": payload.get("UUID") if not errors else None,
        "profile_expiration": (
            utc(payload.get("ExpirationDate")).isoformat()
            if not errors and utc(payload.get("ExpirationDate")) is not None else None
        ),
        "checks": checks,
        "errors": sorted(set(errors)),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
