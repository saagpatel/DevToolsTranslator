#!/usr/bin/env python3
"""Shared fail-closed verification for externally produced Glassbox evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

MAX_EVIDENCE_AGE = timedelta(days=30)
MAX_FUTURE_SKEW = timedelta(minutes=5)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_cms_json(
    cms_path: Path, ca_path: Path
) -> tuple[dict[str, object], list[str]]:
    errors: list[str] = []
    if (
        not cms_path.is_file()
        or cms_path.is_symlink()
        or not ca_path.is_file()
        or ca_path.is_symlink()
    ):
        return {}, ["cms_or_ca_file"]
    with tempfile.TemporaryDirectory(prefix="glassbox-external-evidence.") as temp_name:
        decoded = Path(temp_name) / "payload.json"
        result = subprocess.run(
            [
                "/usr/bin/openssl",
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                str(cms_path),
                "-CAfile",
                str(ca_path),
                "-purpose",
                "any",
                "-out",
                str(decoded),
            ],
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            errors.append("cms_signature")
        try:
            payload = json.loads(decoded.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
            errors.append("cms_payload")
    if not isinstance(payload, dict):
        return {}, sorted(set(errors + ["cms_payload_object"]))
    return payload, sorted(set(errors))


def validate_timestamp(
    value: object,
    *,
    field: str,
    now: datetime | None = None,
) -> list[str]:
    now = now or datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        parsed = parsed.astimezone(timezone.utc)
    except ValueError:
        return [field]
    if parsed > now + MAX_FUTURE_SKEW:
        return [f"{field}_future"]
    if now - parsed > MAX_EVIDENCE_AGE:
        return [f"{field}_stale"]
    return []


def validate_actor(
    actor: object,
    *,
    role: str,
    timestamp_field: str,
    actor_field: str,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    expected = {"identity", "role", timestamp_field}
    if not isinstance(actor, dict) or set(actor) != expected:
        return [actor_field]
    if actor.get("role") != role:
        errors.append(f"{actor_field}.role")
    if not isinstance(actor.get("identity"), str) or not actor["identity"].strip():
        errors.append(f"{actor_field}.identity")
    errors.extend(
        validate_timestamp(
            actor.get(timestamp_field),
            field=f"{actor_field}.{timestamp_field}",
            now=now,
        )
    )
    return errors


def validate_attachments(
    attachments: object,
    *,
    cms_path: Path,
    required_kinds: set[str],
) -> list[str]:
    if not isinstance(attachments, list) or len(attachments) != len(required_kinds):
        return ["evidence_files"]
    errors: list[str] = []
    base = cms_path.parent.resolve()
    seen_kinds: set[str] = set()
    seen_paths: set[Path] = set()
    for index, item in enumerate(attachments):
        label = f"evidence_files[{index}]"
        if not isinstance(item, dict) or set(item) != {"kind", "path", "sha256"}:
            errors.append(label)
            continue
        kind = item.get("kind")
        if (
            not isinstance(kind, str)
            or kind not in required_kinds
            or kind in seen_kinds
        ):
            errors.append(f"{label}.kind")
        else:
            seen_kinds.add(kind)
        raw_path = item.get("path")
        relative = PurePosixPath(raw_path) if isinstance(raw_path, str) else None
        if (
            relative is None
            or not relative.parts
            or relative.is_absolute()
            or ".." in relative.parts
            or "\\" in raw_path
        ):
            errors.append(label)
            continue
        source = cms_path.parent.joinpath(*relative.parts)
        try:
            current = cms_path.parent
            if any((current := current / part).is_symlink() for part in relative.parts):
                errors.append(label)
                continue
            target = source.resolve(strict=True)
        except (OSError, RuntimeError):
            errors.append(label)
            continue
        if (
            source.is_symlink()
            or target in seen_paths
            or base not in target.parents
            or not target.is_file()
            or item.get("sha256") != sha256(target)
        ):
            errors.append(label)
        else:
            seen_paths.add(target)
    if seen_kinds != required_kinds:
        errors.append("evidence_file_kinds")
    return sorted(set(errors))


def self_test() -> bool:
    with tempfile.TemporaryDirectory(
        prefix="glassbox-external-evidence-self-test."
    ) as temp_name:
        root = Path(temp_name)
        key = root / "key.pem"
        cert = root / "cert.pem"
        payload_path = root / "payload.json"
        cms = root / "payload.cms"
        payload = {
            "schema_version": "glassbox-external-evidence-self-test/v1",
            "ok": True,
        }
        payload_path.write_text(json.dumps(payload), encoding="utf-8")
        commands = [
            [
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-subj",
                "/CN=Glassbox Test",
            ],
            [
                "/usr/bin/openssl",
                "cms",
                "-sign",
                "-binary",
                "-in",
                str(payload_path),
                "-signer",
                str(cert),
                "-inkey",
                str(key),
                "-outform",
                "DER",
                "-out",
                str(cms),
                "-nosmimecap",
                "-nodetach",
            ],
        ]
        if any(
            subprocess.run(command, capture_output=True).returncode
            for command in commands
        ):
            return False
        decoded, valid_errors = verify_cms_json(cms, cert)
        valid_signature = decoded == payload and not valid_errors
        tampered = root / "tampered.cms"
        tampered_bytes = bytearray(cms.read_bytes())
        tampered_bytes[-1] ^= 1
        tampered.write_bytes(tampered_bytes)
        _, tampered_errors = verify_cms_json(tampered, cert)
        tamper_rejected = "cms_signature" in tampered_errors

        now = datetime.now(timezone.utc)
        stale_rejected = validate_timestamp(
            (now - MAX_EVIDENCE_AGE - timedelta(seconds=1)).isoformat(),
            field="time",
            now=now,
        ) == ["time_stale"]
        future_rejected = validate_timestamp(
            (now + MAX_FUTURE_SKEW + timedelta(seconds=1)).isoformat(),
            field="time",
            now=now,
        ) == ["time_future"]
        proof = root / "proof.txt"
        proof.write_text("proof", encoding="utf-8")
        attachments = [
            {"kind": "first", "path": proof.name, "sha256": sha256(proof)},
            {"kind": "second", "path": proof.name, "sha256": sha256(proof)},
        ]
        duplicate_rejected = "evidence_files[1]" in validate_attachments(
            attachments,
            cms_path=cms,
            required_kinds={"first", "second"},
        )
        absolute = [dict(item) for item in attachments]
        absolute[0]["path"] = str(proof)
        absolute_rejected = "evidence_files[0]" in validate_attachments(
            absolute,
            cms_path=cms,
            required_kinds={"first", "second"},
        )
        evidence_dir = root / "evidence"
        evidence_dir.mkdir()
        nested = evidence_dir / "nested.txt"
        nested.write_text("nested", encoding="utf-8")
        (root / "linked-evidence").symlink_to(evidence_dir, target_is_directory=True)
        symlink_ancestor = [
            {
                "kind": "first",
                "path": "linked-evidence/nested.txt",
                "sha256": sha256(nested),
            }
        ]
        symlink_ancestor_rejected = "evidence_files[0]" in validate_attachments(
            symlink_ancestor,
            cms_path=cms,
            required_kinds={"first"},
        )
        return all(
            [
                valid_signature,
                tamper_rejected,
                stale_rejected,
                future_rejected,
                duplicate_rejected,
                absolute_rejected,
                symlink_ancestor_rejected,
            ]
        )


if __name__ == "__main__":
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("usage: external_evidence.py --self-test")
    passed = self_test()
    print(
        json.dumps(
            {"schema_version": "glassbox-external-evidence-self-test/v1", "ok": passed}
        )
    )
    raise SystemExit(0 if passed else 1)
