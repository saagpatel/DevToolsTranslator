#!/usr/bin/env python3
"""Freeze and verify the exact Glassbox Apple notarization submission batch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

from candidate_manifest import (
    ARTIFACT_SPECS,
    create as create_candidate_inventory,
    load_and_validate,
    tree_sha256,
)


SCHEMA = "glassbox-notarization-batch/v1"
RECEIPT_SCHEMA = "glassbox-notarization-batch-receipt/v1"
MAX_FUTURE_SKEW = timedelta(minutes=5)
TEAM_ID = "3TGZFKFNA4"
SUBMISSION_SPECS = {
    "core_app": (
        "core_app_bundle",
        "dist/Glassbox.app",
        "Glassbox.app.zip",
        "app",
    ),
    "core_dmg": (
        "core_dmg",
        "dist/Glassbox-0.1.0.dmg",
        "Glassbox-0.1.0.dmg",
        "dmg",
    ),
    "instruments_app": (
        "instruments_adapter_bundle",
        "dist/Glassbox Instruments Adapter.app",
        "Glassbox-Instruments-Adapter.app.zip",
        "app",
    ),
    "instruments_dmg": (
        "instruments_adapter_dmg",
        "dist/Glassbox-Instruments-Adapter-0.1.0.dmg",
        "Glassbox-Instruments-Adapter-0.1.0.dmg",
        "dmg",
    ),
    "browser_app": (
        "browser_adapter_bundle",
        "dist/Glassbox Browser Adapter.app",
        "Glassbox-Browser-Adapter.app.zip",
        "app",
    ),
    "browser_dmg": (
        "browser_dmg",
        "dist/Glassbox-Browser-Adapter-0.1.0.dmg",
        "Glassbox-Browser-Adapter-0.1.0.dmg",
        "dmg",
    ),
    "otlp_app": (
        "otlp_adapter_bundle",
        "dist/Glassbox OTLP Adapter.app",
        "Glassbox-OTLP-Adapter.app.zip",
        "app",
    ),
    "otlp_dmg": (
        "otlp_adapter_dmg",
        "dist/Glassbox-OTLP-Adapter-0.1.0.dmg",
        "Glassbox-OTLP-Adapter-0.1.0.dmg",
        "dmg",
    ),
    "passive_app": (
        "passive_adapter_bundle",
        "dist/Glassbox Passive Context.app",
        "Glassbox-Passive-Context.app.zip",
        "app",
    ),
    "passive_dmg": (
        "passive_adapter_dmg",
        "dist/Glassbox-Passive-Context-0.1.0.dmg",
        "Glassbox-Passive-Context-0.1.0.dmg",
        "dmg",
    ),
    "process_app": (
        "process_adapter_bundle",
        "dist/Glassbox Process Context.app",
        "Glassbox-Process-Context.app.zip",
        "app",
    ),
    "process_dmg": (
        "process_adapter_dmg",
        "dist/Glassbox-Process-Context-0.1.0.dmg",
        "Glassbox-Process-Context-0.1.0.dmg",
        "dmg",
    ),
}
LOG_KEYS = {
    "logFormatVersion",
    "jobId",
    "status",
    "statusSummary",
    "statusCode",
    "archiveFilename",
    "uploadDate",
    "sha256",
    "ticketContents",
    "issues",
}
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
LOWER_CDHASH = re.compile(r"[0-9a-f]{40}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True)


def git(root: Path, *args: str) -> str | None:
    result = run("git", *args, cwd=root)
    return result.stdout.strip() if result.returncode == 0 else None


def clean_source(root: Path) -> tuple[str | None, str | None, list[str]]:
    errors: list[str] = []
    head = git(root, "rev-parse", "HEAD")
    tree = git(root, "rev-parse", "HEAD^{tree}")
    if head is None or tree is None:
        errors.append("git_state")
    if git(root, "status", "--porcelain") != "":
        errors.append("git_dirty")
    return head, tree, errors


def confined(root: Path, path: Path, *, must_exist: bool) -> Path | None:
    try:
        root = root.resolve(strict=True)
        candidate = path if path.is_absolute() else root / path
        relative = candidate.relative_to(root)
        if ".." in relative.parts:
            return None
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                return None
        resolved = candidate.resolve(strict=must_exist)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return resolved


def under_artifacts(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root / "artifacts")
    except ValueError:
        return False
    return True


def exclusive_write(path: Path, value: object) -> None:
    identity: tuple[int, int] | None = None
    try:
        with path.open("xb") as handle:
            created_stat = os.fstat(handle.fileno())
            identity = (created_stat.st_dev, created_stat.st_ino)
            handle.write(canonical_json(value))
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        try:
            current = path.lstat()
        except OSError:
            current = None
        if (
            identity is not None
            and current is not None
            and stat.S_ISREG(current.st_mode)
            and (current.st_dev, current.st_ino) == identity
        ):
            path.unlink()
        raise


def remove_owned_directory(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        current = path.lstat()
    except OSError:
        return
    if (
        stat.S_ISDIR(current.st_mode)
        and not path.is_symlink()
        and (current.st_dev, current.st_ino) == identity
    ):
        shutil.rmtree(path)


def signing_ready(path: Path, kind: str) -> bool:
    verify_args = ["codesign", "--verify", "--strict"]
    if kind == "app":
        verify_args.append("--deep")
    verify = run(*verify_args, str(path))
    details = run("codesign", "-dvvv", "--entitlements", ":-", str(path))
    text = details.stdout + details.stderr
    required = (
        verify.returncode == 0
        and f"TeamIdentifier={TEAM_ID}" in text
        and "Authority=Developer ID Application:" in text
    )
    if kind == "dmg":
        return required and run("hdiutil", "verify", str(path)).returncode == 0
    return required and "flags=0x10000(runtime)" in text


def create_batch(root: Path, output: Path, transport: Path) -> tuple[dict, list[str]]:
    root = root.resolve(strict=True)
    output = confined(root, output, must_exist=False)
    transport = confined(root, transport, must_exist=False)
    if output is None or transport is None:
        return {}, ["output_confinement"]
    if (
        not under_artifacts(root, output)
        or not under_artifacts(root, transport)
        or transport in output.parents
        or output in transport.parents
    ):
        return {}, ["output_location"]
    if (
        output.exists()
        or output.is_symlink()
        or transport.exists()
        or transport.is_symlink()
    ):
        return {}, ["output_exists"]
    head, tree, errors = clean_source(root)
    inventory, inventory_errors = create_candidate_inventory(root)
    errors.extend(f"inventory:{error}" for error in inventory_errors)
    artifacts = inventory.get("artifacts", {})
    for role, (artifact_name, source_name, _, kind) in SUBMISSION_SPECS.items():
        source = confined(root, Path(source_name), must_exist=True)
        item = artifacts.get(artifact_name) if isinstance(artifacts, dict) else None
        if source is None or not isinstance(item, dict):
            errors.append(f"artifact:{role}")
        elif not signing_ready(source, kind):
            errors.append(f"signing:{role}")
    if errors:
        return {}, sorted(set(errors))

    submissions: dict[str, dict[str, str]] = {}
    transport_identity: tuple[int, int] | None = None
    try:
        transport.mkdir(mode=0o700)
        transport_stat = transport.lstat()
        transport_identity = (transport_stat.st_dev, transport_stat.st_ino)
        for role, (
            artifact_name,
            source_name,
            upload_name,
            kind,
        ) in SUBMISSION_SPECS.items():
            source = confined(root, Path(source_name), must_exist=True)
            if source is None:
                raise ValueError(f"artifact:{role}")
            upload = transport / upload_name
            if kind == "app":
                result = run(
                    "/usr/bin/ditto",
                    "-c",
                    "-k",
                    "--keepParent",
                    str(source),
                    str(upload),
                )
                if result.returncode != 0:
                    raise OSError(f"transport:{role}")
                with tempfile.TemporaryDirectory(
                    prefix=".verify-", dir=transport
                ) as temp_name:
                    extracted_root = Path(temp_name)
                    result = run(
                        "/usr/bin/ditto",
                        "-x",
                        "-k",
                        str(upload),
                        str(extracted_root),
                    )
                    extracted = extracted_root / source.name
                    if (
                        result.returncode != 0
                        or {path.name for path in extracted_root.iterdir()}
                        != {source.name}
                        or not extracted.is_dir()
                        or extracted.is_symlink()
                        or tree_sha256(extracted) != artifacts[artifact_name]["sha256"]
                    ):
                        raise OSError(f"transport_round_trip:{role}")
            else:
                with (
                    source.open("rb") as input_handle,
                    upload.open("xb") as output_handle,
                ):
                    shutil.copyfileobj(input_handle, output_handle, 1024 * 1024)
                    output_handle.flush()
                    os.fsync(output_handle.fileno())
                if sha256(upload) != artifacts[artifact_name]["sha256"]:
                    raise OSError(f"transport_copy:{role}")
            submissions[role] = {
                "artifact_name": artifact_name,
                "kind": kind,
                "source_path": source_name,
                "source_sha256": artifacts[artifact_name]["sha256"],
                "upload_path": upload.relative_to(root).as_posix(),
                "upload_sha256": sha256(upload),
            }
        final_inventory, final_inventory_errors = create_candidate_inventory(root)
        if final_inventory_errors or final_inventory.get("artifacts") != artifacts:
            raise ValueError("artifact_race")
        batch = {
            "schema_version": SCHEMA,
            "git_head": head,
            "git_tree": tree,
            "prepared_at": datetime.now(timezone.utc).isoformat(),
            "pre_staple_artifacts": artifacts,
            "submissions": submissions,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        exclusive_write(output, batch)
        return batch, []
    except (OSError, ValueError, KeyError) as exc:
        remove_owned_directory(transport, transport_identity)
        return {}, [str(exc)]


def load_batch(path: Path) -> tuple[dict, list[str]]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}, ["batch_unreadable"]
    expected = {
        "schema_version",
        "git_head",
        "git_tree",
        "prepared_at",
        "pre_staple_artifacts",
        "submissions",
    }
    if not isinstance(value, dict) or set(value) != expected:
        return {}, ["batch_root_keys"]
    return value, []


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def validate_batch(
    root: Path, batch: object, *, require_current_sources: bool
) -> list[str]:
    errors: list[str] = []
    if not isinstance(batch, dict):
        return ["batch_object"]
    if batch.get("schema_version") != SCHEMA:
        errors.append("batch_schema")
    prepared = parse_time(batch.get("prepared_at"))
    if prepared is None or prepared > datetime.now(timezone.utc) + MAX_FUTURE_SKEW:
        errors.append("batch_prepared_at")
    head, tree, source_errors = clean_source(root)
    errors.extend(source_errors)
    if batch.get("git_head") != head:
        errors.append("batch_git_head")
    if batch.get("git_tree") != tree:
        errors.append("batch_git_tree")
    inventory = batch.get("pre_staple_artifacts")
    if not isinstance(inventory, dict) or set(inventory) != set(ARTIFACT_SPECS):
        errors.append("batch_artifact_set")
        inventory = {}
    else:
        for artifact_name, (expected_kind, expected_path) in ARTIFACT_SPECS.items():
            artifact = inventory.get(artifact_name)
            if (
                not isinstance(artifact, dict)
                or set(artifact) != {"kind", "path", "sha256"}
                or artifact.get("kind") != expected_kind
                or artifact.get("path") != expected_path
                or not isinstance(artifact.get("sha256"), str)
                or LOWER_SHA256.fullmatch(artifact["sha256"]) is None
            ):
                errors.append(f"batch_artifact:{artifact_name}")
    submissions = batch.get("submissions")
    if not isinstance(submissions, dict) or set(submissions) != set(SUBMISSION_SPECS):
        errors.append("batch_submission_set")
        submissions = {}
    current_artifacts: dict = {}
    current_errors: list[str] = []
    if require_current_sources:
        current_inventory, current_errors = create_candidate_inventory(root)
        current_artifacts = current_inventory.get("artifacts", {})
        if current_errors or current_artifacts != inventory:
            errors.append("batch_current_inventory")
    upload_paths: list[Path] = []
    for role, (
        artifact_name,
        source_name,
        upload_name,
        kind,
    ) in SUBMISSION_SPECS.items():
        item = submissions.get(role)
        expected_keys = {
            "artifact_name",
            "kind",
            "source_path",
            "source_sha256",
            "upload_path",
            "upload_sha256",
        }
        if not isinstance(item, dict) or set(item) != expected_keys:
            errors.append(f"batch_submission:{role}")
            continue
        artifact = inventory.get(artifact_name)
        if (
            item.get("artifact_name") != artifact_name
            or item.get("kind") != kind
            or item.get("source_path") != source_name
            or not isinstance(artifact, dict)
            or item.get("source_sha256") != artifact.get("sha256")
            or not isinstance(item.get("upload_sha256"), str)
            or LOWER_SHA256.fullmatch(item["upload_sha256"]) is None
        ):
            errors.append(f"batch_identity:{role}")
        upload = confined(root, Path(str(item.get("upload_path", ""))), must_exist=True)
        if (
            upload is None
            or upload.name != upload_name
            or not upload.is_file()
            or sha256(upload) != item.get("upload_sha256")
        ):
            errors.append(f"batch_upload:{role}")
        else:
            upload_paths.append(upload)
        if require_current_sources:
            source = confined(root, Path(source_name), must_exist=True)
            if source is None:
                errors.append(f"batch_source:{role}")
            else:
                current = current_artifacts.get(artifact_name, {})
                if current_errors or current.get("sha256") != item.get("source_sha256"):
                    errors.append(f"batch_source:{role}")
    transport_dirs = {path.parent for path in upload_paths}
    if len(upload_paths) != len(SUBMISSION_SPECS) or len(transport_dirs) != 1:
        errors.append("batch_transport_directory")
    else:
        transport_dir = next(iter(transport_dirs))
        expected_names = {spec[2] for spec in SUBMISSION_SPECS.values()}
        try:
            members = list(transport_dir.iterdir())
        except OSError:
            members = []
        if (
            not under_artifacts(root, transport_dir)
            or {member.name for member in members} != expected_names
            or any(member.is_symlink() or not member.is_file() for member in members)
        ):
            errors.append("batch_transport_set")
    return sorted(set(errors))


def validate_log(
    value: object, *, role: str, item: dict, prepared_at: datetime
) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict) or set(value) != LOG_KEYS:
        return [f"notary_log_keys:{role}"]
    try:
        job_id = str(uuid.UUID(str(value.get("jobId"))))
    except ValueError:
        job_id = ""
        errors.append(f"notary_job_id:{role}")
    if value.get("jobId") != job_id:
        errors.append(f"notary_job_id:{role}")
    uploaded = parse_time(value.get("uploadDate"))
    if (
        uploaded is None
        or uploaded < prepared_at - MAX_FUTURE_SKEW
        or uploaded > datetime.now(timezone.utc) + MAX_FUTURE_SKEW
    ):
        errors.append(f"notary_upload_date:{role}")
    tickets = value.get("ticketContents")
    if not isinstance(tickets, list) or not tickets:
        errors.append(f"notary_ticket_contents:{role}")
    else:
        archive_name = Path(str(item.get("upload_path", ""))).name
        for ticket in tickets:
            if not isinstance(ticket, dict) or set(ticket) not in (
                {"path", "digestAlgorithm", "cdhash"},
                {"path", "digestAlgorithm", "cdhash", "arch"},
            ):
                errors.append(f"notary_ticket_shape:{role}")
                break
            ticket_path = ticket.get("path")
            parsed_path = (
                PurePosixPath(ticket_path) if isinstance(ticket_path, str) else None
            )
            if (
                parsed_path is None
                or parsed_path.is_absolute()
                or ".." in parsed_path.parts
                or not parsed_path.parts
                or parsed_path.parts[0] != archive_name
            ):
                errors.append(f"notary_ticket_path:{role}")
                break
            if ticket.get("digestAlgorithm") != "SHA-256":
                errors.append(f"notary_ticket_digest:{role}")
                break
            cdhash = ticket.get("cdhash")
            if not isinstance(cdhash, str) or LOWER_CDHASH.fullmatch(cdhash) is None:
                errors.append(f"notary_ticket_cdhash:{role}")
                break
            if "arch" in ticket and ticket.get("arch") != "arm64":
                errors.append(f"notary_ticket_arch:{role}")
                break
    reported_sha = value.get("sha256")
    if (
        not isinstance(reported_sha, str)
        or LOWER_SHA256.fullmatch(reported_sha) is None
    ):
        errors.append(f"notary_upload_sha256:{role}")
    if not all(
        [
            value.get("logFormatVersion") == 1,
            value.get("status") == "Accepted",
            value.get("statusSummary") == "Ready for distribution",
            value.get("statusCode") == 0,
            value.get("archiveFilename") == Path(str(item.get("upload_path", ""))).name,
            value.get("sha256") == item.get("upload_sha256"),
            value.get("issues") is None,
        ]
    ):
        errors.append(f"notary_acceptance:{role}")
    if not job_id:
        errors.append(f"notary_job_id:{role}")
    return sorted(set(errors))


def verify_accepted(
    root: Path,
    batch_path: Path,
    logs_dir: Path,
    candidate_manifest: Path,
    receipt: Path,
) -> tuple[dict, list[str]]:
    resolved_batch = confined(root, batch_path, must_exist=True)
    if resolved_batch is None or not under_artifacts(root, resolved_batch):
        batch, errors = {}, ["batch_confinement"]
    else:
        batch, errors = load_batch(resolved_batch)
    errors.extend(validate_batch(root, batch, require_current_sources=False))
    resolved_candidate = confined(root, candidate_manifest, must_exist=True)
    if resolved_candidate is None or not under_artifacts(root, resolved_candidate):
        candidate_digest, candidate_errors = None, ["manifest_confinement"]
    else:
        _, candidate_digest, candidate_errors = load_and_validate(
            root, resolved_candidate
        )
    errors.extend(f"candidate:{error}" for error in candidate_errors)
    logs_dir = confined(root, logs_dir, must_exist=True)
    if logs_dir is None or not under_artifacts(root, logs_dir) or not logs_dir.is_dir():
        errors.append("logs_directory")
    prepared = parse_time(batch.get("prepared_at")) or datetime.max.replace(
        tzinfo=timezone.utc
    )
    results: dict[str, dict[str, str]] = {}
    if logs_dir is not None and logs_dir.is_dir():
        try:
            log_members = list(logs_dir.iterdir())
        except OSError:
            log_members = []
            errors.append("notary_log_set")
        all_logs = sorted(path for path in log_members if path.suffix == ".json")
        batch_submissions = batch.get("submissions")
        if not isinstance(batch_submissions, dict):
            batch_submissions = {}
        for role in SUBMISSION_SPECS:
            matches = [path for path in all_logs if path.name.startswith(f"{role}-")]
            if len(matches) != 1 or matches[0].is_symlink():
                errors.append(f"notary_log_file:{role}")
                continue
            path = matches[0]
            try:
                value = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                errors.append(f"notary_log_unreadable:{role}")
                continue
            errors.extend(
                validate_log(
                    value,
                    role=role,
                    item=batch_submissions.get(role, {}),
                    prepared_at=prepared,
                )
            )
            job_id = str(value.get("jobId", ""))
            if path.name != f"{role}-{job_id}.json":
                errors.append(f"notary_log_filename:{role}")
            results[role] = {
                "job_id": job_id,
                "log_sha256": sha256(path),
                "upload_sha256": str(value.get("sha256", "")),
                "status": str(value.get("status", "")),
            }
        expected_names = {
            f"{role}-{results[role]['job_id']}.json"
            for role in results
            if results[role]["job_id"]
        }
        if {path.name for path in log_members} != expected_names or any(
            path.is_symlink() or not path.is_file() for path in log_members
        ):
            errors.append("notary_log_set")
    resolved_receipt = confined(root, receipt, must_exist=False)
    if (
        resolved_receipt is None
        or not under_artifacts(root, resolved_receipt)
        or resolved_receipt.is_symlink()
    ):
        errors.append("receipt_confinement")
        resolved_receipt = None
    elif resolved_receipt.exists():
        errors.append("receipt_exists")
        resolved_receipt = None
    errors = sorted(set(errors))
    result = {
        "schema_version": RECEIPT_SCHEMA,
        "ok": not errors,
        "readiness_ok": True,
        "gate6_promotable": not errors,
        "git_head": batch.get("git_head"),
        "git_tree": batch.get("git_tree"),
        "git_dirty": bool(git(root, "status", "--porcelain")),
        "candidate_manifest_sha256": candidate_digest if not candidate_errors else None,
        "batch_manifest_sha256": sha256(resolved_batch)
        if resolved_batch is not None and resolved_batch.is_file()
        else None,
        "submissions": results,
        "external_requirements": []
        if not errors
        else [
            "twelve exact Accepted Apple notary logs bound to the preserved uploads",
        ],
        "errors": errors,
    }
    if resolved_receipt is not None:
        try:
            resolved_receipt.parent.mkdir(parents=True, exist_ok=True)
            exclusive_write(resolved_receipt, result)
        except OSError:
            errors = sorted({*errors, "receipt_write"})
            result["ok"] = False
            result["gate6_promotable"] = False
            result["errors"] = errors
    return result, errors


def self_test() -> bool:
    now = datetime.now(timezone.utc)
    item = {
        "upload_path": "artifacts/transport/Glassbox.app.zip",
        "upload_sha256": "a" * 64,
    }
    job_id = "00000000-0000-4000-8000-000000000001"
    valid = {
        "logFormatVersion": 1,
        "jobId": job_id,
        "status": "Accepted",
        "statusSummary": "Ready for distribution",
        "statusCode": 0,
        "archiveFilename": "Glassbox.app.zip",
        "uploadDate": now.isoformat(),
        "sha256": "a" * 64,
        "ticketContents": [
            {
                "path": "Glassbox.app.zip/Glassbox.app",
                "digestAlgorithm": "SHA-256",
                "cdhash": "b" * 40,
                "arch": "arm64",
            }
        ],
        "issues": None,
    }
    accepted = not validate_log(valid, role="core_app", item=item, prepared_at=now)
    rejected: list[bool] = []
    for key, value in (
        ("status", "Invalid"),
        ("sha256", "c" * 64),
        ("issues", [{"message": "fixture"}]),
        ("ticketContents", []),
    ):
        candidate = dict(valid)
        candidate[key] = value
        rejected.append(
            bool(validate_log(candidate, role="core_app", item=item, prepared_at=now))
        )
    for key, value in (
        ("path", "../Glassbox.app.zip/Glassbox.app"),
        ("digestAlgorithm", "SHA-1"),
        ("cdhash", "B" * 40),
        ("arch", "x86_64"),
    ):
        candidate = json.loads(json.dumps(valid))
        candidate["ticketContents"][0][key] = value
        rejected.append(
            bool(validate_log(candidate, role="core_app", item=item, prepared_at=now))
        )
    with tempfile.TemporaryDirectory(prefix="glassbox-notary-self-test.") as temp_name:
        root = Path(temp_name).resolve()
        target = root / "target"
        target.mkdir()
        (target / "fixture").write_text("fixture", encoding="utf-8")
        (root / "link").symlink_to(target, target_is_directory=True)
        symlink_rejected = (
            confined(root, root / "link" / "fixture", must_exist=True) is None
        )
    with tempfile.TemporaryDirectory(prefix="glassbox-notary-batch-test.") as temp_name:
        root = Path(temp_name).resolve()
        (root / ".gitignore").write_text("artifacts/\n", encoding="utf-8")
        (root / "source").write_text("fixture\n", encoding="utf-8")
        commands = (
            ("git", "init", "--quiet"),
            ("git", "add", ".gitignore", "source"),
            (
                "git",
                "-c",
                "user.name=Glassbox Test",
                "-c",
                "user.email=glassbox@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ),
        )
        git_ready = all(run(*command, cwd=root).returncode == 0 for command in commands)
        transport = root / "artifacts" / "transport"
        transport.mkdir(parents=True)
        inventory = {
            name: {"kind": kind, "path": path, "sha256": "a" * 64}
            for name, (kind, path) in ARTIFACT_SPECS.items()
        }
        submissions = {}
        for role, (
            artifact_name,
            source_name,
            upload_name,
            kind,
        ) in SUBMISSION_SPECS.items():
            upload = transport / upload_name
            upload.write_bytes(role.encode())
            submissions[role] = {
                "artifact_name": artifact_name,
                "kind": kind,
                "source_path": source_name,
                "source_sha256": inventory[artifact_name]["sha256"],
                "upload_path": upload.relative_to(root).as_posix(),
                "upload_sha256": sha256(upload),
            }
        batch = {
            "schema_version": SCHEMA,
            "git_head": git(root, "rev-parse", "HEAD"),
            "git_tree": git(root, "rev-parse", "HEAD^{tree}"),
            "prepared_at": now.isoformat(),
            "pre_staple_artifacts": inventory,
            "submissions": submissions,
        }
        batch_valid = git_ready and not validate_batch(
            root, batch, require_current_sources=False
        )
        extra = transport / "extra.txt"
        extra.write_text("extra", encoding="utf-8")
        extra_rejected = "batch_transport_set" in validate_batch(
            root, batch, require_current_sources=False
        )
        extra.unlink()
        mutated = json.loads(json.dumps(batch))
        mutated["pre_staple_artifacts"]["core_app_bundle"]["path"] = "dist/Wrong.app"
        inventory_rejected = "batch_artifact:core_app_bundle" in validate_batch(
            root, mutated, require_current_sources=False
        )
    return (
        accepted
        and all(rejected)
        and symlink_rejected
        and batch_valid
        and extra_rejected
        and inventory_rejected
        and len(SUBMISSION_SPECS) == 12
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", type=Path, metavar="MANIFEST")
    mode.add_argument("--verify-prepared", type=Path, metavar="MANIFEST")
    mode.add_argument("--verify-accepted", type=Path, metavar="MANIFEST")
    mode.add_argument("--readiness", type=Path, metavar="RECEIPT")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--transport-dir", type=Path)
    parser.add_argument("--logs-dir", type=Path)
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if args.self_test:
        passed = self_test()
        print(
            json.dumps(
                {
                    "schema_version": "glassbox-notarization-batch-self-test/v1",
                    "ok": passed,
                },
                sort_keys=True,
            )
        )
        return 0 if passed else 1
    if args.root is None:
        parser.error("--root is required")
    root = args.root.resolve(strict=True)
    if args.readiness is not None:
        head, tree, errors = clean_source(root)
        if not self_test():
            errors.append("self_test")
        result = {
            "schema_version": RECEIPT_SCHEMA,
            "ok": False,
            "readiness_ok": not errors,
            "gate6_promotable": False,
            "git_head": head,
            "git_tree": tree,
            "git_dirty": bool(git(root, "status", "--porcelain")),
            "candidate_manifest_sha256": None,
            "batch_manifest_sha256": None,
            "submissions": {},
            "external_requirements": [
                "Developer ID candidate production and twelve Accepted Apple notary logs",
            ],
            "errors": sorted(set(errors)),
        }
        receipt = confined(root, args.readiness, must_exist=False)
        if receipt is None or receipt.is_symlink():
            result["readiness_ok"] = False
            result["errors"].append("receipt_confinement")
        else:
            receipt.parent.mkdir(parents=True, exist_ok=True)
            receipt.write_bytes(canonical_json(result))
    elif args.prepare is not None:
        if args.transport_dir is None:
            parser.error("--prepare requires --transport-dir")
        batch, errors = create_batch(root, args.prepare, args.transport_dir)
        result = {
            "ok": not errors,
            "manifest": batch if not errors else None,
            "errors": errors,
        }
    elif args.verify_prepared is not None:
        batch_path = confined(root, args.verify_prepared, must_exist=True)
        if batch_path is None or not under_artifacts(root, batch_path):
            batch, errors = {}, ["batch_confinement"]
        else:
            batch, errors = load_batch(batch_path)
        errors.extend(validate_batch(root, batch, require_current_sources=True))
        result = {
            "ok": not errors,
            "manifest": batch if not errors else None,
            "errors": sorted(set(errors)),
        }
    else:
        if (
            args.logs_dir is None
            or args.candidate_manifest is None
            or args.receipt is None
        ):
            parser.error(
                "--verify-accepted requires --logs-dir, --candidate-manifest, and --receipt"
            )
        result, errors = verify_accepted(
            root,
            args.verify_accepted,
            args.logs_dir,
            args.candidate_manifest,
            args.receipt,
        )
        result["errors"] = errors
        result["ok"] = not errors
    print(json.dumps(result, indent=2, sort_keys=True))
    passed = (
        result.get("readiness_ok") is True
        if args.readiness is not None
        else result["ok"]
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
