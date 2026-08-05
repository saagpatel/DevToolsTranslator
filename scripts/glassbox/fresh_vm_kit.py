#!/usr/bin/env python3
"""Build and verify a deterministic, exact-candidate Glassbox fresh-VM kit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Callable


SCHEMA = "glassbox-fresh-vm-kit/v1"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
KIT_MANIFEST = "KIT-MANIFEST.json"
MAX_ARCHIVE_MEMBERS = 32
MAX_MEMBER_SIZE = 512 * 1024 * 1024
MAX_TOTAL_SIZE = 1024 * 1024 * 1024

ARTIFACT_MEMBERS = {
    "core_dmg": "artifacts/Glassbox-0.1.0.dmg",
    "browser_dmg": "artifacts/Glassbox-Browser-Adapter-0.1.0.dmg",
    "otlp_adapter_dmg": "artifacts/Glassbox-OTLP-Adapter-0.1.0.dmg",
    "passive_adapter_dmg": "artifacts/Glassbox-Passive-Context-0.1.0.dmg",
    "process_adapter_dmg": "artifacts/Glassbox-Process-Context-0.1.0.dmg",
    "instruments_adapter_dmg": "artifacts/Glassbox-Instruments-Adapter-0.1.0.dmg",
    "browser_extension_zip": "artifacts/Glassbox-Selected-Tab-Extension-0.1.0.zip",
}

ARTIFACT_SOURCE_PATHS = {
    "core_dmg": "dist/Glassbox-0.1.0.dmg",
    "browser_dmg": "dist/Glassbox-Browser-Adapter-0.1.0.dmg",
    "otlp_adapter_dmg": "dist/Glassbox-OTLP-Adapter-0.1.0.dmg",
    "passive_adapter_dmg": "dist/Glassbox-Passive-Context-0.1.0.dmg",
    "process_adapter_dmg": "dist/Glassbox-Process-Context-0.1.0.dmg",
    "instruments_adapter_dmg": "dist/Glassbox-Instruments-Adapter-0.1.0.dmg",
    "browser_extension_zip": "dist/Glassbox-Selected-Tab-Extension-0.1.0.zip",
}

EXPECTED_CANDIDATE_ARTIFACTS = {
    "core_app_bundle",
    "core_app_binary",
    "core_evidence_helper",
    "core_dmg",
    "browser_adapter_bundle",
    "browser_adapter_binary",
    "browser_host",
    "browser_dmg",
    "browser_extension_zip",
    "otlp_adapter_bundle",
    "otlp_adapter_binary",
    "otlp_broker",
    "otlp_adapter_dmg",
    "passive_adapter_bundle",
    "passive_adapter_binary",
    "passive_broker",
    "passive_adapter_dmg",
    "process_adapter_bundle",
    "process_adapter_binary",
    "process_broker",
    "process_adapter_dmg",
    "instruments_adapter_bundle",
    "instruments_adapter_binary",
    "instruments_adapter_dmg",
}

SOURCE_MEMBERS = {
    "docs/glassbox/FRESH-VM-OPERATOR.md": "README.md",
    "docs/glassbox/LIFECYCLE-EVIDENCE.template.json": "templates/LIFECYCLE-EVIDENCE.template.json",
    "docs/glassbox/ACCESSIBILITY-EVIDENCE.template.json": "templates/ACCESSIBILITY-EVIDENCE.template.json",
    "docs/glassbox/BROWSER-RELEASE-EVIDENCE.md": "templates/BROWSER-RELEASE-EVIDENCE.md",
    "docs/glassbox/AUXILIARY-ADAPTER-EVIDENCE.template.json": "templates/AUXILIARY-ADAPTER-EVIDENCE.template.json",
    "docs/glassbox/AUXILIARY-ADAPTER-RELEASE-EVIDENCE.md": "templates/AUXILIARY-ADAPTER-RELEASE-EVIDENCE.md",
    "docs/glassbox/browser/fresh-vm-evidence-template.json": "templates/browser/fresh-vm-evidence-template.json",
    "scripts/glassbox/fresh_vm_kit.py": "tools/fresh_vm_kit.py",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in value
    )


def is_lower_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def confined_file(root: Path, relative: str) -> Path | None:
    if not safe_relative(relative):
        return None
    try:
        root = root.resolve(strict=True)
        current = root
        for part in PurePosixPath(relative).parts:
            current = current / part
            if current.is_symlink():
                return None
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_file() else None


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def publish_exclusive(source: Path, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise ValueError("output_exists")
    try:
        os.link(source, output)
    except FileExistsError as exc:
        raise ValueError("output_exists") from exc
    directory_fd = os.open(output.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def write_archive(
    output: Path,
    root_name: str,
    members: dict[str, bytes],
    kit_manifest: dict[str, object],
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        raise ValueError("output_exists")
    with tempfile.NamedTemporaryFile(
        prefix=f".{output.name}.", dir=output.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for relative, data in sorted(members.items()):
                archive.writestr(zip_info(f"{root_name}/{relative}"), data)
            archive.writestr(
                zip_info(f"{root_name}/{KIT_MANIFEST}"),
                canonical_json(kit_manifest),
            )
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        publish_exclusive(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def build(root: Path, candidate_path: Path, output: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    candidate_path = candidate_path.resolve(strict=True)
    import sys

    sys.path.insert(0, str(root / "scripts/glassbox"))
    from candidate_manifest import load_and_validate  # pylint: disable=import-outside-toplevel

    candidate, candidate_digest, candidate_errors = load_and_validate(
        root, candidate_path
    )
    if candidate_errors or candidate_digest is None:
        return {
            "ok": False,
            "errors": [f"candidate:{error}" for error in candidate_errors],
        }

    members: dict[str, bytes] = {}
    errors: list[str] = []
    candidate_bytes = candidate_path.read_bytes()
    members["artifacts/glassbox-candidate-manifest.json"] = candidate_bytes
    artifacts = candidate.get("artifacts", {})
    for artifact_name, destination in ARTIFACT_MEMBERS.items():
        item = artifacts.get(artifact_name) if isinstance(artifacts, dict) else None
        if not isinstance(item, dict) or item.get("kind") != "file":
            errors.append(f"candidate_artifact:{artifact_name}")
            continue
        source = confined_file(root, str(item.get("path", "")))
        if source is None:
            errors.append(f"artifact_path:{artifact_name}")
            continue
        data = source.read_bytes()
        if sha256_bytes(data) != item.get("sha256"):
            errors.append(f"artifact_hash:{artifact_name}")
            continue
        members[destination] = data

    for source_name, destination in SOURCE_MEMBERS.items():
        source = confined_file(root, source_name)
        if source is None:
            errors.append(f"source_member:{source_name}")
            continue
        members[destination] = source.read_bytes()

    if errors:
        return {"ok": False, "errors": sorted(errors)}

    root_name = f"glassbox-fresh-vm-kit-{str(candidate['git_head'])[:7]}"
    member_records = {
        relative: {"sha256": sha256_bytes(data), "size": len(data)}
        for relative, data in sorted(members.items())
    }
    kit_manifest: dict[str, object] = {
        "schema_version": SCHEMA,
        "candidate_manifest_sha256": candidate_digest,
        "git_head": candidate["git_head"],
        "git_tree": candidate["git_tree"],
        "root_directory": root_name,
        "members": member_records,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        return {"schema_version": SCHEMA, "ok": False, "errors": ["output_exists"]}
    with tempfile.NamedTemporaryFile(
        prefix=f".{output.name}.verify.", dir=output.parent, delete=False
    ) as handle:
        staging = Path(handle.name)
    staging.unlink()
    try:
        write_archive(staging, root_name, members, kit_manifest)
        result = verify_archive(staging, expected_candidate_sha256=candidate_digest)
        if result["ok"] is not True:
            return result
        try:
            publish_exclusive(staging, output)
        except (OSError, ValueError) as exc:
            return {
                "schema_version": SCHEMA,
                "ok": False,
                "errors": [str(exc)],
            }
    finally:
        staging.unlink(missing_ok=True)
    result["archive"] = str(output.resolve())
    result["archive_sha256"] = sha256_bytes(output.read_bytes())
    return result


def parse_kit_manifest(raw: bytes) -> tuple[dict[str, object], list[str]]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}, ["kit_manifest_unreadable"]
    expected = {
        "schema_version",
        "candidate_manifest_sha256",
        "git_head",
        "git_tree",
        "root_directory",
        "members",
    }
    if not isinstance(value, dict) or set(value) != expected:
        return {}, ["kit_manifest_root_keys"]
    errors: list[str] = []
    if value.get("schema_version") != SCHEMA:
        errors.append("kit_manifest_schema")
    if not is_lower_hex(value.get("candidate_manifest_sha256"), 64):
        errors.append("kit_manifest_candidate_manifest_sha256")
    if not is_lower_hex(value.get("git_head"), 40):
        errors.append("kit_manifest_git_head")
    if not is_lower_hex(value.get("git_tree"), 40):
        errors.append("kit_manifest_git_tree")
    if not isinstance(value.get("root_directory"), str) or not value["root_directory"]:
        errors.append("kit_manifest_root_directory")
    members = value.get("members")
    if not isinstance(members, dict) or not members:
        errors.append("kit_manifest_members")
    else:
        for name, record in members.items():
            if not isinstance(name, str) or not safe_relative(name):
                errors.append("kit_manifest_member_path")
                continue
            if (
                not isinstance(record, dict)
                or set(record) != {"sha256", "size"}
                or not is_lower_hex(record.get("sha256"), 64)
                or not isinstance(record.get("size"), int)
                or record["size"] < 0
            ):
                errors.append(f"kit_manifest_member:{name}")
    return value, sorted(set(errors))


def validate_payload(
    kit_manifest: dict[str, object],
    read_member: Callable[[str], bytes],
    actual_members: set[str],
    *,
    expected_candidate_sha256: str | None,
) -> list[str]:
    errors: list[str] = []
    members = kit_manifest.get("members", {})
    if not isinstance(members, dict):
        return ["kit_manifest_members"]
    required_payload_members = (
        {"artifacts/glassbox-candidate-manifest.json"}
        | set(ARTIFACT_MEMBERS.values())
        | set(SOURCE_MEMBERS.values())
    )
    if set(members) != required_payload_members:
        errors.append("kit_manifest_member_set")
    expected_members = set(members) | {KIT_MANIFEST}
    if actual_members != expected_members:
        errors.append("archive_member_set")
    for name, record in members.items():
        if name not in actual_members or not isinstance(record, dict):
            continue
        try:
            data = read_member(name)
        except (KeyError, OSError):
            errors.append(f"member_unreadable:{name}")
            continue
        if len(data) != record.get("size"):
            errors.append(f"member_size:{name}")
        if sha256_bytes(data) != record.get("sha256"):
            errors.append(f"member_hash:{name}")

    candidate_name = "artifacts/glassbox-candidate-manifest.json"
    try:
        candidate_bytes = read_member(candidate_name)
        candidate = json.loads(candidate_bytes)
    except (KeyError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return sorted(set(errors + ["candidate_manifest_unreadable"]))
    candidate_digest = sha256_bytes(candidate_bytes)
    if candidate_digest != kit_manifest.get("candidate_manifest_sha256"):
        errors.append("candidate_manifest_digest")
    if (
        expected_candidate_sha256 is not None
        and candidate_digest != expected_candidate_sha256
    ):
        errors.append("expected_candidate_manifest_digest")
    if not isinstance(candidate, dict) or set(candidate) != {
        "schema_version",
        "git_head",
        "git_tree",
        "artifacts",
    }:
        return sorted(set(errors + ["candidate_manifest_root_keys"]))
    if candidate.get("schema_version") != "glassbox-candidate-manifest/v1":
        errors.append("candidate_manifest_schema")
    if candidate.get("git_head") != kit_manifest.get("git_head"):
        errors.append("candidate_git_head")
    if candidate.get("git_tree") != kit_manifest.get("git_tree"):
        errors.append("candidate_git_tree")
    expected_root = f"glassbox-fresh-vm-kit-{str(candidate.get('git_head', ''))[:7]}"
    if kit_manifest.get("root_directory") != expected_root:
        errors.append("root_directory")
    artifacts = candidate.get("artifacts")
    if (
        not isinstance(artifacts, dict)
        or set(artifacts) != EXPECTED_CANDIDATE_ARTIFACTS
    ):
        errors.append("candidate_artifacts")
    else:
        for artifact_name, member_name in ARTIFACT_MEMBERS.items():
            item = artifacts.get(artifact_name)
            if (
                not isinstance(item, dict)
                or set(item) != {"kind", "path", "sha256"}
                or item.get("kind") != "file"
                or item.get("path") != ARTIFACT_SOURCE_PATHS[artifact_name]
                or not is_lower_hex(item.get("sha256"), 64)
            ):
                errors.append(f"candidate_artifact:{artifact_name}")
                continue
            try:
                data = read_member(member_name)
            except (KeyError, OSError):
                errors.append(f"artifact_missing:{artifact_name}")
                continue
            if sha256_bytes(data) != item.get("sha256"):
                errors.append(f"artifact_hash:{artifact_name}")
    return sorted(set(errors))


def verify_archive(
    path: Path, *, expected_candidate_sha256: str | None = None
) -> dict[str, object]:
    errors: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if (
                len(infos) > MAX_ARCHIVE_MEMBERS
                or any(item.file_size > MAX_MEMBER_SIZE for item in infos)
                or sum(item.file_size for item in infos) > MAX_TOTAL_SIZE
            ):
                errors.append("archive_size_limit")
            if len(names) != len(set(names)):
                errors.append("duplicate_archive_member")
            if any(
                not safe_relative(name)
                or name.endswith("/")
                or "__MACOSX" in PurePosixPath(name).parts
                or PurePosixPath(name).name.startswith("._")
                or PurePosixPath(name).name == ".DS_Store"
                for name in names
            ):
                errors.append("unsafe_archive_member")
            if any(stat.S_ISLNK(item.external_attr >> 16) for item in infos):
                errors.append("archive_symlink")
            if errors:
                return {
                    "schema_version": SCHEMA,
                    "ok": False,
                    "errors": sorted(set(errors)),
                }
            roots = {
                PurePosixPath(name).parts[0]
                for name in names
                if PurePosixPath(name).parts
            }
            if len(roots) != 1:
                errors.append("archive_root")
                return {
                    "schema_version": SCHEMA,
                    "ok": False,
                    "errors": sorted(set(errors)),
                }
            root_name = next(iter(roots))
            manifest_name = f"{root_name}/{KIT_MANIFEST}"
            try:
                manifest_raw = archive.read(manifest_name)
            except KeyError:
                return {
                    "schema_version": SCHEMA,
                    "ok": False,
                    "errors": sorted(set(errors + ["kit_manifest_missing"])),
                }
            kit_manifest, manifest_errors = parse_kit_manifest(manifest_raw)
            errors.extend(manifest_errors)
            if not manifest_errors:
                relative_names = {
                    str(PurePosixPath(name).relative_to(root_name)) for name in names
                }
                errors.extend(
                    validate_payload(
                        kit_manifest,
                        lambda relative: archive.read(f"{root_name}/{relative}"),
                        relative_names,
                        expected_candidate_sha256=expected_candidate_sha256,
                    )
                )
                if kit_manifest.get("root_directory") != root_name:
                    errors.append("archive_root_binding")
    except (OSError, zipfile.BadZipFile):
        errors.append("archive_unreadable")
    return {"schema_version": SCHEMA, "ok": not errors, "errors": sorted(set(errors))}


def verify_directory(
    path: Path, *, expected_candidate_sha256: str | None = None
) -> dict[str, object]:
    errors: list[str] = []
    try:
        root = path.resolve(strict=True)
    except OSError:
        return {
            "schema_version": SCHEMA,
            "ok": False,
            "errors": ["directory_unreadable"],
        }
    if not root.is_dir() or path.is_symlink():
        return {"schema_version": SCHEMA, "ok": False, "errors": ["directory_invalid"]}
    files: set[str] = set()
    for item in root.rglob("*"):
        relative = item.relative_to(root).as_posix()
        if item.is_symlink():
            errors.append(f"directory_symlink:{relative}")
        elif item.is_file():
            files.add(relative)
        elif not item.is_dir():
            errors.append(f"directory_object:{relative}")
    if errors:
        return {"schema_version": SCHEMA, "ok": False, "errors": sorted(set(errors))}

    def read_confined(relative: str) -> bytes:
        source = confined_file(root, relative)
        if source is None:
            raise OSError("unconfined member")
        return source.read_bytes()

    try:
        manifest_raw = read_confined(KIT_MANIFEST)
    except OSError:
        return {
            "schema_version": SCHEMA,
            "ok": False,
            "errors": sorted(set(errors + ["kit_manifest_missing"])),
        }
    kit_manifest, manifest_errors = parse_kit_manifest(manifest_raw)
    errors.extend(manifest_errors)
    if not manifest_errors:
        errors.extend(
            validate_payload(
                kit_manifest,
                read_confined,
                files,
                expected_candidate_sha256=expected_candidate_sha256,
            )
        )
        if kit_manifest.get("root_directory") != root.name:
            errors.append("directory_root_binding")
    return {"schema_version": SCHEMA, "ok": not errors, "errors": sorted(set(errors))}


def self_test() -> dict[str, bool]:
    with tempfile.TemporaryDirectory(prefix="glassbox-fresh-vm-kit-test.") as temp_name:
        temp = Path(temp_name)
        artifact_data = {name: f"artifact:{name}".encode() for name in ARTIFACT_MEMBERS}
        all_artifacts = {
            name: {
                "kind": "tree" if name.endswith("bundle") else "file",
                "path": f"dist/{name}",
                "sha256": sha256_bytes(name.encode()),
            }
            for name in EXPECTED_CANDIDATE_ARTIFACTS
        }
        for name, data in artifact_data.items():
            all_artifacts[name] = {
                "kind": "file",
                "path": ARTIFACT_SOURCE_PATHS[name],
                "sha256": sha256_bytes(data),
            }
        candidate = {
            "schema_version": "glassbox-candidate-manifest/v1",
            "git_head": "a" * 40,
            "git_tree": "b" * 40,
            "artifacts": all_artifacts,
        }
        candidate_bytes = canonical_json(candidate)
        members = {
            "artifacts/glassbox-candidate-manifest.json": candidate_bytes,
            **{ARTIFACT_MEMBERS[name]: data for name, data in artifact_data.items()},
            **{
                destination: f"source:{destination}\n".encode()
                for destination in SOURCE_MEMBERS.values()
            },
        }
        root_name = "glassbox-fresh-vm-kit-aaaaaaa"
        kit_manifest = {
            "schema_version": SCHEMA,
            "candidate_manifest_sha256": sha256_bytes(candidate_bytes),
            "git_head": candidate["git_head"],
            "git_tree": candidate["git_tree"],
            "root_directory": root_name,
            "members": {
                name: {"sha256": sha256_bytes(data), "size": len(data)}
                for name, data in sorted(members.items())
            },
        }
        first = temp / "first.zip"
        second = temp / "second.zip"
        write_archive(first, root_name, members, kit_manifest)
        write_archive(second, root_name, members, kit_manifest)
        valid = (
            verify_archive(
                first, expected_candidate_sha256=sha256_bytes(candidate_bytes)
            )["ok"]
            is True
        )
        deterministic = first.read_bytes() == second.read_bytes()
        original_first = first.read_bytes()
        try:
            write_archive(first, root_name, members, kit_manifest)
            overwrite_rejected = False
        except ValueError as exc:
            overwrite_rejected = (
                str(exc) == "output_exists" and first.read_bytes() == original_first
            )
        wrong_digest_rejected = (
            verify_archive(first, expected_candidate_sha256="0" * 64)["ok"] is False
        )

        extracted = temp / root_name
        with zipfile.ZipFile(first) as archive:
            archive.extractall(temp)
        valid_directory = (
            verify_directory(
                extracted,
                expected_candidate_sha256=sha256_bytes(candidate_bytes),
            )["ok"]
            is True
        )

        tampered = temp / "tampered.zip"
        with (
            zipfile.ZipFile(first) as source,
            zipfile.ZipFile(tampered, "w") as destination,
        ):
            for info in source.infolist():
                data = source.read(info.filename)
                if info.filename.endswith("/README.md"):
                    data = b"tampered\n"
                destination.writestr(info, data)
        tamper_rejected = verify_archive(tampered)["ok"] is False
        (extracted / "README.md").write_bytes(b"tampered\n")
        tampered_directory_rejected = verify_directory(extracted)["ok"] is False

        symlinked = temp / "symlinked.zip"
        with (
            zipfile.ZipFile(first) as source,
            zipfile.ZipFile(symlinked, "w") as destination,
        ):
            for info in source.infolist():
                destination.writestr(info, source.read(info.filename))
            link = zipfile.ZipInfo(f"{root_name}/link", FIXED_ZIP_TIME)
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            destination.writestr(link, b"README.md")
        symlink_result = verify_archive(symlinked)
        symlink_rejected = (
            symlink_result["ok"] is False
            and "archive_symlink" in symlink_result["errors"]
        )
        return {
            "valid_archive_passes": valid,
            "valid_extracted_directory_passes": valid_directory,
            "deterministic_archive_bytes": deterministic,
            "existing_archive_preserved": overwrite_rejected,
            "wrong_expected_candidate_rejected": wrong_digest_rejected,
            "tampered_member_rejected": tamper_rejected,
            "tampered_directory_rejected": tampered_directory_rejected,
            "archive_symlink_rejected": symlink_rejected,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--build", type=Path, metavar="ARCHIVE")
    mode.add_argument("--verify-archive", type=Path, metavar="ARCHIVE")
    mode.add_argument("--verify-directory", type=Path, metavar="DIRECTORY")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument("--expected-candidate-sha256")
    args = parser.parse_args()

    if args.self_test:
        checks = self_test()
        result = {
            "schema_version": f"{SCHEMA}-self-test",
            "ok": all(checks.values()),
            "checks": checks,
        }
    elif args.build is not None:
        if args.root is None or args.candidate_manifest is None:
            parser.error("--build requires --root and --candidate-manifest")
        result = build(args.root, args.candidate_manifest, args.build)
        result.setdefault("schema_version", SCHEMA)
    elif args.verify_archive is not None:
        result = verify_archive(
            args.verify_archive,
            expected_candidate_sha256=args.expected_candidate_sha256,
        )
    else:
        result = verify_directory(
            args.verify_directory,
            expected_candidate_sha256=args.expected_candidate_sha256,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
