#!/usr/bin/env python3
"""Execute reviewed Apple raw corpora through signed child modes and offline kernel."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import subprocess
import tempfile
import unicodedata
from contextlib import contextmanager
from pathlib import Path

from external_evidence import validate_timestamp
from candidate_manifest import load_and_validate

MAX_FILES = 100_000
MAX_BYTES = 64 * 1024 * 1024 * 1024
MAX_PATH_BYTES = 4_096
MAX_DEPTH = 128
REVIEW_CHECKS = {
    "valid_native_container",
    "non_sensitive_fixture",
    "reviewed_for_distribution",
    "contains_no_unrelated_user_data",
    "representative_success_path",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_sha(root: Path, extension: str) -> str:
    if not root.is_dir() or root.is_symlink() or root.suffix != extension:
        raise ValueError("invalid corpus root")
    files: list[tuple[bytes, Path, int]] = []
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("corpus contains symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("corpus contains unsupported object")
        relative = path.relative_to(root).as_posix().encode()
        if (
            not relative
            or len(relative) > MAX_PATH_BYTES
            or b".." in relative.split(b"/")
        ):
            raise ValueError("invalid relative path")
        size = path.stat().st_size
        total += size
        if len(files) >= MAX_FILES or total > MAX_BYTES:
            raise ValueError("corpus exceeds bound")
        files.append((relative, path, size))
    digest = hashlib.sha256(b"glassbox-selected-directory-v1\0")
    for relative, path, size in sorted(files):
        digest.update(struct.pack(">Q", len(relative)))
        digest.update(relative)
        digest.update(struct.pack(">Q", size))
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def copy_directory_without_links(source: Path, destination: Path) -> None:
    """Copy a directory from opened descriptors without following links."""
    source_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    root_descriptor = os.open(source, source_flags)
    file_count = 0
    total_bytes = 0

    def stable(left: os.stat_result, right: os.stat_result) -> bool:
        return (
            left.st_dev == right.st_dev
            and left.st_ino == right.st_ino
            and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
            and left.st_size == right.st_size
            and left.st_mtime_ns == right.st_mtime_ns
            and left.st_ctime_ns == right.st_ctime_ns
        )

    def copy_open_directory(
        source_descriptor: int,
        destination_descriptor: int,
        relative_parts: tuple[str, ...],
    ) -> None:
        nonlocal file_count, total_bytes
        if len(relative_parts) > MAX_DEPTH:
            raise ValueError("corpus exceeds depth bound")
        directory_before = os.fstat(source_descriptor)
        with os.scandir(source_descriptor) as entries:
            names = sorted(entry.name for entry in entries)
        folded: set[str] = set()
        for name in names:
            encoded_name = os.fsencode(name)
            relative = b"/".join(os.fsencode(part) for part in (*relative_parts, name))
            folded_name = unicodedata.normalize("NFC", name).casefold()
            if (
                not encoded_name
                or encoded_name in {b".", b".."}
                or b"/" in encoded_name
                or b"\0" in encoded_name
                or len(relative) > MAX_PATH_BYTES
                or folded_name in folded
            ):
                raise ValueError("invalid corpus member")
            folded.add(folded_name)
            before = os.stat(name, dir_fd=source_descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise ValueError("corpus contains symlink")
            if stat.S_ISDIR(before.st_mode):
                os.mkdir(name, mode=0o700, dir_fd=destination_descriptor)
                child_source = os.open(name, source_flags, dir_fd=source_descriptor)
                child_destination = os.open(
                    name, source_flags, dir_fd=destination_descriptor
                )
                try:
                    opened = os.fstat(child_source)
                    if not stable(before, opened):
                        raise ValueError("corpus changed during staging")
                    copy_open_directory(
                        child_source, child_destination, (*relative_parts, name)
                    )
                    after = os.fstat(child_source)
                    if not stable(opened, after):
                        raise ValueError("corpus changed during staging")
                finally:
                    os.close(child_destination)
                    os.close(child_source)
                continue
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("corpus contains unsupported object")
            file_count += 1
            total_bytes += before.st_size
            if file_count > MAX_FILES or total_bytes > MAX_BYTES:
                raise ValueError("corpus exceeds bound")
            input_descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=source_descriptor,
            )
            output_descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                mode=0o600,
                dir_fd=destination_descriptor,
            )
            try:
                opened = os.fstat(input_descriptor)
                if not stat.S_ISREG(opened.st_mode) or not stable(before, opened):
                    raise ValueError("corpus changed during staging")
                copied = 0
                while chunk := os.read(input_descriptor, 1024 * 1024):
                    copied += len(chunk)
                    if copied > before.st_size:
                        raise ValueError("corpus changed during staging")
                    view = memoryview(chunk)
                    while view:
                        written = os.write(output_descriptor, view)
                        if written <= 0:
                            raise OSError("short corpus staging write")
                        view = view[written:]
                after = os.fstat(input_descriptor)
                if copied != before.st_size or not stable(opened, after):
                    raise ValueError("corpus changed during staging")
            finally:
                os.close(output_descriptor)
                os.close(input_descriptor)
        if not stable(directory_before, os.fstat(source_descriptor)):
            raise ValueError("corpus changed during staging")

    try:
        destination.mkdir(mode=0o700)
        destination_descriptor = os.open(destination, source_flags)
        try:
            copy_open_directory(root_descriptor, destination_descriptor, ())
        finally:
            os.close(destination_descriptor)
    finally:
        os.close(root_descriptor)


@contextmanager
def sandbox_staged_directory(source: Path, expected_hash: str):
    home = Path.home()
    data = home / "Library/Containers/com.glassbox.desktop/Data"
    for candidate in (
        home / "Library",
        home / "Library/Containers",
        home / "Library/Containers/com.glassbox.desktop",
        data,
    ):
        if candidate.is_symlink() or not candidate.is_dir():
            raise ValueError("invalid Glassbox sandbox container")
    container = data / "tmp"
    container.mkdir(mode=0o700, exist_ok=True)
    if container.is_symlink() or not container.is_dir():
        raise ValueError("invalid Glassbox sandbox container")
    root = Path(tempfile.mkdtemp(prefix="glassbox-apple-promotion.", dir=container))
    destination = root / source.name
    try:
        copy_directory_without_links(source, destination)
        if tree_sha(destination, source.suffix) != expected_hash:
            raise ValueError("sandbox staging identity mismatch")
        yield destination
    finally:
        for path in sorted(
            root.rglob("*"), key=lambda item: len(item.parts), reverse=True
        ):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise ValueError("invalid object in owned staging directory")
            path.unlink() if path.is_file() else path.rmdir()
        root.rmdir()


def child(
    app_binary: Path, command: str, source: Path, env: dict[str, str], timeout: int
) -> subprocess.CompletedProcess[bytes]:
    descriptor = os.open(
        source, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        return subprocess.run(
            [str(app_binary), command],
            stdin=descriptor,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, **env},
            timeout=timeout,
        )
    finally:
        os.close(descriptor)


def bridge_import(bridge: Path, format_name: str, payload: bytes, session: str) -> dict:
    result = subprocess.run(
        [
            str(bridge),
            "--import",
            format_name,
            hashlib.sha256(payload).hexdigest(),
            session,
        ],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if result.returncode or result.stderr:
        return {}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}


def native_unknown(payload: dict, expected: int | None = None) -> bool:
    count = payload.get("total_count")
    return all(
        [
            payload.get("schema_version") == "glassbox-native-shell/v1",
            isinstance(count, int) and count > 0,
            expected is None or count == expected,
            payload.get("kernel", {}).get("inserted") == count,
            payload.get("kernel", {}).get("relation_count") == 0,
            payload.get("view", {}).get("conclusion") == "unknown",
            payload.get("unmarked_drop_count") == 0,
        ]
    )


def self_test() -> dict[str, bool]:
    with tempfile.TemporaryDirectory(
        prefix="glassbox-apple-promotion-self-test."
    ) as name:
        temp = Path(name)
        source = temp / "fixture.trace"
        nested = source / "Run 1"
        nested.mkdir(parents=True)
        (source / "root.bin").write_bytes(b"root")
        (nested / "sample.bin").write_bytes(b"sample")
        expected_hash = tree_sha(source, ".trace")

        direct_destination = temp / "direct.trace"
        copy_directory_without_links(source, direct_destination)
        valid_copy = tree_sha(direct_destination, ".trace") == expected_hash

        linked_source = temp / "linked.trace"
        linked_source.mkdir()
        (linked_source / "escape").symlink_to(source / "root.bin")
        try:
            copy_directory_without_links(linked_source, temp / "linked-copy.trace")
            link_rejected = False
        except ValueError:
            link_rejected = True

        old_home = os.environ.get("HOME")
        os.environ["HOME"] = str(temp / "home")
        (Path.home() / "Library/Containers/com.glassbox.desktop/Data").mkdir(
            parents=True
        )
        container = Path.home() / "Library/Containers/com.glassbox.desktop/Data/tmp"
        try:
            with sandbox_staged_directory(source, expected_hash) as staged:
                sandbox_copy_valid = (
                    staged.parent.parent == container
                    and tree_sha(staged, ".trace") == expected_hash
                )
            sandbox_cleanup_valid = container.is_dir() and not any(container.iterdir())
        finally:
            if old_home is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = old_home

        return {
            "descriptor_relative_copy_preserves_hash": valid_copy,
            "symlink_member_rejected": link_rejected,
            "sandbox_copy_preserves_hash": sandbox_copy_valid,
            "owned_staging_directory_removed": sandbox_cleanup_valid,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument("--app", type=Path)
    parser.add_argument("--instruments-adapter", type=Path)
    parser.add_argument("--local-receipt", type=Path)
    parser.add_argument("--logarchive", type=Path)
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--review-cms", type=Path)
    parser.add_argument("--reviewer-ca", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        checks = self_test()
        result = {
            "schema_version": "glassbox-apple-import-promotion-self-test/v1",
            "ok": all(checks.values()),
            "checks": checks,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["ok"] else 1
    required = {
        "--root": args.root,
        "--candidate-manifest": args.candidate_manifest,
        "--app": args.app,
        "--instruments-adapter": args.instruments_adapter,
        "--local-receipt": args.local_receipt,
        "--logarchive": args.logarchive,
        "--trace": args.trace,
        "--review-cms": args.review_cms,
        "--reviewer-ca": args.reviewer_ca,
        "--receipt": args.receipt,
    }
    missing = [flag for flag, value in required.items() if value is None]
    if missing:
        parser.error(f"required unless --self-test: {', '.join(missing)}")
    errors: list[str] = []
    _, candidate_digest, candidate_errors = load_and_validate(
        args.root.resolve(),
        args.candidate_manifest.resolve(),
    )
    errors.extend(candidate_errors)
    try:
        local = json.loads(args.local_receipt.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        local = {}
        errors.append(f"local readiness unreadable: {exc}")
    if not (
        local.get("schema_version") == "glassbox-apple-import-readiness/v1"
        and local.get("ok") is True
    ):
        errors.append("local_readiness")
    app_binary = args.app / "Contents/MacOS/Glassbox"
    bridge = args.app / "Contents/Helpers/glassbox-native-bridge"
    instruments_binary = (
        args.instruments_adapter / "Contents/MacOS/GlassboxInstrumentsAdapter"
    )
    adapter_verify = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", str(args.instruments_adapter)],
        text=True,
        capture_output=True,
    )
    adapter_details = subprocess.run(
        ["codesign", "-dvvv", "--entitlements", ":-", str(args.instruments_adapter)],
        text=True,
        capture_output=True,
    )
    adapter_signing = adapter_details.stdout + adapter_details.stderr
    adapter_executables = (
        sorted(
            [
                path
                for path in args.instruments_adapter.rglob("*")
                if path.is_file() and os.access(path, os.X_OK)
            ]
        )
        if args.instruments_adapter.is_dir()
        else []
    )
    if not all(
        [
            adapter_verify.returncode == 0,
            instruments_binary.is_file(),
            adapter_executables == [instruments_binary],
            "Identifier=com.glassbox.instruments-adapter" in adapter_signing,
            "Authority=Developer ID Application:" in adapter_signing,
            "flags=0x10000(runtime)" in adapter_signing,
            "<?xml" not in adapter_signing,
        ]
    ):
        errors.append("instruments_adapter_signing_boundary")
    try:
        log_hash = tree_sha(args.logarchive.resolve(), ".logarchive")
        trace_hash = tree_sha(args.trace.resolve(), ".trace")
    except (OSError, ValueError) as exc:
        log_hash = trace_hash = ""
        errors.append(f"corpus: {exc}")

    with tempfile.TemporaryDirectory(prefix="glassbox-apple-review.") as temp_name:
        decoded = Path(temp_name) / "review.json"
        cms = subprocess.run(
            [
                "/usr/bin/openssl",
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                str(args.review_cms),
                "-CAfile",
                str(args.reviewer_ca),
                "-purpose",
                "any",
                "-out",
                str(decoded),
            ],
            text=True,
            capture_output=True,
        )
        try:
            review = json.loads(decoded.read_text())
        except (OSError, json.JSONDecodeError):
            review = {}
    if cms.returncode:
        errors.append("review_cms_signature")
    review_keys = {
        "schema_version",
        "ok",
        "logarchive_sha256",
        "trace_sha256",
        "reviewer",
        "checks",
    }
    if not isinstance(review, dict) or set(review) != review_keys:
        errors.append("review_root_keys")
    else:
        if review.get("schema_version") != "glassbox-apple-corpus-review/v1":
            errors.append("review_schema")
        if review.get("ok") is not True:
            errors.append("review_ok")
        if review.get("logarchive_sha256") != log_hash:
            errors.append("review_logarchive_hash")
        if review.get("trace_sha256") != trace_hash:
            errors.append("review_trace_hash")
        reviewer = review.get("reviewer")
        if not isinstance(reviewer, dict) or set(reviewer) != {
            "identity",
            "role",
            "reviewed_at",
        }:
            errors.append("reviewer")
        else:
            if reviewer.get("role") != "independent_apple_corpus_reviewer":
                errors.append("reviewer_role")
            if (
                not isinstance(reviewer.get("identity"), str)
                or not reviewer["identity"].strip()
            ):
                errors.append("reviewer_identity")
            errors.extend(
                validate_timestamp(reviewer.get("reviewed_at"), field="reviewer_time")
            )
        checks = review.get("checks")
        if (
            not isinstance(checks, dict)
            or set(checks) != REVIEW_CHECKS
            or not all(checks.get(name) is True for name in REVIEW_CHECKS)
        ):
            errors.append("review_checks")

    projection = b""
    har = b""
    log_native: dict = {}
    har_native: dict = {}
    runtime_forbidden_paths = [
        str(args.logarchive.resolve()).encode(),
        str(args.trace.resolve()).encode(),
    ]
    if not errors:
        try:
            with sandbox_staged_directory(
                args.logarchive, log_hash
            ) as staged_logarchive:
                runtime_forbidden_paths.append(
                    str(staged_logarchive.resolve()).encode()
                )
                first = child(
                    app_binary,
                    "--glassbox-apple-log-project",
                    staged_logarchive,
                    {"GLASSBOX_SOURCE_ARTIFACT_SHA256": log_hash},
                    300,
                )
                second = child(
                    app_binary,
                    "--glassbox-apple-log-project",
                    staged_logarchive,
                    {"GLASSBOX_SOURCE_ARTIFACT_SHA256": log_hash},
                    300,
                )
                projection = first.stdout
                if (
                    first.returncode
                    or first.stderr
                    or second.returncode
                    or second.stderr
                    or projection != second.stdout
                ):
                    errors.append("signed_logarchive_projection")
                rows = [json.loads(line) for line in projection.splitlines()]
                entries = [row for row in rows if row.get("type") == "entry"]
                allowed = {
                    "type",
                    "ordinal",
                    "timestamp_unix_ns",
                    "entry_kind",
                    "level",
                    "process_id",
                    "thread_id",
                    "activity_id",
                    "signpost_id",
                    "signpost_type",
                }
                if (
                    not rows
                    or rows[0].get("source_artifact_sha256") != log_hash
                    or any(set(row) - allowed for row in entries)
                ):
                    errors.append("log_projection_privacy_shape")
                log_native = bridge_import(
                    bridge, "apple-log-projection", projection, "apple_corpus_promotion"
                )
                if not native_unknown(log_native, len(entries)):
                    errors.append("log_projection_kernel_import")
            trace_run = child(
                instruments_binary,
                "--glassbox-instruments-har-project",
                args.trace,
                {"GLASSBOX_SOURCE_ARTIFACT_SHA256": trace_hash},
                1_800,
            )
            har = trace_run.stdout
            if (
                trace_run.returncode
                or trace_run.stderr
                or not har
                or len(har) > 4 * 1024 * 1024 * 1024
            ):
                errors.append("signed_instruments_conversion")
            har_native = bridge_import(
                bridge, "har", har, "instruments_corpus_promotion"
            )
            if not native_unknown(har_native):
                errors.append("instruments_har_kernel_import")
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            errors.append(f"execution: {type(exc).__name__}")

    if any(value in projection or value in har for value in runtime_forbidden_paths):
        errors.append("source_path_leak")
    promoted = not errors
    result = dict(local)
    result.update(
        {
            "schema_version": "glassbox-apple-import-readiness/v1",
            "ok": promoted,
            "logarchive_import_enabled": promoted,
            "instruments_import_enabled": promoted,
            "gate2_promotable": promoted,
            "review": review if promoted else None,
            "review_cms_sha256": sha(args.review_cms)
            if args.review_cms.is_file()
            else None,
            "reviewer_ca_sha256": sha(args.reviewer_ca)
            if args.reviewer_ca.is_file()
            else None,
            "candidate_manifest_sha256": candidate_digest if promoted else None,
            "app_binary_sha256": sha(app_binary) if app_binary.is_file() else None,
            "instruments_adapter_binary_sha256": (
                sha(instruments_binary) if instruments_binary.is_file() else None
            ),
            "logarchive_sha256": log_hash or None,
            "trace_sha256": trace_hash or None,
            "projection_sha256": hashlib.sha256(projection).hexdigest()
            if projection
            else None,
            "har_sha256": hashlib.sha256(har).hexdigest() if har else None,
            "remaining": []
            if promoted
            else ["valid reviewed corpora and successful signed conversion"],
            "errors": sorted(set(errors)),
        }
    )
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if promoted else 1


if __name__ == "__main__":
    raise SystemExit(main())
