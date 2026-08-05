#!/usr/bin/env python3
"""Execute reviewed Apple raw corpora through signed child modes and offline kernel."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path

from external_evidence import validate_timestamp
from candidate_manifest import load_and_validate

MAX_FILES = 100_000
MAX_BYTES = 64 * 1024 * 1024 * 1024
MAX_PATH_BYTES = 4_096
REVIEW_CHECKS = {
    "valid_native_container", "non_sensitive_fixture", "reviewed_for_distribution",
    "contains_no_unrelated_user_data", "representative_success_path",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_sha(root: Path, extension: str) -> str:
    if not root.is_dir() or root.is_symlink() or root.suffix != extension:
        raise ValueError("invalid corpus root")
    files: list[tuple[bytes, Path, int]] = []
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink(): raise ValueError("corpus contains symlink")
        if path.is_dir(): continue
        if not path.is_file(): raise ValueError("corpus contains unsupported object")
        relative = path.relative_to(root).as_posix().encode()
        if not relative or len(relative) > MAX_PATH_BYTES or b".." in relative.split(b"/"):
            raise ValueError("invalid relative path")
        size = path.stat().st_size
        total += size
        if len(files) >= MAX_FILES or total > MAX_BYTES: raise ValueError("corpus exceeds bound")
        files.append((relative, path, size))
    digest = hashlib.sha256(b"glassbox-selected-directory-v1\0")
    for relative, path, size in sorted(files):
        digest.update(struct.pack(">Q", len(relative)))
        digest.update(relative)
        digest.update(struct.pack(">Q", size))
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024): digest.update(chunk)
    return digest.hexdigest()


def child(app_binary: Path, command: str, source: Path, env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[bytes]:
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return subprocess.run(
            [str(app_binary), command], stdin=descriptor, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={**os.environ, **env}, timeout=timeout,
        )
    finally:
        os.close(descriptor)


def bridge_import(bridge: Path, format_name: str, payload: bytes, session: str) -> dict:
    result = subprocess.run(
        [str(bridge), "--import", format_name, hashlib.sha256(payload).hexdigest(), session],
        input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )
    if result.returncode or result.stderr: return {}
    try: return json.loads(result.stdout)
    except json.JSONDecodeError: return {}


def native_unknown(payload: dict, expected: int | None = None) -> bool:
    count = payload.get("total_count")
    return all([
        payload.get("schema_version") == "glassbox-native-shell/v1",
        isinstance(count, int) and count > 0,
        expected is None or count == expected,
        payload.get("kernel", {}).get("inserted") == count,
        payload.get("kernel", {}).get("relation_count") == 0,
        payload.get("view", {}).get("conclusion") == "unknown",
        payload.get("unmarked_drop_count") == 0,
    ])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--candidate-manifest", required=True, type=Path)
    parser.add_argument("--app", required=True, type=Path)
    parser.add_argument("--local-receipt", required=True, type=Path)
    parser.add_argument("--logarchive", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--review-cms", required=True, type=Path)
    parser.add_argument("--reviewer-ca", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    errors: list[str] = []
    _, candidate_digest, candidate_errors = load_and_validate(
        args.root.resolve(), args.candidate_manifest.resolve(),
    )
    errors.extend(candidate_errors)
    try: local = json.loads(args.local_receipt.read_text())
    except (OSError, json.JSONDecodeError) as exc: local = {}; errors.append(f"local readiness unreadable: {exc}")
    if not (local.get("schema_version") == "glassbox-apple-import-readiness/v1" and local.get("ok") is True):
        errors.append("local_readiness")
    app_binary = args.app / "Contents/MacOS/Glassbox"
    bridge = args.app / "Contents/Helpers/glassbox-native-bridge"
    try:
        log_hash = tree_sha(args.logarchive.resolve(), ".logarchive")
        trace_hash = tree_sha(args.trace.resolve(), ".trace")
    except (OSError, ValueError) as exc:
        log_hash = trace_hash = ""
        errors.append(f"corpus: {exc}")

    with tempfile.TemporaryDirectory(prefix="glassbox-apple-review.") as temp_name:
        decoded = Path(temp_name) / "review.json"
        cms = subprocess.run([
            "/usr/bin/openssl", "cms", "-verify", "-inform", "DER", "-in", str(args.review_cms),
            "-CAfile", str(args.reviewer_ca), "-purpose", "any", "-out", str(decoded),
        ], text=True, capture_output=True)
        try: review = json.loads(decoded.read_text())
        except (OSError, json.JSONDecodeError): review = {}
    if cms.returncode: errors.append("review_cms_signature")
    review_keys = {"schema_version", "ok", "logarchive_sha256", "trace_sha256", "reviewer", "checks"}
    if not isinstance(review, dict) or set(review) != review_keys:
        errors.append("review_root_keys")
    else:
        if review.get("schema_version") != "glassbox-apple-corpus-review/v1": errors.append("review_schema")
        if review.get("ok") is not True: errors.append("review_ok")
        if review.get("logarchive_sha256") != log_hash: errors.append("review_logarchive_hash")
        if review.get("trace_sha256") != trace_hash: errors.append("review_trace_hash")
        reviewer = review.get("reviewer")
        if not isinstance(reviewer, dict) or set(reviewer) != {"identity", "role", "reviewed_at"}:
            errors.append("reviewer")
        else:
            if reviewer.get("role") != "independent_apple_corpus_reviewer": errors.append("reviewer_role")
            if not isinstance(reviewer.get("identity"), str) or not reviewer["identity"].strip(): errors.append("reviewer_identity")
            errors.extend(validate_timestamp(reviewer.get("reviewed_at"), field="reviewer_time"))
        checks = review.get("checks")
        if not isinstance(checks, dict) or set(checks) != REVIEW_CHECKS or not all(checks.get(name) is True for name in REVIEW_CHECKS):
            errors.append("review_checks")

    projection = b""
    har = b""
    log_native: dict = {}
    har_native: dict = {}
    if not errors:
        try:
            first = child(app_binary, "--glassbox-apple-log-project", args.logarchive, {"GLASSBOX_SOURCE_ARTIFACT_SHA256": log_hash}, 300)
            second = child(app_binary, "--glassbox-apple-log-project", args.logarchive, {"GLASSBOX_SOURCE_ARTIFACT_SHA256": log_hash}, 300)
            projection = first.stdout
            if first.returncode or first.stderr or second.returncode or second.stderr or projection != second.stdout:
                errors.append("signed_logarchive_projection")
            rows = [json.loads(line) for line in projection.splitlines()]
            entries = [row for row in rows if row.get("type") == "entry"]
            allowed = {"type", "ordinal", "timestamp_unix_ns", "entry_kind", "level", "process_id", "thread_id", "activity_id", "signpost_id", "signpost_type"}
            if not rows or rows[0].get("source_artifact_sha256") != log_hash or any(set(row) - allowed for row in entries):
                errors.append("log_projection_privacy_shape")
            log_native = bridge_import(bridge, "apple-log-projection", projection, "apple_corpus_promotion")
            if not native_unknown(log_native, len(entries)): errors.append("log_projection_kernel_import")
            trace_run = child(app_binary, "--glassbox-instruments-har-project", args.trace, {}, 1_800)
            har = trace_run.stdout
            if trace_run.returncode or trace_run.stderr or not har or len(har) > 4 * 1024 * 1024 * 1024:
                errors.append("signed_instruments_conversion")
            har_native = bridge_import(bridge, "har", har, "instruments_corpus_promotion")
            if not native_unknown(har_native): errors.append("instruments_har_kernel_import")
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            errors.append(f"execution: {type(exc).__name__}")

    forbidden_paths = [str(args.logarchive.resolve()).encode(), str(args.trace.resolve()).encode()]
    if any(value in projection or value in har for value in forbidden_paths): errors.append("source_path_leak")
    promoted = not errors
    result = dict(local)
    result.update({
        "schema_version": "glassbox-apple-import-readiness/v1", "ok": promoted,
        "logarchive_import_enabled": promoted, "instruments_import_enabled": promoted,
        "gate2_promotable": promoted, "review": review if promoted else None,
        "review_cms_sha256": sha(args.review_cms) if args.review_cms.is_file() else None,
        "reviewer_ca_sha256": sha(args.reviewer_ca) if args.reviewer_ca.is_file() else None,
        "candidate_manifest_sha256": candidate_digest if promoted else None,
        "app_binary_sha256": sha(app_binary) if app_binary.is_file() else None,
        "logarchive_sha256": log_hash or None, "trace_sha256": trace_hash or None,
        "projection_sha256": hashlib.sha256(projection).hexdigest() if projection else None,
        "har_sha256": hashlib.sha256(har).hexdigest() if har else None,
        "remaining": [] if promoted else ["valid reviewed corpora and successful signed conversion"],
        "errors": sorted(set(errors)),
    })
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if promoted else 1


if __name__ == "__main__": raise SystemExit(main())
