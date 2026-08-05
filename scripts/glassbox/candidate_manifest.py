#!/usr/bin/env python3
"""Freeze and verify one exact Glassbox source tree and release-byte set."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path


SCHEMA = "glassbox-candidate-manifest/v1"
ARTIFACT_SPECS = {
    "core_app_bundle": ("tree", "dist/Glassbox.app"),
    "core_app_binary": ("file", "dist/Glassbox.app/Contents/MacOS/Glassbox"),
    "core_evidence_helper": ("file", "dist/Glassbox.app/Contents/Helpers/glassbox-native-bridge"),
    "core_dmg": ("file", "dist/Glassbox-0.1.0.dmg"),
    "browser_adapter_bundle": ("tree", "dist/Glassbox Browser Adapter.app"),
    "browser_adapter_binary": ("file", "dist/Glassbox Browser Adapter.app/Contents/MacOS/GlassboxBrowserAdapter"),
    "browser_host": ("file", "dist/Glassbox Browser Adapter.app/Contents/Helpers/glassbox-browser-host"),
    "browser_dmg": ("file", "dist/Glassbox-Browser-Adapter-0.1.0.dmg"),
    "browser_extension_zip": ("file", "dist/Glassbox-Selected-Tab-Extension-0.1.0.zip"),
    "otlp_adapter_bundle": ("tree", "dist/Glassbox OTLP Adapter.app"),
    "otlp_adapter_binary": ("file", "dist/Glassbox OTLP Adapter.app/Contents/MacOS/GlassboxOTLPAdapter"),
    "otlp_broker": ("file", "dist/Glassbox OTLP Adapter.app/Contents/Helpers/glassbox-otlp-broker"),
    "passive_adapter_bundle": ("tree", "dist/Glassbox Passive Context.app"),
    "passive_adapter_binary": ("file", "dist/Glassbox Passive Context.app/Contents/MacOS/GlassboxPassiveAdapter"),
    "passive_broker": ("file", "dist/Glassbox Passive Context.app/Contents/Helpers/glassbox-passive-context-broker"),
    "process_adapter_bundle": ("tree", "dist/Glassbox Process Context.app"),
    "process_adapter_binary": ("file", "dist/Glassbox Process Context.app/Contents/MacOS/GlassboxProcessAdapter"),
    "process_broker": ("file", "dist/Glassbox Process Context.app/Contents/Helpers/glassbox-process-context-broker"),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_sha256(path: Path) -> str:
    return sha256(path)


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256(b"glassbox-candidate-tree/v1\0")
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("tree contains symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("tree contains unsupported object")
        files.append(path)
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        size = path.stat().st_size
        mode = path.stat().st_mode & 0o777
        digest.update(struct.pack(">Q", len(relative)))
        digest.update(relative)
        digest.update(struct.pack(">IQ", mode, size))
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)


def source_state(root: Path) -> tuple[str, str, list[str]]:
    errors: list[str] = []
    head = git(root, "rev-parse", "HEAD")
    tree = git(root, "rev-parse", "HEAD^{tree}")
    if head.returncode or tree.returncode:
        return "unknown", "unknown", ["git_state"]
    if git(root, "diff", "--quiet").returncode != 0:
        errors.append("tracked_worktree_dirty")
    if git(root, "diff", "--cached", "--quiet").returncode != 0:
        errors.append("index_dirty")
    untracked = git(root, "ls-files", "--others", "--exclude-standard")
    if untracked.returncode:
        errors.append("untracked_state_unknown")
    else:
        unsafe = [
            path for path in untracked.stdout.splitlines()
            if path and not path.startswith("artifacts/")
        ]
        if unsafe:
            errors.append("untracked_source_files")
    return head.stdout.strip(), tree.stdout.strip(), errors


def confined_artifact(root: Path, relative: str, kind: str) -> Path | None:
    if not relative or relative.startswith("/") or ".." in Path(relative).parts:
        return None
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        current = root.resolve(strict=True)
        for part in Path(relative).parts:
            current = current / part
            if current.is_symlink():
                return None
    except (OSError, ValueError):
        return None
    if kind == "file" and resolved.is_file():
        return resolved
    if kind == "tree" and resolved.is_dir() and not resolved.is_symlink():
        return resolved
    return None


def artifact_sha256(path: Path, kind: str) -> str:
    return sha256(path) if kind == "file" else tree_sha256(path)


def create(root: Path) -> tuple[dict[str, object], list[str]]:
    root = root.resolve()
    head, tree, errors = source_state(root)
    artifacts: dict[str, dict[str, str]] = {}
    for name, (kind, relative) in ARTIFACT_SPECS.items():
        path = confined_artifact(root, relative, kind)
        if path is None:
            errors.append(f"artifact:{name}")
            continue
        try:
            digest = artifact_sha256(path, kind)
        except ValueError:
            errors.append(f"artifact:{name}")
            continue
        artifacts[name] = {"kind": kind, "path": relative, "sha256": digest}
    return {
        "schema_version": SCHEMA,
        "git_head": head,
        "git_tree": tree,
        "artifacts": artifacts,
    }, sorted(set(errors))


def validate(root: Path, manifest: object, *, require_current: bool = True) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "git_head", "git_tree", "artifacts",
    }:
        return ["candidate_manifest_root_keys"]
    if manifest.get("schema_version") != SCHEMA:
        errors.append("candidate_manifest_schema")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(ARTIFACT_SPECS):
        errors.append("candidate_manifest_artifact_set")
    else:
        for name, (expected_kind, expected_path) in ARTIFACT_SPECS.items():
            item = artifacts.get(name)
            if not isinstance(item, dict) or set(item) != {"kind", "path", "sha256"}:
                errors.append(f"candidate_manifest_artifact:{name}")
                continue
            path = confined_artifact(root, expected_path, expected_kind)
            if item.get("kind") != expected_kind or item.get("path") != expected_path or path is None:
                errors.append(f"candidate_manifest_path:{name}")
            else:
                try:
                    matches = item.get("sha256") == artifact_sha256(path, expected_kind)
                except ValueError:
                    matches = False
                if not matches:
                    errors.append(f"candidate_manifest_hash:{name}")
    if require_current:
        head, tree, state_errors = source_state(root)
        errors.extend(f"candidate_{error}" for error in state_errors)
        if manifest.get("git_head") != head:
            errors.append("candidate_git_head")
        if manifest.get("git_tree") != tree:
            errors.append("candidate_git_tree")
    return sorted(set(errors))


def load_and_validate(root: Path, path: Path) -> tuple[dict[str, object], str | None, list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, None, [f"candidate_manifest_unreadable:{type(exc).__name__}"]
    errors = validate(root, data)
    return data, manifest_sha256(path) if path.is_file() else None, errors


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="glassbox-candidate-self-test.") as temp_name:
        root = Path(temp_name)
        (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
        (root / "source.txt").write_text("source\n", encoding="utf-8")
        for name, (kind, relative) in ARTIFACT_SPECS.items():
            path = root / relative
            if kind == "file":
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
            else:
                path.mkdir(parents=True, exist_ok=True)
                (path / "tree-marker").write_bytes(name.encode())
        commands = [
            ["git", "init", "--quiet"],
            ["git", "add", ".gitignore", "source.txt"],
            [
                "git", "-c", "user.name=Glassbox Test", "-c",
                "user.email=glassbox@example.invalid", "commit", "--quiet", "-m", "fixture",
            ],
        ]
        if any(subprocess.run(command, cwd=root, capture_output=True).returncode for command in commands):
            return False
        manifest, create_errors = create(root)
        valid = not create_errors and not validate(root, manifest)
        (root / ARTIFACT_SPECS["core_app_binary"][1]).write_bytes(b"changed")
        hash_drift = "candidate_manifest_hash:core_app_binary" in validate(root, manifest)
        (root / "source.txt").write_text("dirty\n", encoding="utf-8")
        dirty_rejected = "candidate_tracked_worktree_dirty" in validate(root, manifest)
        return valid and hash_drift and dirty_rejected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        passed = self_test()
        print(json.dumps({"schema_version": "glassbox-candidate-manifest-self-test/v1", "ok": passed}))
        return 0 if passed else 1
    if args.root is None:
        parser.error("--root is required")
    if (args.output is None) == (args.verify is None):
        parser.error("exactly one of --output or --verify is required")
    if args.output is not None:
        manifest, errors = create(args.root)
        result = {"ok": not errors, "manifest": manifest, "errors": errors}
        if not errors:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        manifest, digest, errors = load_and_validate(args.root, args.verify)
        result = {
            "ok": not errors, "manifest": manifest if not errors else None,
            "candidate_manifest_sha256": digest, "errors": errors,
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
