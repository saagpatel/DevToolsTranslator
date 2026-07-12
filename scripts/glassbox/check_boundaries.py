#!/usr/bin/env python3
"""Verify Glassbox package and bundle dispositions without building artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/glassbox/COMPONENT-MANIFEST.json"
FORBIDDEN_BY_CLASS = {
    "glassbox_core": {"dtt-core", "dtt-storage", "dtt-correlation", "dtt-detectors", "dtt-export", "dtt-integrity"},
    "glassbox_worker": {"dtt-core", "dtt-storage", "dtt-correlation", "dtt-detectors", "dtt-export", "dtt-integrity", "glassbox-import-coordinator", "glassbox-storage-sqlite", "glassbox-key-lifecycle", "glassbox-privacy"},
    "glassbox_ui": {"dtt-core", "dtt-storage", "dtt-correlation", "dtt-detectors", "dtt-export", "dtt-integrity", "@dtt/shared-types"},
    "glassbox_shell": {"dtt-core", "dtt-storage", "dtt-correlation", "dtt-detectors", "dtt-export", "dtt-integrity", "@dtt/shared-types", "reqwest", "hyper", "ureq", "curl", "tokio-tungstenite", "tungstenite"},
    "glassbox_stdio_broker": {"dtt-core", "dtt-storage", "dtt-correlation", "dtt-detectors", "dtt-export", "dtt-integrity", "@dtt/shared-types"},
    "glassbox_broker_contract": {"dtt-core", "dtt-storage", "dtt-correlation", "dtt-detectors", "dtt-export", "dtt-integrity", "@dtt/shared-types"},
    "glassbox_loopback_broker": {"dtt-core", "dtt-storage", "dtt-correlation", "dtt-detectors", "dtt-export", "dtt-integrity", "@dtt/shared-types", "reqwest", "ureq", "curl", "tokio-tungstenite", "tungstenite"},
    "glassbox_passive_context_broker": {"dtt-core", "dtt-storage", "dtt-correlation", "dtt-detectors", "dtt-export", "dtt-integrity", "@dtt/shared-types", "reqwest", "hyper", "ureq", "curl", "tokio-tungstenite", "tungstenite"},
    "glassbox_parser": {"dtt-core", "dtt-storage", "dtt-correlation", "dtt-detectors", "dtt-export", "dtt-integrity", "@dtt/shared-types"},
}
NETWORK_FORBIDDEN_BY_CLASS = {
    "glassbox_core": {"reqwest", "hyper", "ureq", "curl", "tokio-tungstenite", "tungstenite", "axios", "got", "node-fetch"},
    "glassbox_worker": {"reqwest", "hyper", "ureq", "curl", "tokio-tungstenite", "tungstenite", "axios", "got", "node-fetch"},
    "glassbox_ui": {"axios", "got", "node-fetch"},
    "glassbox_stdio_broker": {"reqwest", "hyper", "ureq", "curl", "tokio-tungstenite", "tungstenite"},
    "glassbox_shell": {"reqwest", "hyper", "ureq", "curl", "tokio-tungstenite", "tungstenite"},
}

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"

def package_name(path: Path) -> str | None:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return data.get("package", {}).get("name")

def dependency_names(data: dict) -> set[str]:
    names: set[str] = set()
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        for alias, value in data.get(table, {}).items():
            names.add(value.get("package", alias) if isinstance(value, dict) else alias)
    return names

def js_dependency_names(data: dict) -> set[str]:
    names: set[str] = set()
    for table in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        names.update(data.get(table, {}).keys())
    return names

def validate() -> tuple[list[str], list[dict]]:
    errors: list[str] = []
    evidence: list[dict] = []
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    components = {item["path"]: item for item in manifest["components"]}
    root_workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["members"]
    runtime_workspace = tomllib.loads((ROOT / "glassbox-runtime/Cargo.toml").read_text(encoding="utf-8"))["workspace"]["members"]
    runtime_paths = {Path("glassbox-runtime", member).resolve().relative_to(ROOT.resolve()).as_posix() for member in runtime_workspace}
    required_runtime = {"crates/glassbox-storage-sqlite", "crates/glassbox-import-coordinator", "crates/glassbox-key-lifecycle"}
    if runtime_paths != required_runtime:
        errors.append(f"runtime workspace members must be exactly {sorted(required_runtime)}, found {sorted(runtime_paths)}")
    if any(path in root_workspace for path in required_runtime):
        errors.append("encrypted storage/coordinator must not be members of the inherited DTT workspace")
    discovered: dict[str, tuple[Path, str]] = {}
    for cargo in ROOT.glob("**/Cargo.toml"):
        if any(part in {"target", ".git"} for part in cargo.parts): continue
        name = package_name(cargo)
        if name: discovered[cargo.parent.relative_to(ROOT).as_posix()] = (cargo, name)
    for path, (cargo, name) in sorted(discovered.items()):
        component = components.get(path)
        if not component:
            errors.append(f"unclassified Rust package: {path} ({name})")
            continue
        data = tomllib.loads(cargo.read_text(encoding="utf-8"))
        dependencies = dependency_names(data)
        forbidden = sorted(dependencies & (FORBIDDEN_BY_CLASS.get(component["class"], set()) | NETWORK_FORBIDDEN_BY_CLASS.get(component["class"], set())))
        if forbidden: errors.append(f"forbidden dependencies for {path}: {', '.join(forbidden)}")
        if path in required_runtime and any(name.startswith("dtt-") for name in dependencies):
            errors.append(f"DTT dependency entered isolated runtime component {path}")
        evidence.append({"path":path,"package":name,"ecosystem":"rust","class":component["class"],"disposition":component["disposition"],"dependencies":sorted(dependencies),"manifest_sha256":sha256(cargo)})
    discovered_js: set[str] = set()
    for package_json in ROOT.glob("**/package.json"):
        if any(part in {"node_modules", "dist", ".vite-dist", "target", ".git"} for part in package_json.parts):
            continue
        path = package_json.parent.relative_to(ROOT).as_posix()
        discovered_js.add(path)
        component = components.get(path)
        data = json.loads(package_json.read_text(encoding="utf-8"))
        name = data.get("name", "unnamed-package")
        if not component:
            errors.append(f"unclassified JavaScript package: {path} ({name})")
            continue
        dependencies = js_dependency_names(data)
        forbidden = sorted(dependencies & (FORBIDDEN_BY_CLASS.get(component["class"], set()) | NETWORK_FORBIDDEN_BY_CLASS.get(component["class"], set())))
        if forbidden:
            errors.append(f"forbidden dependencies for {path}: {', '.join(forbidden)}")
        evidence.append({"path":path,"package":name,"ecosystem":"javascript","class":component["class"],"disposition":component["disposition"],"dependencies":sorted(dependencies),"manifest_sha256":sha256(package_json)})
    declared_present = {path for path, item in components.items() if item.get("present", True) and path != "."}
    missing = sorted(
        path for path in declared_present
        if path not in discovered
        and path not in discovered_js
        and not (ROOT / path / "package.json").is_file()
        and not (ROOT / path / "Cargo.toml").is_file()
    )
    if missing: errors.append("declared present components missing package manifest: " + ", ".join(missing))
    return errors, evidence

def self_test() -> list[str]:
    failures = []
    core = {"dependencies":{"dtt-core":{"path":"../dtt-core"}}}
    if not (dependency_names(core) & FORBIDDEN_BY_CLASS["glassbox_core"]): failures.append("core DTT edge escaped")
    worker = {"dependencies":{"glassbox-import-coordinator":{"path":"../glassbox-import-coordinator"}}}
    if not (dependency_names(worker) & FORBIDDEN_BY_CLASS["glassbox_worker"]): failures.append("worker coordinator edge escaped")
    ui = {"dependencies":{"@dtt/shared-types":"workspace:*"}}
    if not (js_dependency_names(ui) & FORBIDDEN_BY_CLASS["glassbox_ui"]): failures.append("UI DTT edge escaped")
    networked_core = {"dependencies":{"reqwest":"0.12"}}
    if not (dependency_names(networked_core) & NETWORK_FORBIDDEN_BY_CLASS["glassbox_core"]): failures.append("core network edge escaped")
    root = {"workspace":{"members":["crates/dtt-core","crates/glassbox-kernel"]}}
    if dependency_names(root): failures.append("workspace membership treated as dependency")
    return failures

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if args.self_test: errors, packages = self_test(), []
    else: errors, packages = validate()
    receipt = {"schema_version":"glassbox-boundary-receipt/v1","ok":not errors,"mode":"self-test" if args.self_test else "boundary","generated_at":datetime.now(timezone.utc).isoformat(),"git_head":git("rev-parse","HEAD"),"git_tree":git("rev-parse","HEAD^{tree}"),"git_dirty":bool(git("status","--porcelain")),"errors":errors,"packages":packages}
    encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.receipt: args.receipt.parent.mkdir(parents=True, exist_ok=True); args.receipt.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0 if receipt["ok"] else 1

if __name__ == "__main__": raise SystemExit(main())
