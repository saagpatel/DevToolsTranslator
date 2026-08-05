#!/usr/bin/env python3
"""Commit-bound Glassbox Gate 0 contract and negative-requirements oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC_ROOT = ROOT / "docs" / "glassbox"
MANIFEST_PATH = "docs/glassbox/COMPONENT-MANIFEST.json"
CHECKER_PATH = "scripts/glassbox/check_gate0.py"
WORKFLOW_PATH = ".github/workflows/glassbox-gate0.yml"
REQUIRED_FILES = [
    "README.md", "PRODUCT-CONTRACT.md", "NON-GOALS.md", "THREAT-MODEL.md",
    "PERMISSION-MATRIX.md", "DONOR-ALLOWLIST.md", "NEGATIVE-REQUIREMENTS-CI.md",
    "GATE-ORACLE-REGISTRY.md", "BENCHMARK-PROTOCOL.md", "RETIREMENT-PROTOCOL.md",
    "GATE-0-DECISION-REGISTER.md", "GATE-0-IMPLEMENTATION-PLAN.md",
    "GATE-0-REVIEW.md", "COMPONENT-MANIFEST.json",
    *[f"adrs/{i:03d}-{name}.md" for i, name in [
        (1,"kernel-boundary"),(2,"evidence-identity"),(3,"clock-model"),
        (4,"evidence-ontology"),(5,"browser-ipc"),(6,"data-classification"),
        (7,"storage-lifecycle"),(8,"import-security"),(9,"redaction-export"),
        (10,"schema-evolution"),(11,"distribution-uninstall"),
        (12,"egress-and-model-boundary"),(13,"source-trust"),
        (14,"apple-import-adapters"),(15,"otlp-adapter-distribution")]],
]
PROHIBITED = {
    "privileged_service": re.compile(r"SMAppService|LaunchDaemon|LaunchAgent|PrivilegedHelperTools", re.I),
    "bpf_or_spoof": re.compile(r"/dev/bpf|arp[_ -]?spoof|ip[_ -]?forward|chmod\s+[^\n]*bpf", re.I),
    "restricted_entitlement": re.compile(r"com\.apple\.developer\.(?:networking\.networkextension|endpoint-security\.client)", re.I),
    "mitm_or_proxy_install": re.compile(r"install[^\n]*(?:certificate|proxy)|trusted[^\n]*root[^\n]*ca", re.I),
    "protected_input_permission": re.compile(r"NSAppleEventsUsageDescription|NSMicrophoneUsageDescription|ScreenCapture|InputMonitoring|FullDiskAccess|kTCCServiceAccessibility", re.I),
    "root_command": re.compile(r"(?:^|\s)sudo(?:\s|$)", re.I | re.M),
    "broad_browser_permission": re.compile(r"<all_urls>|\"scripting\"", re.I),
}
FORBIDDEN_INTERNAL_DEPS = re.compile(r"\bdtt-(?:core|storage|correlation|detectors|export|integrity)\b", re.I)
ALLOWED_EXCLUSIONS = {
    "docs/glassbox": "normative policy text is structurally validated and intentionally names prohibited controls",
    CHECKER_PATH: "oracle contains prohibited matcher literals and self-test fixtures",
}

def run_git(*args: str, check: bool = True) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def head_bytes(path: str) -> bytes:
    result = subprocess.run(["git", "show", f"HEAD:{path}"], cwd=ROOT, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"required path is not committed at HEAD: {path}")
    return result.stdout

def scan_prohibited(path: Path, text: str, enforce_kernel_deps: bool = True) -> list[str]:
    hits = [name for name, pattern in PROHIBITED.items() if pattern.search(text)]
    if enforce_kernel_deps and path.name == "Cargo.toml" and FORBIDDEN_INTERNAL_DEPS.search(text):
        hits.append("forbidden_dtt_kernel_dependency")
    return hits

def load_manifest() -> dict:
    return json.loads((ROOT / MANIFEST_PATH).read_text(encoding="utf-8"))

def is_excluded(path: str, manifest: dict) -> str | None:
    declared = {item["path"]: item["reason"] for item in manifest["scan_exclusions"]}
    if declared != ALLOWED_EXCLUSIONS:
        return None
    for prefix, reason in ALLOWED_EXCLUSIONS.items():
        prefix = prefix.rstrip("/")
        if path == prefix or path.startswith(prefix + "/"):
            return reason
    return None

def classified(path: str, manifest: dict) -> bool:
    roots = [x["path"].rstrip("/") for x in manifest["components"]]
    roots += [x.rstrip("/") for x in manifest["governed_surfaces"]]
    return any(path == root or path.startswith(root + "/") for root in roots)

def component_for(path: str, manifest: dict) -> dict | None:
    matches = []
    for component in manifest["components"]:
        root = component["path"].rstrip("/")
        if root == "." or path == root or path.startswith(root + "/"):
            matches.append((len(root), component))
    return max(matches, default=(0, None), key=lambda item: item[0])[1]

def discovered_components() -> set[str]:
    found: set[str] = set()
    for pattern in ("**/Cargo.toml", "**/package.json"):
        for path in ROOT.glob(pattern):
            rel = path.relative_to(ROOT).as_posix()
            if any(part in {"target", "node_modules", ".git", "dist", ".build"} for part in path.parts):
                continue
            found.add(path.parent.relative_to(ROOT).as_posix() or ".")
    return found

def changed_paths(base_ref: str, precommit: bool) -> list[str]:
    base = run_git("merge-base", base_ref, "HEAD")
    paths = set(run_git("diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD").splitlines())
    if precommit:
        paths.update(run_git("diff", "--name-only", "--diff-filter=ACMR").splitlines())
        paths.update(run_git("diff", "--cached", "--name-only", "--diff-filter=ACMR").splitlines())
        paths.update(run_git("ls-files", "--others", "--exclude-standard").splitlines())
    return sorted(p for p in paths if p)

def markdown_link_errors(path: Path, text: str) -> list[str]:
    errors = []
    for target in re.findall(r"(?<!!)\[[^]]+\]\(([^)]+)\)", text):
        target = target.split("#", 1)[0]
        if not target or re.match(r"(?:https?|mailto):", target):
            continue
        if not (path.parent / target).resolve().exists():
            errors.append(f"broken relative link in {path.relative_to(ROOT)}: {target}")
    return errors

def run_self_test() -> tuple[list[str], list[str]]:
    failures, controls = [], []
    samples = {
        "privileged_service":"SMAppService.register()", "bpf_or_spoof":"chmod 644 /dev/bpf0",
        "restricted_entitlement":"com.apple.developer.endpoint-security.client",
        "mitm_or_proxy_install":"install trusted root ca certificate",
        "protected_input_permission":"NSAppleEventsUsageDescription", "root_command":"sudo installer -pkg x",
        "broad_browser_permission":"\"<all_urls>\"",
    }
    for expected, sample in samples.items():
        if expected not in scan_prohibited(Path("fixture.rs"), sample): failures.append(f"matcher missed {expected}")
        else: controls.append(expected)
    if "forbidden_dtt_kernel_dependency" not in scan_prohibited(Path("Cargo.toml"), 'dtt-core = { path = "../dtt-core" }'):
        failures.append("matcher missed forbidden DTT dependency")
    else: controls.append("forbidden_dtt_kernel_dependency")
    if "forbidden_dtt_kernel_dependency" in scan_prohibited(Path("Cargo.toml"), 'members = ["crates/dtt-core", "crates/glassbox-kernel"]', False):
        failures.append("legacy root workspace membership was treated as a Glassbox dependency")
    else: controls.append("legacy_workspace_members_allowed")
    # Scope integration fixture: neutral and inherited paths must both be governed/scannable.
    fixture_manifest = {"components":[{"path":"crates/capture-helper"},{"path":"apps/desktop-tauri"}], "governed_surfaces":[], "scan_exclusions":[]}
    with tempfile.TemporaryDirectory() as tmp:
        for rel in ("crates/capture-helper/Cargo.toml", "apps/desktop-tauri/bad.rs"):
            p = Path(tmp) / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("SMAppService", encoding="utf-8")
            if not classified(rel, fixture_manifest) or "privileged_service" not in scan_prohibited(p, p.read_text()):
                failures.append(f"scope fixture escaped: {rel}")
        malicious = {"scan_exclusions":[{"path":".","reason":"skip"}]}
        if is_excluded("apps/desktop-tauri/bad.rs", malicious):
            failures.append("malicious manifest exclusion was accepted")
        binary = Path(tmp) / "crates/capture-helper/helper"
        binary.write_bytes(b"\x00\xffSMAppService")
        try: binary.read_bytes().decode("utf-8"); failures.append("binary fixture decoded unexpectedly")
        except UnicodeDecodeError: controls.append("opaque_payload_fail_closed")
    controls.append("whole_tree_scope_fixture")
    return failures, controls

def validate(precommit: bool, base_ref: str) -> tuple[list[str], dict]:
    errors: list[str] = []
    hashes: dict[str, str] = {}
    manifest = load_manifest()
    declared_exclusions = {x["path"]: x["reason"] for x in manifest.get("scan_exclusions", [])}
    if declared_exclusions != ALLOWED_EXCLUSIONS:
        errors.append("component manifest exclusions must exactly match checker-owned allowlist")
    for component in manifest.get("components", []):
        if component.get("disposition") not in {"scaffold_only", "excluded", "planned_included", "separate_distribution", "test_only"}:
            errors.append(f"component missing valid disposition: {component.get('path')}")
    head = run_git("rev-parse", "HEAD")
    branch = run_git("branch", "--show-current")
    tree = run_git("rev-parse", "HEAD^{tree}")
    if not branch: errors.append("detached or unknown branch")
    status = run_git("status", "--porcelain")
    if not precommit and status: errors.append("authoritative mode requires a clean worktree and index")

    required_paths = [f"docs/glassbox/{x}" for x in REQUIRED_FILES] + [CHECKER_PATH, WORKFLOW_PATH]
    for rel in required_paths:
        path = ROOT / rel
        if not path.is_file(): errors.append(f"missing required Gate 0 artifact: {rel}"); continue
        try: data = path.read_bytes() if precommit else head_bytes(rel)
        except RuntimeError as exc: errors.append(str(exc)); continue
        hashes[rel] = digest(data)
        if path.suffix == ".md":
            text = data.decode("utf-8")
            if re.search(r"\b(?:TBD|TODO|FIXME|PLACEHOLDER)\b", text, re.I): errors.append(f"unresolved placeholder in {rel}")
            errors.extend(markdown_link_errors(path, text))
            if "/adrs/" in f"/{rel}":
                for heading in ("Status:", "Owner:", "## Decision", "## Oracle"):
                    if heading not in text: errors.append(f"ADR missing {heading}: {rel}")

    declared = {x["path"].rstrip("/") for x in manifest["components"] if x.get("present", True)}
    missing = discovered_components() - declared
    if missing: errors.append("unclassified component roots: " + ", ".join(sorted(missing)))
    changes = changed_paths(base_ref, precommit)
    scanned, excluded = [], []
    for rel in changes:
        reason = is_excluded(rel, manifest)
        if reason: excluded.append({"path":rel,"reason":reason}); continue
        if not classified(rel, manifest): errors.append(f"changed path is outside component/governed inventory: {rel}"); continue
        path = ROOT / rel
        if path.is_symlink(): errors.append(f"changed symlink requires explicit security review: {rel}"); continue
        if not path.is_file(): continue
        data = path.read_bytes() if precommit else head_bytes(rel)
        try: text = data.decode("utf-8")
        except UnicodeDecodeError:
            opaque_assets = {x["path"]: x["sha256"] for x in manifest.get("opaque_assets", [])}
            expected_hash = opaque_assets.get(rel)
            if expected_hash is None:
                errors.append(f"changed opaque/binary payload requires explicit hashed asset policy: {rel}")
            elif digest(data) != expected_hash:
                errors.append(f"changed opaque/binary payload hash mismatch: {rel}")
            else:
                scanned.append(rel)
            continue
        mode = run_git("ls-files", "-s", "--", rel, check=False).split()
        if mode and mode[0] == "120000": errors.append(f"tracked symlink requires explicit security review: {rel}")
        scanned.append(rel)
        component = component_for(rel, manifest)
        enforce_deps = bool(component and component.get("class") in {"glassbox_core", "glassbox_worker"})
        for hit in scan_prohibited(path, text, enforce_deps): errors.append(f"{hit}: {rel}")
    register = (DOC_ROOT / "GATE-0-DECISION-REGISTER.md").read_text(encoding="utf-8")
    decisions = re.findall(r"^\| (G0-\d{2}) \|", register, re.M)
    accepted = re.findall(r"^\| (G0-\d{2}) \|.*\| Accepted \|", register, re.M)
    expected = {f"G0-{i:02d}" for i in range(1, 18)}
    if len(decisions) != 17 or set(decisions) != expected or len(accepted) != 17 or set(accepted) != expected:
        errors.append("decision register must contain exactly one Accepted row for each ID G0-01 through G0-17")
    return errors, {"artifact_sha256":hashes,"git_head":head,"git_tree":tree,"git_branch":branch,"git_dirty":bool(status),"base_ref":base_ref,"scanned_files":scanned,"excluded_files":excluded}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--precommit", action="store_true")
    parser.add_argument("--base-ref", default="origin/main")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if args.self_test: errors, controls, evidence = *run_self_test(), {}
    else:
        errors, evidence = validate(args.precommit, args.base_ref); controls = []
    receipt = {"schema_version":"glassbox-gate0-receipt/v2","ok":not errors,
        "mode":"self-test" if args.self_test else "gate0", "binding":"test" if args.self_test else ("provisional" if args.precommit else "commit"),
        "generated_at":datetime.now(timezone.utc).isoformat(),"errors":errors,"controls_tested":controls,**evidence}
    encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.receipt: args.receipt.parent.mkdir(parents=True, exist_ok=True); args.receipt.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0 if receipt["ok"] else 1

if __name__ == "__main__": raise SystemExit(main())
