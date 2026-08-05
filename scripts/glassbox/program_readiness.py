#!/usr/bin/env python3
"""Compose all Glassbox gate receipts without upgrading readiness claims."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from candidate_manifest import load_and_validate


EXPECTED = {
    "gate0": "glassbox-gate0-receipt/v2",
    "boundary": "glassbox-boundary-receipt/v1",
    "storage": "glassbox-storage-spike/v1",
    "key_lifecycle": "glassbox-key-lifecycle-readiness/v1",
    "lifecycle": "glassbox-lifecycle/v1",
    "hostile_import": "glassbox-hostile-import/v1",
    "privacy": "glassbox-privacy-gate/v1",
    "native_import": "glassbox-native-import-workflow/v1",
    "apple_import": "glassbox-apple-import-readiness/v1",
    "mysteries": "glassbox-mystery-gate/v1",
    "browser_ipc": "glassbox-browser-ipc/v1",
    "browser_artifact": "glassbox-browser-artifact/v1",
    "auxiliary_adapters": "glassbox-auxiliary-adapters/v1",
    "live_source": "glassbox-live-source/v1",
    "resource_sampler": "glassbox-resource-sampler/v1",
    "process_context": "glassbox-process-context-gate/v1",
    "observer_effect": "glassbox-observer-effect/v1",
    "network_import": "glassbox-network-import/v1",
    "passive_context": "glassbox-passive-context/v1",
    "accessibility": "glassbox-accessibility/v1",
    "performance": "glassbox-performance/v1",
    "egress": "glassbox-egress/v1",
    "macos_artifact": "glassbox-macos-artifact/v1",
    "notarization": "glassbox-notarization-batch-receipt/v1",
    "benchmark": "glassbox-benchmark-readiness/v1",
    "retirement": "glassbox-retirement/v1",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def receipt_binding_checks(
    loaded: dict[str, dict[str, object]], head: str, tree: str,
) -> dict[str, bool]:
    return {
        f"{name}_current_clean_git_binding": (
            data.get("git_head") == head
            and data.get("git_tree") == tree
            and data.get("git_dirty") is False
        )
        for name, data in loaded.items()
    }


def promotion_summary(
    loaded: dict[str, dict[str, object]], implemented: bool, candidate_bound: bool,
) -> tuple[dict[str, bool], bool, int | None, dict[str, str]]:
    promotion_checks = {
        "gate0_contract_lock": loaded["gate0"].get("ok") is True,
        "frozen_candidate_identity": candidate_bound,
        "gate1_keychain": loaded["key_lifecycle"].get("gate1_promotable") is True,
        "gate2_apple_imports": loaded["apple_import"].get("gate2_promotable") is True,
        "gate6_notarization_batch": loaded["notarization"].get("gate6_promotable") is True,
        "gate6_core_distribution": loaded["macos_artifact"].get("gate6_promotable") is True,
        "gate6_browser_distribution": loaded["browser_artifact"].get("gate6_promotable") is True,
        "gate6_auxiliary_adapter_distribution": loaded["auxiliary_adapters"].get("gate6_promotable") is True,
        "gate6_lifecycle": loaded["lifecycle"].get("gate6_promotable") is True,
        "gate6_accessibility": loaded["accessibility"].get("gate6_promotable") is True,
        "gate6_human_benchmark": loaded["benchmark"].get("gate6_promotable") is True,
        "gate7_retirement": loaded["retirement"].get("gate7_promotable") is True,
    }
    blocker_text = {
        "gate0_contract_lock": "clean committed contract state requires publication authority",
        "frozen_candidate_identity": "one clean-tree candidate manifest must bind every promoted lane to the exact release bytes",
        "gate1_keychain": "product-authorized macOS provisioning profile and signed Keychain lifecycle round-trip",
        "gate2_apple_imports": "reviewed valid logarchive and Instruments corpora plus end-to-end conversion proof",
        "gate6_notarization_batch": "twelve exact Accepted Apple notary logs bound to preserved upload bytes",
        "gate6_core_distribution": "fresh-VM Developer ID notarization, stapling, and Gatekeeper acceptance",
        "gate6_browser_distribution": "production extension identity, fresh-VM Chrome end-to-end evidence, notarization and stapling of the separate adapter, and manual DevTools accessibility/disclosure review",
        "gate6_auxiliary_adapter_distribution": "notarization, stapling, Gatekeeper, and fresh-VM workflow/accessibility/residue evidence for Instruments, OTLP, passive-context, and process-context adapters",
        "gate6_lifecycle": "fresh-VM install, update, downgrade, revoke, reset, uninstall, reinstall, and residue evidence",
        "gate6_accessibility": "manual keyboard, VoiceOver, reduced-motion, zoom, and disclosure review",
        "gate6_human_benchmark": "pilot, power analysis, preregistration, powered held-out human study, and independent verification",
        "gate7_retirement": "two releases, 30-day soak, parity, expert workflows, rollback, final tags, and product-owner approval",
    }
    blockers = {name: blocker_text[name] for name, passed in promotion_checks.items() if not passed}
    promotable = implemented and all(promotion_checks.values())
    if not implemented or not promotion_checks["gate0_contract_lock"]:
        highest = None
    elif not promotion_checks["frozen_candidate_identity"] or not promotion_checks["gate1_keychain"]:
        highest = 0
    elif not promotion_checks["gate2_apple_imports"]:
        highest = 1
    elif not all(value for name, value in promotion_checks.items() if name.startswith("gate6_")):
        highest = 5
    elif not promotion_checks["gate7_retirement"]:
        highest = 6
    else:
        highest = 7
    return promotion_checks, promotable, highest, blockers


def promotion_self_test() -> dict[str, bool]:
    loaded = {
        "gate0": {"ok": True},
        "key_lifecycle": {"gate1_promotable": True},
        "apple_import": {"gate2_promotable": True},
        "notarization": {"gate6_promotable": True},
        "macos_artifact": {"gate6_promotable": True},
        "browser_artifact": {"gate6_promotable": True},
        "auxiliary_adapters": {"gate6_promotable": True},
        "lifecycle": {"gate6_promotable": True},
        "accessibility": {"gate6_promotable": True},
        "benchmark": {"gate6_promotable": True},
        "retirement": {"gate7_promotable": True},
    }
    _, promoted, highest, blockers = promotion_summary(loaded, True, True)
    all_evidence_promotes = promoted and highest == 7 and not blockers
    loaded["browser_artifact"]["gate6_promotable"] = False
    _, blocked, blocked_highest, blocked_reasons = promotion_summary(loaded, True, True)
    missing_gate6_stops_at_gate5 = (
        not blocked and blocked_highest == 5 and set(blocked_reasons) == {"gate6_browser_distribution"}
    )
    loaded["browser_artifact"]["gate6_promotable"] = True
    loaded["notarization"]["gate6_promotable"] = False
    _, notary_blocked, notary_highest, notary_reasons = promotion_summary(
        loaded, True, True,
    )
    missing_notary_stops_at_gate5 = (
        not notary_blocked
        and notary_highest == 5
        and set(notary_reasons) == {"gate6_notarization_batch"}
    )
    loaded["notarization"]["gate6_promotable"] = True
    loaded["auxiliary_adapters"]["gate6_promotable"] = False
    _, auxiliary_blocked, auxiliary_highest, auxiliary_reasons = promotion_summary(
        loaded, True, True,
    )
    missing_auxiliary_stops_at_gate5 = (
        not auxiliary_blocked
        and auxiliary_highest == 5
        and set(auxiliary_reasons) == {"gate6_auxiliary_adapter_distribution"}
    )
    _, local_failure, local_highest, _ = promotion_summary(loaded, False, True)
    local_failure_never_promotes = not local_failure and local_highest is None
    _, unbound, unbound_highest, unbound_reasons = promotion_summary(loaded, True, False)
    missing_candidate_stops_at_gate0 = (
        not unbound and unbound_highest == 0
        and "frozen_candidate_identity" in unbound_reasons
    )
    binding_loaded = {
        name: {"git_head": "head", "git_tree": "tree", "git_dirty": False}
        for name in EXPECTED
    }
    all_current_receipts_bind = all(
        receipt_binding_checks(binding_loaded, "head", "tree").values()
    )
    binding_loaded["benchmark"]["git_head"] = "stale"
    stale_receipt_rejected = not receipt_binding_checks(
        binding_loaded, "head", "tree",
    )["benchmark_current_clean_git_binding"]
    return {
        "all_evidence_promotes": all_evidence_promotes,
        "missing_gate6_stops_at_gate5": missing_gate6_stops_at_gate5,
        "missing_auxiliary_stops_at_gate5": missing_auxiliary_stops_at_gate5,
        "missing_notary_stops_at_gate5": missing_notary_stops_at_gate5,
        "local_failure_never_promotes": local_failure_never_promotes,
        "missing_candidate_stops_at_gate0": missing_candidate_stops_at_gate0,
        "all_current_receipts_bind": all_current_receipts_bind,
        "stale_receipt_rejected": stale_receipt_rejected,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--receipts", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_checks = promotion_self_test()
        print(json.dumps({"schema_version": "glassbox-program-readiness-self-test/v1", "ok": all(self_checks.values()), "checks": self_checks}, indent=2, sort_keys=True))
        return 0 if all(self_checks.values()) else 1
    if args.root is None or args.receipts is None or args.receipt is None:
        parser.error("--root, --receipts, and --receipt are required")
    root = args.root.resolve()
    receipt_dir = args.receipts.resolve()
    candidate_digest: str | None = None
    candidate_errors = ["candidate_manifest_required"]
    if args.candidate_manifest is not None:
        _, candidate_digest, candidate_errors = load_and_validate(
            root, args.candidate_manifest.resolve(),
        )
    loaded: dict[str, dict[str, object]] = {}
    refs: dict[str, dict[str, str]] = {}
    checks: dict[str, bool] = {}
    for name, schema in EXPECTED.items():
        path = receipt_dir / f"{name}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        loaded[name] = data
        checks[f"{name}_receipt_schema"] = data.get("schema_version") == schema
        if path.is_file():
            refs[name] = {"path": str(path), "sha256": sha256(path)}

    current_head = git(root, "rev-parse", "HEAD")
    current_tree = git(root, "rev-parse", "HEAD^{tree}")
    checks.update(receipt_binding_checks(loaded, current_head, current_tree))

    ordinary_ok = [
        "boundary", "storage", "lifecycle", "hostile_import", "privacy",
        "native_import", "mysteries", "browser_ipc", "live_source", "resource_sampler",
        "process_context", "observer_effect", "network_import", "passive_context",
        "accessibility", "performance", "egress",
    ]
    for name in ordinary_ok:
        checks[f"{name}_local_gate_passed"] = loaded[name].get("ok") is True
    checks["apple_import_readiness_or_promotion_state_valid"] = (
        loaded["apple_import"].get("ok") is True
        and isinstance(loaded["apple_import"].get("gate2_promotable"), bool)
        and loaded["apple_import"].get("logarchive_import_enabled")
        is loaded["apple_import"].get("gate2_promotable")
        and loaded["apple_import"].get("instruments_import_enabled")
        is loaded["apple_import"].get("gate2_promotable")
    )
    checks["key_lifecycle_readiness_or_promotion_state_valid"] = (
        loaded["key_lifecycle"].get("readiness_ok") is True
        and loaded["key_lifecycle"].get("signed_keychain_roundtrip_passed")
        is loaded["key_lifecycle"].get("gate1_promotable")
    )
    checks["macos_artifact_readiness_or_promotion_state_valid"] = (
        loaded["macos_artifact"].get("readiness_ok") is True
        and loaded["macos_artifact"].get("artifact_passed")
        is loaded["macos_artifact"].get("gate6_promotable")
        and loaded["macos_artifact"].get("ok")
        is loaded["macos_artifact"].get("artifact_passed")
    )
    checks["notarization_readiness_or_promotion_state_valid"] = (
        loaded["notarization"].get("readiness_ok") is True
        and loaded["notarization"].get("ok")
        is loaded["notarization"].get("gate6_promotable")
    )
    checks["browser_artifact_readiness_or_promotion_state_valid"] = (
        loaded["browser_artifact"].get("readiness_ok") is True
        and loaded["browser_artifact"].get("artifact_passed")
        is loaded["browser_artifact"].get("gate6_promotable")
        and loaded["browser_artifact"].get("ok")
        is loaded["browser_artifact"].get("artifact_passed")
    )
    checks["auxiliary_adapters_readiness_or_promotion_state_valid"] = (
        loaded["auxiliary_adapters"].get("readiness_ok") is True
        and loaded["auxiliary_adapters"].get("artifact_passed")
        is loaded["auxiliary_adapters"].get("gate6_promotable")
        and loaded["auxiliary_adapters"].get("ok")
        is loaded["auxiliary_adapters"].get("artifact_passed")
    )
    checks["benchmark_readiness_or_promotion_state_valid"] = (
        loaded["benchmark"].get("ok") is True
        and isinstance(loaded["benchmark"].get("benchmark_passed"), bool)
        and loaded["benchmark"].get("benchmark_passed")
        is loaded["benchmark"].get("gate6_promotable")
    )
    checks["retirement_readiness_or_promotion_state_valid"] = (
        (
            loaded["retirement"].get("readiness_ok") is True
            and loaded["retirement"].get("ok") is False
            and loaded["retirement"].get("gate7_promotable") is False
        )
        or (
            loaded["retirement"].get("ok") is True
            and loaded["retirement"].get("retirement_passed") is True
            and loaded["retirement"].get("gate7_promotable") is True
        )
    )
    checks["accessibility_readiness_or_promotion_state_valid"] = (
        loaded["accessibility"].get("readiness_ok") is True
        and loaded["accessibility"].get("manual_accessibility_passed")
        is loaded["accessibility"].get("gate6_promotable")
    )
    checks["lifecycle_promotion_state_is_boolean"] = isinstance(
        loaded["lifecycle"].get("gate6_promotable"), bool
    )
    gate0_errors = loaded["gate0"].get("errors", [])
    checks["gate0_authoritative_state_is_valid"] = (
        loaded["gate0"].get("ok") is True
        or (
            loaded["gate0"].get("ok") is False
            and isinstance(gate0_errors, list)
            and "authoritative mode requires a clean worktree and index" in gate0_errors
        )
    )
    implemented_lane_checks_ok = all(checks.values())
    candidate_lanes = {
        "key_lifecycle": "gate1_promotable",
        "apple_import": "gate2_promotable",
        "notarization": "gate6_promotable",
        "macos_artifact": "gate6_promotable",
        "browser_artifact": "gate6_promotable",
        "auxiliary_adapters": "gate6_promotable",
        "lifecycle": "gate6_promotable",
        "accessibility": "gate6_promotable",
        "benchmark": "gate6_promotable",
        "retirement": "gate7_promotable",
    }
    candidate_bound = not candidate_errors and all(
        loaded[name].get(flag) is not True
        or loaded[name].get("candidate_manifest_sha256") == candidate_digest
        for name, flag in candidate_lanes.items()
    )
    promotion_checks, program_promotable, highest_promotable_gate, external_blockers = promotion_summary(
        loaded, implemented_lane_checks_ok, candidate_bound
    )
    result = {
        "schema_version": "glassbox-program-readiness/v1",
        "ok": implemented_lane_checks_ok,
        "implemented_lane_checks_ok": implemented_lane_checks_ok,
        "program_promotable": program_promotable,
        "highest_promotable_gate": highest_promotable_gate,
        "git_head": current_head,
        "git_tree": current_tree,
        "git_dirty": bool(git(root, "status", "--porcelain")),
        "candidate_manifest_sha256": candidate_digest,
        "candidate_manifest_errors": candidate_errors,
        "checks": checks,
        "promotion_checks": promotion_checks,
        "receipt_refs": refs,
        "external_blockers": external_blockers,
        "errors": [name for name, passed in checks.items() if not passed],
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
