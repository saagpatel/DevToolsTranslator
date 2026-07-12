# Glassbox Gate Oracle Registry

Status: accepted for Gate 0 review
Owner: primary implementer and independent verifier

An oracle listed as `planned` is an assigned later-gate deliverable, not evidence that the control currently passes. Gate promotion requires the named executable path, a demonstrated failing fixture, a passing production case, and a versioned receipt bound to the changed artifact or fixture corpus.

| Gate | Oracle | Planned executable path | Required receipt/result | Current state |
|---|---|---|---|---|
| 0 | Contract completeness and prohibited-source matcher | `scripts/glassbox/check_gate0.py` | `glassbox-gate0-receipt/v2`; provisional precommit plus authoritative clean-commit/tree binding | Implemented; self-test, independent review, and commit-bound pass receipt required before promotion |
| 1 | Package/dependency direction | `scripts/glassbox/check_boundaries.py` | `glassbox-boundary-receipt/v1` | Implemented; enforces separate SQLCipher runtime workspace and no DTT edges |
| 1 | Bundle and dependency closure against component dispositions | `scripts/glassbox/check_boundaries.py` | Receipt lists every linked/bundled component and rejects `excluded` or unclassified legacy code | Planned; blocks shell integration |
| 1 | Identity collision, semantic/materialization round trip, clock partial order | Rust tests in `glassbox-contracts` and `glassbox-kernel` | Cargo test evidence | Implemented; package and full inherited-workspace tests pass |
| 1 | Encryption/App Sandbox feasibility | `scripts/glassbox/verify_storage_sandbox_spike.sh` | `glassbox-storage-spike/v1` with candidate/license/WAL/crash/perf/signed-sandbox result | Implemented; passed locally on target arm64 Mac, exact clean-commit receipt required |
| 1 | Atomic migration/staging/crash recovery | Rust tests in `glassbox-storage-sqlite`, `glassbox-import-coordinator`, and worker integration tests | Forced process abort before commit proves no partial canonical publication; replay/collision/wrong-key tests | Storage/coordinator implemented; worker integration remains Gate 2 |
| 2 | Hostile import budgets/confinement | `scripts/glassbox/run_hostile_import_gate.sh` plus per-parser fuzz targets | `glassbox-hostile-import/v1` | Core worker and fixture-NDJSON corpus implemented; ZIP/HAR/OTLP/PCAP parsers remain disabled pending their corpora |
| 2 | Key lifecycle, plaintext residue, retention, crypto-shred | `scripts/glassbox/run_key_lifecycle_gate.sh` | `glassbox-key-lifecycle/v1` | Harness implemented; blocked until product authority supplies a matching Glassbox macOS provisioning profile |
| 2 | Seeded-secret/redaction/export derivation | `scripts/glassbox/run_privacy_gate.sh` | `glassbox-privacy-gate/v1` with zero leaks | Implemented; clean commit-bound receipt required for promotion |
| 3 | Five mystery families and epistemic restraint | `scripts/glassbox/run_mystery_acceptance.sh` | `glassbox-mystery-gate/v1` | Fixture/read-model oracle implemented; rendered UX verification remains |
| 3 | Keyboard, VoiceOver, zoom, reduced motion, tabular equivalence | `scripts/glassbox/run_accessibility_gate.sh` | `glassbox-accessibility/v1` | Planned |
| 4 | Native Messaging identity, frame, replay, revoke, lifecycle | `scripts/glassbox/run_browser_ipc_gate.sh` | `glassbox-browser-ipc/v1` | Planned |
| 4 | Live-source auth, quotas, epoch/replay/gaps | `scripts/glassbox/run_live_source_gate.sh` | `glassbox-live-source/v1` | Planned |
| 4 | Default-deny egress and injected blocked socket | `scripts/glassbox/run_egress_gate.sh` | `glassbox-egress/v1` | Planned |
| 4 | Observer effect | `scripts/glassbox/run_observer_effect_gate.sh` | `glassbox-observer-effect/v1` | Planned |
| 5 | PCAP fidelity, bounded streaming, opacity and no process attribution | `scripts/glassbox/run_network_import_gate.sh` | `glassbox-network-import/v1` | Planned |
| 6 | Million-event performance | `scripts/glassbox/run_performance_gate.sh` | `glassbox-performance/v1` | Planned |
| 6 | Signing, entitlements, Gatekeeper, notarization, staple | `scripts/glassbox/verify_macos_artifact.sh` | `glassbox-macos-artifact/v1`, bound to `.app` and DMG hashes | Planned |
| 6 | Install/update/downgrade/revoke/uninstall/residue | `scripts/glassbox/run_lifecycle_gate.sh` | `glassbox-lifecycle/v1` | Planned |
| 6 | Pilot, power analysis, preregistered human benchmark | `scripts/glassbox/validate_benchmark_results.py` | `glassbox-benchmark/v1` plus external study artifacts | Planned; external dependency |
| 7 | Donor parity/soak/rollback/approval | `scripts/glassbox/check_retirement_readiness.py` | `glassbox-retirement/v1` | Planned; explicit approval required |

## Failure policy

Missing executable, missing failing control fixture, missing receipt, unknown result, or stale artifact binding is `NO-GO`. A prose claim cannot substitute for an oracle result.
