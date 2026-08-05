# Negative Requirements CI Specification

Status: accepted for Gate 0 review
Owner: release owner and privacy/security gatekeeper

Gate 0's deterministic contract/source scanner is `scripts/glassbox/check_gate0.py`; CI runs it and its embedded failing self-test. It emits `glassbox-gate0-receipt/v2`. A `--precommit` receipt is explicitly provisional and may describe dirty or untracked draft files. Only an authoritative run from a clean commit, hashing required artifacts from `HEAD` and recording its tree ID, can promote the gate. Later gates extend the same fail-closed posture with executable IPC, import, key, redaction, egress, distribution, and uninstall suites at the paths named by their implementation plans.

The native supported-file workflow is additionally bound by `scripts/glassbox/run_native_import_workflow_gate.sh`. It must reject a source-digest mismatch without stdout, exclude seeded secrets and selected paths, prove the exact two-entitlement app allowlist and entitlement-free helper, and complete the signed imported-workspace interaction set. A source-level Import button or a direct helper parse is not sufficient evidence for the end-to-end workflow.

## Required failing conditions

Release and merge verification must inspect source, dependency graph, generated bundles, scripts, plists, entitlements, privacy manifest, and installed residue. Fail on:

- `SMAppService`, LaunchDaemon/Agent, privileged helper locations, `sudo`, root installer, or root post-install behavior.
- `/dev/bpf`, BPF chmod/chown mutation, ARP spoof, IP forwarding, packet tunnel, content filter, DNS proxy, Endpoint Security, certificate, or proxy installer.
- Accessibility, Input Monitoring, Screen Recording, Apple Events, Full Disk Access, microphone, or global-input permission strings/entitlements.
- Unapproved `scripting`, `<all_urls>`, background tab enumeration, remote UI content, or permissive CSP.
- Evidence egress outside declared loopback/local IPC and explicit user-reviewed export.
- Secrets in URI, diagnostics, logs, screenshots, support bundles, crash data, or update telemetry.
- Glassbox contracts/kernel depending on `dtt-core`, `dtt-storage`, SwiftUI/AppKit, Tauri, React, or donor repositories; or the shipping shell linking WebKit/Tauri.

## Platform artifact proof

Do not infer signing or notarization from a SHA or configuration flag. Before Gate 6 promotion, `scripts/glassbox/verify_macos_artifact.sh`, `scripts/glassbox/verify_browser_artifact.sh`, and `scripts/glassbox/verify_auxiliary_adapters.py` must bind versioned receipts to every final core and separately distributed adapter `.app`, helper, DMG, and extension ZIP hash and parse failures from:

- `codesign --verify --strict --deep`
- `codesign -d --entitlements :-`
- `spctl -a -vv`
- `stapler validate`
- Expected signing identity/team ID and a reviewed entitlement diff
- Fresh install, update, downgrade, revoke, uninstall, and residue checks

Unknown or unavailable evidence blocks promotion; it does not become `verified`.

## Failure and rollback

Remove the capability/dependency, rebuild from a clean checkout, and regenerate the complete artifact and residue evidence. Waivers require a new product RFC and are not accepted inside the Glassbox core branch.
