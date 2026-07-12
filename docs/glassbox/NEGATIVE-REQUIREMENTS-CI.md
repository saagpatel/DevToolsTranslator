# Negative Requirements CI Specification

Status: accepted for Gate 0 review
Owner: release owner and privacy/security gatekeeper

Gate 0's deterministic contract/source scanner is `scripts/glassbox/check_gate0.py`; CI runs it and its embedded failing self-test. It emits `glassbox-gate0-receipt/v2`. A `--precommit` receipt is explicitly provisional and may describe dirty or untracked draft files. Only an authoritative run from a clean commit, hashing required artifacts from `HEAD` and recording its tree ID, can promote the gate. Later gates extend the same fail-closed posture with executable IPC, import, key, redaction, egress, distribution, and uninstall suites at the paths named by their implementation plans.

## Required failing conditions

Release and merge verification must inspect source, dependency graph, generated bundles, scripts, plists, entitlements, privacy manifest, and installed residue. Fail on:

- `SMAppService`, LaunchDaemon/Agent, privileged helper locations, `sudo`, root installer, or root post-install behavior.
- `/dev/bpf`, BPF chmod/chown mutation, ARP spoof, IP forwarding, packet tunnel, content filter, DNS proxy, Endpoint Security, certificate, or proxy installer.
- Accessibility, Input Monitoring, Screen Recording, Apple Events, Full Disk Access, microphone, or global-input permission strings/entitlements.
- Unapproved `scripting`, `<all_urls>`, background tab enumeration, remote UI content, or permissive CSP.
- Evidence egress outside declared loopback/local IPC and explicit user-reviewed export.
- Secrets in URI, diagnostics, logs, screenshots, support bundles, crash data, or update telemetry.
- Glassbox contracts/kernel depending on `dtt-core`, `dtt-storage`, Tauri, React, or donor repositories.

## Platform artifact proof

Do not infer signing or notarization from a SHA or configuration flag. Before Gate 6 promotion, `scripts/glassbox/verify_macos_artifact.sh` must bind a versioned receipt to the final `.app` and DMG hashes and parse failures from:

- `codesign --verify --strict --deep`
- `codesign -d --entitlements :-`
- `spctl -a -vv`
- `stapler validate`
- Expected signing identity/team ID and a reviewed entitlement diff
- Fresh install, update, downgrade, revoke, uninstall, and residue checks

Unknown or unavailable evidence blocks promotion; it does not become `verified`.

## Failure and rollback

Remove the capability/dependency, rebuild from a clean checkout, and regenerate the complete artifact and residue evidence. Waivers require a new product RFC and are not accepted inside the Glassbox core branch.
