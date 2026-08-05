# ADR-015: Separate OTLP Adapter Distribution

Status: accepted; local lifecycle and evidence handoff implemented, external product workflow gates open
Owner: source-adapter owner and release/security gatekeeper

## Decision

The loopback OTLP receiver is not nested in, launched from, or entitled through the Glassbox core app. It is a separately versioned and separately signed native adapter containing exactly two executables: a SwiftUI/AppKit controller and the Rust `glassbox-otlp-broker` helper. The controller's entitlement allowlist is exactly App Sandbox, `com.apple.security.network.server`, and user-selected read/write access for the explicit `.glassbox` destination. It has no network-client, automation, device, personal-information, or privileged entitlement. The helper is separately signed with Hardened Runtime and no entitlements; as a child process it inherits the controller's sandbox rather than widening it.

After visible consent and a user-selected destination, the controller creates the output descriptor, generates a one-use credential, launches the helper, and displays the framed-TCP loopback endpoint and credential for the instrumented source. The helper accepts one bounded configuration line and loopback-only framed OTLP trace traffic. A per-session credential, source epoch, sequence checks, absolute ceilings, narrower session quotas, hostile-peer limits, watchdog, and exact stop control govern each session. Valid frames are projected without raw span names, attributes, credentials, or unknown content. Any invalid frame poisons the projection. Publication occurs only after complete projection and evidence-kernel validation, to the inherited descriptor, with a completion receipt binding byte count and SHA-256. Invalid sessions publish zero bundle bytes.

The handoff artifact is the portable `GLSBX001` Evidence Bundle. The core app receives no live socket, credential, or adapter IPC capability; it imports the completed user-selected bundle through its existing read-only native import path and Rust evidence kernel. This preserves the core bundle's exact two-executable inventory and network-free sandbox.

The adapter is independently installable, updateable, revocable, and removable. Downgrades fail closed. Revocation removes the session credential without deleting completed evidence exports. Uninstall removes only adapter-owned state and preserves user-owned `.glassbox` exports. No LaunchAgent, LaunchDaemon, privileged helper, system extension, certificate, proxy, or privileged residue is permitted.

Local lifecycle evidence is not release evidence. Product enablement remains blocked until the exact notarized/stapled adapter passes fresh-VM install/update/downgrade/revoke/uninstall, a visible consent and endpoint-disclosure workflow, explicit stop, real instrumented-app capture, user-selected core import, and sustained observer-load studies.

## Oracle

`scripts/glassbox/run_otlp_adapter_lifecycle_gate.sh` emits `glassbox-otlp-adapter-lifecycle/v1` and is composed into `glassbox-live-source/v1`. It verifies signing, Hardened Runtime, exact entitlements, executable inventory, installed watchdog behavior, state permissions, update, downgrade rejection, revocation, uninstall, export preservation, residue, unchanged core bytes, and the core's exact two-executable inventory. It also builds a signed, sandboxed, client-only reference instrumented source; supplies its session configuration only over stdin; exercises the Swift controller and Rust helper; re-imports the exact emitted bundle through the signed core Rust bridge; and binds a `glassbox-reference-instrumented-workflow/v1` receipt proving loopback-only transmission, credential exclusion, raw-content exclusion, atomic kernel publication, and core re-import. This reference is an integration oracle, not independent third-party product evidence.
