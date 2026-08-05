# Glassbox Permission Matrix

Status: accepted for Gate 0 review
Owner: product authority and privacy/security gatekeeper

| Tier | Capability | MVP | Consent/indicator | Revoke/stop | Retention/residue |
|---|---|---|---|---|---|
| 0 | User-selected HAR, PCAP/PCAPNG, OTLP, logarchive, Instruments, Glassbox bundle | Yes | File chooser and pre-import scope preview | Cancel import; delete app-owned derived copy only | Original remains untouched; derived data follows investigation policy |
| 1 | One selected Chrome DevTools tab | Separate zero-entitlement Browser Adapter, Rust Native Messaging host, and permission-minimal MV3 panel implemented; product promotion remains blocked on published extension identity, fresh-VM Chrome workflow, notarization, and manual accessibility proof | Explicit start in the visible DevTools panel bound to its inspected tab; exact extension-origin manifest; persistent panel status | Exact stop seals evidence; replay, malformed input, origin mismatch, or disconnect publishes no bundle; reset removes only the app-owned manifest | Private `0700` app inbox and `0600` atomic bundle; explicit non-overwriting export; headers, cookies, credentials, bodies, raw hosts/path/query values, and raw request IDs are absent; core remains offline and unchanged |
| 1 | App-owned OTel/log/signpost and manual markers | Native consent/endpoint/stop/export workflow, signed reference instrumented-source proof, and local independent-adapter lifecycle implemented; product use remains blocked on fresh-VM notarized proof and an independently instrumented third-party app | User-selected destination, explicit session start, visible framed-TCP endpoint and one-use credential, persistent capture indicator | Exact stop control, revoke credential, and record terminal gap | Separately distributed sandboxed SwiftUI controller plus entitlement-free Rust helper; kernel-validated bundle only through an inherited descriptor; poisoned input publishes zero bytes; no raw live payload residue |
| 1 | Bounded aggregate system sampler | Yes; 500 ms interval and 60-sample/30-second native cap | Visible start/stop and scope disclosure | Stop sampler independently; terminal observation records user stop or maximum | Samples exist only in the active investigation payload |
| 1 | Bounded selected-application process sampler | Separate native consent/export adapter and privacy gate implemented; product promotion remains blocked on fresh-VM, notarization, and manual accessibility/identity proof | Explicit selection from the transient visible-GUI-app list; disclosure names the selected app and retained CPU/memory/wakeup fields | Independent visible stop or cancel; controller EOF is cancellation and publishes zero bytes | Separately distributed, hardened, zero-entitlement SwiftUI controller plus zero-entitlement Rust helper; retains the controller-claimed bundle ID but no PID, path, arguments, user, environment, files, disk, or network activity; emitted bundle re-enters the offline core through ordinary import |
| 2 | Passive `/usr/sbin/arp -an` logical context | Separate native consent/export adapter and metadata-only evidence handoff implemented; product promotion remains blocked on fresh-VM, notarization, and manual accessibility proof | Visible one-shot disclosure plus an ephemeral capability sent only over an inherited descriptor; local-network description where required | Cancel or one-shot completion; capability and child process are discarded before another snapshot | App-Sandboxed SwiftUI controller has only user-selected-file access; entitlement-free Rust helper sends no packets; addresses, link-layer IDs, and interfaces never enter the bundle; only state, conflict, count, and explicit noncausal limitations persist |
| 3 | Live BPF/privileged helper | No | Separate future RFC | Not applicable | Must not exist in core residue |
| 4 | Network Extension, Endpoint Security, MITM, protected-input permissions, ARP spoofing | Rejected for core | New product decision required | Not applicable | Must not exist in core residue |

## Global rules

- Permission denial leaves unrelated workflows usable.
- No fallback silently broadens scope.
- Effective permissions, source coverage, capture state, privacy mode, and retention are visible in every investigation.
- Browser capture is exactly one selected tab; no automatic reattachment or browsing-history collection.
- `scripting` and `<all_urls>` are prohibited unless a separately accepted use case proves necessity.
- Stop records an explicit terminal coverage marker; revoke also invalidates credentials and clears pairing state.
- Aggregate resource samples are context only. They create no relation, causal assertion, process attribution, network attribution, or authenticated-source claim.
- Selected-application samples are also context only. The helper uses PID transiently to perform the requested sample, detects process identity reuse, never retains PID, and does not authenticate the controller-supplied bundle identifier. The separately distributed adapter is not embedded in or launched by the App-Sandboxed core.

## Test oracle

Every permission has allow, deny, revoke, restart, crash, stale-credential, and clean-uninstall cases. A fresh-VM residue report enumerates Application Support data, Keychain items, app-owned Native Messaging host state, caches, logs, and any user-controlled exports that Glassbox cannot delete. The user-installed Chrome extension is not silently removed; its credentials are revoked and manual removal is disclosed.
