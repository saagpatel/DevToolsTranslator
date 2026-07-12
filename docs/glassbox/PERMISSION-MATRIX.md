# Glassbox Permission Matrix

Status: accepted for Gate 0 review
Owner: product authority and privacy/security gatekeeper

| Tier | Capability | MVP | Consent/indicator | Revoke/stop | Retention/residue |
|---|---|---|---|---|---|
| 0 | User-selected HAR, PCAP/PCAPNG, OTLP, logarchive, Instruments, Glassbox bundle | Yes | File chooser and pre-import scope preview | Cancel import; delete app-owned derived copy only | Original remains untouched; derived data follows investigation policy |
| 1 | One selected Chrome tab | Yes after IPC gate | Foreground gesture plus persistent browser/app indicator | Detach on stop, close, restart, revoke, timeout | Clear attachment credential; no background history |
| 1 | App-owned OTel/log/signpost and manual markers | Yes | Explicit endpoint/session start | Close endpoint and record stop/gap marker | Session policy applies |
| 1 | Bounded process/system sampler | Yes after feasibility proof | Visible session scope and interval | Stop sampler independently | Samples expire with investigation |
| 2 | Passive `arp -a` logical context | Optional | Explicit enable; local-network description where required | Stop independently | Logical snapshot only; no active scanning |
| 3 | Live BPF/privileged helper | No | Separate future RFC | Not applicable | Must not exist in core residue |
| 4 | Network Extension, Endpoint Security, MITM, protected-input permissions, ARP spoofing | Rejected for core | New product decision required | Not applicable | Must not exist in core residue |

## Global rules

- Permission denial leaves unrelated workflows usable.
- No fallback silently broadens scope.
- Effective permissions, source coverage, capture state, privacy mode, and retention are visible in every investigation.
- Browser capture is exactly one selected tab; no automatic reattachment or browsing-history collection.
- `scripting` and `<all_urls>` are prohibited unless a separately accepted use case proves necessity.
- Stop records an explicit terminal coverage marker; revoke also invalidates credentials and clears pairing state.

## Test oracle

Every permission has allow, deny, revoke, restart, crash, stale-credential, and clean-uninstall cases. A fresh-VM residue report enumerates Application Support data, Keychain items, app-owned Native Messaging host state, caches, logs, and any user-controlled exports that Glassbox cannot delete. The user-installed Chrome extension is not silently removed; its credentials are revoked and manual removal is disclosed.
