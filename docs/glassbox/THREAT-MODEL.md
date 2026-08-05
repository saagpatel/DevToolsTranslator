# Glassbox Threat Model

Status: accepted for Gate 0 review
Owner: privacy/security gatekeeper

## Protected assets

- Native evidence, normalized observations, relations, claims, annotations, and exports.
- Credentials, cookies, tokens, URLs, queries, path identifiers, hostnames, DNS names, packet bytes, process identity, logs, traces, and user actions.
- IPC attachment credentials, Keychain wrapping keys, signing identities, redaction keys, and retention state.
- The meaning and provenance of evidence, not only its bytes.

## Trust boundaries and abuse cases

| Threat actor/input | Abuse case | Preventive control | Detection and recovery oracle |
|---|---|---|---|
| Malicious website or spoofed browser source | Impersonates the extension, poisons selected-tab evidence, replays frames, or smuggles secrets through request metadata | Separate Native Messaging adapter; public-key-derived exact extension origin; visible DevTools panel; nativeMessaging-only permission; one-use challenge; short credential; monotonic sequence; strict payload; structural URL redaction; private atomic inbox; `signed_untrusted` source label | Wrong-origin/replay/unknown/disconnect zero-bundle controls; seeded-secret scan; exact extension manifest/permission check; signed host workflow; offline core re-import; fresh Chrome proof remains required |
| Same-user local process | Reads temp data or impersonates IPC peer | Application Support permissions, Keychain keys, authenticated IPC, no URI secrets | Local-process attack test; credential invalidation and residue report |
| Hostile import | Archive bomb, traversal, malformed allocation, parser crash, stored HTML/script | Sandboxed/constrained streaming worker, quotas, path rules, no HTML execution | Fuzz/malicious corpus; quarantined failure; no published investigation |
| Supply-chain compromise | Parser/dependency executes or exfiltrates evidence | Locked dependencies, provenance/SBOM review, default-deny egress, isolated worker | Dependency audit, egress monitor, reproducible build review |
| Local backup or export recipient | Recovers sensitive retained data | Per-investigation encryption, short retention, explicit export preview, backup disclosure | Key deletion test; export seeded-secret test; residue disclosure |
| Corrupt or misleading source | Fabricates timestamps/IDs or omits records | Source trust and coverage fields; uncertainty intervals; no implicit authenticity | Conflicting-source fixture; downgrade to `unknown` |
| Unauthenticated/oversized/malformed OTLP producer | Poisons, exhausts, terminates, or partially publishes a live session | Loopback-only broker, per-session credential, source epoch, immutable absolute plus narrower session quotas, bounded rejected peers, pre-auth rejection without session mutation, poisoned projection after any invalid frame, kernel validation before inherited-descriptor publication | Wrong-peer-then-valid, replay, absolute-quota, flood, fragmented-frame, explicit-stop, disconnect, gap, invalid-payload zero-byte publication, digest, raw-content exclusion, and native re-import tests |
| OTLP adapter installation or removal | Silently expands core entitlements, leaves credentials, deletes user exports, or permits downgrade | Separately signed two-executable native adapter, exact controller entitlement allowlist, entitlement-free Rust helper, core executable inventory, user-only state, explicit credential revocation, owned-state-only uninstall | Signed native controller workflow plus local install/update/downgrade/revoke/uninstall/residue oracle; fresh-VM notarized proof remains required |
| Compromised instrumented app | Emits fabricated spans/logs under a plausible identity | Source trust vocabulary, authenticated attachment when available, immutable provenance, quotas | Conflicting-source fixtures; revoke source; never promote its claims |
| Local-network ARP poisoning, sensitive neighbor identifiers, or covert active probing | Mislabels passive context, persists local addresses/link IDs/interfaces, or widens collection | Separate App-Sandboxed native adapter; fixed `/usr/sbin/arp -an`; no network/privileged entitlements; inherited-descriptor one-shot consent; label output unknown-trust logical context; preserve conflicts; strip identifiers; retain only state/count/limitations; never use it alone for identity or cause | Signed sandbox runtime, active-scan rejection, conflicting-neighbor fixture, consent-secret exclusion, raw-identifier exclusion, atomic bundle, malformed zero-byte publication, signed-controller workflow, and core-kernel re-import |
| Reconnecting live source | Replays events or reuses native IDs after restart | Source epoch, replay/idempotency rules, sequence gaps, fresh attachment credential | Restart/replay corpus; explicit disconnect/gap records |
| Resource sampler | Runs indefinitely, exposes process/user data, or turns overlap into cause | Aggregate system allowlist, ordinary APIs, hard interval/sample bounds, visible stop, no relations, source-declared trust | Bounds/stop/terminal negative tests, signed native render, entitlement and egress gates |
| Selected-application process adapter | Core sandbox is weakened; PID is reused; controller mislabels a process; sensitive identity/activity leaks; disconnect silently publishes partial evidence | Separate distribution; zero entitlements; explicit transient GUI-app selection; UUID/start-time reuse check; absolute time/sample bounds; inherited-descriptor consent; PID/path/arguments/user/environment/file/disk/network exclusion; controller bundle-ID claim labeled unauthenticated; EOF cancellation; no relations or causal attribution | Signed positive runtime; signed sandbox denial with zero bytes; stop/disconnect/invalid/consent negative controls; seeded-secret and retained-field scan; core re-import; install/update/downgrade/uninstall/residue oracle |
| Model or detector | Converts correlation into a factual causal claim | Model relations are `model_generated`; output always `inferred`; deterministic evidence grade gate | Adversarial claim fixtures; no grade-promotion property test |
| UI injection | Imported text becomes executable content or escapes its presentation context | Native SwiftUI `Text`/`Table` rendering, no WebKit or remote content, validated deep links | Injection corpus, native-runtime linkage scan, signed imported-workspace interaction gate, and deep-link tests |
| Release pipeline | Claims signing/notarization without actual platform proof | Direct codesign, entitlement, Gatekeeper, notarization, and staple verification | Artifact-bound command receipts; promotion blocks on unknown |

## Data-flow boundary

```text
selected source or file
        -> constrained source/import worker
        -> quarantined immutable native evidence
        -> validated normalized observation
        -> versioned relation and claim derivation
        -> local investigation UI
        -> explicitly reviewed derived export
```

Raw/native data never flows into executable UI content, telemetry, updater, crash upload, or remote model endpoints.

## Residual threats

- A compromised same-user account can access a running app and its unlocked keys.
- FileVault, Time Machine, user copies, screenshots, and recipient behavior are outside crypto-shred guarantees.
- Integrity hashes do not establish organizational signer authority.
- Imported remote clocks may remain unalignable.
- Authenticated transport proves the connected source identity, not the truth or completeness of its content.

These limits must be disclosed rather than described as solved.
