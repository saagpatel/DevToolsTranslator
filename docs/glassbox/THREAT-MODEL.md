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
| Malicious website | Discovers loopback token, impersonates extension, poisons evidence | Native Messaging; exact approved extension identity; foreground consent; one-use attachment credential | Hostile-page/wrong-origin/replay tests; revoke and rotate |
| Same-user local process | Reads temp data or impersonates IPC peer | Application Support permissions, Keychain keys, authenticated IPC, no URI secrets | Local-process attack test; credential invalidation and residue report |
| Hostile import | Archive bomb, traversal, malformed allocation, parser crash, stored HTML/script | Sandboxed/constrained streaming worker, quotas, path rules, no HTML execution | Fuzz/malicious corpus; quarantined failure; no published investigation |
| Supply-chain compromise | Parser/dependency executes or exfiltrates evidence | Locked dependencies, provenance/SBOM review, default-deny egress, isolated worker | Dependency audit, egress monitor, reproducible build review |
| Local backup or export recipient | Recovers sensitive retained data | Per-investigation encryption, short retention, explicit export preview, backup disclosure | Key deletion test; export seeded-secret test; residue disclosure |
| Corrupt or misleading source | Fabricates timestamps/IDs or omits records | Source trust and coverage fields; uncertainty intervals; no implicit authenticity | Conflicting-source fixture; downgrade to `unknown` |
| Unauthenticated/oversized OTLP producer | Poisons or exhausts a live session | Loopback-only broker, per-session credential, source epoch, byte/event/rate quotas | Wrong-token/replay/flood tests; disconnect and explicit gap receipt |
| Compromised instrumented app | Emits fabricated spans/logs under a plausible identity | Source trust vocabulary, authenticated attachment when available, immutable provenance, quotas | Conflicting-source fixtures; revoke source; never promote its claims |
| Local-network ARP poisoning | Mislabels passive neighbor/device context | Label passive ARP as untrusted logical context; never use it alone for identity or cause | Conflicting-neighbor fixture; disable adapter and preserve conflict |
| Reconnecting live source | Replays events or reuses native IDs after restart | Source epoch, replay/idempotency rules, sequence gaps, fresh attachment credential | Restart/replay corpus; explicit disconnect/gap records |
| Model or detector | Converts correlation into a factual causal claim | Model relations are `model_generated`; output always `inferred`; deterministic evidence grade gate | Adversarial claim fixtures; no grade-promotion property test |
| UI injection | Imported text executes or escapes rendering context | Text-only rendering, strict CSP, no remote content, validated deep links | Injection corpus and CSP/deep-link tests |
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

Raw/native data never flows directly into rendered HTML, telemetry, updater, crash upload, or remote model endpoints.

## Residual threats

- A compromised same-user account can access a running app and its unlocked keys.
- FileVault, Time Machine, user copies, screenshots, and recipient behavior are outside crypto-shred guarantees.
- Integrity hashes do not establish organizational signer authority.
- Imported remote clocks may remain unalignable.
- Authenticated transport proves the connected source identity, not the truth or completeness of its content.

These limits must be disclosed rather than described as solved.
