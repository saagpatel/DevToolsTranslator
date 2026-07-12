# Gate 0 Decision Register

Status: decisions accepted; commit-bound promotion pending
Decision date: 2026-07-12
Product authority: user
Primary implementer: Codex

The end-to-end goal and hardened blueprint authorize the decisions below. A change to any accepted row requires an updated ADR, evidence, and product-authority approval when it expands product intent, permissions, egress, publication, or retirement authority.

| ID | Decision | Status | Evidence/test oracle | Failure behavior | Revisit trigger |
|---|---|---|---|---|---|
| G0-01 | Selected-source investigation workbench, not universal Mac observability | Accepted | Product contract mapping and five mysteries | Unsupported chain becomes `unknown` | New ordinary source with independently proven coverage |
| G0-02 | DTT is scaffold; isolated Rust Glassbox kernel and per-investigation database | Accepted | Dependency graph, encryption feasibility, and first vertical slice | Stop Gate 1; consider new repo/backend | Kernel cannot remain independent or storage cannot meet ADR-007 |
| G0-03 | Stable semantic IDs are separate from materialization/lineage IDs | Accepted | Collision and round-trip corpus | Quarantine conflicting collision | Canonicalization version change |
| G0-04 | Uncertainty intervals and partial order govern cross-source time | Accepted | Clock overlap/drift/reset fixtures | No ordering or causal language | New source supplies stronger addressable ordering |
| G0-05 | Separate observation/relation/claim/coverage model; no generic confidence | Accepted | Property and mystery tests | Downgrade to `unknown` | Calibrated detector-specific model proposed |
| G0-06 | Chrome Native Messaging is the target browser IPC | Accepted | Hostile-origin/replay/revoke suite | Browser source disabled | Native Messaging feasibility fails with documented evidence |
| G0-07 | One fully encrypted DB boundary per investigation plus minimal encrypted catalog and Keychain-wrapped key | Accepted | Pre-schema encryption/App-Sandbox spike plus key/restart/WAL/residue tests | Stop persistent schema work | No candidate covers WAL/temp, crash, license, and performance requirements |
| G0-08 | Retention defaults: ephemeral <=24h, saved metadata 7d, raw/full <=24h | Accepted | Restart/sleep/expiry tests | Expired app-owned key destroyed | User explicitly changes a specific investigation expiry |
| G0-09 | Hostile imports use a no-network constrained worker with no canonical DB/key authority; trusted coordinator publishes | Accepted | Malicious/fuzz/crash/capability corpus | No investigation published | Format requires a separately reviewed parser boundary |
| G0-10 | Metadata redaction allowlists and unknown-schema quarantine | Accepted | Zero-leak seeded-secret suite | Import/capture fails closed | Versioned source schema receives classification review |
| G0-11 | MVP export authenticity state is `unsigned_local`; integrity is not authority | Accepted | Manifest/integrity/derivation tests | UI blocks authenticity claim | Separate device/user signing ADR approved |
| G0-12 | Developer ID distribution with App Sandbox/no-network core as the required egress mechanism | Accepted | sandbox feasibility plus codesign/Gatekeeper/notarization/entitlement evidence | Stop and request new product decision; promotion blocked | Mac App Store or unsandboxed core becomes an explicit product proposal |
| G0-13 | PCAP import plus optional passive `arp -a` logical context; no live capture | Accepted | Permission matrix and source fidelity tests | Disable passive adapter independently | Benchmark proves privileged capture is necessary; new RFC required |
| G0-14 | Offline sandboxed core/import worker; network only in narrow signed brokers; no updater through Gate 6 or remote model | Accepted | Entitlement/dependency gate, blocked-socket negative test, egress monitor | Release blocked | Separate broker/updater/model product decision |
| G0-15 | Human formal benchmark is an external completion dependency | Accepted | Pilot, power analysis, preregistration, human results | Goal remains externally blocked, never fabricated | Product authority changes completion criteria explicitly |
| G0-16 | Donor retirement requires two releases, 30-day soak, parity, rollback, approval | Accepted | Retirement protocol evidence | Donor remains supported | Explicit product-authority exception with risk record |
| G0-17 | Privileged capabilities are outside the roadmap, not a later phase | Accepted | Negative-requirements scan and residue report | Build/release blocked | Separate future RFC and fresh approval |

## Gate 0 review result

Gate 0 becomes `GO` only when:

1. All normative files pass formatting/link/static checks.
2. An independent contract reviewer and security reviewer confirm the accepted decisions close their P0 findings.
3. Any remaining P1/P2 item is assigned to a later gate with an executable oracle and cannot invalidate the kernel contract.
4. The worktree and exact commit are recorded.

Until then Gate 1 remains blocked.
