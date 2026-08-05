# Project Glassbox Gate 0

Status: contract lock in progress
Owner: product authority and Glassbox primary implementer
Implementation branch: `codex/glassbox-evidence-kernel`

Glassbox is a local-first macOS investigation workbench. It explains how evidence from explicitly selected sources relates across user action, app runtime, system resources, requests, DNS, traces, and packets. It preserves missing evidence and uncertainty instead of turning temporal proximity into causation.

This directory is the normative Gate 0 contract. Existing DevTools Translator documentation remains accurate for the legacy DTT product but is not the Glassbox data contract.

## Gate 0 exit criteria

- Every decision in `GATE-0-DECISION-REGISTER.md` is accepted with an owner, test oracle, failure behavior, rollback, and revisit trigger.
- The supported source envelope and prohibited capabilities are machine-checkable.
- Identity, time, provenance, storage, import, redaction, schema evolution, IPC, egress, distribution, benchmark, and retirement contracts have no unresolved P0.
- An independent contract and security review returns `GO` or only explicitly accepted lower-severity follow-ups.
- No Gate 1 crate or UI feature begins before this gate passes.

## Normative invariants

1. Native evidence is append-only and source-faithful; normalized and UI projections are rebuildable.
2. Hashes prove internal consistency, not signer authority or authenticity.
3. Temporal adjacency never proves causation.
4. `observed`, `correlated`, `inferred`, and `unknown` are separate from coverage and data quality.
5. Model output is always `inferred`; it cannot mutate evidence or promote grades.
6. Unknown schema, clock, provenance, permission, truncation, encryption, or redaction state fails closed.
7. Every source can be disabled without disabling unrelated investigations.
8. Original user-selected files remain read-only.
9. No source silently broadens permission, privacy mode, retention, or egress.
10. Privileged capability requires a separate future RFC and fresh product/security approval.

## Artifact index

- `PRODUCT-CONTRACT.md`
- `NON-GOALS.md`
- `THREAT-MODEL.md`
- `PERMISSION-MATRIX.md`
- `DONOR-ALLOWLIST.md`
- `NEGATIVE-REQUIREMENTS-CI.md`
- `GATE-ORACLE-REGISTRY.md`
- `BENCHMARK-PROTOCOL.md`
- `RETIREMENT-PROTOCOL.md`
- `GATE-0-DECISION-REGISTER.md`
- `adrs/001-kernel-boundary.md` through `adrs/015-otlp-adapter-distribution.md`
