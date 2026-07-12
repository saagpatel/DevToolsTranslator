# Gate 0 To Gate 1 Implementation Plan

Status: accepted; execution blocked until commit-bound Gate 0 promotion
Owner: Glassbox primary implementer

## First vertical slice

After Gate 0 passes, add only:

- `crates/glassbox-contracts`
- `crates/glassbox-kernel`
- `crates/glassbox-storage-sqlite`
- `crates/glassbox-import`
- `crates/glassbox-import-coordinator`
- `apps/glassbox-import-worker`
- `crates/glassbox-fixtures`

Before persistent schema work, run the ADR-007 encryption/App-Sandbox feasibility spike. Identity/time behavior may be proven in memory while that spike runs. The proof fixture contains two capture sessions with the same CDP native request ID, two overlapping clock domains, one source-asserted relation, one temporal candidate that must remain unordered, one duplicate retry, and one interrupted import.

## Required assertions

- Both native requests survive independently.
- Native observations have no update path.
- Retry is idempotent.
- Interrupted import publishes nothing.
- Forced coordinator crash before commit and during staged publication leaves no partial canonical investigation; retry is atomic and idempotent.
- Overlapping intervals do not produce `precedes` or causal language.
- Every relation resolves to addressable evidence.
- Export/re-import preserves semantic identity while changing materialization/lineage identity, or emits an explicit alias/loss record.
- Contracts/kernel have no dependency on DTT or UI crates.

## Verification sequence

1. Package-local format, clippy, and tests.
2. Migration interruption and property tests.
3. Dependency-direction and negative-requirements checks.
4. Full Cargo workspace format, clippy, test, and build.
5. pnpm gates only if TypeScript/generated projections change.

Package installation is not a verification step. Inspect existing dependency state and lockfiles first.

## Stop boundary

Do not connect browser capture, Tauri UI, packet parsing, resource sampling, or donor code until the vertical slice proves identity, time, immutability, idempotency, atomic publication, and the encryption/App-Sandbox feasibility spike passes. If full per-investigation SQLite/WAL encryption cannot meet ADR-007, stop before persistent schema implementation.
