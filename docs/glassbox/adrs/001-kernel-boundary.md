# ADR-001: Isolated Glassbox Kernel Boundary

Status: accepted for Gate 0 review
Owner: kernel owner

## Decision

Use the DTT repository and Tauri/React shell as the implementation scaffold, but create an isolated Glassbox kernel and database. The first package boundaries are:

- `crates/glassbox-contracts`
- `crates/glassbox-kernel`
- `crates/glassbox-storage-sqlite`
- `crates/glassbox-import`
- `crates/glassbox-import-coordinator`
- `apps/glassbox-import-worker`
- `crates/glassbox-fixtures`

Later adapters and bundle packages may depend on these APIs. Contracts and kernel never depend on `dtt-core`, `dtt-storage`, DTT detectors/correlation, Tauri, React, or donor repositories.

The encrypted storage and trusted coordinator build in the separate `glassbox-runtime/Cargo.toml` workspace. This is a hard dependency-isolation boundary: Cargo unions dependency features when multiple packages are built together, so putting SQLCipher's `rusqlite` feature in the inherited DTT workspace would silently replace the SQLite build used by DTT. The runtime workspace may consume Glassbox contracts/kernel/import as path dependencies but contains no DTT package. The hostile worker remains outside this workspace and can never link storage or coordinator code.

## Dependency direction

`contracts <- kernel <- storage implementation`; `contracts <- import`. The constrained worker depends only on contracts/import and emits bounded framed staging records or a capability-limited staging artifact. `glassbox-import-coordinator` depends on contracts, kernel, and storage; it validates worker records and invokes storage publication, and the worker can never depend on it. Repository port traits live in the kernel. Fixtures are dev/test-only.

The worker has no canonical database path, migration authority, application or investigation key, retention authority, or publication transaction capability.

## Rejected

- Extending DTT's global browser-centric normalized tables.
- Making `dtt-core` a mixed Glassbox/DTT contract.
- A TypeScript-authored second source of truth.

## Oracle

A dependency-graph check enforces the direction. The first vertical slice proves identity collision, clock overlap, idempotent retry, interrupted import rollback, immutable native observations, and addressable relations without invoking browser, Tauri, packet, or donor code. Persistent schema work is blocked on ADR-007's encryption feasibility spike; identity/time rules may first run in memory.

## Abort and rollback

If the isolated packages cannot compile and test without DTT core/storage dependencies, stop Gate 1 and evaluate a new Glassbox repository. Remove the unlanded packages; the legacy DTT product remains unchanged.
