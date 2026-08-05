# ADR-001: Isolated Glassbox Kernel Boundary

Status: accepted; amended at Gate 0 for native macOS shell
Owner: kernel owner

## Decision

Use the DTT repository only as the inherited source scaffold, but create an isolated Glassbox kernel, database, and native macOS shell. The shipping presentation boundary is a multi-file SwiftUI/AppKit executable in `apps/glassbox-macos`; it invokes the Rust evidence boundary through the bundled, signed `apps/glassbox-native-bridge` helper. The helper returns one bounded, versioned JSON projection and never moves evidence authority into Swift. The first package boundaries are:

- `crates/glassbox-contracts`
- `crates/glassbox-kernel`
- `crates/glassbox-storage-sqlite`
- `crates/glassbox-import`
- `crates/glassbox-import-coordinator`
- `apps/glassbox-import-worker`
- `crates/glassbox-fixtures`
- `apps/glassbox-native-bridge`
- `apps/glassbox-macos`

Later adapters and bundle packages may depend on these APIs. Contracts and kernel never depend on `dtt-core`, `dtt-storage`, DTT detectors/correlation, SwiftUI/AppKit, Tauri, React, or donor repositories. The Swift shell validates schema version, bounded row count, identity uniqueness, timeline/table equivalence, explicit gaps, zero unmarked drops, and the kernel receipt before rendering; invalid or unavailable helper output fails closed.

The encrypted storage and trusted coordinator build in the separate `glassbox-runtime/Cargo.toml` workspace. This is a hard dependency-isolation boundary: Cargo unions dependency features when multiple packages are built together, so putting SQLCipher's `rusqlite` feature in the inherited DTT workspace would silently replace the SQLite build used by DTT. The runtime workspace may consume Glassbox contracts/kernel/import as path dependencies but contains no DTT package. The hostile worker remains outside this workspace and can never link storage or coordinator code.

## Dependency direction

`contracts <- kernel <- storage implementation`; `contracts <- import`. The constrained worker depends only on contracts/import and emits bounded framed staging records or a capability-limited staging artifact. `glassbox-import-coordinator` depends on contracts, kernel, and storage; it validates worker records and invokes storage publication, and the worker can never depend on it. Repository port traits live in the kernel. Fixtures are dev/test-only.

The worker has no canonical database path, migration authority, application or investigation key, retention authority, or publication transaction capability.

## Rejected

- Extending DTT's global browser-centric normalized tables.
- Making `dtt-core` a mixed Glassbox/DTT contract.
- A TypeScript-authored second source of truth.
- A Tauri/WKWebView shipping shell or a network client/server boundary between the UI and kernel.

## Oracle

A dependency-graph check enforces the direction. The first vertical slice proves identity collision, clock overlap, idempotent retry, interrupted import rollback, immutable native observations, and addressable relations without invoking browser, WebKit, Tauri, packet, or donor code. Native shell tests additionally prove fail-closed causal-language and gap-accounting rules. Persistent schema work is blocked on ADR-007's encryption feasibility spike; identity/time rules may first run in memory.

## Abort and rollback

If the isolated packages cannot compile and test without DTT core/storage dependencies, stop Gate 1 and evaluate a new Glassbox repository. Remove the unlanded packages; the legacy DTT product remains unchanged.
