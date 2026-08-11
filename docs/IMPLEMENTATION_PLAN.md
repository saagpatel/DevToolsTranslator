# Implementation Plan v1.0 (Doc Pack + Scaffold First)

> Note on sequence alignment (2026-02-22): active delivery track follows the
> phase order used in execution runs, where Phase 6 is MV3 capture + desktop
> pairing transport. This document keeps historical numbering for reference.
>
> Hardening closeout status is tracked in `~/Projects/DevToolsTranslator/docs/PHASE9_HARDENING_REPORT.md`.
>
> Phase 10 operationalization evidence is tracked in `~/Projects/DevToolsTranslator/docs/PHASE10_RELEASE_REPORT.md`.
>
> Phase 11 multi-platform + reliability/perf evidence is tracked in `~/Projects/DevToolsTranslator/docs/PHASE11_IMPLEMENTATION_REPORT.md`.
>
> Phase 12 staged public prerelease + OTLP-optional telemetry + endurance evidence is tracked in `~/Projects/DevToolsTranslator/docs/PHASE12_RELEASE_PROMOTION_REPORT.md`.

## Scope
This plan defines phased delivery order and acceptance criteria for implementing DevTools Translator from scaffold to deterministic release gates.

## Phase 0: Repo Scaffold + Contracts
### Goals
- Create repo structure and docs pack.
- Add workspace manifests and config placeholders.
- No runtime implementation logic.

### Acceptance criteria
- Required docs exist and are populated.
- Required scaffold folders/files exist.
- `.codex/verify.commands` exists with canonical command list.

### Commands target
- `pnpm -v`
- `cargo --version`

## Phase 1: Shared Schemas + Deterministic IDs
### Goals
- Freeze JSON schema/type contracts for envelopes, findings graph, and EvidenceRef.
- Implement canonicalization and deterministic ID policies.

### Acceptance criteria
- Shared contracts compile in TS and Rust.
- Deterministic IDs tested with fixture replay.

### Commands target
- `pnpm -r lint`
- `pnpm -r typecheck`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`

## Phase 2: Extension Capture Pipeline (Metadata-Only Baseline)
### Goals
- Implement attach/detach capture lifecycle.
- Stream envelope events to desktop WS endpoint.
- Enforce buffer caps and capture-drop markers.

### Acceptance criteria
- Extension can pair and stream with token auth.
- Metadata-only mode enforced end-to-end.

### Commands target
- `pnpm --filter @dtt/extension lint`
- `pnpm --filter @dtt/extension test`
- `pnpm --filter @dtt/extension build`

## Phase 3: Desktop Ingest + SQLite Persistence
### Goals
- Implement ws ingestion service and append-only raw persistence.
- Build normalization into required network/console/page tables.
- Add migration runner with checksum validation.

### Acceptance criteria
- Session ingest succeeds with deterministic event sequencing.
- Required tables and indexes are present and queryable.

### Commands target
- `cargo test -p dtt-desktop-core`
- `cargo test -p dtt-storage`
- `cargo build -p dtt-desktop-core`

## Phase 4: Interaction Correlation + Detector Engine
### Goals
- Implement deterministic interaction assignment per locked constants and priorities.
- Implement top-20 detector set.
- Persist findings/claims/evidence refs.

### Acceptance criteria
- Correlation outputs are deterministic on fixture replay.
- Detector outputs match locked catalogs and claim templates.

### Commands target
- `cargo test -p dtt-detectors`
- `cargo test -p dtt-correlation`
- `cargo test --workspace`

## Phase 5: Desktop UI + Evidence Deep-Linking
### Goals
- Implement global nav and session subviews.
- Implement finding detail and evidence click deep-links.
- Implement loading/empty/error/disabled/focus-visible states.

### Acceptance criteria
- Evidence click deep-links and highlights exact field/pointer when available.
- Export flow and warnings match UX spec.

### Commands target
- `pnpm --filter @dtt/desktop-ui test`
- `pnpm --filter @dtt/desktop-ui build`

## Phase 6: Export Bundle + Integrity Chain
### Goals
- Implement deterministic zip exporter.
- Emit manifest/index/report/integrity artifacts.
- Enforce share-safe default and full-export gating.

### Acceptance criteria
- Export evidence resolution works via manifest + indexes.
- Integrity validation passes on deterministic fixture runs.

### Commands target
- `cargo test -p dtt-export`
- `cargo test -p dtt-integrity`

## Phase 7: End-to-End Regression + Release Gate
### Goals
- Run full fixture suite with determinism/evidence/integrity checks.
- Enforce required Rust + TS verification gates.

### Acceptance criteria
- All required gates pass (`fail` and `not-run` are blocking).
- Fixtures produce stable byte-identical analysis/export artifacts.

### Commands target
- `pnpm -r test`
- `pnpm -r build`
- `cargo test --workspace`
- `cargo build --workspace`

## Manual Smoke Checklist
1. Pair extension to desktop.
2. Start and stop capture.
3. Inspect session timeline/network/console.
4. Open finding, click evidence, verify deep-link highlight.
5. Run share-safe export; verify no secrets or blobs.
6. Run full export with non-metadata privacy mode; verify blob gating and warnings.

## Gap Register
- GAP: Canonical JSON algorithm is not explicitly named in the lock.
- SAFE DEFAULT: RFC8785 JCS canonicalization.
- IMPACT: Hash mismatches across Rust/TS if different canonicalizers are used.
- VERIFICATION: Add cross-language fixture hash conformance tests.

- GAP: Deterministic ID tuple fields are not explicitly fixed in lock.
- SAFE DEFAULT: finding/claim/evidence tuple hashing from canonical signatures + rank.
- IMPACT: Potential ID drift on replay.
- VERIFICATION: Determinism replay test for every golden fixture.

- GAP: Secret redaction taxonomy beyond auth/cookie/token is partially underspecified.
- SAFE DEFAULT: Redact case-insensitive keys matching `authorization`, `cookie`, `set-cookie`, `token`, `api-key`, `x-api-key`, `proxy-authorization`.
- IMPACT: Over-redaction or under-redaction edge cases.
- VERIFICATION: Header redaction fixture corpus and export assertion tests.

- GAP: Blob storage location policy (DB vs disk) not fully specified.
- SAFE DEFAULT: Blob bytes on disk, metadata/pointers in DB.
- IMPACT: Migration complexity if strategy changes.
- VERIFICATION: Export/import pointer integrity and blob hash parity tests.
