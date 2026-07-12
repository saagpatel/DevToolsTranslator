# ADR-010: Schema Evolution, Migrations, And Compatibility

Status: accepted for Gate 0 review
Owner: kernel and storage owners

## Decision

Glassbox contracts and bundles use semantic major/minor versions. Unsupported major versions are rejected without mutation. Additive minor fields are tolerated and preserved where possible. Meaning changes require a new major or a new versioned field.

Migration SQL, migration receipt, prior-version/checksum validation, and compatibility metadata update occur in one transaction. Native source artifacts remain immutable and recoverable if projection migration fails. Derived tables and indexes are disposable and rebuildable.

Readers and writers maintain N and N-1 compatibility fixtures. Export/re-import either preserves semantic identity or emits an explicit loss record. No best-effort silent downgrade is permitted.

## Oracle

Upgrade, downgrade/read-only, interrupted migration, checksum mismatch, duplicate replay, unknown minor, unknown major, corrupt receipt, projection rebuild, and native-evidence recovery fixtures run in CI.

## Rollback

Rollback opens the prior compatible database read-only or rebuilds projections from immutable native evidence. Destructive down-migrations are not the recovery mechanism.
