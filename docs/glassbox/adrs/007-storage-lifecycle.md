# ADR-007: Storage, Key Lifecycle, Retention, And Deletion

Status: accepted for Gate 0 review
Owner: storage owner and privacy/security gatekeeper

## Decision

App-owned data lives under macOS Application Support with `0700` directories and `0600` files, never shared temp locations. Each investigation has its own directory, encrypted SQLite database, WAL/journal boundary, native blobs, indexes, staging area, and random 256-bit data-encryption key. The investigation key is wrapped by a Keychain-held application wrapping key.

The global catalog is a separate app-key-encrypted store containing only opaque investigation ID, lifecycle state, schema version, created/expiry time, and key reference. It contains no title, source name, URL, hostname, process, claim, or evidence-derived field. Deleted investigations leave at most an opaque tombstone and deletion time. Cross-investigation comparison opens each authorized investigation store read-only through its own key; it does not denormalize evidence into the catalog.

Encryption covers native evidence, normalized database and WAL/journal, blobs, indexes, staging/temp files, derived caches, and diagnostics that contain evidence. Plain application-layer encryption of selected rows is rejected because it would leave SQLite metadata/index/WAL leakage unspecified.

Before any persistent Glassbox schema is implemented, Gate 1 must select and prove a full-database mechanism such as SQLCipher or an encrypted VFS/container. The spike records license/distribution implications, WAL/temp behavior, crash recovery, key-loss behavior, target-Mac performance, and App Sandbox compatibility. If no candidate covers the entire per-investigation boundary, persistent storage work stops and the storage backend decision is reopened; the identity/time kernel may remain in memory.

The wrapping key is non-synchronizing, app-specific, versioned, and stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Investigation keys are rewrapped atomically during wrapping-key rotation and zeroized from process memory on a best-effort basis after use. No key appears in logs, dumps, diagnostics, or exports.

## Defaults

- Unsaved/ephemeral investigation: delete on explicit close or within 24 hours.
- Saved metadata investigation: seven days.
- Raw/full-content material: 24 hours unless deliberately extended with an explicit expiry.
- `full` mode is non-sticky and per investigation.

Original user-selected files are read-only and never deleted. On app-owned deletion, destroy the investigation key before best-effort file cleanup. The UI calls this crypto-shred, not guaranteed physical erasure. Time Machine, user exports, screenshots, recipient copies, and third-party backups are disclosed limits.

## Oracle

Tests cover restart, sleep/wake expiry, key loss, wrong key, WAL/temp recovery, crash during write, retention extension, crypto-shred, uninstall preserve/delete choices, and residue inventory.

## Rollback

An encrypted bundle export is not yet defined as a recovery path. Until a separate recipient-key/password wrapping ADR is accepted, exports follow ADR-009 and a lost wrapping key makes retained investigations intentionally unrecoverable. This is disclosed and accepted.
