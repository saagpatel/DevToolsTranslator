# ADR-007: Storage, Key Lifecycle, Retention, And Deletion

Status: accepted; SQLCipher Community Edition selected by Gate 1 target-Mac spike
Owner: storage owner and privacy/security gatekeeper

## Decision

App-owned data lives under macOS Application Support with `0700` directories and `0600` files, never shared temp locations. Each investigation has its own directory, encrypted SQLite database, WAL/journal boundary, native blobs, indexes, staging area, and random 256-bit data-encryption key. The investigation key is wrapped by a Keychain-held application wrapping key.

The global catalog is a separate app-key-encrypted store containing only opaque investigation ID, lifecycle state, schema version, created/expiry time, and key reference. It contains no title, source name, URL, hostname, process, claim, or evidence-derived field. Deleted investigations leave at most an opaque tombstone and deletion time. Cross-investigation comparison opens each authorized investigation store read-only through its own key; it does not denormalize evidence into the catalog.

Encryption covers native evidence, normalized database and WAL/journal, blobs, indexes, staging/temp files, derived caches, and diagnostics that contain evidence. Plain application-layer encryption of selected rows is rejected because it would leave SQLite metadata/index/WAL leakage unspecified.

Gate 1 selected SQLCipher Community Edition through `rusqlite`'s `bundled-sqlcipher-vendored-openssl` feature. Every production build must retain compile-time `SQLITE_TEMP_STORE=2`, runtime `PRAGMA temp_store=MEMORY`, WAL encryption, `secure_delete`, and the no-plaintext residue gate. The selected distribution must reproduce the SQLCipher BSD-style notice and copyright, SQLite notice, and OpenSSL Apache-2.0 notice in a user-accessible licenses surface. A change of SQLCipher edition, crypto provider, `rusqlite` feature, temp-store policy, or SQLite/SQLCipher major version reopens the spike.

Canonical observation JSON is stored once. The materialization table stores semantic foreign key, materialization ID, lineage ID, and a versioned compact marker; it does not duplicate the full encrypted observation payload. Readers remain compatible with legacy schema-v2 rows that contain the earlier full payload and validate their semantic and materialization identities before use. Writes use cached prepared statements, `synchronous=FULL`, atomic batches of at most 1,000 observations, a bounded 64 MiB page cache, and a 256 MiB WAL auto-checkpoint threshold. These settings reduce encrypted checkpoint churn without weakening commit durability or allowing unbounded in-memory batches. Changing the marker version, cache bound, checkpoint policy, durability mode, or batch ceiling requires migration/idempotency/collision tests and the exact million-event oracle.

The target-Mac spike records license/distribution implications, encrypted database/WAL behavior, compile-time memory-only temporary storage, crash recovery, missing/wrong-key behavior, performance, file modes, and Developer-ID-signed App Sandbox enforcement. If a future candidate or build fails any result, persistent storage work stops and the storage backend decision is reopened; the identity/time kernel may remain in memory.

The wrapping key is non-synchronizing, app-specific, versioned, and stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Investigation keys are rewrapped atomically during wrapping-key rotation and zeroized from process memory on a best-effort basis after use. No key appears in logs, dumps, diagnostics, or exports.

## Defaults

- Unsaved/ephemeral investigation: delete on explicit close or within 24 hours.
- Saved metadata investigation: seven days.
- Raw/full-content material: 24 hours unless deliberately extended with an explicit expiry.
- `full` mode is non-sticky and per investigation.

Original user-selected files are read-only and never deleted. On app-owned deletion, destroy the investigation key before best-effort file cleanup. The UI calls this crypto-shred, not guaranteed physical erasure. Time Machine, user exports, screenshots, recipient copies, and third-party backups are disclosed limits.

## Oracle

Tests cover restart, sleep/wake expiry, key loss, wrong key, WAL/temp recovery, crash during write, retention extension, crypto-shred, uninstall preserve/delete choices, and residue inventory.

The selection oracle is `scripts/glassbox/verify_storage_sandbox_spike.sh`. Its authoritative receipt is `glassbox-storage-spike/v1`; `ok` requires both the technical probe and a Developer-ID-signed App Sandbox run, including a denied write outside the container.

## Rollback

An encrypted bundle export is not yet defined as a recovery path. Until a separate recipient-key/password wrapping ADR is accepted, exports follow ADR-009 and a lost wrapping key makes retained investigations intentionally unrecoverable. This is disclosed and accepted.
