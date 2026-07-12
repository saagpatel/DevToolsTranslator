# Gate 1 Storage And App Sandbox Spike

Status: candidate selected; exact clean-commit receipt pending
Owner: storage owner and privacy/security gatekeeper
Date: 2026-07-12

## Decision

Select SQLCipher Community Edition through `rusqlite` 0.40's `bundled-sqlcipher-vendored-openssl` feature for the per-investigation encrypted SQLite boundary. This selection is conditional on preserving every build/runtime control in ADR-007 and rerunning the oracle when the crypto/database build changes.

The spike is deliberately isolated from the main Cargo workspace. Cargo feature unification would otherwise cause the inherited DTT `rusqlite` dependency to link SQLCipher too, violating the component boundary and changing the donor scaffold's storage implementation.

## Proven on the target Mac

The executable oracle demonstrated:

- SQLCipher 4.14.0 Community Edition loaded through the intended Rust feature.
- `TEMP_STORE=2` was present in compile options and runtime temp storage was forced to memory.
- Database, WAL, and SHM files contained none of the seeded plaintext.
- Correct-key reopen recovered all 10,000 rows.
- Wrong-key and missing-key reads failed.
- An aborted process with an uncommitted transaction published zero rows and `integrity_check` returned `ok`.
- Investigation directory and database modes were `0700` and `0600`.
- The 10,000-row transaction completed well below the provisional ten-second ceiling.
- A Developer-ID-signed, Hardened Runtime `.app` carrying only the App Sandbox entitlement ran the full probe successfully.
- The sandboxed process was denied a write to the user's real home directory outside its container.

## License and distribution

SQLCipher Community Edition is available under a BSD-style license for open or closed source software with user-accessible attribution. The shipped licenses surface must include the complete SQLCipher notice and copyright plus applicable SQLite and OpenSSL notices. This is a release-blocking artifact check, not a documentation suggestion.

Primary references:

- [SQLCipher Community Edition](https://www.zetetic.net/sqlcipher/community/)
- [SQLCipher design and transient-file requirements](https://www.zetetic.net/sqlcipher/design/)
- [rusqlite SQLCipher build features](https://github.com/rusqlite/rusqlite)
- [Apple App Sandbox file-access model](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox)
- [Apple Developer ID distribution](https://developer.apple.com/support/developer-id/)

## Reopen triggers

Reopen this decision on any crypto provider, SQLCipher edition, `rusqlite` feature, SQLite/SQLCipher major version, temp-store compile option, WAL mode, signing identity class, sandbox entitlement, or target-architecture change. A failure blocks persistent schema migration; it does not authorize plaintext fallback.
