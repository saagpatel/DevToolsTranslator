# ADR-009: Redaction, Pseudonyms, Export Integrity, And Authenticity

Status: accepted for Gate 0 review
Owner: privacy/security gatekeeper and export owner

## Decision

Metadata mode is allowlist-based. URLs are parsed structurally: user-info and fragments are removed; query key names may remain; query values and sensitive path segments are redacted by default. Unknown fields or schema versions enter quarantine rather than pass through.

Pseudonyms use an HMAC key scoped to the investigation or derived export. `full` mode is non-sticky, explicitly warned, encrypted, and short-lived.

A redacted or otherwise derived export receives a new manifest, integrity tree, derivation record, redaction-policy version, and source-bundle hash. It never reuses the source integrity claim.

MVP exports provide deterministic internal integrity and explicitly report authenticity as `unsigned_local`. Device/user signing is deferred to a separate ADR after core bundle semantics pass; the UI never calls a hash a signature or organizational authority.

## Oracle

Seeded secrets cover URLs, paths, queries, headers, bodies, logs, spans, resources, baggage, DNS, packets, unknown fields, diagnostics, and malformed inputs. Required result: zero leaked seeded secrets and a complete field-level preview.
