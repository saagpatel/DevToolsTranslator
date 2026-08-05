# ADR-006: Data Classification

Status: accepted for Gate 0 review
Owner: privacy/security gatekeeper

## Decision

Apply the following mandatory classes to every source field and derived value.

## Classes

1. `public`: product-owned schemas, adapter versions, generic protocol labels.
2. `metadata_sensitive`: timestamps, sizes, status, trace/span identifiers, generalized process/service identity, query key names.
3. `content_sensitive`: URLs, paths, hostnames, DNS names, headers, logs, trace attributes, packet payloads, command lines, user content.
4. `credential`: authorization data, cookies, session identifiers, keys, tokens, secrets, certificate material.
5. `quarantined_native`: unvalidated or full-fidelity source material not eligible for normal rendering/export.

Every field, blob, native locator, diagnostic projection, and export field has a class. Unknown fields and schemas are `quarantined_native`; they do not inherit a permissive default.

## Processing rules

- Metadata mode uses per-source allowlists.
- Credential data never enters normal observations, logs, previews, telemetry, or shareable exports.
- Content-sensitive data requires explicit investigation scope, encryption, short retention, and export review.
- Low-entropy identifiers use keyed HMAC pseudonyms scoped to investigation or export.
- OTel baggage is dropped by default.
- Apple unified-log projection retains only timestamp, entry kind, level, numeric process/thread/activity identifiers, and numeric signpost identifier/type. Those identifiers are `metadata_sensitive` except public enum labels. Composed messages, process names, subsystem, category, sender image, source path, and signpost names never enter the Rust worker protocol.

## Oracle

A generated inventory proves complete classification. Unknown-schema and seeded-secret fixtures fail closed. A schema addition without classification fails CI.
