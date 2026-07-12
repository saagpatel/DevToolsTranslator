# ADR-002: Evidence Identity And Namespacing

Status: accepted for Gate 0 review
Owner: kernel owner

## Decision

Glassbox separates stable semantic evidence identity from storage/export materialization identity.

- `SemanticObservationId` is deterministic from a versioned namespace, preserved source identity, capture session/source epoch, native locator, redirect/connection epoch where relevant, and canonicalization version. It does not include bundle or database identity.
- `MaterializationId` identifies one database row, staged record, bundle member, or derived export representation.
- `LineageId` links materializations and transformations back to semantic observations and source artifacts.

Native identifiers are preserved as locators and are never assumed globally unique.

Required identity components include:

- Observation: preserved source identity, capture session, native locator, source epoch, canonicalization version.
- Browser request: target/session, CDP request ID, redirect index.
- Process: host boot identity, PID, process birth time.
- Connection: interface, protocol, five-tuple, connection epoch.
- DNS: resolver, transport, question, native transaction identity when present, bounded time.
- Trace/span: source resource identity, trace ID, span ID.
- Packet: capture source, interface, packet ordinal, byte range.

## Collision behavior

A semantic-ID collision with identical canonical content is an idempotent duplicate or an additional lineage/materialization reference. A collision with different content is a hard integrity error placed in quarantine. It never overwrites, merges, or moves an existing observation.

Lossless export/re-import preserves the semantic ID and source descriptor while creating new materialization and lineage IDs. Redaction or transformation preserves the semantic ID only when the semantic fields and locator remain equivalent; otherwise it creates an explicit alias mapping or identity-loss record.

## Rejected

Raw CDP IDs, PIDs, five-tuples, DNS transaction IDs, span IDs, timestamps, or hashes without namespace/version as primary identity.

## Oracle

Fixtures reuse the same native IDs across sources, sessions, redirects, process lifetimes, interfaces, and schema versions. Every record survives independently; retries are idempotent; conflicting collisions publish nothing; lossless round trips preserve semantic identity while changing materialization identity.
