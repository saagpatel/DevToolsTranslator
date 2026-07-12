# ADR-008: Hostile Import Security

Status: accepted for Gate 0 review
Owner: import owner and privacy/security gatekeeper

## Decision

All imports are hostile, including internally consistent or signed bundles. Format parsers run in a separate App-Sandboxed worker with no network entitlement, no canonical database or key access, and no migration/publication authority. The trusted host opens the selected source read-only and passes only a read-only handle. The worker emits bounded framed records or writes a capability-limited staging artifact; a trusted import coordinator validates it and asks storage to atomically publish. Cancellation, timeout, or crash publishes nothing.

Initial ceilings are: 4 GiB compressed input, 16 GiB expanded input, 100:1 compression ratio, 10,000 members, one container nesting level, 16 MiB source record, 10 million events, 1 MiB IPC frame, 768 MiB resident worker memory, 30-minute wall time, and a 30-second no-progress watchdog. Per-format policy may lower but not raise these values without an ADR revision. The host kills the worker on budget breach and records a quarantined loss/failure receipt.

Reject absolute/traversal paths, symlinks, devices, executable bits/content, duplicate or case-colliding names, recursive containers, invalid lengths, unsupported major schemas, and manifest/file disagreement. Imported strings render as text only.

## Rejected

UI-process parsing, `read_to_end` for unbounded members, extraction before validation, silent partial import, or treating a signature as parser safety.

## Oracle

Fuzzing and malicious corpora cover ZIP bombs, traversal, malformed HAR/OTLP/PCAP, large strings, duplicate entries, oversized IPC frames, cancellation, forced crash, timeout, and restart. Peak resources remain within the declared budget and no partial investigation becomes visible.
