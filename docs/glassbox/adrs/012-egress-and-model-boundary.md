# ADR-012: Offline Egress And Model Boundary

Status: accepted for Gate 0 review
Owner: privacy/security gatekeeper

## Decision

Core investigation and import workflows are offline-only. The core app and hostile import worker use App Sandbox without network client/server entitlements. They contain no general HTTP client dependency or socket-opening adapter. Source-specific networking lives in separately signed, least-privilege broker processes with a narrow framed IPC contract; each broker has a distinct capability, allowed protocol/address, data contract, disable switch, and audit receipt.

The Native Messaging host communicates only over Chrome stdin/stdout and authenticated local XPC with the signed app. The loopback OTLP broker, when implemented, can bind only `127.0.0.1`/`::1`, requires a per-session attachment credential, enforces rate/byte/event limits, and has no outbound network entitlement. Passive local-network context is a separately consented broker and cannot publish active-scan commands.

No updater is included or required through Gates 1-6. A future updater must be a separately signed, independently disableable evidence-blind process, disabled by default or enabled through an explicit visible policy. Its requests contain no evidence-derived fields or stable investigation identifiers; failure never blocks local operation.

No evidence field, URL, hostname, process identity, trace, packet, log, model prompt, or derived claim enters analytics, telemetry, crash reporting, updater traffic, or a remote model.

A future remote-model feature requires a new product decision, compile-time feature boundary, per-operation consent, exact field preview, redaction, provider/retention disclosure, and a fresh derived bundle. Output remains `model_generated` and `inferred`.

## Oracle

Artifact checks verify the core/import-worker entitlement and dependency denylist. A negative test injects a deliberate socket/fetch attempt and proves the sandbox blocks it. An OS/proxy/network-syscall monitor additionally proves fixture, import, browse, compare, and export workflows make zero outbound connections. Broker loopback/local-network paths are separately counted and disclosed. Any unexpected connection fails closed and blocks release.

## Rollback

Disable or remove the offending component. No core workflow may depend on an updater, telemetry client, crash uploader, or model endpoint.
