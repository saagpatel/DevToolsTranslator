# ADR-014: Apple Logarchive And Instruments Adapters

Status: Apple-log projection and native adapter implemented; raw-source promotion gates remain open
Owner: native import owner and privacy/security gatekeeper

## Decision

Glassbox does not reverse-engineer or directly parse Apple's private `.logarchive` or Instruments `.trace` containers in Rust. Raw Apple containers are opened only by supported Apple tooling in a separately launched, App-Sandboxed process. The Rust evidence kernel remains the sole semantic validation and publication authority.

For `.logarchive`, the existing SwiftUI/AppKit executable has a non-UI child mode using Apple's public [`OSLogStore`](https://developer.apple.com/documentation/oslog/oslogstore). Reusing the existing binary preserves the two-executable distribution boundary. The parent passes the selected archive as an already-open directory handle on standard input, never as a command-line path or URI. A trusted, bounded tree walker rejects links and non-regular files and produces a content-and-relative-path-bound source SHA-256. The child has the same App-Sandbox-only entitlement as the UI and no storage, key, network, migration, or publication dependency.

The native child streams `glassbox-apple-log-projection/v1`: one header, ordered metadata-only entries, and one mandatory terminal count/digest. It retains timestamp, entry kind, log level, numeric process/thread/activity IDs, and numeric signpost ID/type. It never reads into the protocol composed message, process name, subsystem, category, sender image, source path, or signpost name. The Rust hostile worker validates the complete projection and rematerializes observations. Only its final `End` permits the coordinator to publish atomically.

Completed projections also enter the ordinary offline native bridge through the explicit `apple-log-projection` format. That bridge reuses the hostile worker, complete-stream assembler, evidence kernel, and Unknown/no-relation investigation projection used by other supported imports. This closes the post-projection kernel path without enabling raw `.logarchive` selection or weakening the raw-corpus promotion gate.

For Instruments, Glassbox uses Apple's supported [`xctrace`](https://developer.apple.com/documentation/xcode/xcode-command-line-tool-reference) export surface rather than container internals. It is an optional developer-tool adapter, not a bundled dependency. The source is first copied into a bounded, link-free, app-owned staging directory with an opaque name. Invocation uses the resolved Xcode tool path directly, fixed arguments, no shell, a hard timeout, bounded stdout/stderr, cancellation, and residue cleanup. Network traces may convert to HAR and then enter the existing hostile HAR parser. Other trace tables require explicit schema-specific projection contracts; generic XML passthrough is prohibited.

## Promotion gates

Raw `.logarchive` import remains disabled until a reviewed valid archive corpus proves: source-hash stability, security-scoped file-handle inheritance, signed App Sandbox execution, bounded memory/time, message-string exclusion, complete projection, cancellation, and coordinator atomicity.

Instruments import remains disabled until a reviewed valid `.trace` corpus proves: Xcode discovery and version capture, noninteractive conversion within timeout, supported-table allowlisting, bounded staging and cleanup, privacy projection, complete-stream atomicity, and explicit unavailable behavior on machines without a compatible Xcode. A hung or permission-blocked `xctrace` invocation is `UNAVAILABLE`, never success and never an unbounded wait.

The strict promotion executor is `scripts/glassbox/apple_import_promotion.py`. It accepts raw corpora only as local directory paths supplied to the gate, computes the same bounded content-and-relative-path tree identities, verifies a CMS-signed independent review against an explicitly supplied reviewer CA, and passes only directory handles to the signed child modes. It runs log projection twice for determinism, validates the metadata-only shape, converts the Instruments trace to bounded HAR, re-imports both outputs through the offline Rust bridge/kernel, requires Unknown with zero relations, scans for source-path leakage, and records hashes rather than paths. All four external inputs are atomic: partial configuration fails before promotion.

## Rejected

- General ZIP/archive extraction for either format.
- Rust parsing of private Apple container internals.
- Passing user paths in arguments, environment variables, logs, diagnostics, or receipts.
- Importing arbitrary `xctrace` XML, messages, symbols, backtraces, process names, image paths, HTTP headers, or bodies.
- Treating Xcode installation, a successful help command, or an Instruments GUI open as proof that trace conversion works.

## Oracle

`scripts/glassbox/run_apple_import_readiness_gate.sh` verifies hostile projection parsing, metadata-only retention, terminal digest/count enforcement, malformed and incomplete-stream rejection, coordinator atomicity, native adapter boundary structure, and explicit unavailable behavior. Raw-container promotion remains governed by the corpus, signed-runtime, bounded-resource, cancellation, staging-cleanup, and compatible-Xcode requirements above.
