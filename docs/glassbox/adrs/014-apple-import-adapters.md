# ADR-014: Apple Logarchive And Instruments Adapters

Status: Apple-log projection and separate Instruments adapter implemented; raw-source promotion gates remain open
Owner: native import owner and privacy/security gatekeeper

## Decision

Glassbox does not reverse-engineer or directly parse Apple's private `.logarchive` or Instruments `.trace` containers in Rust. Apple containers are opened only by supported Apple tooling. The App-Sandboxed core handles `.logarchive` through public `OSLogStore`; a separately distributed, entitlement-free developer-tool adapter handles `.trace` through `xctrace`. The Rust evidence kernel remains the sole semantic validation and publication authority.

For `.logarchive`, the existing SwiftUI/AppKit executable has a non-UI child mode using Apple's public [`OSLogStore`](https://developer.apple.com/documentation/oslog/oslogstore). Reusing the existing binary preserves the two-executable core distribution boundary. The trusted parent validates and copies the user-selected, link-free archive into a private app-container staging directory, then passes the staged archive as an already-open directory handle on standard input, never as a command-line path or URI. The child performs a second descriptor-relative, bounded, no-follow copy before opening the archive. The original and staged trees must match the same content-and-relative-path SHA-256. The child has the same App-Sandbox-only entitlement as the UI and no storage, key, network, migration, or publication dependency.

The native child streams `glassbox-apple-log-projection/v1`: one header, ordered metadata-only entries, and one mandatory terminal count/digest. It retains timestamp, entry kind, log level, numeric process/thread/activity IDs, and numeric signpost ID/type. It never reads into the protocol composed message, process name, subsystem, category, sender image, source path, or signpost name. The Rust hostile worker validates the complete projection and rematerializes observations. Only its final `End` permits the coordinator to publish atomically.

Completed projections also enter the ordinary offline native bridge through the explicit `apple-log-projection` format. That bridge reuses the hostile worker, complete-stream assembler, evidence kernel, and Unknown/no-relation investigation projection used by other supported imports. This closes the post-projection kernel path without enabling raw `.logarchive` selection or weakening the raw-corpus promotion gate.

For Instruments, Glassbox uses Apple's supported [`xctrace`](https://developer.apple.com/documentation/xcode/xcode-command-line-tool-reference) export surface rather than container internals. App Sandbox correctly prevents the core from discovering or executing Xcode tools, so `Glassbox Instruments Adapter` is a separately versioned, separately signed, entitlement-free app and is never embedded in or launched by the core. The user selects one `.trace` package in that adapter and separately chooses a new HAR destination. The adapter copies the trace descriptor-relatively into bounded, link-free, private staging with an opaque name; in governed promotion it independently requires the staged tree to match the reviewed content-and-relative-path SHA-256. It then resolves the Xcode tool path, invokes fixed arguments without a shell, requires the external-format output-directory contract, enforces a hard timeout and one bounded regular HAR result, and removes app-owned staging. The HAR enters the core through explicit offline file selection and the existing hostile HAR parser. The parser permits only the reviewed Apple extension keys and drops headers, bodies, cookies, host, path, query values, and server addresses. Other trace tables require explicit schema-specific projection contracts; generic XML passthrough is prohibited.

## Promotion gates

Raw `.logarchive` import remains disabled until a reviewed valid archive corpus proves: source-hash stability, security-scoped file-handle inheritance, signed App Sandbox execution, bounded memory/time, message-string exclusion, complete projection, cancellation, and coordinator atomicity.

Instruments import remains disabled until a reviewed valid `.trace` corpus proves: Xcode discovery and version capture, noninteractive conversion within timeout, supported-table allowlisting, bounded staging and cleanup, privacy projection, complete-stream atomicity, and explicit unavailable behavior on machines without a compatible Xcode. A hung or permission-blocked `xctrace` invocation is `UNAVAILABLE`, never success and never an unbounded wait.

The strict promotion executor is `scripts/glassbox/apple_import_promotion.py`. It accepts raw corpora only as local directory paths supplied to the gate, computes bounded content-and-relative-path tree identities, verifies a CMS-signed independent review against an explicitly supplied reviewer CA, stages the logarchive into the core container, and passes only directory handles to the signed core child and separate Instruments adapter. It runs log projection twice for determinism, validates the metadata-only shape, converts the Instruments trace to bounded HAR, re-imports both outputs through the offline Rust bridge/kernel, requires Unknown with zero relations, scans for source-path leakage, and records hashes rather than paths. All external inputs are atomic: partial configuration fails before promotion.

## Rejected

- General ZIP/archive extraction for either format.
- Rust parsing of private Apple container internals.
- Passing user paths in arguments, environment variables, logs, diagnostics, or receipts.
- Embedding an unsandboxed `xctrace` launcher in the core or granting the core a temporary Xcode-path exception.
- Importing arbitrary `xctrace` XML, messages, symbols, backtraces, process names, image paths, HTTP headers, or bodies.
- Treating Xcode installation, a successful help command, or an Instruments GUI open as proof that trace conversion works.

## Oracle

`scripts/glassbox/run_apple_import_readiness_gate.sh` verifies hostile projection parsing, metadata-only retention, terminal digest/count enforcement, malformed and incomplete-stream rejection, coordinator atomicity, native adapter boundary structure, and explicit unavailable behavior. Raw-container promotion remains governed by the corpus, signed-runtime, bounded-resource, cancellation, staging-cleanup, and compatible-Xcode requirements above.
