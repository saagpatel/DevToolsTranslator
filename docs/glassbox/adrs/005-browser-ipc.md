# ADR-005: Browser IPC And Attachment Trust

Status: accepted for Gate 0 review
Owner: browser-adapter owner and privacy/security gatekeeper

## Decision

Chrome Native Messaging is the MVP target because it binds the extension to an installed native host manifest and avoids unauthenticated browser-accessible loopback discovery. The manifest uses one versioned host name, an absolute path to the signed host inside the separately distributed Glassbox Browser Adapter, and `allowed_origins` containing exactly the public-key-derived production extension ID. Development IDs/manifests are separate artifacts and cannot ship in production. The host and adapter never enter the App-Sandboxed two-executable core bundle.

The user-scoped host manifest is app-owned, mode `0600`, installed only after explicit setup, and removed by reset/uninstall. Chrome communicates with the hardened, zero-entitlement Rust host only over Native Messaging stdin/stdout. There is no loopback server, local socket, XPC path, or direct live connection into the core. Message frames have a 1 MiB maximum and bind protocol version, extension ID, browser attachment ID, selected tab ID, request ID, and session nonce. A one-use HMAC challenge, short-lived credential, monotonic sequence, explicit stop, and hard observation/session limits fail closed. Because a same-user local process can invoke an executable and spoof an origin argument outside Chrome's manifest enforcement, browser observations remain `signed_untrusted`; only an explicit panel marker is `user_asserted`.

The MV3 extension is a visible DevTools panel with only `nativeMessaging` permission. It has no host permissions, content scripts, background worker, `scripting`, or tab-wide API. The panel is bound by Chrome to the inspected tab, shows the persistent capture disclosure, observes navigation and completed request metadata, and provides explicit manual-marker and stop controls. The host structurally redacts URLs, pseudonymizes request keys per session, drops headers/cookies/credentials/bodies/raw hosts/path values/query values, kernel-validates the completed session, and atomically publishes a portable bundle to its private app-owned inbox only after exact stop. Replay, unknown fields, origin mismatch, and disconnect publish no bundle. The native adapter lets the user explicitly export a new file; the offline core then imports it through the normal hostile-import/kernel boundary.

Attachment still requires a foreground user gesture, visible approval, exact extension identity, one selected tab, a persistent capture indicator, and a per-attachment session credential. There is no long-lived browser pairing secret. Attachment credentials are short-lived, one-use, rotated, replay-resistant, and never placed in a URI, log, diagnostic, screenshot, or support bundle.

Stop, tab close, browser restart, app exit, watchdog timeout, and revoke detach capture. Revoke invalidates credentials and clears extension pairing state. No automatic reattachment or background tab history is permitted.

## Temporary compatibility path

A loopback path is not part of the default architecture. Any temporary spike must validate exact extension origin/ID, require visible approval and challenge-response, reject browsers/webpages/local tools, reject replacement clients, and meet the same credential rules before handling real evidence.

## Rejected

DTT's unauthenticated discovery endpoint, query-string bearer tokens, silent connection replacement, broad `<all_urls>` or `scripting` permissions without an approved workflow.

## Oracle

Hostile webpage, wrong origin/ID, fake host/app signature, modified/overbroad manifest, oversized frame, local process, replay, duplicate/parallel client, replacement, restart, stale credential, revoke, install/update/uninstall, and permission-denial tests. The production manifest is checked against a committed golden.
