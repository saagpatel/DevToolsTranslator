# ADR-005: Browser IPC And Attachment Trust

Status: accepted for Gate 0 review
Owner: browser-adapter owner and privacy/security gatekeeper

## Decision

Chrome Native Messaging is the MVP target because it binds the extension to an installed native host manifest and avoids unauthenticated browser-accessible loopback discovery. The manifest uses one versioned host name, an absolute path to the signed host inside the Glassbox installation, and `allowed_origins` containing exactly the production extension ID. Development IDs/manifests are separate artifacts and cannot ship in production.

The user-scoped host manifest is app-owned, mode `0600`, installed only after explicit setup, and removed by reset/uninstall. The host and main app must share the expected Developer ID Team ID. Their local XPC connection validates audit token/code signature and a canonical session challenge before transferring evidence. Message frames have a 1 MiB maximum and bind protocol version, extension ID, browser attachment ID, selected tab ID, request ID, and session nonce.

Attachment still requires a foreground user gesture, visible approval, exact extension identity, one selected tab, a persistent capture indicator, and a per-attachment session credential. There is no long-lived browser pairing secret. Attachment credentials are short-lived, one-use, rotated, replay-resistant, and never placed in a URI, log, diagnostic, screenshot, or support bundle.

Stop, tab close, browser restart, app exit, watchdog timeout, and revoke detach capture. Revoke invalidates credentials and clears extension pairing state. No automatic reattachment or background tab history is permitted.

## Temporary compatibility path

A loopback path is not part of the default architecture. Any temporary spike must validate exact extension origin/ID, require visible approval and challenge-response, reject browsers/webpages/local tools, reject replacement clients, and meet the same credential rules before handling real evidence.

## Rejected

DTT's unauthenticated discovery endpoint, query-string bearer tokens, silent connection replacement, broad `<all_urls>` or `scripting` permissions without an approved workflow.

## Oracle

Hostile webpage, wrong origin/ID, fake host/app signature, modified/overbroad manifest, oversized frame, local process, replay, duplicate/parallel client, replacement, restart, stale credential, revoke, install/update/uninstall, and permission-denial tests. The production manifest is checked against a committed golden.
