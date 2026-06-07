# DevTools Translator Demo Plan

## Purpose

Use this plan for local, sanitized demos of DevTools Translator. The demo should show Chrome DevTools capture, deterministic analysis, evidence drilldown, and share-safe export without exposing real accounts, secrets, cookies, proprietary API payloads, or private browsing history.

## Demo Safety Rules

- Use a disposable browser profile with sanitized fixture pages.
- Do not capture real production accounts, authenticated sessions, private URLs, cookies, authorization headers, API keys, or customer data.
- Keep `metadata_only` as the default privacy mode unless the demo explicitly explains a safer fixture-only override.
- Use the share-safe export profile for demo bundles.
- Do not show local Keychain prompts, `.env` files, signing keys, extension store credentials, or updater signing material.
- Treat screenshots in `docs/screenshots/` as UI evidence only, not proof of non-dry-run public release readiness.

## Baseline Scenario

1. Build the desktop UI and MV3 extension from the local workspace.
2. Launch the Tauri desktop shell and load the unpacked extension in a disposable browser profile.
3. Pair the extension to the desktop app through localhost discovery.
4. Enable explicit capture consent.
5. Start a live capture against a sanitized fixture page.
6. Generate controlled browser activity that produces network, console, and lifecycle events.
7. Stop capture and confirm session persistence.
8. Open the findings view and drill into claim/evidence chains.
9. Generate a share-safe export and validate integrity status.
10. Review diagnostics and release-gate status without exposing secrets or local private paths.

## Evidence To Capture

- Extension pairing and consent state.
- Live Capture view with sanitized tab and session state.
- Timeline or Network view with fixture-only rows.
- Findings list with severity, claim, confidence, and evidence references.
- Evidence drilldown showing exact row or field pointer.
- Export flow with share-safe selected.
- Export integrity result.
- Diagnostics or release-gate panel showing safe status only.

## Verification Notes

Before using this demo externally, run:

```bash
pnpm --filter @dtt/desktop-ui build
pnpm --filter @dtt/extension build
cargo test -p dtt-desktop-core
cargo test -p dtt-storage
```

Record what was not verified, especially public extension publishing, updater signing, notarization, and any browser interaction that was not run in a real interactive profile.

## Current Status

The repository already contains local beta and interactive Chrome release smoke evidence in `docs/PHASE6_SMOKE_EVIDENCE.md`. This folder is the reusable demo-script surface for future captures and rehearsals.
