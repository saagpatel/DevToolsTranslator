# Phase 6 Smoke Evidence

Date: 2026-02-22

## Automated Smoke Coverage (Executed)
- `ws_bridge_routes_commands_and_session_events` verifies:
  - `cmd.list_tabs` roundtrip to `evt.tabs_list`
  - `cmd.start_capture` to `evt.session_started`
  - `evt.raw_event` ingest persistence
  - `cmd.stop_capture` to `evt.session_ended`
  - session lifecycle persistence (`ended_at_ms`)
- `ws_bridge_reconnect_replaces_connection_and_keeps_routing` verifies:
  - second extension connection replaces the first connection deterministically
  - diagnostics emits `connection_replaced`
  - command routing continues via active connection
- `ws_bridge_start_capture_surfaces_already_attached_error` verifies:
  - `evt.error` with `already_attached` propagates as a typed command error

## Fixture Regression Coverage Added
- `fixtures/raw/fx_phase6_capture_drop.ndjson`
  - includes `DTT.capture_drop.v1` marker plus network/console/lifecycle events
- `fixtures/raw/fx_phase6_disconnect_reconnect.ndjson`
  - includes reconnect marker plus success/failure network requests and console/lifecycle events
- `dtt-storage` tests now run full pipeline (ingest -> normalize -> correlate -> analyze) against these fixtures.

## Manual Browser Smoke
- Manual Chrome UI validation remains a human-run checklist item for release readiness:
  1. load extension from `apps/extension-mv3/dist`
  2. pair using desktop port/token
  3. enable consent and start capture
  4. verify live `evt.raw_event` flow and clean `evt.session_ended`
  5. verify already-attached UX path

### Promotion Gate Marker
- Required marker format for staged public promotion:
`interactive_chrome_manual: pass|date=YYYY-MM-DD|observer=<name>`
- Current marker status:
`interactive_chrome_manual: not_run|date=2026-02-22|observer=codex_shell`

## Closeout Run (2026-02-22T09:28:40Z)
- Checklist status recorded against available execution surfaces in this environment.

1. `cmd.list_tabs -> evt.tabs_list`: PASS
- Evidence: `cargo test -p dtt-desktop-core` (`ws_bridge_routes_commands_and_session_events`).

2. `cmd.start_capture -> evt.session_started -> evt.raw_event ingest`: PASS
- Evidence: `cargo test -p dtt-desktop-core` (`ws_bridge_routes_commands_and_session_events`).

3. `cmd.stop_capture -> evt.session_ended` and session closure: PASS
- Evidence: `cargo test -p dtt-desktop-core` (`ws_bridge_routes_commands_and_session_events`) and storage lifecycle assertions.

4. Already-attached UX/error path: PASS
- Evidence: `cargo test -p dtt-desktop-core` (`ws_bridge_start_capture_surfaces_already_attached_error`).

5. Extension build/test readiness for manual browser smoke: PASS
- Evidence: `pnpm --filter @dtt/extension test` and `pnpm --filter @dtt/extension build` in canonical gate run.

6. Interactive Chrome manual validation (UI click-through in real browser): NOT RUN in this shell-only environment
- Follow-up: run the manual checklist in this file on a workstation session with interactive Chrome, then append final observer notes.

## Phase 9 Closeout Note (2026-02-22)
- Automated transport/bridge/capture regression remains PASS in canonical verification run:
  - `cargo test -p dtt-desktop-core`
  - `cargo test -p dtt-storage`
  - `pnpm --filter @dtt/extension test`
- Interactive Chrome checklist remains open and must be executed by a human operator before release sign-off.

## Phase 10 Update (2026-02-22)
- Release/inspect operationalization completed in code and CI workflow.
- Manual interactive Chrome checklist status in this execution environment: NOT RUN.
- Blocking release-closeout action remains unchanged:
  1. run browser checklist on a real workstation session
  2. append observer name + timestamp + pass/fail for each item
  3. attach any failure diagnostics before shipping non-dry-run beta.

## Phase 11 Update (2026-02-22)
- Multi-platform release lanes (macOS/Windows/Linux), reliability telemetry, and perf regression gates are now implemented and passing automated checks.
- Manual interactive Chrome checklist status in this execution environment: NOT RUN.
- Release sign-off requirement remains unchanged: complete the human-run browser checklist and append dated observer evidence in this file.

## Phase 14 Follow-up (2026-02-28)
- Rollout controller and publish workflows were exercised in dry-run and guard-check modes.
- Non-dry-run promotion guards remain active and correctly block without:
  - manual smoke evidence pass marker
  - CWS credentials
  - updater signature input
- Interactive browser checklist remains the only human-required gate before non-dry-run promotion.

## Local Beta Validation Update (2026-03-14)
- macOS local-beta recovery and smoke were re-run against the real desktop shell and unpacked MV3 extension.

### Automated Local Smoke Completed
1. `pnpm install --frozen-lockfile`: PASS
2. `pnpm --filter @dtt/desktop-ui build`: PASS
3. `pnpm --filter @dtt/extension build`: PASS
4. `cargo run -p dtt-desktop-core --features desktop_shell`: PASS after startup fix for fresh-db migration bootstrap.
5. Extension discovery + connect against live desktop app: PASS
6. Consent toggle propagation into Live Capture: PASS after fix; no reconnect workaround required
7. Live Capture refresh shows eligible browser tab: PASS
8. Start capture -> browser activity -> stop capture: PASS
9. Session persistence + normalize/correlate/analyze pipeline: PASS
10. Share-safe export generation: PASS

### Evidence Snapshot
- Runtime DB file observed at:
  `/var/folders/gf/3t3h93q52d1fj7d_tldckr6r0000gn/T/dtt-desktop.sqlite3`
- Bridge diagnostics confirmed:
  - `connected=true consent=true ui_capture=false`
  - `session_close_pipeline_ok`
- Session rows confirmed in `sessions`.
- Export row confirmed in `exports_runs` with:
  - `export_profile=share_safe`
  - `status=completed`
  - `integrity_ok=1`

### Bug Fixed During This Run
1. Desktop startup on a fresh machine crashed before migrations were applied.
- Fix: bootstrap desktop storage before pairing-context lookup.
2. Live Capture consent state stayed stale until extension reconnect.
- Fix: extension now emits a fresh `evt.hello` update when consent or UI-capture settings change.

### Manual Browser Smoke Status
- Human interactive release sign-off remains open.
- Current marker status:
`interactive_chrome_manual: not_run|date=2026-03-14|observer=codex_shell`
