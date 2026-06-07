# Screenshot Capture Plan

## Purpose

This folder tracks screenshots needed for portfolio review, release notes, and demo rehearsal. Captures must use sanitized fixture data only.

## Capture Matrix

| File                        | Surface             | Caption                                                             |
| --------------------------- | ------------------- | ------------------------------------------------------------------- |
| `01-pairing.png`            | Pairing             | Extension paired to the desktop app through localhost discovery.    |
| `02-live-capture.png`       | Live Capture        | Sanitized browser tab with explicit consent and active capture.     |
| `03-session-timeline.png`   | Session timeline    | Captured fixture events organized for inspection.                   |
| `04-network-console.png`    | Network and console | Network requests and console entries without secrets or real data.  |
| `05-findings.png`           | Findings            | Severity-ranked findings with claims and confidence.                |
| `06-evidence-drilldown.png` | Evidence drilldown  | Claim evidence resolving to a concrete row or field pointer.        |
| `07-share-safe-export.png`  | Export              | Share-safe export selected before bundle generation.                |
| `08-integrity-result.png`   | Integrity           | Completed export with integrity validation passing.                 |
| `09-diagnostics.png`        | Diagnostics         | Safe bridge, consent, and release-gate status without secrets.      |
| `10-release-readiness.png`  | Release readiness   | Dry-run or readiness checks with unresolved external gates visible. |

## Capture Rules

- Use deterministic fixture traffic or a disposable local test page.
- Hide or replace local filesystem paths unless they are intentionally generic.
- Do not show cookies, authorization headers, API keys, account identifiers, private URLs, extension-store credentials, or updater signing material.
- Include a short caption beside each final screenshot in release or portfolio materials.
- Re-capture screenshots after visible UI changes, detector model changes, export contract changes, or release-gate changes.

## Current Status

No screenshots are committed yet. This plan is the source of truth for the first capture pass.
