# DevTools Translator

[![Main Branch](https://img.shields.io/badge/branch-main-0b7285)](https://github.com/saagpatel/DevToolsTranslator/tree/main)
[![Desktop Release CI](https://img.shields.io/github/actions/workflow/status/saagpatel/DevToolsTranslator/release-internal-beta.yml?branch=main&label=desktop%20release%20ci)](https://github.com/saagpatel/DevToolsTranslator/actions/workflows/release-internal-beta.yml)
[![Perf & Reliability](https://img.shields.io/github/actions/workflow/status/saagpatel/DevToolsTranslator/perf-reliability-regression.yml?branch=main&label=perf%20%26%20reliability)](https://github.com/saagpatel/DevToolsTranslator/actions/workflows/perf-reliability-regression.yml)

Turn noisy DevTools activity into a clear story you can actually use.

DevTools Translator captures browser events, organizes them into human-readable timelines, highlights likely issues, and lets you export evidence bundles you can share safely.

## 30-Second Tour

- **You click Start Capture on a tab.**
- **We collect and organize DevTools activity for that session.**
- **You get a clean timeline, network view, and findings summary.**
- **You export a safe share bundle when you need help from others.**

If Chrome DevTools feels noisy or overwhelming, this gives you the same signal in plain language.

## Why This Exists

Most debugging tools are built for people who live in network panels and raw logs all day.

If you are a PM, founder, designer, support lead, QA tester, or a newer engineer, the signal can be hard to find:

- Too many events
- Too much low-level detail
- Not enough plain-language explanation

DevTools Translator bridges that gap.

## What This App Does

At a high level, it does five things:

1. Captures browser DevTools traffic from a tab you choose (with explicit consent).
2. Normalizes and groups that traffic into meaningful interactions.
3. Runs detectors to surface likely problems and risks.
4. Shows everything in a beginner-friendly desktop UI.
5. Exports a portable evidence bundle with integrity checks.

## Why You’d Want To Use It

Use DevTools Translator when you need to answer questions like:

- Why did this request fail?
- Why is this page slow right now?
- Is this a CORS, auth, caching, or streaming issue?
- What happened during this user session?
- How do I share debugging evidence safely with my team?

It helps you move from “I have logs” to “I understand what happened.”

## Who It’s For

- Product managers validating API behavior
- QA teams reproducing and documenting bugs
- Support teams investigating customer incidents
- Developers who want deterministic capture + analysis
- Teams that need privacy-aware evidence sharing

## Beginner Quick Start (No Terminal)

1. Open the **Desktop App**.
2. In Chrome, open the **DevTools Translator extension**.
3. Click **Find Desktop App**.
4. Click **Connect**.
5. Turn on **Explicit capture consent**.
6. In Desktop App, open **Live Capture**.
7. Pick a tab and click **Start**.
8. Use the tab for 15–30 seconds.
9. Click **Stop**.
10. Open **Sessions** and review **Timeline**, **Network**, and **Findings**.

## Why It Feels Easier Than Raw DevTools

- It groups related events into interactions instead of showing a giant unstructured stream.
- It links findings directly to evidence, so you can see exactly why a finding exists.
- It keeps privacy controls explicit (`metadata_only`, redaction, share-safe exports).
- It is designed for mixed-skill teams, not just deep DevTools experts.

## What You’ll See In The App

- **Sessions**: every capture run, status, duration, and findings count
- **Live Capture**: connection status, tab list, start/stop controls
- **Findings**: likely issues with evidence references
- **Exports**: share-safe and full export options
- **Settings**: privacy defaults, retention controls
- **About/Diagnostics**: connection and reliability diagnostics

## Privacy and Safety Defaults

- Explicit user consent is required before capture starts.
- `metadata_only` mode avoids storing bodies.
- Sensitive headers are redacted.
- Share-safe export excludes secret-bearing artifacts.
- Evidence references are validated for deterministic traceability.

## Repo Layout

- `apps/extension-mv3`: Chrome MV3 capture extension
- `apps/desktop-tauri/src-tauri`: Rust desktop backend + local WS bridge
- `apps/desktop-tauri/ui`: React desktop UI
- `crates/dtt-core`: shared Rust contracts
- `crates/dtt-storage`: SQLite ingest/normalize/correlate/query layer
- `crates/dtt-correlation`: deterministic interaction correlation engine
- `crates/dtt-detectors`: detector engine and built-ins
- `crates/dtt-export`: export bundle generation
- `crates/dtt-integrity`: integrity hashing and validation
- `fixtures`: raw fixtures + expected snapshots
- `docs/SPEC_LOCK.md`: authoritative specification

## Local Launch (Validated)

This repo now has a confirmed local desktop launch path on macOS.

1. Install workspace dependencies:

```bash
pnpm install --frozen-lockfile
```

2. Confirm Rust is available:

```bash
cargo --version
```

3. Build the desktop UI bundle:

```bash
pnpm --filter @dtt/desktop-ui build
```

4. Build the Chrome extension:

```bash
pnpm --filter @dtt/extension build
```

5. Launch the real desktop shell:

```bash
cargo run -p dtt-desktop-core --features desktop_shell
```

6. Load the unpacked extension from:

- `apps/extension-mv3/dist`

7. In the extension popup:

- Click `Find Desktop App`
- Click `Connect`
- Enable `I allow capture for this browser`

8. In the desktop app:

- Open `Live Capture`
- Click `Refresh Capture State`
- Start capture on a tab
- Use the tab briefly, then click `Stop Capture`
- Review the session from `Sessions`

## Developer Setup (Advanced)

- Desktop UI only:

```bash
pnpm --filter @dtt/desktop-ui dev
```

## Canonical Verification

Source of truth: `/Users/d/Projects/DevToolsTranslator/.codex/verify.commands`

Run the full required gate set from that file before claiming done-state.

## Troubleshooting

- Extension says **Cannot find Desktop App**:
  - Ensure desktop app is open
  - Reload extension from `apps/extension-mv3/dist`
  - Click **Find Desktop App** again

- `ERR_FILE_NOT_FOUND` in extension:
  - Remove extension and reload unpacked from `apps/extension-mv3/dist`

- Capture won’t start:
  - Confirm extension is connected
  - Confirm **Explicit capture consent** is enabled
  - Retry from **Live Capture**

## Status Snapshot

- Core capture, normalization, correlation, detectors, UI, export, and hardening flows are implemented.
- Local-beta setup and launch have been validated on macOS with the desktop shell + unpacked MV3 extension flow above.
- Current focus is continued rollout/release operations, usability refinement, and remaining manual release gates.
