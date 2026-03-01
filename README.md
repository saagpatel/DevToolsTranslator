# DevTools Translator

Turn noisy DevTools activity into a clear story you can actually use.

DevTools Translator captures browser events, organizes them into human-readable timelines, highlights likely issues, and lets you export evidence bundles you can share safely.

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

## Developer Setup (Advanced)

1. Install dependencies:

```bash
pnpm install
```

2. Confirm Rust is available:

```bash
cargo --version
```

3. Build extension:

```bash
pnpm --filter @dtt/extension build
```

4. Load extension from:

- `apps/extension-mv3/dist`

5. Run desktop UI (dev):

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
- Current focus is continued rollout/release operations and usability refinement.
