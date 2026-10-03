# DevTools Translator

[![Rust](https://img.shields.io/badge/Rust-dea584?style=flat-square&logo=rust)](#) [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](#)

> Turn noisy DevTools activity into a clear story you can actually use.

DevTools Translator captures browser events from a Chrome tab, organizes them into human-readable timelines, highlights likely issues, and exports safe share bundles for collaboration. If Chrome DevTools feels overwhelming, this gives you the same signal in plain language — built for PMs, founders, QA testers, and newer engineers.

## Features

- **Timeline view** — browser events grouped into meaningful interactions, not raw log noise
- **Detector engine** — built-in detectors surface likely problems and performance risks automatically
- **Safe export bundles** — BLAKE3-integrity-checked bundles you can share without exposing sensitive data
- **Chrome MV3 extension** — explicit capture consent model with tab-level control
- **Local desktop shell** — Tauri 2 app with React UI, no cloud dependency

## Quick Start

### Prerequisites

- Rust toolchain (`rustup`)
- Node.js 24 (matching CI) and pnpm 11.1.2 (pinned in `package.json`)
- Chrome browser

### Installation

```bash
pnpm install --frozen-lockfile
pnpm --filter @dtt/desktop-ui build
pnpm --filter @dtt/extension build
```

### Usage

```bash
# Launch the desktop shell
cargo run -p dtt-desktop-core --features desktop_shell
```

Then load the unpacked extension from `apps/extension-mv3/dist`, click **Find Desktop App** in the popup, connect, and start capturing.

## Tech Stack

| Layer           | Technology                                                                                    |
| --------------- | --------------------------------------------------------------------------------------------- |
| Desktop runtime | Tauri 2 (Rust)                                                                                |
| Browser capture | Chrome MV3 extension                                                                          |
| Core engine     | Rust crates: dtt-core, dtt-storage, dtt-correlation, dtt-detectors, dtt-export, dtt-integrity |
| Storage         | SQLite (SQLx)                                                                                 |
| Desktop UI      | React + TypeScript                                                                            |
| Integrity       | BLAKE3 hashing                                                                                |
| Build           | pnpm workspaces + Cargo workspace                                                             |

## Verification

Run from the repository root after the frozen pnpm install above. The
[canonical command list](.codex/verify.commands) is the full JavaScript/Rust gate;
run it with `bash .codex/scripts/run_verify_commands.sh` when the complete gate is needed.
For a focused change, select the affected package, for example:

```bash
pnpm --filter @dtt/desktop-ui test
cargo test --locked -p dtt-integrity
```

The canonical list covers lint, typecheck, tests, builds, Rust formatting and
Clippy. `pnpm format:check` is an additional repository formatting check.
Desktop-shell checks with `--features desktop_shell` need Tauri's platform
prerequisites; the default Rust workspace gate does not prove native packaging.
For UI/report changes, check the desktop UI with synthetic timeline fixtures and
inspect redaction/export behavior. Loading the extension into a real browser tab,
capturing personal traffic, release scripts, and store publication are separate
operational lanes; do not use them as a fixture smoke test.

## License

MIT
