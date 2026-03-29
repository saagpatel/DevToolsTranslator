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
- Node.js 18+ and pnpm
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

| Layer | Technology |
|-------|------------|
| Desktop runtime | Tauri 2 (Rust) |
| Browser capture | Chrome MV3 extension |
| Core engine | Rust crates: dtt-core, dtt-storage, dtt-correlation, dtt-detectors |
| Storage | SQLite (SQLx) |
| Desktop UI | React + TypeScript |
| Integrity | BLAKE3 hashing |
| Build | pnpm workspaces + Cargo workspace |

## License

MIT
