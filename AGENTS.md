<!-- portfolio-context:start -->

# Portfolio Context

## What This Project Is

DevToolsTranslator is an active local project in the /Users/d/Projects portfolio.

## Current State

Portfolio truth currently marks this project as `active` with `minimum-viable` context. Phase 104 recovered minimum-viable context so future sessions can resume without rediscovery.

## Stack

| Layer           | Technology                                                                                    |
| --------------- | --------------------------------------------------------------------------------------------- |
| Desktop runtime | Tauri 2 (Rust)                                                                                |
| Browser capture | Chrome MV3 extension                                                                          |
| Core engine     | Rust crates: dtt-core, dtt-storage, dtt-correlation, dtt-detectors, dtt-export, dtt-integrity |
| Storage         | SQLite (SQLx)                                                                                 |
| Desktop UI      | React + TypeScript                                                                            |
| Integrity       | BLAKE3 hashing                                                                                |
| Build           | pnpm workspaces + Cargo workspace                                                             |

## How To Run

```bash
# Launch the desktop shell
cargo run -p dtt-desktop-core --features desktop_shell
```

Then load the unpacked extension from `apps/extension-mv3/dist`, click **Find Desktop App** in the popup, connect, and start capturing.

## Known Risks

- This repo only has minimum-viable recovery context today; deeper handoff details may still live in the README and supporting docs.

## Next Recommended Move

Use this context plus the README and supporting docs to resume the next active task, then promote the repo beyond minimum-viable by capturing a dedicated handoff, roadmap, or discovery artifact.

<!-- portfolio-context:end -->
