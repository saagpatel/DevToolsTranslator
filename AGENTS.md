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

- The portfolio context is minimum-viable; verify current state from the README, workspace manifests, and supporting docs before expanding scope.

## Next Recommended Move

If work continues here, capture a small repo-specific handoff or roadmap only after verifying current live files.

<!-- portfolio-context:end -->
