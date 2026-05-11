# DevToolsTranslator — Portfolio Disposition

**Status:** Release Frozen — Tauri 2 + Rust desktop shell + Chrome
MV3 extension on `origin/main`. **Monorepo** (`apps/desktop-tauri/`
+ Chrome extension). Captures Chrome DevTools activity, organizes
into timelines, runs detectors, exports BLAKE3-integrity-checked
share bundles. Joins the signing cluster as the 18th member.

> Disposition uses strict `origin/main` verification.
> **First monorepo + dual-distribution (desktop + Chrome Web Store)
> repo in the cluster** — release machinery differs from single-shell
> apps.

---

## Verification posture

This repo has both `origin` (`saagpatel/DevToolsTranslator`) and
`legacy-origin` (`saagar210/DevToolsTranslator`) remotes. **Local
clone's `main` is tracking `origin/main` correctly** — no trap.

Specifically verified on `origin/main`:

- Tip: `0a6e824` (HEAD)
- Substantive commits on `origin/main`:
  - `cd66551` feat(release): harden local beta rollout
  - `0d4917e` feat(repo): initialize DevToolsTranslator project
- **Monorepo layout** on `origin/main`:
  - `apps/desktop-tauri/src-tauri/` — Rust + Tauri desktop shell
  - Workspace config `pnpm-workspace.yaml` references
    `apps/*`, `apps/desktop-tauri/ui`, `packages/*`
- **Desktop backend modules:**
  - `apps/desktop-tauri/src-tauri/src/anomaly.rs`
  - `apps/desktop-tauri/src-tauri/src/compliance_pack.rs`
  - `apps/desktop-tauri/src-tauri/src/control_plane.rs`
  - `apps/desktop-tauri/src-tauri/src/health_scorecard.rs`
  - `apps/desktop-tauri/src-tauri/src/release.rs`
  - `apps/desktop-tauri/src-tauri/src/rollout_controller.rs`
  - `apps/desktop-tauri/src-tauri/src/tauri_commands.rs`
- **Release workflows on `origin/main`** (more than typical cluster
  members):
  - `.github/workflows/release-extension-public.yml`
  - `.github/workflows/release-extension-stage-controller.yml`
  - `.github/workflows/release-internal-beta.yml`
  - `.github/workflows/release-staged-public-prerelease.yml`
  - `.github/workflows/perf-reliability-regression.yml`
- Top-level `Cargo.toml` (workspace-level Rust manifest)
- Default branch: `main`

---

## Legacy-origin orphan note

`legacy-origin/main` has **zero commits** not on `origin/main`. Clean
state.

---

## Current state in one paragraph

DevTools Translator is a dual-shell developer-experience tool: a
**Chrome MV3 extension** captures browser events with an explicit
consent model and tab-level control, and a **Tauri 2 + Rust desktop
shell** ingests those events to organize them into timelines, run
detector engines to surface likely problems, and export safe share
bundles (BLAKE3 integrity checks). The desktop backend has unusually
heavy release-governance code in tree: `release.rs`,
`rollout_controller.rs`, `release-extension-stage-controller.yml` —
this product internalizes its own staged-rollout machinery. Target
audience per README: PMs, founders, QA testers, newer engineers
overwhelmed by raw Chrome DevTools.

For full detail see `README.md` on `origin/main`.

---

## Why "Release Frozen" instead of other dispositions

- **Active** — wrong. The commit `cd66551 feat(release): harden
  local beta rollout` plus four release workflows on canonical main
  positions this for ship.
- **Cold Storage / Archived** — wrong. Recent product work.
- **Release Frozen** — correct. Joins the cluster, but adds two new
  shapes to the cluster:
  - **Monorepo** — `apps/desktop-tauri/` rather than top-level
    `src-tauri/`. Signing scripts that assume the top-level layout
    will need adjustment.
  - **Dual distribution** — Chrome Web Store extension publishing
    is a parallel release axis to Apple desktop signing.

This is the **18th signing cluster member**: DesktopPEt / ContentEngine
/ AIGCCore / Relay / FreeLanceInvoice / Nexus / DeepTank / OPscinema /
ShipKit / SignalFlow / PixelForge / DatabaseSchema / LegalDocsReview /
WorkdayDebrief / TicketDashboard / EarthPulse / RealEstate /
**DevToolsTranslator**.

---

## Unblock trigger (operator)

When ready to ship:

1. **Apple side:**
   - Wire Apple Developer ID + notarization credentials
   - Confirm signing scripts handle the monorepo path
     (`apps/desktop-tauri/src-tauri/`)
2. **Chrome side:**
   - Confirm Chrome Web Store developer account is registered
   - Stage rollout per `release-extension-stage-controller.yml`
     (the workflow exists; operator runs it)
   - Decide whether the extension ships under the operator's name
     or a brand identity
3. **Cross-shell:**
   - Confirm desktop ↔ extension communication is production-ready
     (likely a local IPC channel — audit before public release)
   - Confirm BLAKE3 integrity on share bundles still verifies after
     packaging
4. Run `perf-reliability-regression.yml` against signed builds.
5. Cut release tags per the staged-prerelease + public workflows.

Estimated operator time once Apple + Chrome credentials are in
hand: ~5 hours (extra time for the cross-shell + Chrome Web Store
review cycles, which can take days).

---

## Portfolio operating system instructions

| Aspect | Posture |
|---|---|
| Portfolio status | `Release Frozen` |
| Distribution shape | **Dual** — Apple-signed desktop + Chrome Web Store extension |
| Review cadence | Suspend overdue counting |
| Resurface conditions | (a) Apple signing credentials wired, (b) Chrome Web Store dev account confirmed, (c) operator decides staged rollout posture, or (d) operator opens a v1.1 scope packet |
| Co-batch with | Signing cluster: …PixelForge / DatabaseSchema / LegalDocsReview / WorkdayDebrief / TicketDashboard / EarthPulse / RealEstate / **DevToolsTranslator** — **now 18 repos** |
| Co-batch with (Chrome) | Currently a cluster of 1 (this repo). If other Chrome extensions enter the cluster, group their Web Store review cycles. |
| Special concern | **Monorepo layout.** Signing scripts assuming top-level `src-tauri/` will break. |
| Special concern | **Chrome Web Store review latency.** Adds days to release cycle that Apple notarization doesn't. |

---

## Why this row is different from the rest of the cluster

Every other cluster member is a single-shell Tauri desktop app
that needs Apple signing. DevToolsTranslator is:

1. **Monorepo** — desktop shell is at `apps/desktop-tauri/`, not at
   repo root. Signing pipelines need to know the path.
2. **Dual-shell** — there's an explicit Chrome MV3 extension that
   ships through Chrome Web Store, not the Apple notarization
   pipeline. Two parallel release tracks with different review
   latencies.
3. **Self-managing rollout** — `rollout_controller.rs` and
   `release-extension-stage-controller.yml` mean the product
   itself has staged-rollout machinery internalized. Most cluster
   members rely on external signaling for rollout pacing.

If a future audit round surfaces other Chrome MV3 extensions or
monorepos, group them with this one rather than the standard
desktop signing cluster.

---

## Reactivation procedure (for the next code session)

1. Verify `git branch -vv` shows `main` tracking `origin/main`.
   Already correct as of this disposition pass.
2. Review the local stash (`r9-devtoolstranslator-stash`) — contains
   mods to `.codex/verify.commands`, `pnpm-workspace.yaml`, plus
   untracked `.codex/scripts/`, `AGENTS.md`. Decide what belongs on
   `origin/main`.
3. Re-run `pnpm install` from monorepo root.
4. Confirm `apps/desktop-tauri/` builds via `pnpm --filter
   desktop-tauri tauri build` or equivalent.
5. **Confirm Chrome MV3 manifest version + permission posture** is
   production-ready before submission.
6. **Pick Apple-side and Chrome-side release order** — they can run
   in parallel but require different operator attention.

---

## Last known reference

| Field | Value |
|---|---|
| `origin/main` tip | `0a6e824` (HEAD) |
| Last substantive commit | `cd66551` feat(release): harden local beta rollout |
| Default branch | `main` |
| Build system | Tauri 2 + Rust (workspace-level Cargo.toml) + Chrome MV3 + pnpm monorepo |
| Layout | **Monorepo** — `apps/desktop-tauri/src-tauri/`, `apps/desktop-tauri/ui`, `packages/*` |
| Release workflows | release-extension-public.yml, release-extension-stage-controller.yml, release-internal-beta.yml, release-staged-public-prerelease.yml, perf-reliability-regression.yml |
| Distinguishing feature | **Monorepo + Chrome extension dual-distribution.** Two parallel release tracks (Apple notarization + Chrome Web Store review). |
| Internal release machinery | `release.rs`, `rollout_controller.rs` in src-tauri — staged rollout is part of the product, not just the pipeline |
| Blocker | Apple signing + Chrome Web Store dev account + signing-script monorepo adjustment (operator-only) |
| Migration state | `legacy-origin` present but local tracking is correct; **zero orphans on `legacy-origin/main`** |
