# One-Pager Outline

## Product Summary

DevTools Translator is a local-first diagnostic desktop app and Chrome MV3 extension that captures DevTools/CDP signals, translates them into human-readable findings, and preserves auditable evidence chains for every claim.

## Audience

- Engineer debugging frontend, API, LLM, or browser integration issues.
- Product or support teammate who needs a safe, understandable diagnostic bundle.
- Reviewer evaluating local-first desktop product quality across Tauri, Rust, React, SQLite, and extension surfaces.

## Key Value

- Turns noisy DevTools traffic into severity-ranked findings with traceable EvidenceRefs.
- Keeps capture, analysis, storage, and export local by default.
- Uses privacy modes and share-safe export defaults to reduce accidental data exposure.
- Provides deterministic detector packs so fixture replay and export integrity can be verified.

## Proof Points

- Tauri 2 desktop shell with scoped capabilities and Rust command surface.
- Chrome MV3 extension pairs to the desktop app over localhost with explicit consent.
- SQLite-backed local storage for raw events, normalized records, findings, claims, exports, and release evidence.
- Detector packs cover general web failures and LLM-specific traffic patterns.
- Share-safe exports include manifest, report, session data, and integrity artifacts.

## Current Demo Limits

- Public extension publishing, updater signing, and notarization require separate release evidence.
- Real authenticated browsing sessions should not be used in public demos.
- Full body capture should remain fixture-only unless a release owner explicitly approves the privacy posture.
- Browser interaction evidence should distinguish automated smoke, local beta validation, and human/operator release sign-off.
