# Demo Deck Outline

## Purpose

Use this outline to build a short demo deck after the screenshot capture pass. The deck should support a live walkthrough, not replace it.

## Suggested Slides

1. **Problem**: DevTools traffic is noisy, technical, and hard to share safely.
2. **Product**: DevTools Translator captures browser diagnostics and turns them into traceable findings.
3. **Local-First Architecture**: Chrome MV3 extension, Tauri 2 desktop shell, Rust analysis pipeline, SQLite storage, and share-safe export.
4. **Capture Workflow**: Pairing, consent, Live Capture, and controlled fixture traffic.
5. **Analysis Workflow**: Normalization, correlation, detector packs, claims, confidence, and evidence references.
6. **Evidence Drilldown**: Every explanation links back to concrete captured rows and fields.
7. **Export Workflow**: Share-safe export, manifest, report, integrity files, and verification.
8. **Security Posture**: Metadata-only defaults, redaction contracts, no telemetry, scoped Tauri capability, and sanitized demo rules.
9. **Verification**: Automated tests, local beta smoke, interactive Chrome release smoke, and unresolved external release gates.
10. **Next Steps**: Screenshot capture, one-pager rendering, deck build, and release evidence refresh.

## Rehearsal Notes

- Keep the live demo on sanitized fixtures and a disposable browser profile.
- State the active privacy mode before capture begins.
- Do not open real accounts, private browser profiles, Keychain prompts, `.env` files, signing keys, or extension-store credentials.
- Keep a fallback path: screenshots can carry the story if the desktop shell, extension, or browser profile is unavailable.
