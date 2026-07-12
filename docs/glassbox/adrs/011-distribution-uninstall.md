# ADR-011: macOS Distribution, Signing, Sandbox, And Uninstall

Status: accepted for Gate 0 review
Owner: release owner and privacy/security gatekeeper

## Decision

Target Developer ID distribution outside the Mac App Store. The core app must also pass an App Sandbox feasibility gate with no network client/server entitlement; this is the default-deny egress enforcement selected in ADR-012. Require Hardened Runtime, minimal entitlements, valid nested signatures, notarization, stapling, a strict CSP, no remote UI content, narrow Tauri capabilities, and a reviewed privacy manifest.

Gate 1 must prove App Sandbox with security-scoped imports, per-investigation storage, Keychain access, the constrained import worker, and authenticated communication with the signed Native Messaging host/source brokers. If it fails, stop and request a new product decision; an unsandboxed release is not an automatic fallback.

The initial CSP golden is `default-src 'self'; base-uri 'none'; object-src 'none'; frame-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'`. Any required Tauri custom protocol is enumerated narrowly rather than using a wildcard. Glassbox removes DTT deep-link registration for Gates 1-6; a future deep-link workflow needs its own grammar, size limits, secret/path prohibition, confirmation, and negative tests.

The initial `PrivacyInfo.xcprivacy` declares no tracking, no linked data collection, and no evidence transmission. A generated required-reason API and privacy-data inventory is diffed against that manifest; any changed API/data category blocks promotion until the manifest and product disclosure are reviewed.

Signing and notarization are verified from the final artifact using direct platform commands defined in `NEGATIVE-REQUIREMENTS-CI.md`; configuration flags and hashes are not proof.

Uninstall/reset supports: stop sources, revoke browser credentials, delete app-owned keys/data/caches/logs, clear security-scoped bookmarks, remove the app-owned Native Messaging host manifest/binary, and enumerate user exports it cannot delete. The user-installed Chrome extension remains user-owned: Glassbox revokes connectivity and provides accurate manual-removal instructions but does not claim to remove it silently. The core must leave no helper, daemon, certificate, proxy, privileged component, or app-owned host residue.

## Oracle

Fresh-VM install, first launch, denied permission, update, downgrade, revoke, reset, uninstall, reinstall, Gatekeeper, entitlement diff, notarization, staple, CSP, deep-link, privacy-report, and residue checks.
