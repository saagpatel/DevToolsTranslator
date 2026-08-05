# ADR-011: macOS Distribution, Signing, Sandbox, And Uninstall

Status: accepted; amended at Gate 0 for native macOS shell
Owner: release owner and privacy/security gatekeeper

## Decision

Target Developer ID distribution outside the Mac App Store. The core app must pass an App Sandbox feasibility gate with exactly the App Sandbox entitlement and no network client/server or privileged entitlement; this is the default-deny egress enforcement selected in ADR-012. Require Hardened Runtime, minimal entitlements, valid nested signatures, notarization, stapling, no WebKit or Tauri runtime, no remote UI content, and a reviewed privacy manifest.

Gate 1 must prove App Sandbox with security-scoped imports, per-investigation storage, Keychain access, the constrained import worker, and authenticated communication with the signed Native Messaging host/source brokers. If it fails, stop and request a new product decision; an unsandboxed release is not an automatic fallback.

The signed bundle contains exactly two executables: the SwiftUI/AppKit app and the Rust evidence helper. The app invokes that helper by fixed bundle-relative path with no shell, URL scheme, listener, or network transport. The app entitlement allowlist contains only `com.apple.security.app-sandbox` and the standard `com.apple.security.files.user-selected.read-only` capability needed for explicit imports. It has no ambient filesystem, network client/server, privileged, automation, device, or personal-information entitlement. The helper is nested-signed with Hardened Runtime and no entitlements of its own, inheriting the sandbox when launched by the app. Glassbox removes DTT deep-link registration for Gates 1-6; a future deep-link workflow needs its own grammar, size limits, secret/path prohibition, confirmation, and negative tests.

The initial `PrivacyInfo.xcprivacy` declares no tracking, no linked data collection, and no evidence transmission. A generated required-reason API and privacy-data inventory is diffed against that manifest; any changed API/data category blocks promotion until the manifest and product disclosure are reviewed.

Signing and notarization are verified from the final artifact using direct platform commands defined in `NEGATIVE-REQUIREMENTS-CI.md`; configuration flags and hashes are not proof.

Uninstall/reset supports: stop sources, revoke browser credentials, delete app-owned keys/data/caches/logs, clear security-scoped bookmarks, remove the app-owned Native Messaging manifest and separately distributed Browser Adapter, and enumerate user exports it cannot delete. Browser inbox evidence is adapter-owned and deleted only through an explicit scoped action or uninstall choice; user exports remain untouched. The user-installed Chrome extension remains user-owned: Glassbox revokes connectivity and provides accurate manual-removal instructions but does not claim to remove it silently. The core must leave no helper, daemon, certificate, proxy, privileged component, or app-owned host residue.

## Oracle

Fresh-VM install, first launch, denied permission, update, downgrade, revoke, reset, uninstall, reinstall, Gatekeeper, app/helper entitlement and signature diff, native-runtime linkage scan, notarization, staple, deep-link, privacy-report, and residue checks.
