# Browser Adapter Release Evidence

Status: required before Gate 6 promotion  
Owner: browser adapter owner and release verifier

The separately distributed Browser Adapter is not release-ready merely because it builds or carries a Developer ID signature. Promotion requires one receipt bound to the final adapter DMG and extension ZIP plus independently retained evidence from a fresh macOS VM.

## Local artifact readiness

Run `scripts/glassbox/run_browser_artifact_readiness.sh`. It produces persistent candidate artifacts under `dist/` and a `glassbox-browser-artifact/v1` receipt. Local readiness requires:

- exactly the native SwiftUI/AppKit controller and Rust Native Messaging host;
- Hardened Runtime Developer ID signatures and zero entitlements on both executables;
- a no-collection privacy manifest;
- an extension payload containing only the six reviewed shipping files;
- exact public-key-derived extension identity and `nativeMessaging`-only permission;
- a signed, valid DMG and a safe extension ZIP;
- no browser executable or host added to the App-Sandboxed core.

The readiness command may exit successfully while the receipt has `ok: false`. That means the local artifact is ready for external verification, not that Gate 6 passed.

## Apple distribution evidence

Submit the exact candidate app and final DMG through the approved Apple notarization workflow. Retain the Accepted logs, staple and validate both final artifacts, and rerun the strict verifier. Rebuilding either artifact invalidates downstream hash-bound evidence.

## Fresh-VM Chrome protocol

Start from a fresh supported macOS VM with no prior Glassbox files, Chrome extension, Native Messaging manifest, app container, or browser-adapter Application Support directory.

1. Record macOS and stable Chrome versions without including machine or user identifiers.
2. Verify Gatekeeper accepts the final adapter artifact.
3. Install the exact production extension identity and the exact notarized adapter.
4. Use the native adapter's explicit setup control and verify the user-scoped manifest is private and targets the final installed host.
5. Open DevTools on one selected tab, start capture visibly, and prove another tab is not captured.
6. Verify the persistent indicator, manual marker, request/response metadata, explicit stop, private bundle publication, non-overwriting export, and offline core import.
7. Exercise wrong origin, replay, malformed frame, abrupt disconnect, revoke, reset, browser restart, and app exit. No rejected or incomplete session may publish a bundle.
8. Complete keyboard, visible-focus, VoiceOver, and disclosure review in both DevTools and the native adapter.
9. Uninstall the adapter and remove its owned state. Confirm no daemon, helper, credential, manifest, cache, or Application Support residue remains. Confirm user exports remain and disclose manual extension removal.

Copy `browser/fresh-vm-evidence-template.json` beside at least four redacted text or image evidence files. Fill only verified booleans, bind the frozen candidate-manifest, final DMG, and extension ZIP hashes, then have the independent reviewer sign that JSON as DER CMS with the approved reviewer certificate. Run:

```sh
GLASSBOX_CANDIDATE_MANIFEST=/absolute/path/to/glassbox-candidate-manifest.json \
GLASSBOX_BROWSER_FRESH_VM_CMS=/absolute/path/to/fresh-vm-evidence.cms \
GLASSBOX_BROWSER_REVIEWER_CA=/absolute/path/to/reviewer-ca.pem \
  scripts/glassbox/verify_browser_artifact.sh \
  'dist/Glassbox Browser Adapter.app' \
  dist/Glassbox-Browser-Adapter-0.1.0.dmg \
  dist/Glassbox-Selected-Tab-Extension-0.1.0.zip \
  artifacts/glassbox-browser-artifact-final.json
```

The verifier rejects signature or CA failures, stale or future reviewer time, unknown fields, missing/duplicate/symlinked attachments, path escapes, hash drift, incomplete check sets, non-boolean successes, an unexpected extension ID, candidate-manifest drift, or an artifact rebuilt after testing. Evidence files must be redacted and must not contain browser history, credentials, raw URLs, request bodies, usernames, machine identifiers, or unrelated user data.
