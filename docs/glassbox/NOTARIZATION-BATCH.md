# Glassbox Notarization Batch

Status: required before Gate 6 promotion
Owner: release owner

Glassbox ships six separately signed macOS apps: the sandboxed core plus the Browser, Instruments, OTLP, passive-context, and process-context adapters. Apple notarization therefore has twelve exact submissions: one preserved app transport ZIP and one preserved DMG for each app. An Accepted result for fewer than all twelve is incomplete.

This procedure does not authorize signing, Apple submission, stapling, publication, merge, or release. Obtain exact-candidate authority first. Run it only from a clean checkout at the authorized source commit.

## 1. Produce the Developer ID candidate once

With no frozen candidate manifest configured, run the three local production gates exactly once:

```sh
scripts/glassbox/run_macos_artifact_readiness.sh artifacts/glassbox-macos-artifact-readiness.json
scripts/glassbox/run_browser_artifact_readiness.sh artifacts/glassbox-browser-artifact-readiness.json
scripts/glassbox/run_auxiliary_adapter_artifact_readiness.sh artifacts/glassbox-auxiliary-adapters-readiness.json
```

Each receipt must report local readiness. The core must remain App-Sandboxed with only user-selected read access and no network or privileged entitlements. The Instruments adapter must remain a separate, entitlement-free, one-executable app. Do not rebuild or re-sign after freezing the submission batch.

## 2. Freeze preserved upload bytes

Choose a new, non-existing transport directory and manifest path:

```sh
python3 scripts/glassbox/notarization_batch.py \
  --root . \
  --prepare artifacts/glassbox-notarization-batch.json \
  --transport-dir artifacts/glassbox-notary-transport

python3 scripts/glassbox/notarization_batch.py \
  --root . \
  --verify-prepared artifacts/glassbox-notarization-batch.json
```

Preparation rejects a dirty source tree, missing member of the 24-artifact inventory, wrong signing team, non-Developer-ID signature, missing Hardened Runtime on an app, invalid DMG, symlink or path escape, non-`artifacts/` output, nested manifest/transport paths, or existing output. It creates six app ZIPs and six DMG copies without overwriting any prior evidence. Each app ZIP is extracted into an owned temporary directory and must reproduce the source bundle tree hash; each copied DMG must reproduce its source hash; and the complete source inventory must remain unchanged across transport production. The manifest is exclusively created and durably flushed, and binds every upload SHA-256 to the clean source commit/tree and its pre-staple artifact identity.

## 3. Submit and retain Apple logs

Submit only the twelve `upload_path` values in the batch manifest with the approved `xcrun notarytool submit ... --wait` credential route. Record each returned job UUID. Fetch the authoritative log with `xcrun notarytool log <job-uuid> ...` and save it under a new evidence directory using the exact name `<role>-<job-uuid>.json`, where `<role>` is one of:

```text
core_app core_dmg instruments_app instruments_dmg browser_app browser_dmg
otlp_app otlp_dmg passive_app passive_dmg process_app process_dmg
```

Do not edit Apple logs. Preserve the upload directory because the verifier binds each Apple-reported SHA-256 to those exact bytes.

## 4. Staple, freeze the final candidate, and verify acceptance

Only after all twelve Apple jobs are Accepted, staple and validate the corresponding app and DMG in `dist/`. Do not repackage a DMG after stapling. Create the final 24-artifact candidate manifest only after every staple has been applied:

```sh
python3 scripts/glassbox/candidate_manifest.py \
  --root . --output artifacts/glassbox-candidate-manifest.json
python3 scripts/glassbox/candidate_manifest.py \
  --root . --verify artifacts/glassbox-candidate-manifest.json

python3 scripts/glassbox/notarization_batch.py \
  --root . \
  --verify-accepted artifacts/glassbox-notarization-batch.json \
  --logs-dir artifacts/glassbox-notary-logs \
  --candidate-manifest artifacts/glassbox-candidate-manifest.json \
  --receipt artifacts/glassbox-notarization-final.json
```

The final receipt promotes only when the transport directory contains exactly the twelve preserved upload files and the log directory contains exactly twelve regular, non-symlink JSON files. Every log must use Apple's exact Accepted shape, have status code zero, use its canonical UUID filename, contain SHA-256 tickets rooted at the submitted archive name with valid lowercase CDHashes and only the expected arm64 architecture when present, name the preserved upload, match its SHA-256, contain no issues, and bind the current clean source plus valid final candidate manifest. The final receipt is also exclusively created so prior evidence cannot be overwritten. Stapler, Gatekeeper, entitlement, fresh-VM, accessibility, lifecycle, and human evidence remain separate mandatory gates.
