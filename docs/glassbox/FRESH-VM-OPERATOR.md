# Glassbox Fresh-VM Operator Guide

This kit carries the exact frozen Glassbox distribution artifacts used for independent Gate 6 review. It does not authorize a release and it does not turn local observations into independent evidence.

## 1. Authenticate the kit before testing

Obtain the expected candidate-manifest SHA-256 through the release owner's separate trusted channel. Extract the archive without renaming its top-level directory, enter that directory, and run:

```sh
python3 tools/fresh_vm_kit.py \
  --verify-directory . \
  --expected-candidate-sha256 EXPECTED_64_CHARACTER_SHA256
```

Continue only when the receipt reports `"ok": true`. The verifier rejects unexpected or missing files, symlinks, unsafe paths, candidate drift, and any artifact or template whose bytes differ from `KIT-MANIFEST.json`. Preserve the original archive and its SHA-256 with the review record.

## 2. Keep the candidate immutable

- Do not rebuild, re-sign, repackage, or staple anything in the kit.
- Install only from the six supplied DMGs and the supplied browser-extension ZIP.
- Work from a fresh supported macOS VM with no prior Glassbox installation, containers, helper state, browser extension, Native Messaging manifest, or adapter Application Support directory.
- Record macOS and stable Chrome versions without machine identifiers, usernames, browser history, credentials, raw URLs, request bodies, or unrelated user data.

## 3. Collect independent evidence

Copy the templates out of the immutable kit before filling them. Complete only checks you directly observed and retain the required redacted attachments beside each evidence document.

- Core install/update/downgrade/revoke/reset/uninstall/reinstall: `templates/LIFECYCLE-EVIDENCE.template.json`
- Core keyboard, VoiceOver, reduced-motion, zoom, and disclosure review: `templates/ACCESSIBILITY-EVIDENCE.template.json`
- Browser adapter and Chrome workflow: `templates/BROWSER-RELEASE-EVIDENCE.md` and `templates/browser/fresh-vm-evidence-template.json`
- OTLP, passive-context, process-context, and Instruments adapters: `templates/AUXILIARY-ADAPTER-RELEASE-EVIDENCE.md` and `templates/AUXILIARY-ADAPTER-EVIDENCE.template.json`

Every evidence document must bind the candidate-manifest digest and the exact artifact hashes it names. A reviewer with the approved role and CA must inspect the primary evidence and produce an attached DER CMS envelope. Self-attestation by the build operator is not independent review.

## 4. Return the evidence package

Return the CMS envelopes, reviewer CA certificates, completed source evidence documents, and their confined redacted attachments. Do not place secrets, Apple credentials, signing keys, private browsing data, or unrelated user files in the package.

The release owner must run the repository's strict candidate-bound verifiers. Passing this kit verifier proves transfer integrity only; it does not prove accessibility, lifecycle, browser, adapter, or release promotion by itself.

Kit production is create-only. Always choose a new output path; the builder refuses to overwrite or follow an existing file or symlink, and publishes the verified archive atomically only after its bytes and candidate binding pass local verification.
