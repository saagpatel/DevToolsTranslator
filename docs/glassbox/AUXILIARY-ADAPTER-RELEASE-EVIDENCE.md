# Auxiliary Adapter Release Evidence

Status: required before Gate 6 promotion
Owner: adapter release owner and independent fresh-VM reviewer

The OTLP, passive-context, process-context, and Instruments adapters are separate products at the distribution boundary. Their local workflow gates do not prove that their shipping bytes were notarized, accepted by Gatekeeper, usable on a fresh Mac, accessible, or cleanly removable.

## Candidate production

Run `scripts/glassbox/run_auxiliary_adapter_artifact_readiness.sh` to build and locally verify these eight distributable artifacts:

- `dist/Glassbox OTLP Adapter.app` and `dist/Glassbox-OTLP-Adapter-0.1.0.dmg`
- `dist/Glassbox Passive Context.app` and `dist/Glassbox-Passive-Context-0.1.0.dmg`
- `dist/Glassbox Process Context.app` and `dist/Glassbox-Process-Context-0.1.0.dmg`
- `dist/Glassbox Instruments Adapter.app` and `dist/Glassbox-Instruments-Adapter-0.1.0.dmg`

Local readiness requires Developer ID and Hardened Runtime signatures, the exact reviewed entitlement allowlist for each controller, entitlement-free Rust helpers where present, the exact one- or two-executable closure, a no-collection privacy manifest, and a signed valid DMG. The Instruments adapter is entitlement-free, contains one executable, invokes only the supported `xctrace` HAR export surface, and is never embedded in or launched by the App-Sandboxed core. Local readiness is readiness for Apple submission, not Gate 6 evidence.

Submit those exact apps and DMGs to the approved Apple notarization workflow. After Accepted status, staple and validate every app and DMG. Do not rebuild or re-sign any artifact after creating the frozen candidate manifest or beginning external review.

## Coordinated fresh-VM review

On one clean supported macOS VM, use the exact frozen artifacts and verify each adapter independently:

1. Gatekeeper acceptance, installation, first launch, and correct product identity.
2. Visible disclosure and explicit consent before collection.
3. The intended bounded capture, persistent state, explicit stop, and private non-overwriting export.
4. Permission denial, malformed input, broker failure, revoke, and reset behavior without partial publication.
5. Uninstall and residue behavior while preserving user-selected exports.
6. Keyboard-only use, visible focus, VoiceOver labels/status, and truthful disclosures.

For the Instruments adapter specifically, use a reviewed non-sensitive Network `.trace`; verify explicit selection, successful conversion and offline core import, compatible-Xcode-unavailable behavior, cancellation and temporary-file cleanup, and the warning that HAR may contain sensitive HTTP metadata.

Copy `AUXILIARY-ADAPTER-EVIDENCE.template.json` beside the six required redacted attachments, fill only observed results, and have the independent reviewer sign the JSON as attached DER CMS with the approved reviewer certificate. Then run strict verification:

```sh
GLASSBOX_CANDIDATE_MANIFEST=/absolute/path/to/glassbox-candidate-manifest.json \
GLASSBOX_AUXILIARY_FRESH_VM_CMS=/absolute/path/to/auxiliary-adapters.cms \
GLASSBOX_AUXILIARY_REVIEWER_CA=/absolute/path/to/reviewer-ca.pem \
  scripts/glassbox/run_auxiliary_adapter_artifact_readiness.sh \
  artifacts/glassbox-auxiliary-adapters-final.json
```

The strict verifier rejects missing or partial configuration, signature or CA failure, stale or future reviewer time, unknown fields, incomplete or non-boolean checks, duplicate or escaping attachments, candidate drift, artifact hash drift, invalid signing or entitlement posture, missing staples, or Gatekeeper rejection. A local app lifecycle receipt cannot substitute for this distribution evidence.
