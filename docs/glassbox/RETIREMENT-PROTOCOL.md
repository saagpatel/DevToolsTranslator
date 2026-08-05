# Glassbox Donor Retirement Protocol

Status: accepted for Gate 0 review
Owner: product authority and release owner

Every candidate retirement record must be signed as attached DER CMS by the product authority and chain to the explicitly supplied retirement-authority CA. Unsigned JSON, a self-declared signer field, or hash-matched files without that authenticated envelope cannot promote Gate 7. Evidence paths must be relative, traversal-free, and free of symlink components. The two qualifying releases must use distinct semantic versions, release timestamps, and artifact evidence. Future-dated release, soak, defect, or approval timestamps fail closed, and the final `as_of` timestamp must not precede soak completion, the last defect scan, or approval.

Copying code does not retire a product. Grotto and NetworkDecoder remain expert tools. NetworkMapper remains separate/manual-only. Codec, Pulse Orbit, and Echolocate are candidates only after the requirements below pass.

## Required evidence per retirement candidate

- A feature/workflow parity matrix with addressable tests and migration instructions.
- Import/export compatibility from the donor's last supported format.
- Two successful Glassbox releases containing the replacement capability.
- At least a 30-day soak after the second release.
- No open P0/P1 parity, privacy, performance, accessibility, or fidelity defect.
- Donor expert workflow verified either in Glassbox or a deliberately retained tool.
- Final clean/tagged donor release with exact commit and dependency/security posture.
- Rollback instructions to the last supported donor build.
- Explicit product-authority approval before archival.

## Archive posture

Never delete donor history. Preserve tags, releases, source, issues/decisions needed for provenance, and a final README naming Glassbox or the retained expert tool. Archive read-only only after remote state and rollback artifacts are verified.

Strict verification requires all three candidate CMS records together:

```sh
GLASSBOX_CANDIDATE_MANIFEST=/absolute/path/to/glassbox-candidate-manifest.json \
GLASSBOX_RETIREMENT_AUTHORITY_CA=/absolute/path/to/product-authority-ca.pem \
GLASSBOX_CODEC_RETIREMENT_EVIDENCE=/absolute/path/to/codec-retirement.cms \
GLASSBOX_PULSE_RETIREMENT_EVIDENCE=/absolute/path/to/pulse-orbit-retirement.cms \
GLASSBOX_ECHOLOCATE_RETIREMENT_EVIDENCE=/absolute/path/to/echolocate-retirement.cms \
  scripts/glassbox/run_program_readiness.sh
```

## Rollback

If a post-retirement parity failure appears, unarchive or direct users to the tagged donor release while repairing Glassbox. Do not rewrite retirement evidence or conceal the regression.
