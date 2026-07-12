# Glassbox Donor Retirement Protocol

Status: accepted for Gate 0 review
Owner: product authority and release owner

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

## Rollback

If a post-retirement parity failure appears, unarchive or direct users to the tagged donor release while repairing Glassbox. Do not rewrite retirement evidence or conceal the regression.
