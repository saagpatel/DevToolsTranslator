# ADR-013: Source Trust And Conflicts

Status: accepted for Gate 0 review
Owner: kernel owner and product authority

## Decision

Source trust is a non-ordinal provenance label, not an evidence grade or numeric score:

- `authenticated_local`: attached through an OS/code-signature authenticated local channel; says nothing about content truth.
- `signed_untrusted`: signature is valid but signer authority is not trusted by policy.
- `source_declared`: source identifies itself without independently authenticated authority.
- `unsigned_import`: imported material has no verified signer.
- `user_asserted`: an explicit operator marker or annotation.
- `unknown`: provenance cannot be established.

Revocation is a separate lifecycle state. Transport authentication, integrity, authority, coverage, and epistemic status remain separate fields.

## Conflict behavior

Trust labels never silently select a winning observation or create a causal relation. Conflicting sources remain visible with their provenance, native evidence, clock/coverage limitations, and explicit conflict relation. Deterministic joins require their own rule basis. A user may annotate a preferred hypothesis, but that annotation is `user_asserted` and does not rewrite source evidence.

## Display rules

Every investigation exposes source trust and its exact meaning. `authenticated_local` is worded as “local source authenticated,” not “verified evidence.” `signed_untrusted` is worded as “signature valid; signer authority unknown.” Unknown trust fails closed for export authenticity and automated cross-source joins that require authenticated identity.

## Oracle

Fixtures cover valid/invalid signatures, unknown authority, authenticated transport with false content, revoked sources, conflicting observations, and operator annotations. No trust label promotes `correlated` or `inferred` to `observed`.
