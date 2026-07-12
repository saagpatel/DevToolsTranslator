# ADR-004: Evidence, Relation, Claim, And Coverage Ontology

Status: accepted for Gate 0 review
Owner: kernel owner and product authority

## Decision

The model has separate immutable native artifacts, normalized observations, entities, relations, claims, and coverage/loss records.

Relations carry one provenance class:

- `source_asserted`
- `deterministic_join`
- `heuristic_join`
- `user_asserted`
- `model_generated`

Every relation records rule/adapter version, input IDs, exact basis, clock uncertainty, supporting evidence, counterevidence, missing evidence, and a falsifier where applicable.

Claims use only `observed`, `correlated`, `inferred`, or `unknown`. These labels do not encode completeness, integrity, source trust, clock quality, sampling, or privacy; those remain separate fields.

## Causal wording

Source structure such as trace parentage or browser initiator is described as that source's asserted structure. It is not automatically a real-world causal effect. Causal effect requires explicit instrumentation semantics or a documented intervention/counterfactual.

## Rejected

DTT `verified` as a generic truth grade, one uncalibrated confidence score, model promotion of grades, or destructive normalization that loses the native locator.

## Oracle

Property tests prove models cannot emit observed claims, temporal-only joins cannot emit causal wording, every conclusion resolves to evidence, and missing/contradictory inputs yield `unknown`.
