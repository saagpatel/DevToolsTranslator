# Glassbox Benchmark Protocol

Status: accepted for Gate 0 review
Owner: product authority and independent benchmark reviewer

## Purpose

Measure whether Glassbox improves evidence-supported investigation without increasing unsupported causal claims, privacy failures, permission surprises, or observer effect.

## Corpus

Maintain at least 25 held-out variants across five mystery families:

1. Upload coinciding with an app freeze.
2. One action producing a request cascade.
3. DNS delay versus connection reuse/cached lookup.
4. Backend latency during local CPU/disk/memory contention.
5. Deliberately insufficient evidence whose correct conclusion is `unknown`.

Every family includes counterfactual and negative-control variants plus burst, corruption, truncation, clock-skew, missing-span, encryption, privacy, crash, and high-cardinality cases. Designers and implementers do not see held-out answer keys.

The checked-in `mystery-families.json` file is a public 60-scenario rehearsal corpus for rendering, epistemic invariants, failure variants, and scoring-tool mechanics. It is explicitly labeled `public_rehearsal_not_held_out`; its expected statuses are visible and it is never eligible as formal efficacy evidence. The independent benchmark reviewer creates and retains the real held-out corpus and answer keys outside implementer access, publishing a frozen manifest hash before collection and only the allowed study artifacts afterward.

## Scoring rubric

Primary measures:

- Correct evidence-supported conclusion and correct `unknown` rate.
- Time to first evidence-supported conclusion.
- Unsupported causal-claim rate.
- Evidence-link and provenance accuracy.

Safety/operational measures:

- Seeded-secret leakage.
- Permission surprises or silent escalation.
- Capture/import overhead, unmarked drops, crash recovery, and accessibility completion.

Goldens score structured claims, relations, evidence, counterevidence, and missing evidence—not prose.

## Study sequence

1. Freeze the exact clean-tree candidate manifest, rubric, exclusions, comparator tasks, training, instrumentation, and analysis plan.
2. Run a randomized, counterbalanced 10-12 participant pilot against the relevant existing toolchain.
3. Use pilot variance for a power analysis; do not claim efficacy from the pilot.
4. Pre-register the formal sample size, primary outcome, statistical test, exclusions, and stopping rule.
5. Run the held-out formal study with independent scoring and blinded adjudication of disagreements.

Agents may build fixtures and scoring tools but do not substitute for human participants.

`scripts/glassbox/validate_benchmark_results.py` validates the required external artifact shape, frozen-candidate digest, record hashes, and product thresholds. Structural validation does not authenticate participant identity, preregistration, or study records; an independent reviewer must verify those primary sources and sign a second payload bound to both the study artifact and the same candidate manifest. The signed payload must carry typed, relative-path, SHA-256 attachments for the participant registry, study records, scoring export, adjudication log, preregistration record, held-out corpus manifest, and metric recomputation output. Every attachment must be a distinct regular file confined beside the CMS envelope, and its digest must match the corresponding hash in the study artifact. Bare booleans or hash strings without the bound files cannot promote. `scripts/glassbox/run_benchmark_readiness_gate.sh` must report `benchmark_passed: false` and `gate6_promotable: false` until a genuine external artifact passes that review and validation.

## Product targets

- At least 90% of conclusions cite addressable evidence.
- Under 5% unsupported causal claims.
- Zero seeded-secret leakage.
- Every dropped, truncated, opaque, or clock-uncertain region is visible.
- A meaningful improvement in time to evidence-supported conclusion, supported by the formal study rather than assumed as 30% from an underpowered pilot.

## Stop rule

If held-out results fail epistemic, privacy, or workflow gates, do not consolidate or retire donors. Repair the smallest causal failure class, preserve the preregistered result, create new held-out variants, and rerun only under a documented follow-up protocol.
