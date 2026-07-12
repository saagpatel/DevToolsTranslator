# Glassbox Product Contract

Status: accepted for Gate 0 review
Decision owner: product authority

## Promise

Glassbox helps an investigator answer, “What did the selected evidence show, how are these observations related, what remains uncertain, and what evidence would reduce that uncertainty?”

Glassbox does not promise universal Mac observability or automatic root cause.

## MVP evidence envelope

| Source | Allowed scope | Required user action | Unsupported implication |
|---|---|---|---|
| Chrome | One foreground, user-selected tab | Explicit attach and visible capture | Other tabs, browser history, or arbitrary app activity |
| Instrumented app | App-owned OTel, logs, signposts, or manual markers | App/operator instrumentation | Global user input or uninstrumented runtime internals |
| Imports | User-selected HAR, PCAP/PCAPNG, OTLP, `.logarchive`, Instruments, and Glassbox bundle | File selection | Original file ownership or process attribution not present in the source |
| Resource sampler | Bounded read-only system/process session | Visible start/stop | Cause of a freeze from temporal overlap alone |
| Passive context | `arp -a`-style logical device/service context where ordinary access permits | Explicit enable | Physical topology, ownership, or packet attribution |

## Epistemic contract

- **Observed:** directly recorded by a named source with an addressable native locator.
- **Correlated:** linked by a declared deterministic or bounded matching rule; no causal assertion.
- **Inferred:** proposed by a versioned rule or model with premises, alternatives, counterevidence, and a falsifier.
- **Unknown:** evidence is missing, opaque, dropped, redacted, conflicting, unsupported, or temporally unreliable.

Coverage, clock quality, sampling, truncation, integrity, and privacy are independent dimensions. A high-quality observation can still be incomplete; an exact trace parent edge does not prove that resource pressure caused a symptom.

## Primary investigation workflow

1. Show capture/import scope, permission tier, privacy mode, clocks, gaps, drops, and opaque regions.
2. Anchor on a symptom, action, request, span, process, or time interval.
3. Present a virtualized actor-lane timeline and complete tabular equivalent.
4. Explain every relation through “Why are these linked?” with basis and uncertainty.
5. Compare competing hypotheses and counterevidence.
6. Compare a bad run with a healthy run.
7. Resolve every conclusion to native evidence.
8. Export only through a field-level redaction preview.

## Acceptance oracle

Each advertised workflow must map to permitted sources. If a requested chain cannot be supported from those sources, the UI must return `unknown`, name the missing evidence, and propose the smallest safe next source. No silent permission escalation is allowed.

## Failure and rollback

An adapter that violates the envelope is independently disableable. Investigations remain readable from immutable evidence and compatible bundle exports without that adapter.
