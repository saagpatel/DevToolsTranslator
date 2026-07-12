# ADR-003: Clock Domains, Uncertainty, And Ordering

Status: accepted for Gate 0 review
Owner: kernel owner

## Decision

Represent event time as a bounded interval in a named clock domain, not a scalar global timestamp. A clock descriptor records source clock type, unit, resolution, calibration anchors, offset estimate, drift/error bound, boot/sleep/reset segment, and whether the clock is local, imported, or remote.

Nanosecond bounds use signed 128-bit integers in the Rust kernel and canonical decimal strings on JSON/IPC wires. JSON numbers are forbidden for these bounds because browser and JavaScript intermediaries cannot preserve the full integer range.

For interval `A=[a0,a1]` and `B=[b0,b1]`:

- `A before B` only when `a1 < b0` or the source asserts an addressable ordering.
- `A after B` only when `b1 < a0` or the source asserts it.
- Otherwise their order is `indeterminate`; the UI may show overlap but may not invent a sequence or duration between them.

Monotonic time orders events only inside the same uninterrupted clock segment. Sleep, wake, reboot, process restart, browser restart, clock adjustment, and import boundaries create explicit segments. Remote traces without trustworthy alignment remain remote-domain observations.

## Rejected

Sorting scalar epoch timestamps as ground truth, silently estimating missing precision, or converting adjacency into cause.

## Oracle

Clock-overlap, drift, sleep/wake, reset, remote-skew, missing-anchor, precision-loss, and conflicting-source fixtures must downgrade ordering and explanatory language deterministically.
