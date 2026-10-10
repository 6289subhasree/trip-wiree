# ADR 0007: Deliberately insecure "baseline" gateway profile for comparison

**Status:** Accepted (added on hackday, 10-11 Oct 2026).

## Context

Showing that attacks are "rejected" doesn't show what they would have *done* without the controls. Judges need to see the counterfactual.

## Decision

The gateway has a `baseline` profile that skips sender registration, MAC, route, freshness, replay, sequence, rate-limit and strict-payload checks. It also lets the validator pass through a sender-supplied `to` field, which mirrors a naive agent framework. The firewall still applies in baseline.

## Safeguards

- `strict` is always the default, and every profile change is audited.
- The dashboard shows a full-width red warning banner while baseline is active.
- Tests assert that baseline is measurably vulnerable (unauthorized emails > 0) and that strict produces 0 for the same scenarios.

## Consequences

`python -m tripwire attack-demo` prints a side-by-side matrix measured from real runs.
