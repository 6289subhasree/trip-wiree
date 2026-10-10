# ADR 0006: Firewall state machine enforced inside the gateway lock

**Status:** Accepted (added on hackday, 10-11 Oct 2026).

## Context

The v1 firewall was a boolean checked by the receiver. Nothing guaranteed that a request which saw "off" couldn't finish its side effect after the switch was turned on. There was also no distinction between an operator kill switch and an emergency lockdown, and no recovery procedure.

## Decision

- States `NORMAL`, `BLOCKING` (operator kill switch, operator-releasable) and `LOCKDOWN` (manual or automatic, cleared only by `recover(code)`).
- The gateway's entire pipeline, including the email side effect, runs while holding `Firewall.lock`, and every transition takes the same lock. A transition is therefore totally ordered against every decision, and a concurrency test asserts that no email is ever audited after a BLOCKING transition.
- While engaged, *all* agent messages and protected actions are denied. Authentic, otherwise-valid denied messages have their nonce and sequence number *burned*, so captured traffic can't be replayed after recovery.
- Automatic lockdown is driven by *intrusion pressure*: each rejection adds a severity weight, and the total decays with a 120 s half-life. Crossing the threshold (default 200) triggers LOCKDOWN.
- Recovery uses a constant-time code comparison. Five failures within five minutes start a 60 s cooldown. The code is printed on the server console and never returned by the API. Demo reset preserves the current mode, so reset can't bypass LOCKDOWN.

## Trade-offs

A single lock serializes all traffic. That's fine for a demo throughput, and it's the simplest way to make correctness obvious. The pressure weights are heuristic and documented, not learned.
