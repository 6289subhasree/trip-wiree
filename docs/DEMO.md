# TripWire: 3-minute judge demo

## Before judges arrive (2 min)

```powershell
Set-Location -LiteralPath 'C:\Users\MOUSHIMI\tripwire_in\tripwire_in\trip-wiree'
python -m unittest discover -t . -s tests      # expect: OK (54 tests)
$env:TRIPWIRE_RECOVERY_CODE = "TW-JUDGE-42"
python -m tripwire serve --open
```

- Keep the terminal visible on a second window. It shows the recovery code and the outbox and audit file paths.
- Browser zoom at 80-90% so the status row, the flow diagram and the guided demo panel fit on one screen.
- If anything looks off: **Reset demo** (top right). If the firewall isn't NORMAL, recover first. Reset deliberately won't clear LOCKDOWN.
- Fallback with no browser: `python -m tripwire demo` and `python -m tripwire attack-demo`.

## Script (press *Run next step* in "Guided demo")

| # | Say (about 15 s each) | Point at |
|---|---|---|
| — | "Agents now send each other instructions and trigger actions like email. TripWire is a policy-enforced gateway between them. Nothing reaches another agent or an action without passing through it." | Flow diagram |
| 1 | "Fresh start, strict profile." | Firewall NORMAL, metrics 0 |
| 2 | "Agent 1 watches a security event stream and scores risk. Normal traffic: signed, verified, accepted, no email." | Decision feed, green rows |
| 3 | "An incident unfolds: failed logins, port scan, privilege escalation, malware. The score crosses 70. Agent 1 asks Agent 2 to alert; Agent 2 re-checks and asks the gateway for the email action. Exactly one simulated email, with the same correlation id end to end." | Risk gauge, outbox `SIMULATED`, last decision panel (nested action) |
| 4 | "Agent 3 attacks. It tampers with a captured message and forges Agent 2's identity to email itself. Both fail the HMAC check, and nothing reaches the outbox." | Red rows `BAD_MAC`, outbox unchanged |
| 5 | "Operator hits the kill switch. That's real backend state, not a UI colour." | Firewall BLOCKING, agents shown as isolated |
| 6 | "Agent 1 tries the alert again. It's blocked, and the outbox records a BLOCKED attempt with no delivery. The message is also burned, so it can't be replayed later." | Outbox `BLOCKED` row |
| 7 | "Release, and let the attacker run all ten scenarios: replay, stale injection, reordering, privilege escalation with a stolen key, recipient injection, flooding. Each one is stopped by a specific check. Intrusion pressure builds until the gateway locks itself down **automatically**." | Attack results table, pressure meter, red LOCKDOWN banner |
| 8 | "Every decision is in an HMAC-chained audit log." Then click **Tamper a record** and **Verify chain**: "an intruder edits one record and we find exactly which one." | Audit panel toast |
| 9 | "Only the operator's recovery code gets us out." Type `TW-JUDGE-42` and press Recover. | Firewall NORMAL |

## The "why it matters" closer (30 s)

Click **Baseline (insecure, for comparison)**, then launch *Forged sender*, *Privilege escalation* and *Recipient injection*. The outbox fills with deliveries to `exfil@attacker.invalid` (shown in red). Click **Strict** and run them again: rejected, 0 unauthorized emails. The terminal `attack-demo` prints the measured matrix: baseline 6 unauthorized emails, strict 0.

## Likely judge questions

- **"Is the block real?"** Yes. The firewall check and the email side effect run under one lock. A concurrency test races 8 senders against the kill switch and proves no email is written after the transition.
- **"What if an agent's key is stolen?"** It can still send in-policy messages as that agent, and we say so. But it can't reach the email action directly (route policy), can't choose recipients (strict schema, server-side recipients), can't flood (rate limit), gets one email per incident, and the pressure-based lockdown contains it.
- **"Is the risk score a probability?"** No. It's a deterministic 0-100 severity index: a decayed sum of signal weights. The same stream gives the same scores every run.
- **"Why HMAC instead of signatures?"** We stayed standard-library-only for reliability. Each agent has its own key; the gateway is the trusted verifier. Ed25519 is the production upgrade (ADR 0005).
- **"Does it send email?"** Never. Every record is `simulated: true`, and there's no network code.
