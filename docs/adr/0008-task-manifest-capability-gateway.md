# ADR 0008: Task-scoped manifest and a capability tool gateway on top of the message gateway

**Status:** Accepted (phase 2, 10 Oct 2026).

## Context

Version 0.2 authenticated and validated messages between agents, but an authenticated agent that had been misled by a document could still ask for anything its route allowed. The PRD's rule is that untrusted content may supply evidence and can never grant authority. That needs a notion of what one task is allowed to do, and a place where every tool call is checked against it.

## Decision

1. **One manifest per task.** `ManifestAuthority.issue()` builds a frozen `Manifest` from a system-policy template (tools, forbidden tools, destinations, limit, approval rules) and the user's task (goal and records). It is signed with a gateway-only HMAC key and its hash is written to the audit log. There is no amend operation.
2. **Tool calls are messages.** A new message type `tool.request` (Agent 1 → `gateway:tools`) carries the PRD justification. It passes the existing envelope pipeline first, so authentication, replay protection, schemas, rate limits and the firewall apply unchanged.
3. **A second pipeline behind the first.** `ToolGateway` evaluates: manifest validity, arguments, tool, data scope, destination, intent, evidence provenance, canary egress, thresholds, approval rules. Every stage is evaluated and recorded; the first violated stage gives the decision code. A tool function is called only on `ALLOW` or after a re-checked approval.
4. **Agent 2 stays behind the gateway.** The gateway does the manifest, scope and destination stages itself. It consults Agent 2 for intent and evidence authority, and treats the findings as additional violations only.
5. **Evidence is verified, not believed.** The gateway holds the task goal and documents, so a claim labelled `user_task` must be in the goal, a document quote must be in the document, and a policy clause must be in the manifest.
6. **Approval-gated actions escalate.** When an action falls under an approval rule and its only evidence is untrusted, the gateway pauses it for a person instead of refusing it. The approver becomes the authority and the card says the evidence is untrusted.
7. **Low pressure weights for tool refusals** (2-6, against 40-50 for forged or misrouted envelopes), so one misled task cannot trigger automatic lockdown while the full channel-attack sequence still does.

## Alternatives considered

- **Checking tool calls inside Agent 2.** Rejected: enforcement would depend on an agent, and a compromised validator could allow anything.
- **Blocking on the instruction detector.** Rejected: any heuristic can be rephrased around. The detector is kept for display only.
- **A separate HTTP gateway process.** Out of scope for a single-file offline demo; the trust boundary is the same lock-protected call path.

## Consequences

- Authority has exactly two sources: the signed manifest and a human approval. Both are checked at execution time.
- Every refusal names a rule, so the ledger explains itself.
- The baseline profile now also skips the capability checks and executes tool requests unchecked, recording what the protected gateway would have decided. It is used by the replay view in throwaway sessions and remains a labelled counterfactual (see ADR 0007).
- A new tool needs an argument schema, an effect class and a data class before it can be requested. That is deliberate.
- A compromised Agent 2 can fail to report an intent mismatch for a call that is otherwise inside the manifest. It cannot widen the manifest or approve anything.
- The PRD's `new_vendor` trigger exists, but the PRD's tool list has no create-vendor tool; an unknown vendor is refused earlier, by data scope.
