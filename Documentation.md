# TripWire Technical Documentation

## 1. Overview
TripWire is a runtime containment and security gateway system for AI agents. It ensures that untrusted content (like documents processed by agents) cannot grant authority to perform sensitive actions. It operates as a centralized single enforcement point that evaluates every message and tool execution request against a signed task policy manifest.

The project is implemented in pure Python (requires Python 3.10+) and has **no external dependencies**, relying entirely on the standard library.

## 2. Core Components

The codebase in the `tripwire/` directory is modularized into several key responsibilities:

- **Protocol & Envelopes (`protocol.py`)**: Defines the `v2` message envelope schema, canonical JSON generation, and cryptographic signing (`KeyRing`/`Signer`). It strictly validates payload schemas to prevent malformed or malicious payloads.
- **Message Gateway (`gateway.py`)**: Acts as the central validation pipeline. Every agent-to-agent message must pass a sequence of checks (schema, firewall, authentication, replay, rate limiting, and action policy) before delivery.
- **Firewall (`firewall.py`)**: Manages the system's state machine (`NORMAL` -> `BLOCKING` -> `LOCKDOWN`). If the system detects malicious activity crossing a threshold, it automatically enters `LOCKDOWN`, blocking all protected actions and inter-agent messages.
- **Task Manifest (`manifest.py`)**: Defines `ManifestAuthority` and `PolicyTemplate`. It issues signed task policies that dictate allowed tools, data scopes, destination endpoints, limits, and required approvals for a specific task.
- **Capability Tool Gateway (`tools_gateway.py`)**: Evaluates `tool.request` envelopes against the signed task manifest. It verifies arguments, data scopes, intent, evidence provenance, canary tokens, and limits. It returns `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`.
- **Agents (`agents.py`)**: 
  - *Agent 1 (Monitor)*: Ingests events, tracks risk scores, and requests actions based on findings.
  - *Agent 2 (Validator)*: Validates actions and ensures intent aligns with system policies.
- **Adversary (`attacks.py`)**: Contains Agent 3, a built-in adversarial agent used to simulate 10 different attack scenarios (e.g., tampering, replay, forged sender) to test gateway resilience.
- **Trust Context & Provenance (`context.py`)**: Defines trust boundaries (`system_policy`, `user_task`, `document`, `tool_output`). Ensures that evidence cited for a tool call genuinely originates from a trusted context.
- **Approvals (`approvals.py`)**: Queues high-risk but policy-permitted actions (e.g., bank changes, out-of-limit payments) for human review.

## 3. Trust Model & Security Architecture

TripWire treats the **Gateway**, **Firewall**, **Key Ring**, and **Audit Key** as the **Trusted Computing Base (TCB)**. 
- Agents are treated as potentially compromised entities.
- Browser input is fully untrusted and validated upon entry.
- A **Default Deny** approach is enforced: a message is only delivered or a tool executed if all sequential checks pass.
- **Blast Radius Tracking (`lineage.py`, `report.py`)**: Computes the severity of what was attempted versus what successfully executed, providing a real-time view of compromised data or tools.

## 4. Message & Execution Lifecycle

When an Agent proposes a tool (e.g., `create_payment_draft`), the lifecycle follows these steps:
1. **Agent 1** drafts a proposal with justification and evidence, signing it as a `tool.request`.
2. **Gateway Pipeline** inspects the envelope for structural integrity, authentication (HMAC), rate limits, and replay attacks.
3. **Capability Checks**: The `ToolGateway` validates the requested tool against the task's signed manifest. It checks if the data scope is allowed, if the destination is approved, and whether the intent matches the task goal.
4. **Decision**:
   - **ALLOW**: Tool is executed safely.
   - **BLOCK**: Tool execution is aborted; event is logged in the HMAC audit chain.
   - **REQUIRE_APPROVAL**: The action is paused and placed in the `ApprovalQueue` for an operator to review.

## 5. Risk Scoring & Firewall Pressure

TripWire employs a deterministic risk model (`risk.py`):
- Security events add weighted points to an incident's severity index (0-100).
- Automatic firewall `LOCKDOWN` is triggered based on "intrusion pressure" derived from protocol violations (e.g., `BAD_MAC` counts heavily, `RATE_LIMITED` counts less).
- Recovery from a lockdown requires an operator-supplied recovery code.

## 6. Audit & Evidence

Every decision, state transition, and payload delivery is recorded in an HMAC-chained audit log (`audit.py`). Any tampering, reordering, or deletion of history breaks the hash chain, immediately highlighting unauthorized edits.
