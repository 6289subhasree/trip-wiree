# TripWire: Comprehensive Technical Architecture & Documentation

TripWire is a deterministic runtime security gateway for autonomous AI agents. It protects AI systems against indirect prompt injections, confused deputy attacks, and authorization bypasses by placing a zero-trust cryptographic gateway (a "Firewall") between cognitive agents and their execution environments.

This document serves as the **deeply detailed** technical reference for the architecture, file structure, component relationships, data schemas, and execution flows of the project.

---

## 1. System Architecture: The Three-Agent Topology

TripWire operates on a strict **Three-Agent Topology** simulation with a split backend/frontend boundary. The core philosophy is **"Content is Evidence. Never Authority."**

1. **Agent 1 (Cognitive Writer / Planner):** 
   - **Role:** Ingests human intent (e.g., "Draft an invoice") and synthesizes the payload or tool call.
   - **Risk:** Highly vulnerable to indirect prompt injections hiding in the context window (e.g., inside an invoice document).
2. **TripWire Gateway (Firewall & Validator):** 
   - **Role:** Intercepts all outgoing tool calls from Agent 1. It verifies intent against allowed data classes, enforces policy schemas, evaluates risk scores, and verifies HMAC signatures across the audit chain. 
   - **Action:** Can block threats (generating SOC alerts) or allow safe execution by cryptographically signing the payload.
3. **Agent 2 (Verifier / Executor):** 
   - **Role:** Executes kinetic actions (e.g., `send_email` or `execute_payment`).
   - **Constraint:** Will *only* execute a payload if it carries a valid HMAC signature from the TripWire Gateway.
4. **Agent 3 (Attacker / Threat Actor):** 
   - **Role:** Simulates external threats that continuously attempt to inject malicious instructions into Agent 1's context window.

---

## 2. Global Directory Structure

```text
trip-wiree/
├── pyproject.toml              # Python project and dependency configuration
├── README.md                   # High-level overview
├── ARCHITECTURE.md             # Theoretical security model and cryptography details
├── generate_whitepaper.py      # Script to compile the LaTeX academic whitepaper
├── tests/                      # Extensive test suite (230+ tests)
├── docs/                       # LaTeX Whitepapers and generated PDFs
├── tripwire/                   # Core Python Backend Package
│   ├── __main__.py             # Entry point (`python -m tripwire serve`)
│   ├── server.py               # HTTP Server routing (Classic UI + Next.js out + API)
│   ├── demo_sim.py             # 3-Agent Attack/Defense Pipeline State Machine
│   ├── session.py              # Global orchestrator, state manager, and memory
│   ├── firewall.py             # Threat blocking and state machine logic
│   ├── gateway.py              # The core TripWire Gateway and Rule Engine
│   ├── attacks.py              # Defines adversarial prompt injection scenarios
│   ├── agents.py               # EventMonitor and Validator agent classes
│   ├── notifications.py        # SMTP / Outbox mocking and SOC alerts
│   ├── approvals.py            # Human-in-the-loop and HMAC cryptographic signatures
│   ├── protocol.py             # HMAC signing and Canonicalization logic
│   ├── intent.py               # Intent resolution and payload data classification
│   ├── scenarios.py            # Pre-defined simulation attack vectors
│   ├── planner.py              # LLM logic / deterministic mock execution
│   └── web/                    # Classic Vanilla JS Web UI
│       ├── app.js              # Vanilla dashboard logic
│       ├── app.css             # Vanilla dashboard styles
│       └── *.html              # Classic views (arena, evidence, console)
└── vantage/                    # Next.js Modern Frontend
    ├── app/                    # Next.js App Router (page.tsx, layout.tsx)
    ├── components/             # Reusable React components (Header, Background)
    └── out/                    # Static Export (Served by `tripwire/server.py`)
```

---

## 3. Core Backend Modules & API Surface (`tripwire/`)

### `tripwire/server.py`
The backbone of the application. It spins up a `ThreadingHTTPServer` (port 3000 by default).
*   **Routing Logic:** 
    *   Serves the modern Next.js static build from `vantage/out` (if it exists) for paths like `/`.
    *   Serves the classic Vanilla UI from `tripwire/web/` as fallbacks (`/classic`, `/console`).
    *   Hosts the unified REST API (`/api/tasks/start`, `/api/replay`, `/api/health`, `/api/demo/execute`, `/api/chat`).
*   **Security:** Enforces strict `Content-Security-Policy` headers (`default-src 'self'`). Drops cross-origin requests.

### `tripwire/session.py`
The global orchestrator. Manages the lifecycle of a simulation session.
*   **Key Classes & Methods:**
    *   `class Session`: Holds the `Firewall`, `Vault`, `AuditLog`, `Toolbox`, and `ApprovalQueue`.
    *   `start_task()`: Initializes a new simulation task with a specific document and intent.
    *   `run_agent()`: Invokes Agent 1 (`Planner`) to synthesize a tool call based on the document.
    *   `chat_request(message, session_id, attack_simulation)`: Facilitates direct interaction with the pipeline.
    *   `replay()`: Automatically runs an entire simulation end-to-end (baseline vs protected) for the dashboard.

### `tripwire/firewall.py` & `tripwire/gateway.py`
The enforcement engine and cryptographic authority.
*   **`class Firewall`:**
    *   State Machine: Transitions between `NORMAL`, `BLOCKING`, and `LOCKDOWN`.
    *   If risk thresholds are exceeded rapidly, transitions to `BLOCKING`, severing the egress pipeline completely.
*   **`class Gateway`:**
    *   Intercepts `tool_call` requests.
    *   Validates intent: Calls `intent.evaluate()` to ensure the tool call matches the authorized human goal.
    *   If validation passes, calls `protocol.resign()` to append a cryptographic HMAC to the payload.
    *   If validation fails, raises `FirewallError` or `ApprovalError`.

### `tripwire/protocol.py` & `tripwire/approvals.py`
The zero-trust cryptographic layer.
*   **`protocol.py`:**
    *   `canonical_bytes()`: Converts JSON payloads into deterministic byte strings for hashing.
    *   `compute_mac()`: Generates an HMAC-SHA256 signature using a specific agent's private key.
    *   `check_structure()`: Enforces a strict JSON schema for all inter-agent messages.
*   **`class ApprovalQueue`:**
    *   Manages human-in-the-loop (HITL) overrides.
    *   When an intent mismatches but is not outright malicious, it drops into an approval queue for the human operator to manually sign off.

### `tripwire/planner.py` & `tripwire/agents.py`
The AI simulation layer.
*   **`class DeterministicPlanner`:** A mock implementation of Agent 1 that consistently synthesizes payloads based on the input scenarios, guaranteeing deterministic test results without requiring an actual LLM during CI/CD.
*   **`class EventMonitor` & `class Validator`:** Monitors telemetry and calculates running risk scores (`RiskModel`).

### `tripwire/notifications.py`
Mocks kinetic tool execution.
*   **`class MockEmailService`:**
    *   Verifies `TRIPWIRE_PASSWORD`.
    *   Dumps simulated outbound emails to a local JSONL outbox instead of the real network.
    *   Generates **SOC Alerts** when the firewall blocks a payload, notifying the operator of an attempted prompt injection (`UNTRUSTED_AUTHORITY`).

---

## 4. Frontend Architecture

### The Next.js UI (`vantage/`)
A premium, dark-mode glassmorphic interface built with Next.js 14 and React.
*   **Landing Page (`vantage/app/page.tsx`):** The marketing and overview portal with dynamic CSS grid backgrounds and telemetry components.
*   **Interactive Simulation Dashboard:** A split-screen layout dividing:
    *   **Attacker Dashboard:** (Crimson theme) Features raw terminal outputs showing exactly what the attacker injected into the prompt.
    *   **Defender Dashboard:** (Cyan theme) Features an interactive `AgentTopology` SVG map that pulses as the payload moves from User -> Agent 1 -> Gateway -> Agent 2. Displays the gateway intercept ledger.
*   **Static Export:** The Next.js app is completely statically exported (`next build` outputs to `vantage/out`). The Python backend directly mounts and serves these static HTML files.

### The Classic UI (`tripwire/web/`)
A pure Vanilla JS/HTML5 implementation ensuring zero heavy dependencies.
*   **`app.js`**: Handles Vanilla DOM manipulation and `fetch()` calls. 
*   **`arena.html` / `evidence.html`**: Tables and graphs rendering the underlying data structures, correlation IDs, and HMAC chains directly from the `GET /api/tasks/{id}/timeline` endpoint.

---

## 5. Security Model & Testing

TripWire adheres to strict test-driven development (TDD) and cryptographic security:

1. **Provable Execution:** Agent 2 (the Executor) will crash if the payload lacks a valid HMAC signature from the Gateway. Agent 1 does not possess the signing keys.
2. **Deterministic Risk:** The `RiskModel` analyzes rapid sequential failures (e.g., brute force tool calls) and dynamically trips the firewall threshold.
3. **Data Classification (Data-as-Evidence):** Content parsed from external documents (like an invoice) is flagged as `UNTRUSTED_AUTHORITY`. The Gateway restricts `UNTRUSTED` data from being used in sensitive tool fields (like the `destination` of an email).
4. **Test Suite (`tests/`):** 
    *   Contains 230+ unit tests.
    *   Tests validate deterministic generation, firewall state transitions, HMAC tampering detection (`test_chain_verifies_and_detects_tampering`), and UI adherence to the CSP.
    *   Run via: `python3.11 -m unittest discover tests/ -v`
