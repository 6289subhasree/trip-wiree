# ADR 0005: Protocol v2 with per-agent HMAC keys

**Status:** Accepted (added on hackday, 10-11 Oct 2026).

## Context

Protocol v1 signed every envelope with one shared secret. Any agent, including a compromised one, could therefore produce valid messages *as any other agent*. The "forged sender" check only compared a string field. The envelope also lacked a receiver, a message type, a nonce, a sequence number and a correlation id, so route policy, replay-by-nonce, ordering and end-to-end tracing could not be enforced.

## Decision

- Every registered agent gets its own random 32-byte key (`secrets.token_bytes`) and a `key_id`. The agent's `Signer` holds only its own key. The gateway's `KeyRing` holds all verification keys.
- The MAC (HMAC-SHA256 over canonical JSON) covers every envelope field plus `alg` and `key_id`.
- The envelope schema is exact (no extra or missing fields). Payload schemas are strict per `message_type`.
- The route table (`protocol.ROUTES`) is the allowlist of who may send which type to whom.

## Trade-offs

This is still symmetric cryptography: the gateway could forge messages, and there is no non-repudiation. Ed25519 would fix that but needs a third-party package. We chose to stay standard-library-only so the project runs reliably on any venue laptop. Keys are per-process and in memory, with no rotation or persistence.

## Consequences

A key compromise is now limited to that one agent's identity *and* its allowed routes. For example, a stolen Monitor key cannot call the email action (`UNAUTHORIZED_ROUTE`). Attacker-held keys produce `BAD_MAC`/`UNKNOWN_SENDER`.
