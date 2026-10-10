# ADR 0003: Record alerts in a local JSONL outbox

**Status:** Accepted (current implementation decision; documented with the architecture work).

## Context

Threshold crossing should have a visible side effect, but a hackathon demo should not send real email, require credentials, or depend on an external notification provider.

## Decision

Append one JSON object per alert to a configurable local JSON Lines file. Use `demo-operator@example.invalid` as an explicitly non-deliverable placeholder recipient.

## Trade-offs

The file is easy to inspect and needs no service account. It has no delivery guarantee, retry queue, rotation policy, or coordination between multiple processes. A failed filesystem write raises an error and is not retried.

## Consequences

Alert behaviour remains local and reproducible. Resetting the in-memory demo session does not remove historical outbox records. Documentation must not describe this as email delivery.

## Update (hackday, protocol v2)

The outbox is now `MockEmailService` (`tripwire/notifications.py`). It records **every email attempt** with status `SIMULATED_DELIVERY`, `BLOCKED` or `REJECTED`, plus the correlation id and the denial code. Only authorised deliveries are appended to `outbox.jsonl`. Recipients come from server-side configuration (`soc-oncall@tripwire.invalid`), never from the message. Each session uses a fresh file in a per-session temp directory, and the path is printed at startup.
