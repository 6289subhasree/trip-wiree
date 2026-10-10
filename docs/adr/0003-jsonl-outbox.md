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
