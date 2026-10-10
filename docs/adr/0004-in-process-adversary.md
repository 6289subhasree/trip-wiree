# ADR 0004: Simulate the adversary with in-process fixtures

**Status:** Accepted (current implementation decision; documented with the architecture work).

## Context

The project needs to show how Relay handles representative malicious or malformed inputs while keeping a hackathon demonstration contained and predictable.

## Decision

Construct local envelopes and transformations for payload tampering, message replay, forged sender names, and schema-invalid telemetry. Do not create network traffic or attack external systems.

## Trade-offs

Fixtures are deterministic, safe to test, and require no external target. They do not model a real attacker controlling a host, stealing keys, evading monitoring, or exploiting a transport implementation.

## Consequences

Tests and reviewers can inspect exact input/output behaviour. UI labels and documentation must call these cases simulations, not live attacks. Future threat-model expansion must remain explicitly authorized and isolated.
