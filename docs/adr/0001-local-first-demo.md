# ADR 0001: Keep the demonstration local-first

**Status:** Accepted (current implementation decision; documented with the architecture work).

## Context

The project needs to be easy to launch and safe to demonstrate on a developer's machine without cloud accounts, network exposure, or external dependencies. The three agent roles are conceptual participants in a protocol flow.

## Decision

Run one Python process with a standard-library HTTP server bound to `127.0.0.1` by default. Pass agent messages directly in process. Serve a static dashboard from that local server.

## Trade-offs

This avoids dependency setup, deployment configuration, and remote attack surface. It does not demonstrate real transport security, independent process identity, multi-host behaviour, or production isolation. The optional host override can expose the service if misused.

## Consequences

A reviewer can launch the whole demo locally with Python alone. Documentation must call out loopback binding and advise against public exposure. Any future remote-agent design needs a separate transport and authentication threat model.
