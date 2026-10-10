# TripWire Protocol

A local-first defensive-security hackathon demo: two trusted agents exchange authenticated messages and trigger an alert when a threshold is crossed, while a third agent simulates attacks against the protocol. A fail-closed firewall switch blocks processing and notifications.

## Features

- **Sentinel (Agent A):** creates telemetry events.
- **Relay (Agent B):** verifies signatures, timestamps, sender identity, payload shape, and replay protection.
- **Adversary (Agent C):** simulates tampering, replay, malformed payloads, and forged-sender cases entirely in-process.
- **Firewall kill switch:** blocks message processing while engaged.
- **Local notification outbox:** logs threshold alerts as JSON Lines; it does not send real email.

> This is an application-level simulation, not an operating-system firewall or production security product. The adversary does not scan networks or send external traffic.

## Quick start

Requires Python 3.10+. No third-party packages required.

```bash
python -m tripwire --demo
python -m tripwire --attack-demo
python -m unittest discover -s tests -v
```

Optional environment variables: `TRIPWIRE_THRESHOLD` (default `75`), `TRIPWIRE_FIREWALL=on` to start with the firewall engaged, and `TRIPWIRE_OUTBOX` to choose the outbox path.

The built-in secret is for local demonstration only. A deployment should use secret management, key rotation, durable replay state, and explicit configuration for any real email provider.

## Protocol

Each envelope includes a version, unique message ID, sender, timestamp, payload, and HMAC-SHA256 signature. The receiver validates the signature using constant-time comparison and checks freshness, sender allowlist, payload shape, duplicate IDs, and firewall state before accepting events.

## Layout

```text
tripwire/
  __init__.py
  __main__.py
  protocol.py
  firewall.py
  notifications.py
  agents.py
tests/
  test_protocol.py
pyproject.toml
```
