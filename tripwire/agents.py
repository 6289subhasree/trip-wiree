"""Trusted agents and the in-process adversary simulator."""
from __future__ import annotations

import math
from dataclasses import dataclass, replace
from typing import Any

from .firewall import Firewall
from .notifications import JsonlOutbox
from .protocol import Envelope, ProtocolError, SignedProtocol


@dataclass(frozen=True)
class ReceiveResult:
    status: str
    detail: str
    alert_sent: bool = False


class SentinelAgent:
    """Agent A: trusted telemetry producer."""
    def __init__(self, protocol: SignedProtocol):
        self.protocol = protocol

    def report(self, metric: str, value: float) -> Envelope:
        return self.protocol.sign("sentinel", {"metric": metric, "value": value})


class RelayAgent:
    """Agent B: authenticates, validates, and routes events."""
    def __init__(self, protocol: SignedProtocol, firewall: Firewall, outbox: JsonlOutbox):
        self.protocol, self.firewall, self.outbox = protocol, firewall, outbox

    def receive(self, envelope: Envelope, threshold: float) -> ReceiveResult:
        if not self.firewall.permits():
            return ReceiveResult("BLOCKED", f"firewall engaged ({self.firewall.reason})")
        try:
            payload: dict[str, Any] = self.protocol.verify(envelope)
        except (ProtocolError, TypeError, ValueError) as exc:
            return ReceiveResult("REJECTED", str(exc))
        metric, value = payload.get("metric"), payload.get("value")
        if not isinstance(metric, str) or not metric.strip():
            return ReceiveResult("REJECTED", "metric must be a non-empty string")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return ReceiveResult("REJECTED", "value must be numeric")
        try:
            numeric_value = float(value)
        except (OverflowError, ValueError):
            return ReceiveResult("REJECTED", "value must be finite")
        if not math.isfinite(numeric_value):
            return ReceiveResult("REJECTED", "value must be finite")
        if value >= threshold:
            self.outbox.send_alert(metric, numeric_value, threshold, envelope.message_id)
            return ReceiveResult("ALERT", f"{metric}={value:g} crossed {threshold:g}", True)
        return ReceiveResult("ACCEPTED", f"{metric}={value:g} is below threshold {threshold:g}")


class AdversaryAgent:
    """Agent C: deterministic malicious-message fixtures; no network activity."""
    @staticmethod
    def tamper_value(envelope: Envelope, value: float) -> Envelope:
        return replace(envelope, payload={**envelope.payload, "value": value})

    @staticmethod
    def malformed_payload(envelope: Envelope, protocol: SignedProtocol | None = None) -> Envelope:
        payload = {"metric": ["not", "a", "string"], "value": "high"}
        if protocol is not None:
            return protocol.sign(envelope.sender, payload)
        return replace(envelope, payload=payload)

    @staticmethod
    def forge_sender(envelope: Envelope, sender: str) -> Envelope:
        return replace(envelope, sender=sender)

    @staticmethod
    def replay(envelope: Envelope) -> Envelope:
        return envelope
