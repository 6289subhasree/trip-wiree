"""The two trusted agents. Neither one can bypass the gateway: they only *produce* envelopes,
and the session hands every envelope to ``Gateway.submit``. The Validator is invoked only by
the gateway, and only for messages that already passed every gateway check."""
from __future__ import annotations

import uuid
from typing import Any, Callable, Dict, Optional, Tuple

from .protocol import ALERT, EMAIL_ACTION, EMAIL_SEND, TELEMETRY, VALIDATOR, Signer
from .risk import WEIGHTS, RiskModel


class EventMonitor:
    """Agent 1 - watches a simulated event stream, scores risk, and requests alerts."""

    def __init__(self, signer: Signer, threshold: Callable[[], float]):
        self.signer = signer
        self.threshold = threshold
        self.model = RiskModel()
        self.incident: Optional[str] = None     # correlation id of the open incident
        self.incident_delivered = False
        self.last_status = "idle"

    @property
    def agent_id(self) -> str:
        return self.signer.agent_id

    def observe(self, event: str) -> Dict[str, Any]:
        self.model.ingest(event)
        return self._compose(source=f"event:{event}")

    def observe_score(self, score: float) -> Dict[str, Any]:
        self.model.override(score)
        return self._compose(source="manual_score")

    def _compose(self, source: str) -> Dict[str, Any]:
        score, threshold = self.model.score, self.threshold()
        if score >= threshold:
            if self.incident is None:
                self.incident, self.incident_delivered = f"inc-{uuid.uuid4().hex[:10]}", False
            if not self.incident_delivered:
                return self.alert(self.incident)
        else:
            self.incident, self.incident_delivered = None, False
        self.last_status = f"telemetry score={score:g}"
        return self.signer.sign(VALIDATOR, TELEMETRY, {
            "risk_score": score, "signals": self.model.signals(), "source": source[:40]})

    def alert(self, correlation_id: Optional[str] = None) -> Dict[str, Any]:
        """Explicitly attempt the protected alert workflow for the current score."""
        score, threshold = self.model.score, self.threshold()
        corr = correlation_id or f"inc-{uuid.uuid4().hex[:10]}"
        self.last_status = f"alert requested score={score:g} (threshold {threshold:g})"
        return self.signer.sign(VALIDATOR, ALERT, {
            "risk_score": score, "threshold": threshold, "signals": self.model.signals(),
            "summary": f"Risk score {score:g} reached threshold {threshold:g}. Signals: "
                       f"{', '.join(self.model.signals()) or 'manual'}"[:200]}, correlation_id=corr)

    def acknowledge(self, correlation_id: str, delivered: bool) -> None:
        if delivered and correlation_id == self.incident:
            self.incident_delivered = True


class Validator:
    """Agent 2 - semantic validation of authenticated requests; asks the gateway for actions."""

    def __init__(self, signer: Signer, threshold: Callable[[], float]):
        self.signer = signer
        self.threshold = threshold
        self.naive = False  # mirrors the gateway's insecure baseline profile
        self.last_status = "idle"
        self.handled = 0

    @property
    def agent_id(self) -> str:
        return self.signer.agent_id

    def handle(self, wire: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]]]:
        self.handled += 1
        payload, mtype = wire["payload"], wire["message_type"]
        if mtype == TELEMETRY:
            self.last_status = f"telemetry ack score={payload['risk_score']:g}"
            return self.last_status, None
        if mtype == ALERT:
            score, threshold = float(payload["risk_score"]), self.threshold()
            if score < threshold:
                self.last_status = f"refused alert: score {score:g} < threshold {threshold:g}"
                return "refused: " + self.last_status, None
            action_payload: Dict[str, Any] = {
                "template": "threshold_alert", "incident_id": wire["correlation_id"],
                "risk_score": score, "summary": str(payload["summary"])[:200]}
            if self.naive and "to" in payload:  # the vulnerable baseline trusts sender-chosen recipients
                action_payload["to"] = payload["to"]
            self.last_status = f"alert validated score={score:g}; requesting email action"
            return "validated: requesting email action", self.signer.sign(
                EMAIL_ACTION, EMAIL_SEND, action_payload, correlation_id=wire["correlation_id"])
        self.last_status = f"ignored {mtype}"
        return "refused: unsupported message type", None


__all__ = ["EventMonitor", "Validator", "WEIGHTS"]
