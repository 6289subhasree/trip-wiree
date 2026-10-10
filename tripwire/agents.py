"""The two trusted agents. Neither one can bypass the gateway: they only *produce* envelopes,
and the session hands every envelope to ``Gateway.submit``. The Validator is invoked only by
the gateway, and only for messages that already passed every gateway check.

Each agent has two modes that run side by side:

* event mode (original): Agent 1 scores a security event stream and requests an alert at the
  threshold; Agent 2 validates the alert and asks the gateway for the SOC email.
* task mode (PRD): Agent 1 is the intake agent that proposes tool calls for a document task;
  Agent 2 is the policy validator that reviews each proposal against the manifest, keeps the
  task's risk score and raises the same SOC email when the threshold is crossed."""
from __future__ import annotations

import uuid
from typing import Any, Callable, Dict, Optional, Tuple

from . import intent as intent_rules
from .planner import DeterministicPlanner, Planner
from .protocol import ALERT, EMAIL_ACTION, EMAIL_SEND, TELEMETRY, TOOL_GATEWAY, TOOL_REQUEST, VALIDATOR, Signer
from .risk import TOOL_WEIGHTS, WEIGHTS, RiskModel


class EventMonitor:
    """Agent 1 - watches a simulated event stream, scores risk, and requests alerts."""

    def __init__(self, signer: Signer, threshold: Callable[[], float]):
        self.signer = signer
        self.threshold = threshold
        self.model = RiskModel()
        self.incident: Optional[str] = None     # correlation id of the open incident
        self.incident_delivered = False
        self.last_status = "idle"
        self.planner: Planner = DeterministicPlanner()   # task mode; rule-based, no model, no network

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

    # -- task mode (intake agent) ---------------------------------------------------------
    def request_tool(self, task_id: str, manifest_hash: str, correlation_id: str,
                     proposal: Dict[str, Any]) -> Dict[str, Any]:
        """Sign a ``tool.request`` for the gateway. This is the only thing Agent 1 can do about
        a tool: propose it, with a justification. It holds no tool handles."""
        self.last_status = f"proposed {str(proposal.get('tool'))[:40]} for task {task_id}"
        return self.signer.sign(TOOL_GATEWAY, TOOL_REQUEST, {
            "task_id": task_id, "manifest_hash": manifest_hash, "tool": proposal.get("tool"),
            "args": proposal.get("args", {}), "purpose": proposal.get("purpose"),
            "task_link": proposal.get("task_link"), "evidence": proposal.get("evidence"),
            "resources_requested": proposal.get("resources_requested", []),
            "destination": proposal.get("destination"), "risk_level": proposal.get("risk_level", "low"),
        }, correlation_id=correlation_id)


class Validator:
    """Agent 2 - semantic validation of authenticated requests; asks the gateway for actions."""

    def __init__(self, signer: Signer, threshold: Callable[[], float]):
        self.signer = signer
        self.threshold = threshold
        self.naive = False  # mirrors the gateway's insecure baseline profile
        self.last_status = "idle"
        self.handled = 0
        self.reviewed = 0
        self.task_risk: Dict[str, RiskModel] = {}
        self.task_alerted: Dict[str, float] = {}

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

    # -- task mode (policy validator) -----------------------------------------------------
    def review(self, manifest: Any, verdict: Any) -> Dict[str, Any]:
        """Semantic review of one proposal against the manifest the gateway just verified.

        Two questions, both answered without reading the agent's wording as an instruction:
        does the *effect* of the tool fit the task, and does any *verified trusted* source stand
        behind the request? The gateway treats the findings as additional violations only.
        """
        self.reviewed += 1
        approval_effects = {p.effect for p in intent_rules.TOOL_PROFILES.values()
                            if p.approval_trigger and p.approval_trigger in manifest.approval_required}
        external = [d for d in verdict.destinations if not intent_rules.destination_is_internal(d)]
        action = intent_rules.classify(verdict.tool, verdict.resources,
                                       external[0] if external else (verdict.destinations or [None])[0],
                                       extra_classes=verdict.data_classes)
        result = intent_rules.evaluate(manifest.goal, manifest.goal_effects, manifest.allowed_data, action,
                                       approval_effects)
        findings = []
        if result.mismatch:
            findings.append({"stage": "intent", "code": "INTENT_MISMATCH",
                             "reason": f"intent mismatch {result.score}/100: " + "; ".join(result.reasons)})
        trusted = [e for e in verdict.evidence if e["authorising"]]
        if not trusted:
            cited = ", ".join(f"{(e.get('source') or {}).get('context', '?')}:{(e.get('source') or {}).get('id', '?')}"
                              f"{'' if e['verified'] else ' (unverified)'}" for e in verdict.evidence)
            findings.append({"stage": "evidence", "code": "UNTRUSTED_AUTHORITY",
                             "reason": f"the only reason given comes from untrusted content ({cited}); "
                                       f"documents and tool outputs are evidence, not authority"})
        self.last_status = (f"reviewed {verdict.tool}: " + (", ".join(f["code"] for f in findings) or "in scope"))
        return {"intent": result.to_dict(), "findings": findings,
                "ok": {"intent": f"effect {', '.join(sorted(action.effects))} fits the task",
                       "evidence": f"{len(trusted)} verified trusted source(s) behind the request"}}

    def observe(self, task: Any, verdict: Any) -> Optional[Dict[str, Any]]:
        """Fold the gateway's decision into the task's risk score; alert the SOC at the threshold.

        The alert is the one email that is allowed: an ``action.email.send`` to the server-side
        SOC recipient, through the gateway, at most once per task.
        """
        if self.naive:
            return None
        model = self.task_risk.setdefault(task.task_id, RiskModel())
        weight = 0.0 if verdict.decision == "ALLOW" else TOOL_WEIGHTS.get(verdict.code, 20)
        score, threshold = model.ingest_weight(verdict.code, weight), self.threshold()
        verdict.task_risk = score
        if score < threshold or task.task_id in self.task_alerted:
            return None
        self.task_alerted[task.task_id] = score
        self.last_status = f"task {task.task_id} risk {score:g} >= {threshold:g}; requesting SOC email"
        summary = (f"Task {task.task_id}: agent risk {score:g} reached threshold {threshold:g}. "
                   f"Last: {verdict.code} on {verdict.tool}. Signals: {', '.join(model.signals())}")
        return self.signer.sign(EMAIL_ACTION, EMAIL_SEND, {
            "template": "threshold_alert", "incident_id": task.correlation_id, "risk_score": score,
            "summary": summary[:200]}, correlation_id=task.correlation_id)


IntakeAgent = EventMonitor       # Agent 1, task mode name
PolicyValidator = Validator      # Agent 2, task mode name

__all__ = ["EventMonitor", "Validator", "IntakeAgent", "PolicyValidator", "WEIGHTS"]
