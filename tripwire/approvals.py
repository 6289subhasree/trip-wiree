"""Human approval boundary (PRD 7.8).

When the tool gateway returns ``REQUIRE_APPROVAL`` it files a pending approval here and the
tool does **not** run. Only an operator can decide it, through ``Session.decide_approval`` (the
dashboard endpoint behind the CSRF guard). There is no message type, route or tool through
which an agent could approve anything: an agent can only *cause* an approval to be requested.

Approving is not executing. After an approval the gateway re-checks the firewall and the
manifest (``ToolGateway.execute_approved``); a LOCKDOWN, an expired capability or a tampered
manifest still stops the action, and the approval is spent either way.

Triggers: a payment above the task limit, a vendor bank-account change, a new vendor, and any
outbound email or upload to a non-internal destination.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, Iterable, List, Optional

from .tools_gateway import masked

PENDING = "PENDING"
APPROVED = "APPROVED"        # decided, execution in progress (transient)
EXECUTED = "EXECUTED"        # approved and the tool ran
BLOCKED = "BLOCKED"          # approved, but the re-check at execution time refused it
REJECTED = "REJECTED"
EXPIRED = "EXPIRED"

DEFAULT_TTL_S = 10 * 60


class ApprovalError(PermissionError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


class ApprovalQueue:
    def __init__(self, *, clock: Callable[[], float] = time.time, audit: Any = None, ttl_s: float = DEFAULT_TTL_S,
                 operators: Iterable[str] = ("operator",), agent_ids: Iterable[str] = ()):
        self.clock, self.audit, self.ttl_s = clock, audit, ttl_s
        self.operators = frozenset(operators)
        self.agent_ids = frozenset(agent_ids)
        self.items: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ filed by the gateway
    def create(self, task: Any, verdict: Any) -> str:
        approval_id = f"apr-{len(self.items) + 1:04d}"
        now = self.clock()
        amount = verdict.args.get("amount") if verdict.tool == "create_payment_draft" else None
        self.items[approval_id] = {
            "id": approval_id, "task_id": task.task_id, "status": PENDING, "created_at": now,
            "expires_at": now + self.ttl_s, "manifest_hash": task.signed.hash, "request_n": verdict.n,
            # requested action
            "tool": verdict.tool, "args": dict(verdict.args), "destinations": list(verdict.destinations),
            # agent justification
            "justification": {"purpose": verdict.purpose, "task_link": verdict.task_link,
                              "agent_risk_level": verdict.risk_level},
            # evidence source, with provenance and whether the gateway could verify it
            "evidence": [dict(e) for e in verdict.evidence],
            "untrusted_only": not any(e["authorising"] for e in verdict.evidence),
            # affected data
            "affected_data": list(verdict.resources), "data_classes": list(verdict.data_classes),
            "amount_inr": float(amount) if amount is not None else None,
            # risk
            "risk": verdict.risk, "triggers": list(verdict.triggers), "reason": verdict.reason,
            "review": verdict.intent, "lineage_id": None,
            "decided_by": None, "decided_at": None, "outcome": None,
        }
        self._audit("approval.requested", approval_id)
        return approval_id

    # ------------------------------------------------------------------ decided by the operator
    def decide(self, approval_id: Any, approve: Any, approver: Any) -> Dict[str, Any]:
        if not isinstance(approve, bool):
            raise ApprovalError("APPROVAL_INVALID", "decision must be approve or reject")
        item = self.items.get(approval_id) if isinstance(approval_id, str) else None
        if item is None:
            raise ApprovalError("APPROVAL_UNKNOWN", "no such approval request")
        if not isinstance(approver, str) or approver in self.agent_ids or approver not in self.operators:
            self._audit("approval.refused", approval_id, attempted_by=str(approver)[:64])
            raise ApprovalError("APPROVER_NOT_AUTHORISED", "only a human operator can decide an approval")
        if item["status"] != PENDING:
            raise ApprovalError("APPROVAL_ALREADY_DECIDED", f"approval is already {item['status']}")
        now = self.clock()
        if now >= item["expires_at"]:
            item["status"], item["outcome"] = EXPIRED, {"code": "APPROVAL_EXPIRED", "reason": "approval window elapsed"}
            self._audit("approval.expired", approval_id)
            raise ApprovalError("APPROVAL_EXPIRED", "approval window elapsed; the agent must ask again")
        item["status"] = APPROVED if approve else REJECTED
        item["decided_by"], item["decided_at"] = approver, now
        if not approve:
            item["outcome"] = {"executed": False, "code": "APPROVAL_REJECTED", "reason": "rejected by the operator"}
        self._audit("approval.decided", approval_id)
        return item

    def settle(self, approval_id: str, outcome: Dict[str, Any]) -> Dict[str, Any]:
        """Record what happened when the gateway tried to run an approved action."""
        item = self.items[approval_id]
        item["status"] = EXECUTED if outcome.get("executed") else BLOCKED
        item["outcome"] = outcome
        self._audit("approval.executed" if outcome.get("executed") else "approval.blocked", approval_id)
        return item

    # ------------------------------------------------------------------ views
    def pending(self, task_id: Optional[str] = None) -> List[Dict[str, Any]]:
        now = self.clock()
        return [i for i in self.items.values()
                if i["status"] == PENDING and now < i["expires_at"] and task_id in (None, i["task_id"])]

    def for_task(self, task_id: str) -> List[Dict[str, Any]]:
        return [i for i in self.items.values() if i["task_id"] == task_id]

    def view(self, item: Dict[str, Any]) -> Dict[str, Any]:
        out = masked(dict(item))
        if item["status"] == PENDING and self.clock() >= item["expires_at"]:
            out["status"] = EXPIRED
        return out

    def _audit(self, kind: str, approval_id: str, **extra: Any) -> None:
        if self.audit is None:
            return
        item = self.items.get(approval_id, {})
        self.audit.append(kind, masked({
            "approval_id": approval_id, "task_id": item.get("task_id"), "tool": item.get("tool"),
            "status": item.get("status"), "triggers": item.get("triggers"), "decided_by": item.get("decided_by"),
            "outcome": item.get("outcome") and {k: item["outcome"].get(k) for k in ("executed", "code", "reason")},
            **extra}))
