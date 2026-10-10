"""Capability tool gateway (PRD 7.4): the only way an agent can reach a tool.

An agent never calls a tool. It signs a ``tool.request`` envelope carrying a structured
justification (PRD 7.6) and submits it to ``Gateway.submit`` like any other message. After the
envelope checks pass, the request lands here and goes through these stages, in order:

    manifest validity -> arguments -> tool allowed/forbidden -> data scope -> destination ->
    intent-to-task -> evidence provenance -> canary egress -> thresholds -> approval rules ->
    execute

The decision is ``ALLOW``, ``BLOCK`` or ``REQUIRE_APPROVAL``. A tool function is called only on
``ALLOW`` (or later, on an operator approval that is re-checked). Every stage is evaluated and
recorded so the ledger can show every violated rule; the decision code is the first violation
in stage order.

Authority comes from the signed manifest and from human approval, never from the request's
wording or from the document it quotes. The intent and evidence stages are performed by
Agent 2 (the policy validator); its findings can only add violations. The manifest, scope and
destination stages are done here and do not depend on any agent.

Everything in this module runs while the caller holds ``Firewall.lock``.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .context import DOCUMENT, SYSTEM_POLICY, TOOL_OUTPUT, USER_TASK, CONTEXTS, Labelled, Provenance
from .intent import TOOL_PROFILES, data_class_of, destination_is_internal
from .manifest import (BANK_ACCOUNT_CHANGE, EXTERNAL_DESTINATION, NEW_VENDOR, PAYMENT_OVER_LIMIT, Manifest,
                       ManifestAuthority, ManifestError, PolicyTemplate, SignedManifest)

ALLOW = "ALLOW"
BLOCK = "BLOCK"
REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

STRICT = "strict"
BASELINE = "baseline"

# Stage order; the first violated stage supplies the decision code.
STAGES = ("manifest", "arguments", "tool", "data_scope", "destination", "intent", "evidence", "canary",
          "threshold", "approval")

CANARY_RE = re.compile(r"TRIPWIRE-CANARY-[A-Z0-9]+(?:-[A-Z0-9]+)*")
ARTIFACT_RE = re.compile(r"\bart-\d{4}\b")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")

OPEN = "open"
AWAITING_APPROVAL = "awaiting_approval"
COMPLETED = "completed"


def mask_canary(token: str) -> str:
    """Canary values are never shown in full: keep the prefix and the last two characters."""
    return "TRIPWIRE-CANARY-" + "*" * 6 + token[-2:] if CANARY_RE.fullmatch(token) else "*" * 8


def mask_text(text: str) -> str:
    return CANARY_RE.sub(lambda m: mask_canary(m.group(0)), text)


def masked(value: Any) -> Any:
    """Deep copy of a JSON-like value with every canary token masked."""
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, dict):
        return {mask_text(k) if isinstance(k, str) else k: masked(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [masked(v) for v in value]
    return value


# ---------------------------------------------------------------------------
# Tool argument schemas (exact keys, typed, bounded)
# ---------------------------------------------------------------------------
def _id(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID_RE.match(value))


def _amount(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < float(value) <= 1e9


def _str(limit: int) -> Callable[[Any], bool]:
    return lambda v: isinstance(v, str) and 0 < len(v) <= limit


TOOL_ARGS: Dict[str, Dict[str, Callable[[Any], bool]]] = {
    "extract_invoice_fields": {"invoice_id": _id},
    "get_vendor_record": {"vendor_id": _id},
    "create_payment_draft": {"invoice_id": _id, "amount": _amount},
    "change_vendor_bank_account": {"vendor_id": _id, "bank": _str(120)},
    "export_customer_list": {},
    "get_customer_records": {},
    "send_email": {"destination": _str(80), "body": _str(600)},
    "upload_external_file": {"destination": _str(80), "data": _str(600)},
}


def resources_for(tool: str, args: Dict[str, Any]) -> List[str]:
    """Records a tool call touches, derived from the tool and its arguments (not from the agent's claim)."""
    if tool in ("extract_invoice_fields", "create_payment_draft"):
        return [f"invoice:{args.get('invoice_id')}"]
    if tool in ("get_vendor_record", "change_vendor_bank_account"):
        return [f"vendor:{args.get('vendor_id')}"]
    if tool in ("export_customer_list", "get_customer_records"):
        return ["customer:*"]
    return []


class ToolError(Exception):
    """A tool refused its input (unknown record and so on). Not a policy decision."""


# ---------------------------------------------------------------------------
# Tasks, registry, verdicts
# ---------------------------------------------------------------------------
@dataclass
class Task:
    task_id: str
    goal: Labelled
    signed: SignedManifest
    documents: Dict[str, str]
    correlation_id: str
    created_at: float
    state: str = OPEN
    closed_reason: str = ""
    scenario: Optional[str] = None
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    verdicts: List["ToolVerdict"] = field(default_factory=list)
    artifacts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    outputs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def manifest(self) -> Manifest:
        return self.signed.manifest

    def log(self, kind: str, at: float, **data: Any) -> Dict[str, Any]:
        event = {"seq": len(self.timeline) + 1, "at": at, "kind": kind, **masked(data)}
        self.timeline.append(event)
        return event

    def add_artifact(self, kind: str, *, content: str, resources: List[str], records: List[str],
                     canaries: List[str], transformation: str) -> str:
        handle = f"art-{len(self.artifacts) + 1:04d}"
        self.artifacts[handle] = {"handle": handle, "kind": kind, "content": content, "resources": list(resources),
                                  "records": list(records), "canaries": list(canaries),
                                  "transformation": transformation,
                                  "classes": sorted({c for c in map(data_class_of, resources) if c})}
        return handle


class ToolRegistry:
    """The tool functions, plus a per-tool execution counter that tests and the UI read."""

    def __init__(self) -> None:
        self._tools: Dict[str, Callable[[Dict[str, Any], Task], Dict[str, Any]]] = {}
        self.executions: Dict[str, int] = {name: 0 for name in TOOL_ARGS}
        self.log: List[Dict[str, Any]] = []

    def register(self, name: str, fn: Callable[[Dict[str, Any], Task], Dict[str, Any]]) -> None:
        self._tools[name] = fn
        self.executions.setdefault(name, 0)

    def has(self, name: str) -> bool:
        return name in self._tools

    def count(self, name: str) -> int:
        return self.executions.get(name, 0)

    def run(self, name: str, args: Dict[str, Any], task: Task, at: float) -> Dict[str, Any]:
        """Call the tool. Only ``ToolGateway`` calls this, and only after an ALLOW or an approval."""
        fn = self._tools[name]
        self.executions[name] = self.executions.get(name, 0) + 1
        entry = {"n": len(self.log) + 1, "at": at, "tool": name, "task_id": task.task_id, "ok": True}
        self.log.append(entry)
        try:
            return fn(dict(args), task)
        except ToolError as exc:
            entry["ok"] = False
            return {"error": str(exc)}


@dataclass
class ToolVerdict:
    task_id: str
    tool: str
    args: Dict[str, Any]
    purpose: str
    task_link: str
    risk_level: str                      # what the agent declared
    declared_resources: List[str]
    destination: str
    at: float
    profile: str = STRICT
    decision: str = BLOCK
    code: str = ""
    reason: str = ""
    violations: List[Dict[str, str]] = field(default_factory=list)
    checks: List[Dict[str, Any]] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    destinations: List[str] = field(default_factory=list)
    data_classes: List[str] = field(default_factory=list)
    canaries: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    intent: Optional[Dict[str, Any]] = None
    risk: str = "low"                    # what the gateway computed
    executed: bool = False
    result: Optional[Dict[str, Any]] = None
    approval_id: Optional[str] = None
    lineage_id: Optional[str] = None
    counterfactual: bool = False
    would: Optional[Dict[str, Any]] = None   # baseline only: what the protected gateway would decide
    task_risk: Optional[float] = None
    manifest_hash: Optional[str] = None
    n: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Display form. Canary values are masked; nothing here is secret key material."""
        return masked(dict(self.__dict__))

    def summary(self) -> Dict[str, Any]:
        return {"task_id": self.task_id, "tool": self.tool, "decision": self.decision, "code": self.code,
                "codes": [v["code"] for v in self.violations], "triggers": list(self.triggers),
                "executed": self.executed, "approval_id": self.approval_id, "manifest_hash": self.manifest_hash,
                "resources": list(self.resources), "destinations": list(self.destinations),
                "counterfactual": self.counterfactual}


class Reviewer:
    """What the gateway needs from Agent 2. ``agents.Validator`` implements it."""

    def review(self, manifest: Manifest, verdict: ToolVerdict) -> Dict[str, Any]:  # pragma: no cover
        raise NotImplementedError

    def observe(self, task: Task, verdict: ToolVerdict) -> Optional[Dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError


# ---------------------------------------------------------------------------
# The gateway
# ---------------------------------------------------------------------------
class ToolGateway:
    def __init__(self, authority: ManifestAuthority, registry: ToolRegistry, *,
                 clock: Callable[[], float] = time.time, audit: Any = None):
        self.authority, self.registry, self.clock, self.audit = authority, registry, clock, audit
        self.tasks: Dict[str, Task] = {}
        self.approvals: Any = None          # set by the session (tripwire.approvals.ApprovalQueue)
        self.lineage: Any = None            # set by the session (tripwire.lineage.LineageLog)
        self.vendor_exists: Callable[[str], bool] = lambda vendor_id: True
        self._n = 0

    # ------------------------------------------------------------------ tasks
    def open_task(self, *, task_id: str, goal: Labelled, template: PolicyTemplate, allowed_data: List[Labelled],
                  documents: Optional[Dict[str, str]] = None, ttl_s: float = 900.0,
                  scenario: Optional[str] = None) -> Task:
        if task_id in self.tasks:
            raise ManifestError("MANIFEST_INVALID", f"task '{task_id[:40]}' already exists")
        signed = self.authority.issue(task_id=task_id, goal=goal, template=template, allowed_data=allowed_data,
                                      ttl_s=ttl_s)
        now = self.clock()
        task = Task(task_id, goal, signed, dict(documents or {}), f"task-{task_id}", now, scenario=scenario)
        self.tasks[task_id] = task
        task.log("task.assigned", now, source=goal.provenance.to_dict(), action=goal.text,
                 decision="-", code="-", reason="task assigned by the user; manifest issued and signed",
                 risk="low", data_scope=list(signed.manifest.allowed_data), manifest_hash=signed.hash)
        if self.audit is not None:
            self.audit.append("task.start", {"task_id": task_id, "goal": goal.text, "manifest_hash": signed.hash,
                                             "key_id": signed.key_id, "manifest": signed.manifest.to_dict(),
                                             "documents": sorted(task.documents), "scenario": scenario})
        return task

    def close_task(self, task_id: str, reason: str = "task completed") -> None:
        task = self.tasks.get(task_id)
        if task is None or task.state == COMPLETED:
            return
        task.state, task.closed_reason = COMPLETED, reason
        task.log("task.closed", self.clock(), source={"context": SYSTEM_POLICY, "id": "gateway", "trust": "trusted"},
                 action="capability expired", decision="-", code="-", reason=reason, risk="low", data_scope=[])
        if self.audit is not None:
            self.audit.append("task.close", {"task_id": task_id, "reason": reason,
                                             "manifest_hash": task.signed.hash})

    # ------------------------------------------------------------------ entry point
    def handle(self, wire: Dict[str, Any], profile: str, reviewer: Optional[Reviewer]) \
            -> Tuple[ToolVerdict, Optional[Dict[str, Any]]]:
        """Evaluate one authenticated ``tool.request``; execute it only if allowed.

        Returns the verdict and, optionally, an envelope Agent 2 wants sent next (the SOC alert).
        """
        p = wire["payload"]
        self._n += 1
        v = ToolVerdict(task_id=p["task_id"], tool=p["tool"], args=dict(p["args"]), purpose=p["purpose"],
                        task_link=p["task_link"], risk_level=p["risk_level"],
                        declared_resources=list(p["resources_requested"]), destination=p["destination"],
                        at=self.clock(), profile=profile, manifest_hash=p["manifest_hash"], n=self._n)
        task = self.tasks.get(v.task_id)
        manifest = self._evaluate(v, task, p, reviewer, naive=profile == BASELINE)
        self._decide(v, manifest)

        if profile == BASELINE:
            # Counterfactual red-team profile: record what the protected gateway would have said,
            # then run the tool anyway. Arguments must still be well formed for the tool to run.
            v.counterfactual = True
            v.would = {"decision": v.decision, "code": v.code, "reason": v.reason,
                       "codes": [x["code"] for x in v.violations], "triggers": list(v.triggers)}
            runnable = task is not None and self.registry.has(v.tool) and self._args_ok(v.tool, v.args)
            if runnable:
                v.decision, v.code = ALLOW, "BASELINE_UNCHECKED"
                v.reason = "baseline (counterfactual): no policy checks; tool executed as requested"
            else:
                v.decision = BLOCK
                v.code = v.code if v.code in ("PAYLOAD_INVALID", "CAPABILITY_EXPIRED") else "TOOL_NOT_IN_MANIFEST"
                v.reason = "baseline: request cannot run (" + v.reason + ")"

        if v.decision == ALLOW:
            self._execute(v, task)
        elif v.decision == REQUIRE_APPROVAL and self.approvals is not None:
            v.approval_id = self.approvals.create(task, v)
            task.state = AWAITING_APPROVAL

        outbound = None
        if task is not None:
            if reviewer is not None:
                outbound = reviewer.observe(task, v)
            if self.lineage is not None:
                v.lineage_id = self.lineage.record(task, v)
            task.verdicts.append(v)
            self._timeline(task, v)
        return v, outbound

    # ------------------------------------------------------------------ stages
    def _check(self, v: ToolVerdict, stage: str, code: Optional[str], detail: str) -> None:
        v.checks.append({"stage": stage, "ok": code is None, "code": code, "detail": detail})
        if code is not None:
            v.violations.append({"stage": stage, "code": code, "reason": detail})

    @staticmethod
    def _args_ok(tool: str, args: Dict[str, Any]) -> bool:
        schema = TOOL_ARGS.get(tool)
        return schema is not None and set(args) == set(schema) and all(ok(args[k]) for k, ok in schema.items())

    def _evaluate(self, v: ToolVerdict, task: Optional[Task], p: Dict[str, Any], reviewer: Optional[Reviewer],
                  naive: bool) -> Optional[Manifest]:
        # 1. manifest validity -------------------------------------------------------------
        if task is None:
            self._check(v, "manifest", "CAPABILITY_EXPIRED", "no active capability: unknown task")
            return None
        try:
            manifest = self.authority.verify(task.signed, presented_hash=p["manifest_hash"])
        except ManifestError as exc:
            self._check(v, "manifest", exc.code, exc.detail)
            return None
        if task.state == COMPLETED:
            self._check(v, "manifest", "CAPABILITY_EXPIRED", f"capability expired: {task.closed_reason}")
            return None
        if self.authority.expired(manifest):
            self._check(v, "manifest", "CAPABILITY_EXPIRED", "capability expired: manifest lifetime elapsed")
            return None
        self._check(v, "manifest", None, f"manifest {task.signed.hash[:12]} verified and active")

        # 2. arguments ---------------------------------------------------------------------
        known = v.tool in TOOL_ARGS
        if known and not self._args_ok(v.tool, v.args):
            self._check(v, "arguments", "PAYLOAD_INVALID",
                        f"arguments for {v.tool} must be exactly: {', '.join(TOOL_ARGS[v.tool]) or '(none)'}")
            return None
        self._check(v, "arguments", None, "arguments match the tool schema" if known else "unknown tool")

        # 3. tool allowed / forbidden ------------------------------------------------------
        profile = TOOL_PROFILES.get(v.tool)
        gated = bool(profile and profile.approval_trigger and profile.approval_trigger in manifest.approval_required)
        if v.tool in manifest.forbidden_tools:
            self._check(v, "tool", "TOOL_FORBIDDEN", f"{v.tool} is forbidden for this task")
        elif v.tool in manifest.allowed_tools:
            self._check(v, "tool", None, f"{v.tool} is in the manifest")
        elif gated:
            self._check(v, "tool", None, f"{v.tool} is not granted; possible only with approval "
                                         f"({profile.approval_trigger})")
        else:
            self._check(v, "tool", "TOOL_NOT_IN_MANIFEST", f"{v.tool[:40]} is not in the task manifest")

        # 4. data scope: resources derived from the arguments, the referenced artifacts and the
        #    agent's own declaration must all be inside allowed_data ------------------------
        payload_text = " ".join(str(x) for x in v.args.values() if isinstance(x, str))
        resources = resources_for(v.tool, v.args) if known else []
        extra_classes: List[str] = []
        canaries = set(CANARY_RE.findall(payload_text))
        for handle in dict.fromkeys(ARTIFACT_RE.findall(payload_text)):
            art = task.artifacts.get(handle)
            if art is not None:
                v.artifacts.append(handle)
                resources.extend(art["resources"])
                extra_classes.extend(art["classes"])
                canaries.update(art["canaries"])
        v.resources = list(dict.fromkeys(resources + v.declared_resources))
        outside = [r for r in v.resources if r not in manifest.allowed_data]
        if outside:
            self._check(v, "data_scope", "DATA_OUT_OF_SCOPE",
                        f"{', '.join(outside[:4])} outside task scope ({', '.join(manifest.allowed_data)})")
        else:
            self._check(v, "data_scope", None, "all records are inside the task scope")

        # 5. destination -------------------------------------------------------------------
        dests = [v.destination]
        if isinstance(v.args.get("destination"), str):
            dests.append(v.args["destination"])
        v.destinations = list(dict.fromkeys(d.strip() for d in dests))
        bad = [d for d in v.destinations if d not in manifest.allowed_destinations]
        if bad:
            self._check(v, "destination", "DESTINATION_NOT_ALLOWED",
                        f"destination {', '.join(x[:60] for x in bad)} is not allowlisted "
                        f"({', '.join(manifest.allowed_destinations)})")
        else:
            self._check(v, "destination", None, "destination is allowlisted")

        # 6 + 7. intent-to-task and evidence provenance (Agent 2; findings are additive only) -
        v.evidence = self._verify_evidence(task, manifest, p["evidence"])
        v.data_classes = sorted({c for c in map(data_class_of, v.resources) if c} | set(extra_classes)
                                | ({"canary"} if canaries else set()))
        v.canaries = sorted(canaries)
        if naive:
            self._check(v, "intent", None, "baseline: semantic review skipped")
        elif reviewer is None:
            self._check(v, "intent", "VALIDATOR_REFUSED", "no policy validator is registered; failing closed")
        else:
            review = reviewer.review(manifest, v)
            v.intent = review.get("intent")
            for stage in ("intent", "evidence"):
                found = [f for f in review.get("findings", []) if f["stage"] == stage]
                if found:
                    for f in found:
                        self._check(v, stage, f["code"], f["reason"])
                else:
                    self._check(v, stage, None, review.get("ok", {}).get(stage, "ok"))

        # 8. canary egress -----------------------------------------------------------------
        egress = bool(profile and profile.egress)
        if egress and canaries:
            self._check(v, "canary", "CANARY_EGRESS",
                        f"egress payload carries {len(canaries)} canary token(s): "
                        f"{', '.join(mask_canary(c) for c in sorted(canaries))}")
        else:
            self._check(v, "canary", None, "no canary in an egress payload")

        # 9. thresholds --------------------------------------------------------------------
        if v.tool == "create_payment_draft" and float(v.args["amount"]) > manifest.payment_limit_inr:
            detail = (f"payment draft of INR {float(v.args['amount']):,.0f} exceeds the task limit of "
                      f"INR {manifest.payment_limit_inr:,}")
            if PAYMENT_OVER_LIMIT in manifest.approval_required:
                v.triggers.append(PAYMENT_OVER_LIMIT)
                v.checks.append({"stage": "threshold", "ok": True, "code": None, "detail": detail + " (needs approval)"})
            else:
                self._check(v, "threshold", "PAYMENT_OVER_LIMIT", detail)
        else:
            self._check(v, "threshold", None, "within configured limits")

        # 10. approval rules (PRD 7.8) -----------------------------------------------------
        if profile and profile.approval_trigger == BANK_ACCOUNT_CHANGE:
            v.triggers.append(BANK_ACCOUNT_CHANGE)
        for resource in v.resources:
            if resource.startswith("vendor:") and resource in manifest.allowed_data \
                    and not self.vendor_exists(resource.split(":", 1)[1]):
                v.triggers.append(NEW_VENDOR)
        if egress and any(not destination_is_internal(d) for d in v.destinations):
            v.triggers.append(EXTERNAL_DESTINATION)
        v.triggers = list(dict.fromkeys(v.triggers))
        v.checks.append({"stage": "approval", "ok": True, "code": None,
                         "detail": ("needs human approval: " + ", ".join(v.triggers)) if v.triggers
                         else "no approval rule applies"})
        return manifest

    def _verify_evidence(self, task: Task, manifest: Manifest, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check each cited source against what the gateway itself holds for the task.

        A claim only counts as coming from a trusted context if it really is there: a request
        that labels document text as ``user_task`` is caught because the text is not in the goal.
        """
        def norm(text: str) -> str:
            return " ".join(text.lower().split())

        clauses = {norm(f"allowed_tools: {t}") for t in manifest.allowed_tools}
        out = []
        for item in items:
            claim = str(item.get("claim", ""))
            entry: Dict[str, Any] = {"claim": claim, "source": item.get("source"), "verified": False,
                                     "authorising": False, "note": ""}
            try:
                prov = Provenance.from_wire(item.get("source"))
            except ValueError as exc:
                entry["note"] = f"malformed source: {exc}"
                out.append(entry)
                continue
            entry["source"] = prov.to_dict()
            if prov.context == USER_TASK:
                ok = prov.source_id == task.task_id and len(norm(claim)) >= 8 and norm(claim) in norm(task.goal.text)
                entry["note"] = "matches the user task" if ok else "claimed user_task text is not in the task record"
            elif prov.context == SYSTEM_POLICY:
                ok = prov.source_id == task.signed.hash and norm(claim) in clauses
                entry["note"] = "matches a manifest clause" if ok else "claimed policy text is not in the manifest"
            elif prov.context == DOCUMENT:
                doc = task.documents.get(prov.source_id)
                if doc is None:
                    ok = False
                elif prov.span is not None:
                    ok = doc[prov.span[0]:prov.span[1]] == claim
                else:
                    ok = bool(claim) and claim in doc
                entry["note"] = "quoted from the task document" if ok else "quote not found in a task document"
            else:  # TOOL_OUTPUT
                ok = prov.source_id in task.outputs
                entry["note"] = "refers to a tool output of this task" if ok else "unknown tool output"
            entry["verified"] = ok
            entry["authorising"] = ok and CONTEXTS[prov.context].can_authorize
            out.append(entry)
        return out

    # ------------------------------------------------------------------ decision
    def _decide(self, v: ToolVerdict, manifest: Optional[Manifest]) -> None:
        # Untrusted-only evidence does not refuse an approval-gated action outright: the human
        # approver becomes the authority, and the card shows that the evidence is untrusted.
        gated = bool(v.triggers)
        blocking = [x for x in v.violations if not (gated and x["code"] == "UNTRUSTED_AUTHORITY")]
        score = int((v.intent or {}).get("score", 0))
        if blocking:
            v.decision, v.code, v.reason = BLOCK, blocking[0]["code"], blocking[0]["reason"]
            critical = score >= 70 or any(x["code"] in ("CANARY_EGRESS", "MANIFEST_TAMPERED") for x in blocking)
            v.risk = "critical" if critical else "high" if score >= 40 or len(blocking) > 1 else "medium"
        elif v.triggers:
            v.decision = REQUIRE_APPROVAL
            v.code = "PAYMENT_OVER_LIMIT" if v.triggers == [PAYMENT_OVER_LIMIT] else "APPROVAL_REQUIRED"
            v.reason = "needs human approval: " + ", ".join(v.triggers)
            if any(x["code"] == "UNTRUSTED_AUTHORITY" for x in v.violations):
                v.reason += "; the only evidence is untrusted content, so it cannot authorise this"
            v.risk = "medium" if v.triggers == [PAYMENT_OVER_LIMIT] else "high"
        else:
            v.decision, v.code, v.reason = ALLOW, "OK", "inside the task manifest; all checks passed"
            v.risk = "low"

    # ------------------------------------------------------------------ execution
    def _execute(self, v: ToolVerdict, task: Task) -> None:
        if not self.registry.has(v.tool):
            v.result = {"error": f"tool '{v.tool[:40]}' is not installed"}
            return
        v.result = self.registry.run(v.tool, v.args, task, self.clock())
        v.executed = True
        handle = f"out-{len(task.outputs) + 1:04d}"
        task.outputs[handle] = {"tool": v.tool, "result": v.result}
        v.result = dict(v.result, output_id=handle)

    def _timeline(self, task: Task, v: ToolVerdict) -> None:
        sources = [e["source"] for e in v.evidence if isinstance(e.get("source"), dict)] or \
                  [{"context": "unknown", "id": "-", "trust": "unknown"}]
        untrusted = [s for s in sources if s.get("context") in (DOCUMENT, TOOL_OUTPUT)]
        source = (untrusted or sources)[0] if not any(e["authorising"] for e in v.evidence) else \
            next(e["source"] for e in v.evidence if e["authorising"])
        stamp = {ALLOW: "ALLOW", BLOCK: "BLOCK", REQUIRE_APPROVAL: "APPROVAL"}[v.decision]
        task.log("tool.decision", v.at, n=v.n, source=source, action=v.tool, args=v.args, decision=stamp,
                 code=v.code, codes=[x["code"] for x in v.violations], reason=v.reason, risk=v.risk,
                 data_scope=v.resources, destinations=v.destinations, executed=v.executed,
                 approval_id=v.approval_id, lineage_id=v.lineage_id, counterfactual=v.counterfactual,
                 purpose=v.purpose, evidence=v.evidence, checks=v.checks, triggers=v.triggers,
                 intent=v.intent, would=v.would, task_risk=v.task_risk)
