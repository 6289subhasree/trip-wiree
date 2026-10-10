"""Intent-to-task mismatch (PRD 7.7): deterministic, explainable, and not phrase-based.

The evaluator never reads the agent's wording to decide. It looks at what the requested tool
*does*:

* every tool has an **effect class** (what kind of action it is) and a **data class** (what
  kind of record it touches); the destination and the resources refine both;
* every task goal maps to the set of effect classes that goal needs.

An action is off-task when its effect class is not in the goal's set, or when it touches a
data class the manifest does not scope. So "export customer records for billing verification"
is ``bulk_export`` on ``customer_pii`` however politely it is phrased, and an invoice task
never needs that. The result carries a 0-100 score and the reasons, for the ledger.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

# Effect classes
READ_INVOICE = "read_invoice"
READ_VENDOR = "read_vendor"
DRAFT_PAYMENT = "draft_payment"
MODIFY_VENDOR_BANK = "modify_vendor_bank"
READ_CUSTOMER_PII = "read_customer_pii"
BULK_EXPORT = "bulk_export"
EXTERNAL_EGRESS = "external_egress"
INTERNAL_NOTIFY = "internal_notify"
UNKNOWN_EFFECT = "unknown_effect"
EFFECTS = (READ_INVOICE, READ_VENDOR, DRAFT_PAYMENT, MODIFY_VENDOR_BANK, READ_CUSTOMER_PII, BULK_EXPORT,
           EXTERNAL_EGRESS, INTERNAL_NOTIFY)

# Data classes
INVOICE = "invoice"
VENDOR = "vendor"
CUSTOMER_PII = "customer_pii"
CANARY = "canary"
DATA_CLASSES = (INVOICE, VENDOR, CUSTOMER_PII, CANARY)
SENSITIVE_CLASSES = frozenset({CUSTOMER_PII, CANARY})

INTERNAL_DESTINATIONS = frozenset({"internal-accounting", "internal-soc", "employee-email"})


@dataclass(frozen=True)
class ToolProfile:
    effect: str
    data_class: Optional[str]
    egress: bool = False                   # can carry data out of the task
    approval_trigger: Optional[str] = None  # manifest approval rule this tool always falls under


TOOL_PROFILES: Dict[str, ToolProfile] = {
    "extract_invoice_fields": ToolProfile(READ_INVOICE, INVOICE),
    "get_vendor_record": ToolProfile(READ_VENDOR, VENDOR),
    "create_payment_draft": ToolProfile(DRAFT_PAYMENT, INVOICE),
    "change_vendor_bank_account": ToolProfile(MODIFY_VENDOR_BANK, VENDOR, approval_trigger="bank_account_change"),
    "export_customer_list": ToolProfile(BULK_EXPORT, CUSTOMER_PII),
    "get_customer_records": ToolProfile(READ_CUSTOMER_PII, CUSTOMER_PII),
    "send_email": ToolProfile(EXTERNAL_EGRESS, None, egress=True),
    "upload_external_file": ToolProfile(EXTERNAL_EGRESS, None, egress=True),
}

# How far outside an invoice-style task each effect or data class is (for the 0-100 score).
EFFECT_WEIGHT = {BULK_EXPORT: 45, EXTERNAL_EGRESS: 40, READ_CUSTOMER_PII: 35, MODIFY_VENDOR_BANK: 30,
                 UNKNOWN_EFFECT: 30, DRAFT_PAYMENT: 20, READ_INVOICE: 15, READ_VENDOR: 15, INTERNAL_NOTIFY: 10}
DATA_WEIGHT = {CUSTOMER_PII: 30, CANARY: 40, INVOICE: 10, VENDOR: 10}

_RESOURCE_CLASS = (("invoice:", INVOICE), ("vendor:", VENDOR), ("customer:", CUSTOMER_PII), ("canary:", CANARY))


def destination_is_internal(destination: Any) -> bool:
    return isinstance(destination, str) and destination.strip().lower() in INTERNAL_DESTINATIONS


def data_class_of(resource: str) -> Optional[str]:
    for prefix, name in _RESOURCE_CLASS:
        if resource.startswith(prefix):
            return name
    return None


@dataclass(frozen=True)
class ActionIntent:
    tool: str
    effects: FrozenSet[str]
    data_classes: FrozenSet[str]
    egress: bool

    def to_dict(self) -> Dict[str, Any]:
        return {"tool": self.tool, "effects": sorted(self.effects), "data_classes": sorted(self.data_classes),
                "egress": self.egress}


def classify(tool: str, resources: Iterable[str] = (), destination: Any = None,
             extra_classes: Iterable[str] = ()) -> ActionIntent:
    """What a tool call does, derived from the tool, its resources and its destination only."""
    profile = TOOL_PROFILES.get(tool)
    if profile is None:
        effects, classes, egress = {UNKNOWN_EFFECT}, set(), False
    else:
        effects, egress = {profile.effect}, profile.egress
        classes = {profile.data_class} if profile.data_class else set()
        if profile.egress and destination_is_internal(destination):
            effects = {INTERNAL_NOTIFY}
    for resource in resources:
        name = data_class_of(str(resource))
        if name:
            classes.add(name)
    classes.update(c for c in extra_classes if c in DATA_CLASSES)
    return ActionIntent(tool, frozenset(effects), frozenset(classes), egress)


# ---------------------------------------------------------------------------
# Goal -> allowed effects. The goal text is TRUSTED (it comes from the user task), so reading
# it for keywords is safe. Untrusted text is never interpreted here.
# ---------------------------------------------------------------------------
_GOAL_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (r"\binvoices?\b|\bbill\b", (READ_INVOICE, READ_VENDOR)),
    (r"\bvendor\b|\bsupplier\b", (READ_VENDOR,)),
    (r"\bpayment\s+draft\b|\bdraft\b[^.]{0,30}\bpayment\b|\bprepare\b[^.]{0,30}\bpayment\b",
     (READ_INVOICE, READ_VENDOR, DRAFT_PAYMENT)),
    (r"\bremittance\b|\bemail\b|\bsend\b|\bnotify\b", (EXTERNAL_EGRESS,)),
)


def effects_for_goal(goal: str, ceiling: Iterable[str] = EFFECTS) -> Tuple[str, ...]:
    """Effect classes a goal needs, capped by the system policy's ceiling."""
    text, wanted = goal.lower(), set()
    for pattern, effects in _GOAL_RULES:
        if re.search(pattern, text):
            wanted.update(effects)
    if wanted:
        wanted.add(INTERNAL_NOTIFY)
    allowed = set(ceiling)
    return tuple(e for e in EFFECTS if e in wanted and e in allowed)


@dataclass(frozen=True)
class IntentVerdict:
    mismatch: bool
    score: int
    reasons: Tuple[str, ...]
    off_task_effects: Tuple[str, ...]
    off_scope_classes: Tuple[str, ...]
    needs_approval_effects: Tuple[str, ...]
    intent: ActionIntent

    def to_dict(self) -> Dict[str, Any]:
        return {"mismatch": self.mismatch, "score": self.score, "reasons": list(self.reasons),
                "off_task_effects": list(self.off_task_effects), "off_scope_classes": list(self.off_scope_classes),
                "needs_approval_effects": list(self.needs_approval_effects), **self.intent.to_dict()}


def evaluate(goal: str, goal_effects: Iterable[str], allowed_data: Iterable[str], intent: ActionIntent,
             approval_effects: Iterable[str] = ()) -> IntentVerdict:
    """Compare what an action does with what the task needs.

    ``approval_effects`` are effects the manifest hands to a human instead of refusing outright
    (a vendor bank change). They are not a mismatch on their own, but they never run without
    an approval.
    """
    goal_set, escalate = set(goal_effects), set(approval_effects)
    scoped = {c for c in (data_class_of(r) for r in allowed_data) if c}
    off_effects = sorted(e for e in intent.effects if e not in goal_set and e not in escalate)
    gated = sorted(e for e in intent.effects if e not in goal_set and e in escalate)
    off_classes = sorted(c for c in intent.data_classes if c not in scoped)
    reasons: List[str] = []
    for effect in off_effects:
        reasons.append(f"effect '{effect}' is not needed for the task \"{goal[:60]}\" "
                       f"(task effects: {', '.join(sorted(goal_set)) or 'none'})")
    for name in off_classes:
        reasons.append(f"data class '{name}' is outside the task scope ({', '.join(sorted(scoped)) or 'none'})")
    for effect in gated:
        reasons.append(f"effect '{effect}' is outside the task and is only possible with human approval")
    score = min(100, sum(EFFECT_WEIGHT.get(e, 30) for e in off_effects)
                + sum(DATA_WEIGHT.get(c, 20) for c in off_classes)
                + sum(EFFECT_WEIGHT.get(e, 30) // 2 for e in gated))
    return IntentVerdict(bool(off_effects or off_classes), score, tuple(reasons), tuple(off_effects),
                         tuple(off_classes), tuple(gated), intent)
