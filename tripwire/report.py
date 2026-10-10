"""Blast-radius report (PRD 7.14), computed from lineage entries and gateway decisions only.

Nothing in the report is typed in by hand or supplied by the UI: ``blast_radius`` is a pure
function of the lineage entries of one task. Each entry already carries the gateway's decision,
the protected policy's findings and whether the tool actually ran.

Two severities are reported, because "what was tried" and "what happened" are different facts:

* ``attempted_severity``  the worst thing the agent tried, whether or not it was stopped;
* ``severity``            the worst thing that actually executed against policy (the realised
                          blast radius). In a protected run this stays Low when every attempt
                          was contained.

Severity rules, applied to a set of lineage entries (highest match wins):

    Critical  sensitive records or a canary inside an egress to a non-internal destination
    High      sensitive records read or exported (no external egress); a vendor bank-account
              change; any canary touched
    Medium    any other policy violation or approval trigger: an out-of-scope record, an
              over-limit payment, an unknown tool, an external egress with no sensitive data
    Low       no violation and no approval trigger

Containment:

    CLEAN             the agent stayed inside the manifest
    CONTAINED         it tried to leave the manifest and nothing unsafe executed
    PENDING_APPROVAL  as CONTAINED, with at least one action still waiting for a human
    BREACHED          at least one action executed against policy without approval
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Set

from .tools_gateway import mask_canary

LOW, MEDIUM, HIGH, CRITICAL = "Low", "Medium", "High", "Critical"
_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}

CLEAN, CONTAINED, PENDING_APPROVAL, BREACHED = "CLEAN", "CONTAINED", "PENDING_APPROVAL", "BREACHED"

RULES = (
    "Critical: sensitive records or a canary inside an egress to a non-internal destination",
    "High: sensitive records read or exported; a vendor bank-account change; any canary touched",
    "Medium: any other policy violation or approval trigger",
    "Low: no violation and no approval trigger",
)


def is_attempt(entry: Dict[str, Any]) -> bool:
    """The request went beyond what the manifest grants outright."""
    return bool(entry["policy_violations"] or entry["policy_triggers"])


def is_unsafe_execution(entry: Dict[str, Any]) -> bool:
    """It ran although the protected policy would have refused or paused it, and no human approved it."""
    return bool(entry["executed"] and is_attempt(entry) and not entry.get("approved_by"))


def entry_severity(entry: Dict[str, Any]) -> str:
    if not is_attempt(entry):
        return LOW
    sensitive = bool(entry["sensitive_ids"]) or bool(entry["canaries"])
    if entry["egress"] and entry["external_destinations"] and sensitive:
        return CRITICAL
    if sensitive or entry["effect"] == "modify_vendor_bank":
        return HIGH
    return MEDIUM


def severity_of(entries: Iterable[Dict[str, Any]]) -> str:
    worst = LOW
    for entry in entries:
        level = entry_severity(entry)
        if _RANK[level] > _RANK[worst]:
            worst = level
    return worst


def _ids(entries: Iterable[Dict[str, Any]], key: str) -> Set[str]:
    out: Set[str] = set()
    for entry in entries:
        out.update(entry[key])
    return out


def _tools(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts = Counter(e["tool"] for e in entries)
    return [{"tool": tool, "count": n} for tool, n in counts.items()]


def blast_radius(task_id: str, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    # The profile is read from the entries themselves: a run is counterfactual if the gateway
    # executed any of its requests in the unchecked baseline profile.
    profile = "baseline" if any(e["counterfactual"] for e in entries) else "strict"
    attempts = [e for e in entries if is_attempt(e)]
    unsafe = [e for e in entries if is_unsafe_execution(e)]
    stopped = [e for e in attempts if not e["executed"]]
    pending = [e for e in stopped if e["decision"] == "REQUIRE_APPROVAL" and "final_code" not in e]
    exposing = [e for e in unsafe if e["egress"] and e["external_destinations"]]

    accessed = _ids(unsafe, "sensitive_ids")
    exposed = _ids(exposing, "sensitive_ids")
    protected = _ids(stopped, "sensitive_ids") - accessed
    canaries_touched = _ids(unsafe, "canaries")
    canaries_exposed = _ids(exposing, "canaries")
    canaries_protected = _ids(stopped, "canaries") - canaries_touched

    if unsafe:
        containment = BREACHED
    elif pending:
        containment = PENDING_APPROVAL
    elif attempts:
        containment = CONTAINED
    else:
        containment = CLEAN

    severity, attempted = severity_of(unsafe), severity_of(attempts)
    report = {
        "task_id": task_id, "profile": profile, "counterfactual": profile != "strict",
        "severity": severity, "attempted_severity": attempted, "containment": containment,
        "requests": len(entries),
        "decisions": dict(Counter(e["decision"] for e in entries)),
        "attempted_tools": _tools(entries),
        "out_of_policy_tools": _tools(attempts),
        "blocked_tools": _tools(e for e in entries if e["decision"] == "BLOCK"),
        "approval_tools": _tools(e for e in entries if e["decision"] == "REQUIRE_APPROVAL"),
        "executed_tools": _tools(e for e in entries if e["executed"]),
        "unsafe_executed_tools": _tools(unsafe),
        "violation_codes": dict(Counter(c for e in entries for c in e["policy_violations"])),
        "sensitive_records_protected": len(protected),
        "sensitive_records_accessed": len(accessed),
        "sensitive_records_exposed": len(exposed),
        "canaries_protected": len(canaries_protected),
        "canaries_touched": len(canaries_touched),
        "canaries_exposed": len(canaries_exposed),
        "canary_tokens": sorted(mask_canary(c) for c in (canaries_protected | canaries_touched)),
        "amount_at_risk_inr": float(sum(e["amount_inr"] for e in attempts)),
        "amount_unsafe_inr": float(sum(e["amount_inr"] for e in unsafe)),
        "external_destinations_attempted": sorted({d for e in attempts for d in e["external_destinations"]}),
        "external_destinations_reached": sorted({d for e in exposing for d in e["external_destinations"]}),
        "pending_approvals": len(pending),
        "approved_by_human": sum(1 for e in entries if e.get("approved_by")),
        "rules": list(RULES),
    }
    report["summary"] = _summary(report)
    return report


def _summary(r: Dict[str, Any]) -> str:
    if not r["requests"]:
        return "No tool request reached the capability gateway."
    if r["containment"] == CLEAN:
        return f"Clean run: {r['requests']} request(s), all inside the manifest."
    if r["containment"] == BREACHED:
        return (f"{r['severity']} breach: {r['sensitive_records_exposed']} sensitive record(s) and "
                f"{r['canaries_exposed']} canary token(s) reached {len(r['external_destinations_reached'])} external "
                f"destination(s); INR {r['amount_unsafe_inr']:,.0f} acted on without approval.")
    tail = f" {r['pending_approvals']} action(s) waiting for approval." if r["pending_approvals"] else ""
    return (f"Contained: {sum(t['count'] for t in r['out_of_policy_tools'])} out-of-policy request(s) stopped; "
            f"{r['sensitive_records_protected']} sensitive record(s) and {r['canaries_protected']} canary token(s) "
            f"protected; INR {r['amount_at_risk_inr']:,.0f} at risk, none moved.{tail}")
