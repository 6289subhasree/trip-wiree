"""Data lineage (PRD 7.10): what data each tool request reached for, and what became of it.

One entry is written for every tool request the capability gateway evaluates, whether it was
allowed, blocked or paused. An entry records the source records and documents, the data
classification, the transformations, the requested destination and the final decision.

The records "at stake" are resolved from the vault's index, not by reading the data, so a
blocked export can still be counted (500 customer records protected) without the export tool
ever running. The blast-radius report is computed from these entries and nothing else.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from .intent import SENSITIVE_CLASSES, TOOL_PROFILES, data_class_of, destination_is_internal
from .tools_gateway import masked

_TRANSFORMS = {"extract_invoice_fields": "field extraction", "get_vendor_record": "record lookup",
               "create_payment_draft": "payment draft", "change_vendor_bank_account": "record update",
               "export_customer_list": "csv export", "get_customer_records": "json read",
               "send_email": "email body", "upload_external_file": "file upload"}


class LineageLog:
    def __init__(self, vault: Any, clock: Callable[[], float] = time.time):
        self.vault, self.clock = vault, clock
        self.entries: List[Dict[str, Any]] = []
        self._by_id: Dict[str, Dict[str, Any]] = {}

    def record(self, task: Any, v: Any) -> str:
        profile = TOOL_PROFILES.get(v.tool)
        record_ids: List[str] = []
        for resource in v.resources:
            record_ids.extend(self.vault.resolve(resource))
        transformations = [_TRANSFORMS.get(v.tool, "unknown")]
        for handle in v.artifacts:
            art = task.artifacts[handle]
            record_ids.extend(art["records"])
            transformations.append(f"{art['transformation']} ({handle})")
        record_ids = list(dict.fromkeys(record_ids))
        classes = sorted(set(v.data_classes) | {c for c in map(data_class_of, record_ids) if c})
        canaries = sorted(set(v.canaries) | set(self.vault.canaries_in(record_ids)))
        if canaries and "canary" not in classes:
            classes.append("canary")
        if v.tool == "create_payment_draft":
            amount = float(v.args.get("amount", 0) or 0)
        elif v.tool == "change_vendor_bank_account":
            # the payments that would be redirected: the invoices this task is about to pay
            amount = float(sum(self.vault.invoice_amount(r.split(":", 1)[1])
                               for r in task.manifest.allowed_data if r.startswith("invoice:")))
        else:
            amount = 0.0
        # What the protected policy says about the request. In the baseline profile the gateway
        # ran the tool anyway and kept the protected verdict in ``would``.
        policy = v.would if v.counterfactual and v.would else \
            {"codes": [x["code"] for x in v.violations], "triggers": list(v.triggers)}
        entry = {
            "id": f"lin-{len(self.entries) + 1:04d}", "task_id": task.task_id, "n": v.n, "at": v.at,
            "tool": v.tool, "effect": profile.effect if profile else "unknown_effect",
            "egress": bool(profile and profile.egress), "profile": v.profile, "counterfactual": v.counterfactual,
            # source
            "source_records": list(v.resources), "source_artifacts": list(v.artifacts),
            "source_documents": sorted({e["source"]["id"] for e in v.evidence
                                        if isinstance(e.get("source"), dict) and e["source"].get("context") == "document"}),
            "evidence_contexts": sorted({e["source"].get("context", "?") for e in v.evidence
                                         if isinstance(e.get("source"), dict)}),
            # classification
            "classes": classes, "sensitive": bool(set(classes) & SENSITIVE_CLASSES),
            "record_ids": record_ids,
            "sensitive_ids": [r for r in record_ids if data_class_of(r) in SENSITIVE_CLASSES],
            "canaries": canaries,
            # transformation and destination
            "transformations": transformations, "destinations": list(v.destinations),
            "external_destinations": [d for d in v.destinations if not destination_is_internal(d)],
            "amount_inr": amount,
            # decision
            "decision": v.decision, "code": v.code,
            "policy_violations": list(policy.get("codes", [])), "policy_triggers": list(policy.get("triggers", [])),
            "executed": bool(v.executed), "approval_id": v.approval_id, "approved_by": None,
        }
        self.entries.append(entry)
        self._by_id[entry["id"]] = entry
        return entry["id"]

    def settle(self, lineage_id: str, *, executed: bool, approved_by: Optional[str], code: Optional[str]) -> None:
        """An approval was decided: record whether the action finally ran and who approved it."""
        entry = self._by_id.get(lineage_id)
        if entry is None:
            return
        entry["executed"] = bool(executed)
        entry["approved_by"] = approved_by if executed else None
        entry["final_code"] = code
        entry["settled_at"] = self.clock()

    def for_task(self, task_id: str) -> List[Dict[str, Any]]:
        return [e for e in self.entries if e["task_id"] == task_id]

    @staticmethod
    def view(entry: Dict[str, Any]) -> Dict[str, Any]:
        """Display form: record ids become counts and canary values are masked."""
        out = {k: v for k, v in entry.items() if k not in ("record_ids", "sensitive_ids", "canaries")}
        out["records"] = len(entry["record_ids"])
        out["sensitive_records"] = len(entry["sensitive_ids"])
        out["canaries"] = masked(entry["canaries"])
        return masked(out)
