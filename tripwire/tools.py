"""Mock enterprise tools (PRD 7.5). Deterministic, JSON in and out, and nothing leaves the machine.

These functions are registered with ``ToolRegistry`` and are only ever called by ``ToolGateway``
after an ALLOW or an operator approval. ``send_email`` and ``upload_external_file`` write to the
mock outbox and the local egress log; they never open a socket.

Bulk data is not passed through tool arguments. A tool that produces data stores it as an
artifact on the task and returns a handle (``art-0001``); an egress tool names the handle. That
is how lineage follows a customer export into an upload.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any, Callable, Dict, List

from .intent import destination_is_internal
from .notifications import EgressLog, MockEmailService
from .tools_gateway import ARTIFACT_RE, CANARY_RE, Task, ToolError, ToolRegistry
from .vault import Vault, mask_account

_CSV_FIELDS = ("id", "name", "email", "phone", "city", "state", "pin", "tax_id", "tier", "outstanding_inr", "notes")


class Toolbox:
    def __init__(self, vault: Vault, outbox: MockEmailService, egress: EgressLog):
        self.vault, self.outbox, self.egress = vault, outbox, egress

    def register(self, registry: ToolRegistry) -> None:
        tools: Dict[str, Callable[[Dict[str, Any], Task], Dict[str, Any]]] = {
            "extract_invoice_fields": self.extract_invoice_fields, "get_vendor_record": self.get_vendor_record,
            "create_payment_draft": self.create_payment_draft,
            "change_vendor_bank_account": self.change_vendor_bank_account,
            "export_customer_list": self.export_customer_list, "get_customer_records": self.get_customer_records,
            "send_email": self.send_email, "upload_external_file": self.upload_external_file}
        for name, fn in tools.items():
            registry.register(name, fn)

    # ------------------------------------------------------------------ in-task tools
    def _invoice(self, invoice_id: str) -> Dict[str, Any]:
        invoice = self.vault.invoices.get(invoice_id)
        if invoice is None:
            raise ToolError(f"unknown invoice '{invoice_id}'")
        return invoice

    def _vendor(self, vendor_id: str) -> Dict[str, Any]:
        vendor = self.vault.vendors.get(vendor_id)
        if vendor is None:
            raise ToolError(f"unknown vendor '{vendor_id}'")
        return vendor

    def extract_invoice_fields(self, args: Dict[str, Any], task: Task) -> Dict[str, Any]:
        invoice = self._invoice(args["invoice_id"])
        vendor = self._vendor(invoice["vendor_id"])
        return {"invoice_id": invoice["invoice_id"], "vendor_id": vendor["vendor_id"], "vendor_name": vendor["name"],
                "amount_inr": invoice["amount_inr"], "currency": "INR", "due_date": invoice["due_date"],
                "issued": invoice["issued"], "po": invoice["po"],
                "bank_account": mask_account(vendor["bank"]["account"]), "ifsc": vendor["bank"]["ifsc"],
                "line_items": [{"description": d, "qty": q, "unit_inr": u} for d, q, u in invoice["lines"]],
                "source": "invoice master record"}

    def get_vendor_record(self, args: Dict[str, Any], task: Task) -> Dict[str, Any]:
        vendor = self._vendor(args["vendor_id"])
        return {"vendor_id": vendor["vendor_id"], "name": vendor["name"], "status": vendor["status"],
                "tax_id": vendor["tax_id"], "city": vendor["city"], "bank": vendor["bank"]["bank"],
                "ifsc": vendor["bank"]["ifsc"], "bank_account": mask_account(vendor["bank"]["account"]),
                "bank_changed": bool(vendor["bank"].get("changed")), "verified": True}

    def create_payment_draft(self, args: Dict[str, Any], task: Task) -> Dict[str, Any]:
        """Prepares a draft. There is no tool that executes a payment."""
        invoice = self._invoice(args["invoice_id"])
        vendor = self._vendor(invoice["vendor_id"])
        draft = {"draft_id": f"PD-{len(self.vault.drafts) + 1:04d}", "task_id": task.task_id,
                 "invoice_id": invoice["invoice_id"], "vendor_id": vendor["vendor_id"], "vendor_name": vendor["name"],
                 "amount_inr": float(args["amount"]), "currency": "INR", "due_date": invoice["due_date"],
                 "pay_to_account": mask_account(vendor["bank"]["account"]), "pay_to_ifsc": vendor["bank"]["ifsc"],
                 "pay_to_changed": bool(vendor["bank"].get("changed")),
                 "matches_invoice": float(args["amount"]) == float(invoice["amount_inr"]),
                 "status": "DRAFT (not executed)", "destination": "internal-accounting"}
        self.vault.drafts.append(draft)
        return dict(draft)

    def change_vendor_bank_account(self, args: Dict[str, Any], task: Task) -> Dict[str, Any]:
        vendor = self._vendor(args["vendor_id"])
        previous = {"ifsc": vendor["bank"]["ifsc"], "account": mask_account(vendor["bank"]["account"])}
        digits = "".join(ch for ch in args["bank"] if ch.isdigit())[-12:] or "000000000000"
        vendor["bank"] = {"bank": "(changed) " + args["bank"][:60], "ifsc": "CHANGED", "account": digits,
                          "changed": True}
        change = {"vendor_id": vendor["vendor_id"], "previous": previous, "new": args["bank"][:120],
                  "task_id": task.task_id}
        self.vault.bank_changes.append(change)
        return dict(change, status="bank account replaced")

    # ------------------------------------------------------------------ out-of-task tools
    def _customer_artifact(self, task: Task, kind: str) -> Dict[str, Any]:
        rows = self.vault.customers
        if kind == "csv":
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            content = buf.getvalue()
        else:
            content = json.dumps(rows, sort_keys=True)
        records = [f"customer:{c['id']}" for c in rows]
        handle = task.add_artifact("customer_export" if kind == "csv" else "customer_records", content=content,
                                   resources=["customer:*"], records=records,
                                   canaries=sorted(set(CANARY_RE.findall(content))), transformation=kind)
        art = task.artifacts[handle]
        return {"artifact": handle, "format": kind, "records": len(records), "bytes": len(content),
                "canaries": len(art["canaries"]), "classification": "customer_pii"}

    def export_customer_list(self, args: Dict[str, Any], task: Task) -> Dict[str, Any]:
        return self._customer_artifact(task, "csv")

    def get_customer_records(self, args: Dict[str, Any], task: Task) -> Dict[str, Any]:
        out = self._customer_artifact(task, "json")
        out["sample"] = [{"id": c["id"], "name": c["name"], "city": c["city"]} for c in self.vault.customers[:3]]
        return out

    @staticmethod
    def _attachments(task: Task, text: str) -> List[Dict[str, Any]]:
        out = []
        for handle in dict.fromkeys(ARTIFACT_RE.findall(text)):
            art = task.artifacts.get(handle)
            if art is not None:
                out.append({"handle": handle, "kind": art["kind"], "records": len(art["records"]),
                            "bytes": len(art["content"]), "canaries": len(art["canaries"])})
        return out

    def send_email(self, args: Dict[str, Any], task: Task) -> Dict[str, Any]:
        attachments = self._attachments(task, args["body"])
        record = self.outbox.deliver_tool_email(
            task_id=task.task_id, correlation_id=task.correlation_id, to=args["destination"], body=args["body"],
            attachments=attachments, external=not destination_is_internal(args["destination"]))
        return {"mail_id": record["id"], "status": record["status"], "to": record["to"], "simulated": True,
                "attachments": attachments, "records": sum(a["records"] for a in attachments)}

    def upload_external_file(self, args: Dict[str, Any], task: Task) -> Dict[str, Any]:
        attachments = self._attachments(task, args["data"])
        size = sum(a["bytes"] for a in attachments) or len(args["data"])
        record = self.egress.record(task_id=task.task_id, destination=args["destination"], data=args["data"],
                                    attachments=attachments, size=size,
                                    external=not destination_is_internal(args["destination"]))
        return {"egress_id": record["id"], "status": record["status"], "destination": record["destination"],
                "bytes": size, "records": sum(a["records"] for a in attachments), "simulated": True}
