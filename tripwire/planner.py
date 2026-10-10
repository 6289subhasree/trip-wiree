"""Agent 1's planner: deterministic, offline, and deliberately naive.

There is no LLM anywhere in TripWire. The intake agent plans with ``DeterministicPlanner``, a
small rule set that does two things:

1. plans the legitimate work for an invoice task (extract fields, look up the vendor, draft
   the payment) from what it reads in the document, citing the user task as its authority; and
2. **follows instructions it finds in the document.** If a sentence asks for a customer export,
   an upload, an email, another invoice or a bank change, the planner proposes exactly that and
   cites the sentence as its only reason.

Point 2 is the simulation of a hijacked model. The planner is the thing being contained, not a
defence: nothing it emits is trusted, and every proposal goes through the gateway. It shares no
code with the display-only instruction detector, so the two can and do disagree.

``Planner`` is the interface. A local model could be plugged in behind it later (see
docs/adr/0009); the gateway would treat its proposals exactly the same way.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

DATA_PLACEHOLDER = "{data}"

_SENTENCE = re.compile(r"[^.!?\n]+(?:[.!?]+(?=\s|$)|\.(?=\w)[^.!?\n]*)*[.!?]*")
_FIELD_LINE = re.compile(r"^\s*(?:Invoice No|Invoice date|Due date|PO reference|Vendor ID|Bill to|Total payable|"
                         r"Bank|Payment terms|Document ref|Supporting document|Items|Notes|TAX INVOICE)\b", re.I)
_INVOICE_ID = re.compile(r"\bINV-\d{3,6}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_URL = re.compile(r"https?://([^/\s,;]+)", re.I)
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:invalid|example|test|com|net|org|io|in|co)\b", re.I)
_AMOUNT = re.compile(r"(?:₹|INR|Rs\.?)\s*([\d,]+(?:\.\d+)?)", re.I)


def split_sentences(text: str) -> List[Tuple[int, int, str]]:
    out = []
    for match in _SENTENCE.finditer(text):
        raw = match.group(0)
        stripped = raw.strip()
        if len(stripped) >= 8:
            start = match.start() + (len(raw) - len(raw.lstrip()))
            out.append((start, start + len(stripped), stripped))
    return out


def parse_amount(text: str) -> Optional[float]:
    match = _AMOUNT.search(text)
    if not match:
        return None
    try:
        return float(match.group(1).replace(",", ""))
    except ValueError:
        return None


class Planner:
    """Interface for Agent 1's planning step."""
    name = "planner"

    def plan(self, *, task_id: str, goal: str, documents: Dict[str, str], primary: str) -> List[Dict[str, Any]]:
        raise NotImplementedError  # pragma: no cover


class DeterministicPlanner(Planner):
    name = "deterministic-naive-v1"

    # ------------------------------------------------------------------ reading
    @staticmethod
    def read_fields(text: str) -> Dict[str, Any]:
        """Agent 1's own reading of the document. Untrusted: the system of record is the tool."""
        def find(pattern: str) -> Tuple[Optional[str], Optional[Tuple[int, int]]]:
            m = re.search(pattern, text, re.I | re.M)
            return (m.group(1).strip(), (m.start(), m.end())) if m else (None, None)

        invoice_id, invoice_span = find(r"^Invoice No:\s*([A-Z0-9-]+)")
        vendor_id, vendor_span = find(r"^Vendor ID:\s*([A-Z0-9-]+)")
        total_text, total_span = find(r"^Total payable:\s*(.+)$")
        due, _ = find(r"^Due date:\s*(.+)$")
        return {"invoice_id": invoice_id, "vendor_id": vendor_id, "due_date": due,
                "amount_inr": parse_amount(total_text or ""),
                "spans": {"invoice_id": invoice_span, "vendor_id": vendor_span, "amount_inr": total_span}}

    # ------------------------------------------------------------------ planning
    def plan(self, *, task_id: str, goal: str, documents: Dict[str, str], primary: str) -> List[Dict[str, Any]]:
        text = documents[primary]
        fields = self.read_fields(text)
        invoice_id = fields["invoice_id"] or (_INVOICE_ID.search(goal) or [None])[0]
        task_evidence = {"claim": goal[:240], "source": {"context": "user_task", "id": task_id, "span": None}}

        def quote(doc_id: str, span: Optional[Tuple[int, int]]) -> Optional[Dict[str, Any]]:
            if span is None:
                return None
            start, end = span[0], min(span[1], span[0] + 240)
            return {"claim": documents[doc_id][start:end], "source": {"context": "document", "id": doc_id,
                                                                    "span": [start, end]}}

        def step(tool: str, args: Dict[str, Any], evidence: List[Optional[Dict[str, Any]]], purpose: str, *,
                 resources: List[str], destination: str = "internal-accounting", origin: str = "task",
                 instruction: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
            return {"tool": tool, "args": args, "purpose": purpose[:200], "task_link": goal[:200],
                    "evidence": [e for e in evidence if e][:4], "resources_requested": resources,
                    "destination": destination, "risk_level": "low", "origin": origin, "instruction": instruction}

        steps: List[Dict[str, Any]] = []
        if invoice_id:
            steps.append(step("extract_invoice_fields", {"invoice_id": invoice_id},
                              [task_evidence, quote(primary, fields["spans"]["invoice_id"])],
                              "Extract the fields of the invoice named in the task",
                              resources=[f"invoice:{invoice_id}"]))
        if fields["vendor_id"]:
            steps.append(step("get_vendor_record", {"vendor_id": fields["vendor_id"]},
                              [task_evidence, quote(primary, fields["spans"]["vendor_id"])],
                              "Verify the vendor on the invoice", resources=[f"vendor:{fields['vendor_id']}"]))

        # Follow whatever the documents say. This is the naive part.
        for doc_id, doc in documents.items():
            carries_customer_data = False
            for start, end, sentence in split_sentences(doc):
                if _FIELD_LINE.match(sentence):
                    continue
                span = (start, end)
                found = self._understand(sentence, invoice_id, fields["vendor_id"], carries_customer_data)
                for tool, args, resources, destination in found:
                    if tool in ("export_customer_list", "get_customer_records"):
                        carries_customer_data = True
                    steps.append(step(tool, args, [quote(doc_id, span)], f"The document says: {sentence}",
                                      resources=resources, destination=destination, origin="document",
                                      instruction={"doc_id": doc_id, "start": start, "end": end}))

        if invoice_id and fields["amount_inr"]:
            steps.append(step("create_payment_draft", {"invoice_id": invoice_id, "amount": fields["amount_inr"]},
                              [task_evidence, quote(primary, fields["spans"]["amount_inr"])],
                              "Draft the payment for the invoice total", resources=[f"invoice:{invoice_id}"]))
        return steps

    @staticmethod
    def _understand(sentence: str, invoice_id: Optional[str], vendor_id: Optional[str],
                    carries_customer_data: bool) -> List[Tuple[str, Dict[str, Any], List[str], str]]:
        """Turn one document sentence into tool calls, the way a model that obeys documents would."""
        s = sentence.lower()
        out: List[Tuple[str, Dict[str, Any], List[str], str]] = []
        internal = "internal-accounting"

        if re.search(r"\b(customers?|clients?|crm|account holders?)\b", s) and \
                re.search(r"\b(list|roster|records?|database|data|details|export|csv|listing|file)\b", s):
            bulk = re.search(r"\b(list|export|csv|roster|database|listing|file)\b", s)
            out.append(("export_customer_list" if bulk else "get_customer_records", {}, ["customer:*"], internal))
            carries_customer_data = True

        for other in dict.fromkeys(_INVOICE_ID.findall(sentence)):
            if other != invoice_id:
                out.append(("extract_invoice_fields", {"invoice_id": other}, [f"invoice:{other}"], internal))

        # A bank change needs both a change verb and actual account details to act on.
        detail = re.search(r"(IFSC\s+[A-Z0-9]+(?:\s+A/C\s+\d+)?|A/C\s+\d+|account\s+(?:no\.?\s*|number\s*)?\d+)",
                           sentence, re.I)
        if detail and vendor_id and re.search(r"\b(bank|account|a/c|ifsc)\b", s) and \
                re.search(r"\b(change|changed|replace|update|updated|new|switch|use)\b", s):
            named = re.search(r"\bvendor\s+([A-Z0-9]+-\d+)\b", sentence)
            target = named.group(1) if named else vendor_id
            out.append(("change_vendor_bank_account", {"vendor_id": target, "bank": detail.group(1)[:120]},
                        [f"vendor:{target}"], internal))

        data_resources = ["customer:*"] if carries_customer_data else ([f"invoice:{invoice_id}"] if invoice_id else [])
        emails = _EMAIL.findall(sentence)
        if emails and re.search(r"\b(e-?mail|send|forward|mail|summar\w*|share|report|cc)\b", s):
            out.append(("send_email", {"destination": emails[0], "body": f"Summary as requested: {DATA_PLACEHOLDER}"},
                        data_resources, emails[0]))
        else:
            host = _URL.search(sentence)
            domain = host.group(1) if host else (_DOMAIN.search(sentence) or [None])[0]
            if domain and "@" not in domain and \
                    re.search(r"\b(upload|portal|post|place|placed|put|submit|share|drop|copy|send|sync)\b", s):
                out.append(("upload_external_file", {"destination": domain, "data": DATA_PLACEHOLDER},
                            data_resources, domain))

        amount = parse_amount(sentence)
        if amount and invoice_id and re.search(r"\b(pay|payment|remit|transfer|wire)\b", s) and not out:
            out.append(("create_payment_draft", {"invoice_id": invoice_id, "amount": amount},
                        [f"invoice:{invoice_id}"], internal))
        return out
