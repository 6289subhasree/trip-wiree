"""Mock email service and egress log. Neither one ever sends anything off this machine.

Every email *attempt* is recorded with one of these statuses:

* ``SIMULATED_DELIVERY`` - authorised by the gateway and written to the local outbox file.
  No network traffic occurs; ``simulated`` is always ``True``.
* ``BLOCKED``  - denied because the firewall was BLOCKING or in LOCKDOWN.
* ``REJECTED`` - denied by protocol validation or action policy.

Only ``SIMULATED_DELIVERY`` records are appended to the delivered-mail JSONL file.

Two kinds of delivered mail exist: ``soc_alert`` (the internal threshold alert, always to the
server-configured SOC recipient) and ``agent_email`` (the ``send_email`` tool, which only runs
after the tool gateway allowed it, after an operator approval, or in the counterfactual
baseline). ``EgressLog`` plays the same role for ``upload_external_file``.
"""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

SIMULATED_DELIVERY = "SIMULATED_DELIVERY"
BLOCKED = "BLOCKED"
REJECTED = "REJECTED"

DEFAULT_RECIPIENTS = ("soc-oncall@tripwire.invalid",)
_CANARY = re.compile(r"TRIPWIRE-CANARY-[A-Z0-9]+(?:-[A-Z0-9]+)*")


def _mask(text: str) -> str:
    """Stored bodies never keep a full canary value (same rule as tools_gateway.mask_canary)."""
    def one(m):
        token = m.group(0)
        return token[:16] + "".join(c if c == "-" else "*" for c in token[16:-2]) + token[-2:]
    return _CANARY.sub(one, text)


class MockEmailService:
    MAX_RECORDS = 500

    def __init__(self, path: str, recipients=DEFAULT_RECIPIENTS, clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.recipients = tuple(recipients)
        self._clock = clock
        self._lock = threading.Lock()
        self.records: List[Dict[str, Any]] = []
        self.delivered_count = 0

    def _add(self, record: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            record = {"id": f"mail-{len(self.records) + 1:04d}", "at": self._clock(), "simulated": True, **record}
            self.records.append(record)
            del self.records[:-self.MAX_RECORDS]
            if record["status"] == SIMULATED_DELIVERY:
                self.delivered_count += 1
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, sort_keys=True) + "\n")
            return record

    def deliver(self, *, correlation_id: str, incident_id: str, risk_score: float, summary: str,
                to: Optional[List[str]] = None) -> Dict[str, Any]:
        recipients = list(to) if to else list(self.recipients)
        return self._add({
            "status": SIMULATED_DELIVERY, "kind": "soc_alert", "external": False,
            "correlation_id": correlation_id, "incident_id": incident_id,
            "to": recipients, "subject": f"[TripWire] Risk threshold crossed ({risk_score:g}/100)",
            "body": summary, "reason": "authorised by gateway; simulated delivery, no email left this machine",
        })

    def deliver_tool_email(self, *, task_id: str, correlation_id: str, to: str, body: str,
                           attachments: List[Dict[str, Any]], external: bool) -> Dict[str, Any]:
        """Record an email produced by the ``send_email`` tool. Simulated; nothing is transmitted."""
        return self._add({
            "status": SIMULATED_DELIVERY, "kind": "agent_email", "external": bool(external),
            "correlation_id": correlation_id, "incident_id": task_id, "to": [to],
            "subject": f"(agent email) task {task_id}", "body": _mask(body)[:600], "attachments": attachments,
            "records": sum(int(a.get("records", 0)) for a in attachments),
            "canaries": sum(int(a.get("canaries", 0)) for a in attachments) + len(_CANARY.findall(body)),
            "reason": "send_email tool executed; simulated delivery, no email left this machine",
        })

    def deny(self, status: str, *, correlation_id: str, reason: str, code: str,
             message_type: str, sender_id: str) -> Dict[str, Any]:
        return self._add({
            "status": status, "correlation_id": correlation_id, "incident_id": correlation_id,
            "to": [], "subject": f"(not sent) {message_type} from {sender_id}", "body": "",
            "reason": reason, "code": code,
        })

    def file_count(self) -> int:
        with self.path.open("r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())


class EgressLog:
    """Local record of ``upload_external_file`` calls. The "upload" is a line in a JSONL file."""

    MAX_RECORDS = 500

    def __init__(self, path: str, clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self._clock = clock
        self._lock = threading.Lock()
        self.records: List[Dict[str, Any]] = []

    def record(self, *, task_id: str, destination: str, data: str, attachments: List[Dict[str, Any]],
               size: int, external: bool) -> Dict[str, Any]:
        with self._lock:
            entry = {"id": f"egr-{len(self.records) + 1:04d}", "at": self._clock(), "simulated": True,
                     "status": "SIMULATED_UPLOAD", "task_id": task_id, "destination": destination,
                     "external": bool(external), "data": _mask(data)[:200], "attachments": attachments,
                     "bytes": int(size), "records": sum(int(a.get("records", 0)) for a in attachments),
                     "canaries": sum(int(a.get("canaries", 0)) for a in attachments) + len(_CANARY.findall(data))}
            self.records.append(entry)
            del self.records[:-self.MAX_RECORDS]
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
            return entry

    def file_count(self) -> int:
        with self.path.open("r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())
