"""Mock email service. It NEVER sends real email.

Every email *attempt* is recorded with one of these statuses:

* ``SIMULATED_DELIVERY`` - authorised by the gateway and written to the local outbox file.
  No network traffic occurs; ``simulated`` is always ``True``.
* ``BLOCKED``  - denied because the firewall was BLOCKING or in LOCKDOWN.
* ``REJECTED`` - denied by protocol validation or action policy.

Only ``SIMULATED_DELIVERY`` records are appended to the delivered-mail JSONL file.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

SIMULATED_DELIVERY = "SIMULATED_DELIVERY"
BLOCKED = "BLOCKED"
REJECTED = "REJECTED"

DEFAULT_RECIPIENTS = ("soc-oncall@tripwire.invalid",)


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
            "status": SIMULATED_DELIVERY, "correlation_id": correlation_id, "incident_id": incident_id,
            "to": recipients, "subject": f"[TripWire] Risk threshold crossed ({risk_score:g}/100)",
            "body": summary, "reason": "authorised by gateway; simulated delivery, no email left this machine",
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
