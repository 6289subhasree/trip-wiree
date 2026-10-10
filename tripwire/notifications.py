"""Local JSON Lines notification outbox; never sends external email."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class JsonlOutbox:
    def __init__(self, path: str):
        self.path = Path(path)

    def send_alert(self, metric: str, value: float, threshold: float, message_id: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "kind": "threshold_alert",
            "to": "demo-operator@example.invalid",
            "subject": f"TripWire threshold crossed: {metric}",
            "body": f"{metric}={value:g} crossed threshold {threshold:g}.",
            "message_id": message_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    def count(self) -> int:
        if not self.path.exists():
            return 0
        with self.path.open("r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())
