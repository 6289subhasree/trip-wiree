"""Tamper-evident audit log: an HMAC-SHA256 hash chain.

Each entry stores ``prev`` (the previous entry's MAC) and ``mac`` = HMAC(key, entry-without-mac).
Editing, deleting or reordering any retained entry breaks verification from that point on.

Limits (stated honestly): the chain key lives in the same process. Someone who obtains the key
can forge a consistent chain, and truncating the *tail* is only detectable by comparing the
current head MAC with a previously recorded one (the dashboard shows the head for that reason).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

GENESIS = "0" * 64


def _canon(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class AuditLog:
    MAX_IN_MEMORY = 20000

    def __init__(self, path: Optional[str] = None, key: Optional[bytes] = None,
                 clock: Callable[[], float] = time.time):
        self._key = key or secrets.token_bytes(32)
        self._clock = clock
        self._lock = threading.RLock()
        self.entries: List[Dict[str, Any]] = []
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("", encoding="utf-8")

    def _mac(self, body: Dict[str, Any]) -> str:
        return hmac.new(self._key, _canon(body), hashlib.sha256).hexdigest()

    @property
    def head(self) -> str:
        with self._lock:
            return self.entries[-1]["mac"] if self.entries else GENESIS

    def append(self, kind: str, data: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            body = {"seq": len(self.entries) + 1, "ts": self._clock(), "kind": kind,
                    "data": data, "prev": self.head}
            entry = dict(body, mac=self._mac(body))
            if len(self.entries) >= self.MAX_IN_MEMORY:
                raise RuntimeError("audit log capacity reached; reset the demo session")
            self.entries.append(entry)
            if self.path:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
            return entry

    def verify(self) -> Dict[str, Any]:
        with self._lock:
            prev = GENESIS
            for index, entry in enumerate(self.entries, start=1):
                body = {k: entry.get(k) for k in ("seq", "ts", "kind", "data", "prev")}
                if entry.get("seq") != index:
                    return {"ok": False, "checked": index - 1, "broken_at": index, "why": "sequence gap or reorder"}
                if entry.get("prev") != prev:
                    return {"ok": False, "checked": index - 1, "broken_at": index, "why": "chain link mismatch"}
                if not hmac.compare_digest(self._mac(body), str(entry.get("mac", ""))):
                    return {"ok": False, "checked": index - 1, "broken_at": index, "why": "entry MAC mismatch (content modified)"}
                prev = entry["mac"]
            return {"ok": True, "checked": len(self.entries), "broken_at": None, "head": prev}

    def tail(self, n: int = 80) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self.entries[-n:]]
