"""Authenticated message envelopes and validation."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable


class ProtocolError(ValueError):
    """Raised when an envelope fails protocol validation."""


@dataclass(frozen=True)
class Envelope:
    version: int
    message_id: str
    sender: str
    created_at: float
    payload: dict[str, Any]
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {"version": self.version, "message_id": self.message_id,
                "sender": self.sender, "created_at": self.created_at,
                "payload": self.payload}


class SignedProtocol:
    VERSION = 1

    def __init__(self, secret: bytes, allowed_senders: set[str] | None = None,
                 max_age_seconds: float = 60.0, clock: Callable[[], float] = time.time):
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("secret must be non-empty bytes")
        self._secret = secret
        self.allowed_senders = set({"sentinel"} if allowed_senders is None else allowed_senders)
        if not all(isinstance(sender, str) and sender for sender in self.allowed_senders):
            raise ValueError("allowed senders must be non-empty strings")
        if not isinstance(max_age_seconds, (int, float)) or isinstance(max_age_seconds, bool) or not math.isfinite(max_age_seconds) or max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be a finite positive number")
        self.max_age_seconds = max_age_seconds
        self._clock = clock
        self._seen_ids: set[str] = set()
        self._seen_lock = threading.Lock()

    @staticmethod
    def _canonical(data: dict[str, Any]) -> bytes:
        return json.dumps(data, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")

    def sign(self, sender: str, payload: dict[str, Any]) -> Envelope:
        if not isinstance(sender, str) or not sender:
            raise ValueError("sender must be a non-empty string")
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        unsigned = {"version": self.VERSION, "message_id": str(uuid.uuid4()),
                    "sender": sender, "created_at": float(self._clock()),
                    "payload": payload}
        signature = hmac.new(self._secret, self._canonical(unsigned), hashlib.sha256).hexdigest()
        return Envelope(**unsigned, signature=signature)

    def verify(self, envelope: Envelope) -> dict[str, Any]:
        if not isinstance(envelope, Envelope):
            raise ProtocolError("envelope has invalid type")
        if type(envelope.version) is not int or envelope.version != self.VERSION:
            raise ProtocolError("unsupported protocol version")
        if not isinstance(envelope.message_id, str) or not envelope.message_id or len(envelope.message_id) > 128:
            raise ProtocolError("message ID must be a non-empty string of at most 128 characters")
        if not isinstance(envelope.sender, str) or envelope.sender not in self.allowed_senders:
            raise ProtocolError("sender is not authorized")
        if isinstance(envelope.created_at, bool) or not isinstance(envelope.created_at, (int, float)) or not math.isfinite(envelope.created_at):
            raise ProtocolError("message timestamp must be finite numeric seconds")
        if not isinstance(envelope.payload, dict):
            raise ProtocolError("payload must be an object")
        if not isinstance(envelope.signature, str):
            raise ProtocolError("signature must be a string")
        try:
            expected = hmac.new(self._secret, self._canonical(envelope.unsigned_dict()),
                                hashlib.sha256).hexdigest()
        except (TypeError, ValueError) as exc:
            raise ProtocolError("message is not canonicalizable") from exc
        if not hmac.compare_digest(expected, envelope.signature):
            raise ProtocolError("signature mismatch")
        age = self._clock() - envelope.created_at
        if age < -5 or age > self.max_age_seconds:
            raise ProtocolError("message timestamp outside freshness window")
        with self._seen_lock:
            if envelope.message_id in self._seen_ids:
                raise ProtocolError("replay detected: message ID already seen")
            self._seen_ids.add(envelope.message_id)
        return dict(envelope.payload)
