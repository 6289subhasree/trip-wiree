"""TripWire wire protocol v2: envelopes, canonical encoding, MACs and payload schemas.

Trust model (be precise about what this is):

* Every registered agent owns its *own* HMAC-SHA256 key. An agent can only produce a
  valid ``integrity_proof`` for its own ``sender_id``.
* The gateway holds a copy of every registered key (a symmetric key ring), so it is the
  trusted verifier. HMAC gives integrity and origin authentication *towards the gateway*;
  it does not give non-repudiation and does not encrypt anything.
* Keys are generated randomly per process (``secrets.token_bytes``) and never leave the
  Python process; they are never sent to the dashboard.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

PROTOCOL_VERSION = 2
MAC_ALGORITHM = "HMAC-SHA256"
MAX_ENVELOPE_BYTES = 4096

# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------
MONITOR = "agent-1-monitor"
VALIDATOR = "agent-2-validator"
ADVERSARY = "agent-3-adversary"
EMAIL_ACTION = "action:email"

# ---------------------------------------------------------------------------
# Message types and the strict route table (default deny: anything not listed is refused)
# ---------------------------------------------------------------------------
TELEMETRY = "telemetry.report"
ALERT = "alert.request"
EMAIL_SEND = "action.email.send"

ROUTES: Dict[str, Dict[str, Any]] = {
    TELEMETRY: {"senders": {MONITOR}, "receiver": VALIDATOR},
    ALERT: {"senders": {MONITOR}, "receiver": VALIDATOR},
    EMAIL_SEND: {"senders": {VALIDATOR}, "receiver": EMAIL_ACTION},
}
EMAIL_BEARING_TYPES = {ALERT, EMAIL_SEND}

ENVELOPE_FIELDS = {
    "protocol_version": int,
    "message_id": str,
    "correlation_id": str,
    "sender_id": str,
    "receiver_id": str,
    "message_type": str,
    "timestamp": float,
    "nonce": str,
    "sequence_number": int,
    "payload": dict,
    "integrity_proof": dict,
}
PROOF_FIELDS = {"alg", "key_id", "mac"}


class ProtocolError(ValueError):
    """A message failed validation. ``code`` is a stable machine-readable reason."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def canonical_bytes(data: Any) -> bytes:
    """Deterministic JSON encoding used for MACs and size limits."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False,
                      ensure_ascii=True).encode("ascii")


def compute_mac(key: bytes, unsigned: Dict[str, Any]) -> str:
    return hmac.new(key, canonical_bytes(unsigned), hashlib.sha256).hexdigest()


def _is_number(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(float(value)))


# ---------------------------------------------------------------------------
# Structural validation (schema of the envelope itself)
# ---------------------------------------------------------------------------
def check_structure(wire: Any) -> None:
    if not isinstance(wire, dict):
        raise ProtocolError("SCHEMA_INVALID", "envelope must be a JSON object")
    keys = set(wire)
    missing = sorted(set(ENVELOPE_FIELDS) - keys)
    extra = sorted(keys - set(ENVELOPE_FIELDS))
    if missing:
        raise ProtocolError("SCHEMA_INVALID", f"missing field(s): {', '.join(missing)}")
    if extra:
        raise ProtocolError("SCHEMA_INVALID", f"unexpected field(s): {', '.join(extra[:5])}")
    for name, kind in ENVELOPE_FIELDS.items():
        value = wire[name]
        if kind is float:
            ok = _is_number(value)
        elif kind is int:
            ok = isinstance(value, int) and not isinstance(value, bool)
        else:
            ok = isinstance(value, kind)
        if not ok:
            raise ProtocolError("SCHEMA_INVALID", f"field '{name}' has the wrong type")
    for name in ("message_id", "correlation_id", "sender_id", "receiver_id", "message_type"):
        if not wire[name] or len(wire[name]) > 128:
            raise ProtocolError("SCHEMA_INVALID", f"field '{name}' must be 1-128 characters")
    nonce = wire["nonce"]
    if len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
        raise ProtocolError("SCHEMA_INVALID", "nonce must be 32 lowercase hex characters")
    if wire["sequence_number"] < 1:
        raise ProtocolError("SCHEMA_INVALID", "sequence_number must be >= 1")
    proof = wire["integrity_proof"]
    if set(proof) != PROOF_FIELDS or not all(isinstance(proof[k], str) for k in PROOF_FIELDS):
        raise ProtocolError("SCHEMA_INVALID", "integrity_proof must contain string alg, key_id, mac")


def unsigned_view(wire: Dict[str, Any]) -> Dict[str, Any]:
    """Everything covered by the MAC: all envelope fields except the proof's mac itself."""
    data = {k: v for k, v in wire.items() if k != "integrity_proof"}
    data["integrity_proof"] = {"alg": wire["integrity_proof"].get("alg"),
                               "key_id": wire["integrity_proof"].get("key_id")}
    return data


# ---------------------------------------------------------------------------
# Payload schemas (strict: exact keys, typed, bounded)
# ---------------------------------------------------------------------------
def _signals(value: Any) -> bool:
    return (isinstance(value, list) and len(value) <= 10
            and all(isinstance(s, str) and 0 < len(s) <= 40 for s in value))


def _score(value: Any) -> bool:
    return _is_number(value) and 0 <= float(value) <= 100


def _text(limit: int) -> Callable[[Any], bool]:
    return lambda v: isinstance(v, str) and 0 < len(v) <= limit


PAYLOAD_SCHEMAS: Dict[str, Dict[str, Callable[[Any], bool]]] = {
    TELEMETRY: {"risk_score": _score, "signals": _signals, "source": _text(40)},
    ALERT: {"risk_score": _score, "threshold": _score, "signals": _signals, "summary": _text(200)},
    EMAIL_SEND: {"template": lambda v: v == "threshold_alert", "incident_id": _text(128),
                 "risk_score": _score, "summary": _text(200)},
}


def check_payload(message_type: str, payload: Dict[str, Any], strict: bool = True) -> None:
    schema = PAYLOAD_SCHEMAS[message_type]
    keys = set(payload)
    missing = sorted(set(schema) - keys)
    if missing:
        raise ProtocolError("PAYLOAD_INVALID", f"payload missing: {', '.join(missing)}")
    extra = sorted(keys - set(schema))
    if extra and strict:
        raise ProtocolError("PAYLOAD_INVALID", f"payload has unexpected field(s): {', '.join(extra[:5])}")
    for name, valid in schema.items():
        if not valid(payload[name]):
            raise ProtocolError("PAYLOAD_INVALID", f"payload field '{name}' is invalid")


# ---------------------------------------------------------------------------
# Keys and signing
# ---------------------------------------------------------------------------
@dataclass
class AgentKey:
    agent_id: str
    key_id: str
    secret: bytes = field(repr=False)


class KeyRing:
    """Gateway-side registry of agent verification keys."""

    def __init__(self) -> None:
        self._keys: Dict[str, AgentKey] = {}

    def register(self, agent_id: str, secret: Optional[bytes] = None) -> AgentKey:
        key = AgentKey(agent_id, f"{agent_id}#{secrets.token_hex(4)}", secret or secrets.token_bytes(32))
        self._keys[agent_id] = key
        return key

    def get(self, agent_id: str) -> Optional[AgentKey]:
        return self._keys.get(agent_id)

    def __contains__(self, agent_id: object) -> bool:
        return agent_id in self._keys

    def agents(self) -> list:
        return sorted(self._keys)


class Signer:
    """Agent-side signer. Holds exactly one key and a monotonically increasing sequence."""

    def __init__(self, key: AgentKey, clock: Callable[[], float] = time.time):
        self.key = key
        self._clock = clock
        self._seq = 0
        self._lock = threading.Lock()

    @property
    def agent_id(self) -> str:
        return self.key.agent_id

    def sign(self, receiver_id: str, message_type: str, payload: Dict[str, Any], *,
             correlation_id: Optional[str] = None, sender_id: Optional[str] = None,
             timestamp: Optional[float] = None, sequence_number: Optional[int] = None) -> Dict[str, Any]:
        """Build a wire envelope. Overrides exist so the adversary can craft hostile messages."""
        with self._lock:
            if sequence_number is None:
                self._seq += 1
                sequence_number = self._seq
        wire = {
            "protocol_version": PROTOCOL_VERSION,
            "message_id": str(uuid.uuid4()),
            "correlation_id": correlation_id or f"inc-{uuid.uuid4().hex[:12]}",
            "sender_id": sender_id or self.key.agent_id,
            "receiver_id": receiver_id,
            "message_type": message_type,
            "timestamp": float(self._clock() if timestamp is None else timestamp),
            "nonce": secrets.token_hex(16),
            "sequence_number": sequence_number,
            "payload": payload,
            "integrity_proof": {"alg": MAC_ALGORITHM, "key_id": self.key.key_id, "mac": ""},
        }
        wire["integrity_proof"]["mac"] = compute_mac(self.key.secret, unsigned_view(wire))
        return wire


def resign(wire: Dict[str, Any], key: AgentKey) -> Dict[str, Any]:
    """Recompute a MAC with ``key`` (used by the adversary with its *own* key)."""
    out = json.loads(json.dumps(wire))
    out["integrity_proof"] = {"alg": MAC_ALGORITHM, "key_id": key.key_id, "mac": ""}
    out["integrity_proof"]["mac"] = compute_mac(key.secret, unsigned_view(out))
    return out
