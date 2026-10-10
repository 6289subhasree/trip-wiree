"""The security gateway: the single enforcement point for agent traffic and protected actions.

Agents never call each other directly. Every envelope - legitimate or hostile - enters through
``Gateway.submit``. The pipeline is default-deny:

    size -> firewall -> envelope schema -> version -> message type -> sender registered ->
    MAC (key id + HMAC) -> route policy -> freshness -> replay -> sequence -> payload schema ->
    rate limit -> deliver to receiver -> (for actions) action policy -> side effect

Nothing is delivered and no side effect happens unless every step passes. The whole pipeline,
including the side effect, runs under ``Firewall.lock`` so firewall transitions cannot race it.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from . import firewall as fw
from .audit import AuditLog
from .firewall import Firewall
from .notifications import BLOCKED as MAIL_BLOCKED
from .notifications import REJECTED as MAIL_REJECTED
from .notifications import MockEmailService
from .protocol import (EMAIL_ACTION, EMAIL_BEARING_TYPES, EMAIL_SEND, MAC_ALGORITHM, MAX_ENVELOPE_BYTES,
                       PROTOCOL_VERSION, ROUTES, KeyRing, ProtocolError, canonical_bytes, check_payload,
                       check_structure, compute_mac, unsigned_view)
import hmac

ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"
BLOCKED = "BLOCKED"

STRICT = "strict"
BASELINE = "baseline"  # deliberately vulnerable comparison profile; never the default

# Intrusion-pressure weight for each rejection reason (heuristic, documented in ARCHITECTURE.md).
SEVERITY: Dict[str, int] = {
    "SCHEMA_INVALID": 10, "OVERSIZE": 15, "UNSUPPORTED_VERSION": 10, "UNKNOWN_MESSAGE_TYPE": 20,
    "UNKNOWN_SENDER": 30, "BAD_MAC": 40, "UNAUTHORIZED_ROUTE": 50, "STALE": 15,
    "FUTURE_TIMESTAMP": 15, "REPLAY": 35, "SEQUENCE_REGRESSION": 25, "PAYLOAD_INVALID": 30,
    "RATE_LIMITED": 5, "ACTION_DENIED": 20, "VALIDATOR_REFUSED": 10,
}

CODE_HELP: Dict[str, str] = {
    "SCHEMA_INVALID": "Envelope is not a well-formed v2 envelope",
    "OVERSIZE": f"Envelope exceeds {MAX_ENVELOPE_BYTES} bytes",
    "UNSUPPORTED_VERSION": "Protocol version is not supported",
    "UNKNOWN_MESSAGE_TYPE": "Message type is not on the allowlist",
    "UNKNOWN_SENDER": "Sender is not a registered agent",
    "BAD_MAC": "Integrity proof does not verify with the sender's key",
    "UNAUTHORIZED_ROUTE": "Sender is not allowed to send this type to this receiver",
    "STALE": "Message is older than the freshness window",
    "FUTURE_TIMESTAMP": "Message timestamp is in the future",
    "REPLAY": "Nonce or message ID was already used",
    "SEQUENCE_REGRESSION": "Sequence number is not greater than the last accepted one",
    "PAYLOAD_INVALID": "Payload does not match the strict schema for its type",
    "RATE_LIMITED": "Sender exceeded its message budget",
    "ACTION_DENIED": "Action policy refused the protected action",
    "VALIDATOR_REFUSED": "Receiver refused the request on semantic grounds",
    "FIREWALL_BLOCKING": "Firewall kill switch engaged",
    "FIREWALL_LOCKDOWN": "System is in LOCKDOWN",
}


@dataclass
class Decision:
    seq: int
    at: float
    outcome: str
    code: str
    reason: str
    message_id: str = "?"
    correlation_id: str = "?"
    sender_id: str = "?"
    receiver_id: str = "?"
    message_type: str = "?"
    firewall_mode: str = fw.NORMAL
    profile: str = STRICT
    severity: int = 0
    latency_ms: float = 0.0
    would_fail: Optional[str] = None
    handled: Optional[str] = None
    email: Optional[Dict[str, Any]] = None
    action: Optional["Decision"] = None
    origin: str = "unknown"  # simulation ground-truth label added by the session, never used to decide

    def walk(self) -> List["Decision"]:
        out: List[Decision] = [self]
        if self.action is not None:
            out.extend(self.action.walk())
        return out

    def to_dict(self) -> Dict[str, Any]:
        data = {k: v for k, v in self.__dict__.items() if k != "action"}
        data["action"] = self.action.to_dict() if self.action else None
        return data


class _Bucket:
    def __init__(self, capacity: float, refill_per_s: float, now: float):
        self.capacity, self.refill, self.tokens, self.at = capacity, refill_per_s, capacity, now

    def available(self, now: float) -> float:
        return min(self.capacity, self.tokens + (now - self.at) * self.refill)

    def take(self, now: float) -> None:
        self.tokens, self.at = self.available(now) - 1, now


Handler = Callable[[Dict[str, Any]], Tuple[str, Optional[Dict[str, Any]]]]


class Gateway:
    def __init__(self, keyring: KeyRing, firewall: Firewall, audit: AuditLog, outbox: MockEmailService, *,
                 clock: Callable[[], float] = time.time, freshness_s: float = 30.0, max_skew_s: float = 5.0,
                 rate_capacity: int = 12, rate_refill_per_s: float = 2.0, email_limit: int = 5,
                 email_window_s: float = 60.0, lockdown_threshold: float = 200.0,
                 pressure_half_life_s: float = 120.0, auto_lockdown: bool = True):
        self.keys, self.firewall, self.audit, self.outbox = keyring, firewall, audit, outbox
        self.clock = clock
        self.freshness_s, self.max_skew_s = freshness_s, max_skew_s
        self.rate_capacity, self.rate_refill = rate_capacity, rate_refill_per_s
        self.email_limit, self.email_window_s = email_limit, email_window_s
        self.lockdown_threshold, self.half_life = lockdown_threshold, pressure_half_life_s
        self.auto_lockdown = auto_lockdown
        self.profile = STRICT
        self.receivers: Dict[str, Handler] = {}
        self.decisions: Deque[Decision] = deque(maxlen=300)
        self._seq = 0
        self._seen: Dict[str, float] = {}           # nonce / message id -> first seen time
        self._last_seq: Dict[str, int] = {}
        self._buckets: Dict[str, _Bucket] = {}
        self._emailed: Dict[str, float] = {}       # correlation id -> delivery time
        self._email_times: Deque[float] = deque()
        self._pressure, self._pressure_at = 0.0, clock()
        self.last_lockdown_trigger: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------ config
    def register_receiver(self, receiver_id: str, handler: Handler) -> None:
        self.receivers[receiver_id] = handler

    def set_profile(self, profile: str, actor: str = "operator") -> None:
        if profile not in (STRICT, BASELINE):
            raise ValueError("profile must be 'strict' or 'baseline'")
        with self.firewall.lock:
            if profile != self.profile:
                self.profile = profile
                self.audit.append("gateway.profile", {"profile": profile, "actor": actor,
                                                      "warning": "INSECURE baseline" if profile == BASELINE else None})

    def pressure(self) -> float:
        with self.firewall.lock:
            now = self.clock()
            return self._pressure * 0.5 ** (max(0.0, now - self._pressure_at) / self.half_life)

    def reset_pressure(self) -> None:
        with self.firewall.lock:
            self._pressure, self._pressure_at = 0.0, self.clock()

    # ------------------------------------------------------------------ entry point
    def submit(self, wire: Any, origin: str = "unknown") -> Decision:
        with self.firewall.lock:
            decision = self._process(wire, depth=0)
            for d in decision.walk():
                d.origin = origin
            return decision

    def _process(self, wire: Any, depth: int) -> Decision:
        started = time.perf_counter()
        now = self.clock()
        self._seq += 1
        meta = self._meta(wire)
        d = Decision(self._seq, now, ACCEPTED, "OK", "accepted", firewall_mode=self.firewall.mode,
                     profile=self.profile, **meta)
        try:
            size = len(canonical_bytes(wire))
        except (TypeError, ValueError):
            size = -1
        if size < 0:
            self._reject(d, ProtocolError("SCHEMA_INVALID", "envelope is not canonical JSON"))
        elif size > MAX_ENVELOPE_BYTES:
            self._reject(d, ProtocolError("OVERSIZE", f"envelope is {size} bytes (limit {MAX_ENVELOPE_BYTES})"))
        elif not self.firewall.permits():
            mode = self.firewall.mode
            d.outcome, d.code = BLOCKED, f"FIREWALL_{mode}"
            d.reason = f"firewall {mode}: {self.firewall.reason}"
            try:  # inspection, to label what else was wrong with it
                self._validate(wire, now, commit=False)
                # Authentic, otherwise-valid message denied by the firewall: burn its nonce, id and
                # sequence so a MITM who captured it cannot re-inject it after recovery.
                self._burn(wire, now)
            except ProtocolError as exc:
                d.would_fail = exc.code
        else:
            try:
                self._validate(wire, now, commit=True)
            except ProtocolError as exc:
                self._reject(d, exc)
        d.latency_ms = round((time.perf_counter() - started) * 1000, 3)

        if d.outcome == ACCEPTED:
            self._deliver(wire, d, depth)
        self._record(d)
        return d

    # ------------------------------------------------------------------ validation
    def _validate(self, wire: Any, now: float, commit: bool) -> None:
        check_structure(wire)
        if wire["protocol_version"] != PROTOCOL_VERSION:
            raise ProtocolError("UNSUPPORTED_VERSION", f"version {wire['protocol_version']} is not supported")
        mtype, sender = wire["message_type"], wire["sender_id"]
        if mtype not in ROUTES:
            raise ProtocolError("UNKNOWN_MESSAGE_TYPE", f"message type '{mtype[:40]}' is not allowed")
        strict = self.profile == STRICT
        if strict:
            key = self.keys.get(sender)
            if key is None:
                raise ProtocolError("UNKNOWN_SENDER", f"sender '{sender[:40]}' is not a registered agent")
            proof = wire["integrity_proof"]
            if proof["alg"] != MAC_ALGORITHM or proof["key_id"] != key.key_id:
                raise ProtocolError("BAD_MAC", "integrity proof uses an unknown key id or algorithm")
            if not hmac.compare_digest(compute_mac(key.secret, unsigned_view(wire)), proof["mac"]):
                raise ProtocolError("BAD_MAC", "integrity proof does not verify (forged or tampered)")
            route = ROUTES[mtype]
            if sender not in route["senders"] or wire["receiver_id"] != route["receiver"]:
                raise ProtocolError("UNAUTHORIZED_ROUTE",
                                    f"{sender} may not send {mtype} to {wire['receiver_id'][:40]}")
            age = now - float(wire["timestamp"])
            if age > self.freshness_s:
                raise ProtocolError("STALE", f"message is {age:.0f}s old (window {self.freshness_s:.0f}s)")
            if age < -self.max_skew_s:
                raise ProtocolError("FUTURE_TIMESTAMP", f"message is {-age:.0f}s in the future")
            if wire["nonce"] in self._seen or ("id:" + wire["message_id"]) in self._seen:
                raise ProtocolError("REPLAY", "nonce/message ID already used")
            last = self._last_seq.get(sender, 0)
            if wire["sequence_number"] <= last:
                raise ProtocolError("SEQUENCE_REGRESSION",
                                    f"sequence {wire['sequence_number']} <= last accepted {last}")
        check_payload(mtype, wire["payload"], strict=strict)
        bucket = None
        if strict:
            bucket = self._buckets.get(sender) or _Bucket(self.rate_capacity, self.rate_refill, now)
            if bucket.available(now) < 1:
                raise ProtocolError("RATE_LIMITED", f"{sender} exceeded {self.rate_capacity} msgs burst "
                                                    f"/ {self.rate_refill:g} per s")
        if commit and strict:
            self._buckets[sender] = bucket
            bucket.take(now)
            self._seen[wire["nonce"]] = now
            self._seen["id:" + wire["message_id"]] = now
            self._last_seq[sender] = wire["sequence_number"]
            self._prune(now)

    def _burn(self, wire: Dict[str, Any], now: float) -> None:
        if self.profile != STRICT:
            return
        self._seen[wire["nonce"]] = now
        self._seen["id:" + wire["message_id"]] = now
        self._last_seq[wire["sender_id"]] = max(self._last_seq.get(wire["sender_id"], 0), wire["sequence_number"])

    def _prune(self, now: float) -> None:
        # Entries older than the freshness window can be forgotten: such messages are STALE anyway.
        if len(self._seen) > 4000:
            horizon = now - self.freshness_s - self.max_skew_s - 1
            self._seen = {k: t for k, t in self._seen.items() if t >= horizon}

    # ------------------------------------------------------------------ delivery and actions
    def _deliver(self, wire: Dict[str, Any], d: Decision, depth: int) -> None:
        receiver = ROUTES[wire["message_type"]]["receiver"] if self.profile == STRICT else wire["receiver_id"]
        if receiver == EMAIL_ACTION:
            self._email_action(wire, d)
            return
        handler = self.receivers.get(receiver)
        if handler is None:
            d.outcome, d.code, d.reason = REJECTED, "UNAUTHORIZED_ROUTE", f"no receiver '{receiver[:40]}'"
            return
        note, outbound = handler(wire)
        d.handled = note
        if note.startswith("refused"):
            d.code = "VALIDATOR_REFUSED"
            d.severity = SEVERITY["VALIDATOR_REFUSED"]
            self._add_pressure(d)
        if outbound is not None and depth < 2:
            d.action = self._process(outbound, depth + 1)

    def _email_action(self, wire: Dict[str, Any], d: Decision) -> None:
        payload, now = wire["payload"], self.clock()
        if self.profile == STRICT:
            while self._email_times and now - self._email_times[0] > self.email_window_s:
                self._email_times.popleft()
            denial = None
            if wire["correlation_id"] in self._emailed:
                denial = "an email was already sent for this incident (one email per incident)"
            elif len(self._email_times) >= self.email_limit:
                denial = f"email rate limit: {self.email_limit} per {self.email_window_s:.0f}s"
            if denial:
                self._reject(d, ProtocolError("ACTION_DENIED", denial))
                return
            recipients = None  # server-side configuration only
        else:
            to = payload.get("to")
            recipients = to if isinstance(to, list) and all(isinstance(x, str) for x in to) else None
        record = self.outbox.deliver(correlation_id=wire["correlation_id"], incident_id=str(payload["incident_id"]),
                                     risk_score=float(payload["risk_score"]), summary=str(payload["summary"]),
                                     to=recipients)
        self._emailed[wire["correlation_id"]] = now
        self._email_times.append(now)
        d.email = {"id": record["id"], "status": record["status"], "to": record["to"]}
        d.handled = "email simulated-delivered to " + ", ".join(record["to"])
        self.audit.append("email.delivered", {"mail_id": record["id"], "correlation_id": wire["correlation_id"],
                                              "to": record["to"], "simulated": True, "profile": self.profile})

    # ------------------------------------------------------------------ bookkeeping
    def _reject(self, d: Decision, exc: ProtocolError) -> None:
        d.outcome, d.code, d.reason = REJECTED, exc.code, exc.detail
        d.severity = SEVERITY.get(exc.code, 10)
        self._add_pressure(d)

    def _add_pressure(self, d: Decision) -> None:
        now = self.clock()
        self._pressure = self.pressure() + d.severity
        self._pressure_at = now
        if self.auto_lockdown and self._pressure >= self.lockdown_threshold and self.firewall.mode != fw.LOCKDOWN:
            reason = (f"auto: intrusion pressure {self._pressure:.0f} >= {self.lockdown_threshold:.0f} "
                      f"(last: {d.code} from {d.sender_id[:40]})")
            self.last_lockdown_trigger = {"at": now, "code": d.code, "pressure": round(self._pressure, 1),
                                          "decision_seq": d.seq}
            self.firewall.lockdown("gateway:auto", reason, automatic=True)

    def _record(self, d: Decision) -> None:
        if d.message_type in EMAIL_BEARING_TYPES and (d.outcome != ACCEPTED or d.code == "VALIDATOR_REFUSED"):
            status = MAIL_BLOCKED if d.outcome == BLOCKED else MAIL_REJECTED
            self.outbox.deny(status, correlation_id=d.correlation_id, reason=d.reason, code=d.code,
                             message_type=d.message_type, sender_id=d.sender_id)
        self.audit.append("gateway.decision", {
            "decision": d.seq, "outcome": d.outcome, "code": d.code, "reason": d.reason[:200],
            "message_id": d.message_id, "correlation_id": d.correlation_id, "sender": d.sender_id,
            "receiver": d.receiver_id, "type": d.message_type, "firewall": d.firewall_mode,
            "profile": d.profile, "would_fail": d.would_fail, "handled": d.handled})
        self.decisions.append(d)

    @staticmethod
    def _meta(wire: Any) -> Dict[str, str]:
        out = {}
        if isinstance(wire, dict):
            for key in ("message_id", "correlation_id", "sender_id", "receiver_id", "message_type"):
                value = wire.get(key)
                if isinstance(value, str) and value:
                    out[key] = value[:64]
        return out
