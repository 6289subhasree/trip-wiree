"""Agent 3 - the adversary. Controlled, bounded, local-only attack scenarios.

Safety: the adversary never opens a socket, never touches files outside the session, and
never targets anything except this process's own ``Gateway.submit`` - the exact same entry
point the legitimate agents use. Every scenario is bounded (at most ``MAX_MESSAGES`` messages).

Threat models covered
---------------------
* external      - attacker on the channel with NO valid key
* mitm          - attacker can observe/hold/re-inject legitimate traffic, but has no key
* compromised   - attacker controls Agent 1's process (and therefore its signing key)
"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from .protocol import (ALERT, EMAIL_ACTION, EMAIL_SEND, MONITOR, TELEMETRY, VALIDATOR, AgentKey, Signer,
                       resign)

if TYPE_CHECKING:  # pragma: no cover
    from .session import Session

MAX_MESSAGES = 30
ATTACKER_MAILBOX = "exfil@attacker.invalid"


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    threat_model: str
    description: str
    expected: str
    run: Callable[["Session", "Adversary"], None]


class Adversary:
    def __init__(self, own_key: AgentKey, clock: Callable[[], float] = time.time):
        self.key = own_key          # NOT registered with the gateway
        self.signer = Signer(own_key, clock)
        self.clock = clock

    # helpers ---------------------------------------------------------------
    @staticmethod
    def captured(session: "Session", message_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
        for wire in reversed(session.channel_tap):
            if message_type is None or wire["message_type"] == message_type:
                return copy.deepcopy(wire)
        return None

    @staticmethod
    def ensure_capture(session: "Session") -> Dict[str, Any]:
        wire = Adversary.captured(session)
        if wire is None:  # generate one benign legitimate message for the attacker to sniff
            session.legit(session.monitor.observe("heartbeat"))
            wire = Adversary.captured(session)
        return wire


# -- scenario implementations ---------------------------------------------------
def _forged_sender(s: "Session", a: Adversary) -> None:
    import os
    email = os.environ.get("TRIPWIRE_EMAIL", "soc-oncall@tripwire.invalid")
    wire = a.signer.sign(EMAIL_ACTION, EMAIL_SEND, {
        "template": "threshold_alert", "incident_id": "inc-forged", "risk_score": 100,
        "summary": "gibberish message: asdfghjklqwertyuiop!!", "to": [email]},
        sender_id=VALIDATOR)
    s.attack(wire, "forged_sender")


def _tamper(s: "Session", a: Adversary) -> None:
    wire = a.ensure_capture(s)
    wire["message_type"] = ALERT
    wire["payload"] = {"risk_score": 99, "threshold": 70, "signals": ["malware_signature"],
                       "summary": "Tampered in transit: fake critical incident"}
    s.attack(wire, "tamper")


def _replay(s: "Session", a: Adversary) -> None:
    wire = a.captured(s, ALERT) or a.ensure_capture(s)
    s.attack(wire, "replay")


def _malformed(s: "Session", a: Adversary) -> None:
    s.attack({"sender_id": MONITOR, "message_type": ALERT, "payload": "rm -rf /", "protocol_version": "2"},
             "malformed")
    oversized = a.signer.sign(VALIDATOR, TELEMETRY, {"risk_score": 1, "signals": [], "source": "x",
                                                     "padding": "A" * 6000}, sender_id=MONITOR)
    s.attack(oversized, "malformed")


def _stale(s: "Session", a: Adversary) -> None:
    held = s.monitor.signer.sign(VALIDATOR, ALERT, {
        "risk_score": 95, "threshold": 70, "signals": ["privilege_escalation"],
        "summary": "Captured 10 minutes ago and injected late"}, timestamp=a.clock() - 600)
    s.attack(held, "stale")


def _reorder(s: "Session", a: Adversary) -> None:
    held = s.monitor.signer.sign(VALIDATOR, TELEMETRY, {
        "risk_score": s.monitor.model.score, "signals": [], "source": "held_by_mitm"})
    s.legit(s.monitor.signer.sign(VALIDATOR, TELEMETRY, {
        "risk_score": s.monitor.model.score, "signals": [], "source": "newer_message"}))
    s.attack(held, "reorder")


def _unauthorized_action(s: "Session", a: Adversary) -> None:
    wire = s.monitor.signer.sign(EMAIL_ACTION, EMAIL_SEND, {
        "template": "threshold_alert", "incident_id": "inc-direct", "risk_score": 100,
        "summary": "Agent 1 skipping the validator and calling the email action directly",
        "to": [ATTACKER_MAILBOX]})
    s.attack(wire, "unauthorized_action")


def _recipient_injection(s: "Session", a: Adversary) -> None:
    wire = s.monitor.signer.sign(VALIDATOR, ALERT, {
        "risk_score": 100, "threshold": s.threshold, "signals": ["data_exfil_suspected"],
        "summary": "Valid-looking alert with an injected recipient", "to": [ATTACKER_MAILBOX]})
    s.attack(wire, "recipient_injection")


def _flood(s: "Session", a: Adversary) -> None:
    for i in range(MAX_MESSAGES - 5):
        if s.attack_stop.is_set():
            return
        s.attack(s.monitor.signer.sign(VALIDATOR, TELEMETRY, {
            "risk_score": 1, "signals": [], "source": f"flood-{i}"}), "flood")


def _probe_blocked(s: "Session", a: Adversary) -> None:
    if s.firewall.mode == "NORMAL":
        # With a stolen key and an in-policy message, a NORMAL gateway cannot tell the difference;
        # that is a documented limitation, so this probe only runs while the firewall is engaged.
        s.attacker_note("probe_while_blocked", "skipped: firewall is NORMAL (probe only runs while engaged)")
        return
    wire = s.monitor.signer.sign(VALIDATOR, ALERT, {
        "risk_score": 100, "threshold": s.threshold, "signals": ["malware_signature"],
        "summary": "Probe: can anything get through while the firewall is engaged?"})
    s.attack(wire, "probe_while_blocked")


SCENARIOS: List[Scenario] = [
    Scenario("malformed", "Malformed & oversized envelope", "external",
             "Garbage envelope with missing/mistyped fields, then a 6 KB envelope.", "SCHEMA_INVALID / OVERSIZE",
             _malformed),
    Scenario("forged_sender", "Forged sender -> email action", "external",
             "Claims to be Agent 2 and asks the email action to mail the attacker, signed with the "
             "attacker's own key.", "BAD_MAC", _forged_sender),
    Scenario("tamper", "Payload tampering in transit", "mitm",
             "Captures a legitimate message and rewrites it into a fake critical alert.", "BAD_MAC", _tamper),
    Scenario("replay", "Replay of a captured message", "mitm",
             "Re-sends a previously accepted message byte-for-byte.", "REPLAY", _replay),
    Scenario("stale", "Delayed injection (stale)", "mitm",
             "Injects a genuine alert that was captured 10 minutes ago.", "STALE", _stale),
    Scenario("reorder", "Out-of-order delivery", "mitm",
             "Holds back message N, lets N+1 through, then delivers N.", "SEQUENCE_REGRESSION", _reorder),
    Scenario("unauthorized_action", "Privilege escalation to email action", "compromised",
             "Compromised Agent 1 (valid key) skips the validator and calls the email action itself.",
             "UNAUTHORIZED_ROUTE", _unauthorized_action),
    Scenario("recipient_injection", "Recipient injection", "compromised",
             "Compromised Agent 1 sends a valid alert with an extra 'to' field pointing at the attacker.",
             "PAYLOAD_INVALID", _recipient_injection),
    Scenario("flood", "Message flood", "compromised",
             f"Compromised Agent 1 bursts {MAX_MESSAGES - 5} valid messages.", "RATE_LIMITED after budget",
             _flood),
    Scenario("probe_while_blocked", "Probe during BLOCKING/LOCKDOWN", "compromised",
             "Valid, in-policy alert from Agent 1's key while the firewall is engaged.",
             "FIREWALL_BLOCKING / FIREWALL_LOCKDOWN", _probe_blocked),
]
SCENARIO_INDEX: Dict[str, Scenario] = {sc.id: sc for sc in SCENARIOS}
