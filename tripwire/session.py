"""One running TripWire system: agents, gateway, firewall, outbox, audit, attacker and metrics.

The HTTP server, the CLI demos and the tests all drive the system through this class, so the
dashboard shows exactly what the tested code does.
"""
from __future__ import annotations

import copy
import secrets
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from . import firewall as fw
from .agents import EventMonitor, Validator
from .attacks import SCENARIO_INDEX, SCENARIOS, Adversary
from .audit import AuditLog
from .firewall import Firewall, FirewallError
from .gateway import ACCEPTED, BASELINE, BLOCKED, CODE_HELP, REJECTED, STRICT, Decision, Gateway
from .notifications import MockEmailService
from .protocol import ADVERSARY, EMAIL_ACTION, MONITOR, ROUTES, VALIDATOR, AgentKey, KeyRing, Signer
from .risk import DEFAULT_THRESHOLD, STREAMS, WEIGHTS


def new_recovery_code() -> str:
    return "TW-" + secrets.token_hex(3).upper()


class Session:
    def __init__(self, threshold: float = DEFAULT_THRESHOLD, *, recovery_code: Optional[str] = None,
                 data_dir: Optional[str] = None, attack_delay_s: float = 0.6, auto_lockdown: bool = True,
                 lockdown_threshold: float = 200.0, firewall_mode: str = fw.NORMAL, clock=time.time):
        self.clock = clock
        self.recovery_code = recovery_code or new_recovery_code()
        self.data_dir = Path(data_dir or tempfile.mkdtemp(prefix="tripwire-"))
        self.attack_delay_s = attack_delay_s
        self.threshold = self._check_threshold(threshold)
        self.attack_stop = threading.Event()
        self._attack_thread: Optional[threading.Thread] = None
        self._build(firewall_mode, STRICT, auto_lockdown, lockdown_threshold)

    # ------------------------------------------------------------------ construction
    def _build(self, mode: str, profile: str, auto_lockdown: bool, lockdown_threshold: float) -> None:
        self.audit = AuditLog(str(self.data_dir / "audit.jsonl"), clock=self.clock)
        self.firewall = Firewall(self.recovery_code, mode=mode, clock=self.clock,
                                 on_transition=lambda t: self.audit.append("firewall.transition", dict(t.__dict__)),
                                 on_event=lambda k, d: self.audit.append("firewall." + k, d))
        self.lock = self.firewall.lock
        self.outbox = MockEmailService(str(self.data_dir / "outbox.jsonl"), clock=self.clock)
        self.keyring = KeyRing()
        monitor_key = self.keyring.register(MONITOR)
        validator_key = self.keyring.register(VALIDATOR)
        adversary_key = AgentKey(ADVERSARY, f"{ADVERSARY}#{secrets.token_hex(4)}", secrets.token_bytes(32))
        self.gateway = Gateway(self.keyring, self.firewall, self.audit, self.outbox, clock=self.clock,
                               auto_lockdown=auto_lockdown, lockdown_threshold=lockdown_threshold)
        self.monitor = EventMonitor(Signer(monitor_key, self.clock), lambda: self.threshold)
        self.validator = Validator(Signer(validator_key, self.clock), lambda: self.threshold)
        self.gateway.register_receiver(VALIDATOR, self.validator.handle)
        self.adversary = Adversary(adversary_key, self.clock)
        self.channel_tap: Deque[Dict[str, Any]] = deque(maxlen=50)
        self.feed: Deque[Dict[str, Any]] = deque(maxlen=80)
        self.attack_log: Deque[Dict[str, Any]] = deque(maxlen=120)
        self.stream_pos: Dict[str, int] = {name: 0 for name in STREAMS}
        self.attack_run: Dict[str, Any] = {"running": False, "current": None, "done": 0, "total": 0,
                                           "started_at": None, "finished_at": None, "stopped": False}
        self.m: Dict[str, Any] = {k: 0 for k in (
            "messages", "accepted", "rejected", "blocked", "legit", "legit_accepted", "legit_rejected",
            "legit_blocked", "attack_attempts", "attack_detected", "attack_rejected", "attack_blocked",
            "attack_passed", "unauthorized_emails", "emails_delivered", "email_denied", "validator_refused")}
        self._attack_latencies: List[float] = []
        self.audit.append("session.start", {"threshold": self.threshold, "firewall": mode, "profile": STRICT,
                                            "agents": self.keyring.agents(), "adversary": ADVERSARY,
                                            "routes": {k: {"senders": sorted(v["senders"]), "receiver": v["receiver"]}
                                                       for k, v in ROUTES.items()}})
        self.set_profile(profile)

    @staticmethod
    def _check_threshold(value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not (1 <= float(value) <= 100):
            raise ValueError("threshold must be a number between 1 and 100")
        return float(value)

    # ------------------------------------------------------------------ message paths
    def submit(self, wire: Any, origin: str) -> Decision:
        with self.lock:
            d = self.gateway.submit(wire, origin=origin)
            self._account(d, origin)
            self.feed.appendleft(d.to_dict())
            return d

    def legit(self, wire: Dict[str, Any]) -> Decision:
        with self.lock:
            self.channel_tap.append(copy.deepcopy(wire))  # the channel is observable by a MITM
            d = self.submit(wire, "legit")
            for node in d.walk():
                if node.email and node.message_type and d.correlation_id:
                    self.monitor.acknowledge(d.correlation_id, True)
            return d

    def attack(self, wire: Any, scenario: str) -> Decision:
        with self.lock:
            d = self.submit(wire, "attack:" + scenario)
            detected = d.outcome == REJECTED or (d.outcome == BLOCKED and d.would_fail is not None) \
                or d.code == "VALIDATOR_REFUSED"
            self.attack_log.appendleft({"at": d.at, "scenario": scenario, "outcome": d.outcome, "code": d.code,
                                        "reason": d.reason, "would_fail": d.would_fail, "detected": detected,
                                        "email": any(n.email for n in d.walk()), "decision": d.seq})
            return d

    def attacker_note(self, scenario: str, note: str) -> None:
        with self.lock:
            self.attack_log.appendleft({"at": self.clock(), "scenario": scenario, "outcome": "SKIPPED",
                                        "code": "-", "reason": note, "would_fail": None, "detected": False,
                                        "email": False, "decision": None})

    def _account(self, d: Decision, origin: str) -> None:
        m = self.m
        for node in d.walk():
            m["messages"] += 1
            m[{ACCEPTED: "accepted", REJECTED: "rejected", BLOCKED: "blocked"}[node.outcome]] += 1
            if node.code == "VALIDATOR_REFUSED":
                m["validator_refused"] += 1
            if node.email:
                m["emails_delivered"] += 1
                if origin.startswith("attack:"):
                    m["unauthorized_emails"] += 1
            elif node.message_type in ("alert.request", "action.email.send") and \
                    (node.outcome != ACCEPTED or node.code == "VALIDATOR_REFUSED"):
                m["email_denied"] += 1
        if origin == "legit":
            m["legit"] += 1
            m[{ACCEPTED: "legit_accepted", REJECTED: "legit_rejected", BLOCKED: "legit_blocked"}[d.outcome]] += 1
        elif origin.startswith("attack:"):
            m["attack_attempts"] += 1
            if d.outcome == REJECTED:
                m["attack_rejected"] += 1
                m["attack_detected"] += 1
                self._attack_latencies.append(d.latency_ms)
            elif d.outcome == BLOCKED:
                m["attack_blocked"] += 1
                if d.would_fail:
                    m["attack_detected"] += 1
            elif d.code == "VALIDATOR_REFUSED":
                m["attack_detected"] += 1
            else:
                m["attack_passed"] += 1

    # ------------------------------------------------------------------ agent 1 controls
    def event(self, event_type: str) -> Decision:
        with self.lock:
            if event_type not in WEIGHTS:
                raise ValueError(f"unknown event type; choose one of {', '.join(WEIGHTS)}")
            return self.legit(self.monitor.observe(event_type))

    def stream_step(self, name: str) -> Dict[str, Any]:
        with self.lock:
            if name not in STREAMS:
                raise ValueError(f"unknown stream; choose one of {', '.join(STREAMS)}")
            pos = self.stream_pos[name]
            if pos >= len(STREAMS[name]):
                raise ValueError(f"stream '{name}' finished; reset streams to replay it")
            event_type = STREAMS[name][pos]
            self.stream_pos[name] = pos + 1
            d = self.legit(self.monitor.observe(event_type))
            return {"event": event_type, "step": pos + 1, "of": len(STREAMS[name]), "decision": d}

    def reset_streams(self) -> None:
        with self.lock:
            self.stream_pos = {name: 0 for name in STREAMS}
            self.monitor.model.score = 0.0
            self.monitor.model.recent = []
            self.monitor.incident = None
            self.audit.append("monitor.stream_reset", {})

    def report_score(self, score: Any) -> Decision:
        with self.lock:
            if isinstance(score, bool) or not isinstance(score, (int, float)) or not (0 <= float(score) <= 100):
                raise ValueError("score must be a number between 0 and 100")
            return self.legit(self.monitor.observe_score(float(score)))

    def send_alert(self) -> Decision:
        with self.lock:
            return self.legit(self.monitor.alert())

    # ------------------------------------------------------------------ operator controls
    def set_threshold(self, value: Any) -> None:
        with self.lock:
            self.threshold = self._check_threshold(value)
            self.audit.append("config.threshold", {"threshold": self.threshold})

    def set_firewall(self, mode: str, actor: str = "operator") -> None:
        with self.lock:
            if mode == fw.BLOCKING:
                self.firewall.engage(actor, "operator kill switch")
            elif mode == fw.LOCKDOWN:
                self.firewall.lockdown(actor, "manual emergency lockdown", automatic=False)
            elif mode == fw.NORMAL:
                self.firewall.release(actor)
            else:
                raise ValueError("mode must be NORMAL, BLOCKING or LOCKDOWN")

    def recover(self, code: Any, actor: str = "operator") -> None:
        with self.lock:
            self.firewall.recover(code if isinstance(code, str) else "", actor)
            self.gateway.reset_pressure()

    def set_profile(self, profile: str) -> None:
        with self.lock:
            self.gateway.set_profile(profile)
            self.validator.naive = profile == BASELINE

    def set_auto_lockdown(self, enabled: Any, threshold: Any = None) -> None:
        with self.lock:
            if not isinstance(enabled, bool):
                raise ValueError("enabled must be true or false")
            if threshold is not None:
                if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not 20 <= threshold <= 1000:
                    raise ValueError("lockdown threshold must be between 20 and 1000")
                self.gateway.lockdown_threshold = float(threshold)
            self.gateway.auto_lockdown = enabled
            self.audit.append("config.auto_lockdown", {"enabled": enabled,
                                                       "threshold": self.gateway.lockdown_threshold})

    # ------------------------------------------------------------------ attacker controls
    def run_attack(self, scenario_id: str) -> List[Dict[str, Any]]:
        sc = SCENARIO_INDEX.get(scenario_id)
        if sc is None:
            raise ValueError(f"unknown attack scenario '{scenario_id[:40]}'")
        with self.lock:
            before = len(self.attack_log)
            self.audit.append("adversary.scenario", {"scenario": sc.id, "threat_model": sc.threat_model})
            self.attack_run["current"] = sc.id
            sc.run(self, self.adversary)
            produced = list(self.attack_log)[: max(0, len(self.attack_log) - before)]
            return list(reversed(produced))

    def start_attack_sequence(self, ids: Optional[List[str]] = None) -> None:
        ids = ids or [sc.id for sc in SCENARIOS]
        for i in ids:
            if i not in SCENARIO_INDEX:
                raise ValueError(f"unknown attack scenario '{str(i)[:40]}'")
        with self.lock:
            if self.attack_run["running"]:
                raise ValueError("an attack sequence is already running")
            self.attack_stop.clear()
            self.attack_run.update(running=True, current=None, done=0, total=len(ids), started_at=self.clock(),
                                   finished_at=None, stopped=False, lockdown_after_s=None)
            self.audit.append("adversary.sequence_start", {"scenarios": ids})
        thread = threading.Thread(target=self._sequence, args=(ids,), daemon=True, name="tripwire-adversary")
        self._attack_thread = thread
        thread.start()

    def _sequence(self, ids: List[str]) -> None:
        try:
            for i, sid in enumerate(ids):
                if self.attack_stop.is_set():
                    break
                with self.lock:
                    was_locked = self.firewall.mode == fw.LOCKDOWN
                    self.run_attack(sid)
                    self.attack_run["done"] = i + 1
                    if not was_locked and self.firewall.mode == fw.LOCKDOWN and self.attack_run.get("lockdown_after_s") is None:
                        self.attack_run["lockdown_after_s"] = round(self.clock() - self.attack_run["started_at"], 2)
                if self.attack_delay_s and self.attack_stop.wait(self.attack_delay_s):
                    break
        finally:
            with self.lock:
                self.attack_run.update(running=False, current=None, finished_at=self.clock(),
                                       stopped=self.attack_stop.is_set())
                self.audit.append("adversary.sequence_end", {"completed": self.attack_run["done"],
                                                             "stopped": self.attack_run["stopped"]})

    def stop_attacks(self, wait: float = 5.0) -> None:
        self.attack_stop.set()
        thread = self._attack_thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(wait)

    # ------------------------------------------------------------------ audit + reset
    def verify_audit(self) -> Dict[str, Any]:
        result = self.audit.verify()
        with self.lock:
            self.audit.append("audit.verify", {"ok": result["ok"], "checked": result["checked"],
                                               "broken_at": result["broken_at"]})
        return result

    def tamper_audit(self) -> Dict[str, Any]:
        """Demo: an intruder with file access but no audit key edits an old decision record."""
        with self.lock:
            for entry in self.audit.entries:
                if entry["kind"] == "gateway.decision" and entry["data"].get("outcome") != ACCEPTED:
                    entry["data"] = dict(entry["data"], outcome=ACCEPTED, code="OK", reason="(edited by intruder)")
                    return {"tampered_seq": entry["seq"]}
            raise ValueError("no rejected/blocked decision in the log yet to tamper with")

    def reset(self) -> None:
        self.stop_attacks()
        with self.lock:
            mode, profile = self.firewall.mode, self.gateway.profile
            auto, lthr = self.gateway.auto_lockdown, self.gateway.lockdown_threshold
        # Reset never bypasses LOCKDOWN/BLOCKING: the current mode is carried into the new session.
        self._build(mode, profile, auto, lthr)
        self.attack_stop.clear()

    # ------------------------------------------------------------------ read model
    def metrics(self) -> Dict[str, Any]:
        m = dict(self.m)
        lat = sorted(self._attack_latencies)
        m["attack_decision_ms_avg"] = round(sum(lat) / len(lat), 3) if lat else None
        m["attack_decision_ms_max"] = round(lat[-1], 3) if lat else None
        m["attack_stopped"] = m["attack_attempts"] - m["attack_passed"]
        m["stopped_rate"] = round(m["attack_stopped"] / m["attack_attempts"], 3) if m["attack_attempts"] else None
        m["outbox_file_deliveries"] = self.outbox.file_count()
        return m

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            fwsnap = self.firewall.snapshot()
            return {
                "firewall": fwsnap,
                "profile": self.gateway.profile,
                "threshold": self.threshold,
                "pressure": {"value": round(self.gateway.pressure(), 1), "threshold": self.gateway.lockdown_threshold,
                             "auto_lockdown": self.gateway.auto_lockdown,
                             "last_trigger": self.gateway.last_lockdown_trigger},
                "agents": {
                    "monitor": {"id": MONITOR, "score": self.monitor.model.score, "signals": self.monitor.model.recent,
                                "incident": self.monitor.incident, "status": self.monitor.last_status,
                                "state": "online" if self.firewall.mode == fw.NORMAL else "isolated"},
                    "validator": {"id": VALIDATOR, "status": self.validator.last_status, "handled": self.validator.handled,
                                  "state": "online" if self.firewall.mode == fw.NORMAL else "isolated"},
                    "adversary": {"id": ADVERSARY, "registered": False,
                                  "state": "attacking" if self.attack_run["running"] else "idle",
                                  "run": dict(self.attack_run)},
                    "gateway": {"keys": self.keyring.agents(), "email_action": EMAIL_ACTION},
                },
                "streams": {n: {"pos": self.stream_pos[n], "events": STREAMS[n]} for n in STREAMS},
                "events": WEIGHTS,
                "scenarios": [{"id": s.id, "title": s.title, "threat_model": s.threat_model,
                               "description": s.description, "expected": s.expected} for s in SCENARIOS],
                "metrics": self.metrics(),
                "feed": list(self.feed)[:40],
                "attack_log": list(self.attack_log)[:40],
                "outbox": list(reversed(self.outbox.records[-40:])),
                "audit": list(reversed(self.audit.tail(60))),
                "audit_head": self.audit.head,
                "audit_count": len(self.audit.entries),
                "codes": CODE_HELP,
                "paths": {"outbox": str(self.outbox.path), "audit": str(self.audit.path)},
                "now": self.clock(),
            }
