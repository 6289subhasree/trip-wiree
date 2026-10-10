"""Application-level firewall state machine (does NOT touch OS firewall rules).

States
------
NORMAL    Agent traffic and protected actions may proceed, subject to gateway policy.
BLOCKING  Operator kill switch. *All* agent-to-agent messages and protected actions are
          denied. An operator may release it (BLOCKING -> NORMAL) without the recovery code.
LOCKDOWN  Severe threat (automatic or manual). Everything is denied and the only way out is
          ``recover()`` with the operator recovery code. LOCKDOWN can never be downgraded to
          BLOCKING or released without that code.

Every check-and-act in the gateway runs while holding ``Firewall.lock`` and every transition
also takes that lock, so a request can never observe NORMAL and then perform its side effect
after a transition to BLOCKING/LOCKDOWN has been committed.
"""
from __future__ import annotations

import hmac
import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional

NORMAL = "NORMAL"
BLOCKING = "BLOCKING"
LOCKDOWN = "LOCKDOWN"
BYPASSED = "BYPASSED"
MODES = (NORMAL, BLOCKING, LOCKDOWN, BYPASSED)


class FirewallError(PermissionError):
    pass


@dataclass(frozen=True)
class Transition:
    at: float
    from_mode: str
    to_mode: str
    actor: str
    reason: str
    automatic: bool


class Firewall:
    MAX_FAILED_RECOVERIES = 5
    RECOVERY_COOLDOWN_S = 60.0

    def __init__(self, recovery_code: str, *, mode: str = NORMAL,
                 on_transition: Optional[Callable[[Transition], None]] = None,
                 on_event: Optional[Callable[[str, dict], None]] = None,
                 clock: Callable[[], float] = time.time):
        if not isinstance(recovery_code, str) or len(recovery_code) < 6:
            raise ValueError("recovery code must be a string of at least 6 characters")
        if mode not in MODES:
            raise ValueError(f"unknown firewall mode {mode!r}")
        self.lock = threading.RLock()
        self._code = recovery_code
        self._clock = clock
        self._on_transition = on_transition
        self._on_event = on_event
        self.mode = mode
        self.reason = "startup"
        self.actor = "system"
        self.automatic = False
        self.since = clock()
        self.history: List[Transition] = []
        self._failed: List[float] = []
        self._cooldown_until = 0.0

    # -- queries -------------------------------------------------------------
    def permits(self) -> bool:
        with self.lock:
            return self.mode == NORMAL

    def snapshot(self) -> dict:
        with self.lock:
            return {"mode": self.mode, "reason": self.reason, "actor": self.actor,
                    "automatic": self.automatic, "since": self.since,
                    "recovery_locked_until": self._cooldown_until if self._cooldown_until > self._clock() else None,
                    "history": [t.__dict__ for t in self.history[-12:]]}

    # -- transitions -----------------------------------------------------------
    def _move(self, to_mode: str, actor: str, reason: str, automatic: bool) -> Transition:
        t = Transition(self._clock(), self.mode, to_mode, actor, reason[:200], automatic)
        self.mode, self.actor, self.reason, self.automatic, self.since = to_mode, actor, t.reason, automatic, t.at
        self.history.append(t)
        del self.history[:-100]
        if self._on_transition:
            self._on_transition(t)
        return t

    def engage(self, actor: str = "operator", reason: str = "manual kill switch") -> Transition:
        with self.lock:
            if self.mode == LOCKDOWN:
                raise FirewallError("already in LOCKDOWN; use the recovery procedure")
            if self.mode == BLOCKING:
                raise FirewallError("firewall is already BLOCKING")
            return self._move(BLOCKING, actor, reason, False)

    def release(self, actor: str = "operator") -> Transition:
        with self.lock:
            if self.mode == LOCKDOWN:
                raise FirewallError("LOCKDOWN can only be cleared with the recovery code")
            if self.mode == NORMAL:
                raise FirewallError("firewall is already NORMAL")
            return self._move(NORMAL, actor, "operator released kill switch", False)

    def lockdown(self, actor: str, reason: str, automatic: bool) -> Optional[Transition]:
        with self.lock:
            if self.mode == LOCKDOWN:
                return None
            return self._move(LOCKDOWN, actor, reason, automatic)

    def recover(self, code: str, actor: str = "operator") -> Transition:
        with self.lock:
            now = self._clock()
            if self.mode == NORMAL:
                raise FirewallError("nothing to recover; firewall is NORMAL")
            if now < self._cooldown_until:
                self._emit("recovery.throttled", {"actor": actor, "retry_after_s": round(self._cooldown_until - now, 1)})
                raise FirewallError(f"too many failed attempts; retry in {self._cooldown_until - now:.0f}s")
            supplied = code if isinstance(code, str) else ""
            if not hmac.compare_digest(supplied.encode("utf-8", "replace"), self._code.encode("utf-8")):
                self._failed = [t for t in self._failed if now - t < 300] + [now]
                if len(self._failed) >= self.MAX_FAILED_RECOVERIES:
                    self._cooldown_until = now + self.RECOVERY_COOLDOWN_S
                    self._failed.clear()
                self._emit("recovery.failed", {"actor": actor, "mode": self.mode})
                raise FirewallError("recovery code rejected")
            self._failed.clear()
            return self._move(NORMAL, actor, "authorized recovery (recovery code verified)", False)

    def _emit(self, kind: str, data: dict) -> None:
        if self._on_event:
            self._on_event(kind, data)
