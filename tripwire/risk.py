"""Deterministic heuristic risk scoring for Agent 1.

The score is a 0-100 *severity index*, NOT a probability. It is an exponentially decayed sum
of signal weights:

    score_t = min(100, DECAY * score_(t-1) + WEIGHT[event_t])

so one noisy signal fades out while a cluster of serious signals accumulates. The same input
stream always yields the same scores, which makes tests and the live demo repeatable.
"""
from __future__ import annotations

from typing import Dict, List

DECAY = 0.8
DEFAULT_THRESHOLD = 70.0

WEIGHTS: Dict[str, float] = {
    "heartbeat": 0, "config_change": 6, "failed_login": 8, "port_scan": 12,
    "data_exfil_suspected": 25, "privilege_escalation": 30, "malware_signature": 35,
}

STREAMS: Dict[str, List[str]] = {
    # Stays well below 70 the whole time.
    "baseline": ["heartbeat", "failed_login", "config_change", "heartbeat", "failed_login", "heartbeat"],
    # Crosses 70 on step 5 (malware_signature) and stays above on step 6.
    "incident": ["failed_login", "failed_login", "port_scan", "privilege_escalation",
                 "malware_signature", "data_exfil_suspected"],
}


class RiskModel:
    def __init__(self) -> None:
        self.score = 0.0
        self.recent: List[str] = []

    def ingest(self, event: str) -> float:
        if event not in WEIGHTS:
            raise ValueError(f"unknown event type '{event}'")
        self.score = round(min(100.0, DECAY * self.score + WEIGHTS[event]), 2)
        self.recent = (self.recent + [event])[-6:]
        return self.score

    def override(self, score: float, label: str = "external_detector") -> float:
        self.score = round(max(0.0, min(100.0, float(score))), 2)
        self.recent = (self.recent + [label])[-6:]
        return self.score

    def signals(self) -> List[str]:
        return [s for s in self.recent if WEIGHTS.get(s, 1) > 0][-5:]


def simulate(stream: List[str]) -> List[float]:
    model = RiskModel()
    return [model.ingest(e) for e in stream]
