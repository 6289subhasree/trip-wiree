"""Application-level kill switch; does not change OS firewall rules."""
from dataclasses import dataclass


@dataclass
class Firewall:
    enabled: bool = False
    reason: str = "manual"

    def enable(self, reason: str = "manual") -> None:
        self.enabled = True
        self.reason = reason

    def disable(self) -> None:
        self.enabled = False
        self.reason = "manual"

    def permits(self) -> bool:
        return not self.enabled
