"""Command-line demos for TripWire."""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from .agents import AdversaryAgent, RelayAgent, SentinelAgent
from .firewall import Firewall
from .notifications import JsonlOutbox
from .protocol import SignedProtocol

# Development-only secret. Never use this constant in a deployment.
_DEMO_SECRET = b"tripwire-local-demo-key-change-me"


def build_demo(outbox_path: str | None = None, firewall_on: bool = False):
    protocol = SignedProtocol(_DEMO_SECRET, allowed_senders={"sentinel"})
    firewall = Firewall(enabled=firewall_on)
    outbox = JsonlOutbox(outbox_path or str(Path(tempfile.gettempdir()) / "tripwire-outbox.jsonl"))
    return SentinelAgent(protocol), RelayAgent(protocol, firewall, outbox), firewall, outbox


def run_demo(args: argparse.Namespace) -> int:
    threshold = float(os.getenv("TRIPWIRE_THRESHOLD", "75"))
    firewall_on = os.getenv("TRIPWIRE_FIREWALL", "").lower() in {"1", "true", "on"}
    firewall_on = firewall_on or getattr(args, "firewall_on", False)
    sentinel, relay, firewall, outbox = build_demo(getattr(args, "outbox", None) or os.getenv("TRIPWIRE_OUTBOX"), firewall_on)
    print("TRIPWIRE :: three-agent communication demo")
    print(f"threshold={threshold:g} firewall={'ON' if firewall.enabled else 'OFF'}")
    for value in (42, 68, 82):
        result = relay.receive(sentinel.report("risk_score", value), threshold)
        print(f"Sentinel -> Relay | risk_score={value} | {result.status}: {result.detail}")
    print(f"Outbox: {outbox.path} ({outbox.count()} notification(s))")
    return 0


def run_attack_demo(args: argparse.Namespace) -> int:
    sentinel, relay, firewall, outbox = build_demo(getattr(args, "outbox", None))
    adversary = AdversaryAgent()
    original = sentinel.report("risk_score", 10)
    relay.receive(original, threshold=75)  # mark the original ID as seen for replay test
    scenarios = [
        ("tampered payload", adversary.tamper_value(sentinel.report("risk_score", 10), 99)),
        ("replay", adversary.replay(original)),
        ("malformed payload", adversary.malformed_payload(sentinel.report("risk_score", 10))),
        ("forged sender", adversary.forge_sender(sentinel.report("risk_score", 10), "adversary")),
    ]
    print("TRIPWIRE :: in-process adversarial simulation")
    for name, envelope in scenarios:
        result = relay.receive(envelope, threshold=75)
        print(f"{name}: {result.status} — {result.detail}")
    firewall.enable("attack simulation")
    result = relay.receive(sentinel.report("risk_score", 99), threshold=75)
    print(f"firewall enabled: {result.status} — {result.detail}")
    print(f"Outbox: {outbox.path} ({outbox.count()} notification(s))")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="TripWire secure agent communication demo")
    sub = parser.add_subparsers(dest="command")
    demo = sub.add_parser("demo", help="run threshold-trigger demo")
    demo.add_argument("--firewall-on", action="store_true", help="start with firewall engaged")
    demo.add_argument("--outbox", help="JSONL outbox path")
    attacks = sub.add_parser("attack-demo", help="run simulated adversarial scenarios")
    attacks.add_argument("--outbox", help="JSONL outbox path")
    parser.add_argument("--demo", action="store_true", help="shortcut for demo")
    parser.add_argument("--attack-demo", action="store_true", help="shortcut for attack-demo")
    args = parser.parse_args()
    if args.attack_demo or args.command == "attack-demo":
        return run_attack_demo(args)
    if args.demo or args.command in (None, "demo"):
        return run_demo(args)
    parser.print_help()
    return 0
