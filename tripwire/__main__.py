"""Command-line demos for TripWire."""
from __future__ import annotations

import argparse
import json
import math
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .agents import AdversaryAgent, RelayAgent, SentinelAgent
from .firewall import Firewall
from .notifications import JsonlOutbox
from .protocol import SignedProtocol

# Development-only secret. Never use this constant in a deployment.
_DEMO_SECRET = b"tripwire-local-demo-key-change-me"


class DashboardSession:
    """Thread-safe, in-memory state for one local browser demo session."""

    def __init__(self, threshold: float = 75, firewall_on: bool = False, outbox_path: str | None = None):
        self.lock = threading.RLock()
        self.sentinel, self.relay, self.firewall, self.outbox = build_demo(outbox_path, firewall_on)
        self.threshold = threshold
        self.accepted = self.rejected = self.alerts = 0
        self.feed: list[dict] = []
        self.alert_items: list[dict] = []
        self.last_envelope = None

    def state(self) -> dict:
        return {"firewall": self.firewall.enabled, "threshold": self.threshold,
                "accepted": self.accepted, "rejected": self.rejected, "alerts": self.alerts,
                "feed": list(self.feed), "alert_items": list(self.alert_items)}

    def record(self, envelope, result, kind="telemetry"):
        if result.status == "BLOCKED":
            pass
        elif result.status == "REJECTED":
            self.rejected += 1
        else:
            self.accepted += 1
            if result.alert_sent:
                self.alerts += 1
                self.alert_items.insert(0, {"metric": envelope.payload.get("metric", "unknown"),
                                            "value": envelope.payload.get("value"),
                                            "threshold": self.threshold, "message_id": envelope.message_id,
                                            "time": envelope.created_at})
        self.feed.insert(0, {"time": envelope.created_at, "sender": envelope.sender,
                             "message_id": envelope.message_id, "metric": str(envelope.payload.get("metric", "?"))[:80],
                             "value": str(envelope.payload.get("value", "?"))[:40], "kind": kind,
                             "status": result.status, "detail": result.detail})
        self.feed[:] = self.feed[:100]
        self.alert_items[:] = self.alert_items[:50]
        return result

    def send(self, metric, value):
        envelope = self.sentinel.report(metric, value)
        self.last_envelope = envelope
        return self.record(envelope, self.relay.receive(envelope, self.threshold))

    def attack(self, kind):
        from .agents import AdversaryAgent
        adversary = AdversaryAgent()
        if kind == "replay":
            if self.last_envelope is None or self.last_envelope.message_id not in self.relay.protocol._seen_ids:
                self.send("risk_score", 20)
            envelope = adversary.replay(self.last_envelope)
        else:
            base = self.sentinel.report("risk_score", 20)
            envelope = {"tamper": lambda: adversary.tamper_value(base, 99),
                        "forged": lambda: adversary.forge_sender(base, "adversary"),
                        "malformed": lambda: self.sentinel.protocol.sign("sentinel", {"metric": ["bad"], "value": "high"})}.get(kind, lambda: None)()
        if envelope is None:
            raise ValueError("unknown attack scenario")
        return self.record(envelope, self.relay.receive(envelope, self.threshold), kind)


def make_handler(session: DashboardSession):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            print("TripWire HTTP: " + fmt % args)

        def respond(self, status, data):
            raw = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def body(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("Content-Length must be an integer") from exc
            if length < 0:
                raise ValueError("Content-Length must not be negative")
            if length > 4096:
                raise ValueError("request body too large")
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            return payload

        def do_GET(self):
            if urlparse(self.path).path == "/api/state":
                with session.lock:
                    self.respond(200, session.state())
            elif urlparse(self.path).path == "/":
                page = Path(__file__).with_name("dashboard.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
            else:
                self.respond(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            try:
                data = self.body()
                with session.lock:
                    if path == "/api/telemetry":
                        metric, value = data.get("metric"), data.get("value")
                        if not isinstance(metric, str) or not metric.strip() or len(metric) > 80:
                            raise ValueError("metric must be 1–80 characters")
                        result = session.send(metric.strip(), finite_number(value, "value"))
                    elif path == "/api/threshold":
                        value = finite_number(data.get("threshold"), "threshold")
                        if not -1e9 <= value <= 1e9:
                            raise ValueError("threshold must be between -1,000,000,000 and 1,000,000,000")
                        session.threshold = value
                        result = None
                    elif path == "/api/firewall":
                        enabled = data.get("enabled")
                        if not isinstance(enabled, bool):
                            raise ValueError("enabled must be true or false")
                        session.firewall.enable("dashboard kill switch") if enabled else session.firewall.disable()
                        result = None
                    elif path.startswith("/api/attack/"):
                        result = session.attack(path.rsplit("/", 1)[-1])
                    elif path == "/api/attack-suite":
                        results = [session.attack(k) for k in ("tamper", "replay", "forged", "malformed")]
                        result = results[-1]
                    elif path == "/api/reset":
                        enabled = session.firewall.enabled; threshold = session.threshold
                        session.sentinel, session.relay, session.firewall, session.outbox = build_demo(str(session.outbox.path), enabled)
                        session.threshold = threshold
                        session.accepted = session.rejected = session.alerts = 0
                        session.feed.clear(); session.alert_items.clear(); session.last_envelope = None
                        result = None
                    else:
                        self.respond(404, {"error": "not found"})
                        return
                    self.respond(200, {"result": None if result is None else {"status": result.status, "detail": result.detail}, "state": session.state()})
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self.respond(400, {"error": str(exc)})
    return Handler


def finite_number(value, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite number") from exc
    if not math.isfinite(number):
        raise ValueError(f"{name} must be a finite number")
    return number


def run_server(host="127.0.0.1", port=8765, threshold=75, firewall_on=False):
    session = DashboardSession(threshold, firewall_on, os.getenv("TRIPWIRE_OUTBOX"))
    server = ThreadingHTTPServer((host, port), make_handler(session))
    print(f"TripWire dashboard: http://{host}:{server.server_port} (Ctrl+C to stop)")
    server.serve_forever()


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
        ("malformed payload", adversary.malformed_payload(sentinel.report("risk_score", 10), sentinel.protocol)),
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
    web = sub.add_parser("serve", help="launch the local interactive dashboard")
    web.add_argument("--host", default="127.0.0.1", help="bind address (defaults to localhost)")
    web.add_argument("--port", type=int, default=8765)
    parser.add_argument("--demo", action="store_true", help="shortcut for demo")
    parser.add_argument("--attack-demo", action="store_true", help="shortcut for attack-demo")
    args = parser.parse_args()
    if args.command == "serve":
        run_server(args.host, args.port, float(os.getenv("TRIPWIRE_THRESHOLD", "75")), os.getenv("TRIPWIRE_FIREWALL", "").lower() in {"1", "true", "on"})
        return 0
    if args.attack_demo or args.command == "attack-demo":
        return run_attack_demo(args)
    if args.demo or args.command in (None, "demo"):
        return run_demo(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
