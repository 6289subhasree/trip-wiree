"""Local HTTP API + dashboard (Python standard library only).

Every dashboard control maps to a POST endpoint that calls the same ``Session`` methods the
tests exercise. Browser-side state is never trusted: the UI re-renders from ``GET /api/state``.

Local hardening: binds to 127.0.0.1 by default, POSTs must carry ``X-TripWire-Client`` (a
custom header forces a CORS pre-flight, which this server never approves) and any ``Origin``
header must match the ``Host`` header. The recovery code is never returned by any endpoint.
"""
from __future__ import annotations

import json
import math
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

from .firewall import FirewallError
from .session import Session

MAX_BODY = 4096


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _num(data: Dict[str, Any], name: str) -> float:
    value = data.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    try:
        number = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be a finite number") from exc
    if not math.isfinite(number):
        raise ValueError(f"{name} must be a finite number")
    return number


def _decision(d) -> Optional[Dict[str, Any]]:
    return None if d is None else d.to_dict()


def build_routes(s: Session) -> Dict[str, Callable[[Dict[str, Any], str], Any]]:
    def telemetry(data, _):
        # accepts {"score": n} or the legacy {"metric": "...", "value": n}
        key = "score" if "score" in data else "value"
        return {"decision": _decision(s.report_score(_num(data, key)))}

    def event(data, _):
        return {"decision": _decision(s.event(str(data.get("type", ""))))}

    def stream(data, _):
        r = s.stream_step(str(data.get("stream", "")))
        r["decision"] = _decision(r["decision"])
        return r

    def firewall(data, _):
        if "enabled" in data:  # legacy boolean toggle
            if not isinstance(data["enabled"], bool):
                raise ValueError("enabled must be true or false")
            mode = "BLOCKING" if data["enabled"] else "NORMAL"
        else:
            mode = str(data.get("mode", ""))
        s.set_firewall(mode)
        return {}

    def attack(data, path):
        return {"results": s.run_attack(path.rsplit("/", 1)[-1])}

    def suite(data, _):
        ids = data.get("scenarios")
        if ids is not None and (not isinstance(ids, list) or not all(isinstance(i, str) for i in ids)):
            raise ValueError("scenarios must be a list of scenario ids")
        s.start_attack_sequence(ids)
        return {}

    def auto(data, _):
        s.set_auto_lockdown(data.get("enabled"), data.get("threshold"))
        return {}

    def tamper(data, _):
        return s.tamper_audit()

    return {
        "/api/telemetry": telemetry,
        "/api/score": telemetry,
        "/api/event": event,
        "/api/stream/step": stream,
        "/api/stream/reset": lambda d, p: s.reset_streams() or {},
        "/api/alert": lambda d, p: {"decision": _decision(s.send_alert())},
        "/api/threshold": lambda d, p: s.set_threshold(_num(d, "threshold")) or {},
        "/api/firewall": firewall,
        "/api/recover": lambda d, p: s.recover(d.get("code")) or {},
        "/api/profile": lambda d, p: s.set_profile(str(d.get("profile", ""))) or {},
        "/api/auto-lockdown": auto,
        "/api/attack-suite": suite,
        "/api/attack/stop": lambda d, p: s.stop_attacks() or {},
        "/api/audit/verify": lambda d, p: {"verify": s.verify_audit()},
        "/api/audit/tamper": tamper,
        "/api/reset": lambda d, p: s.reset() or {},
        "/api/attack/": attack,  # prefix route
    }


def make_handler(session: Session, quiet: bool = False):
    routes = build_routes(session)
    page_path = Path(__file__).with_name("dashboard.html")

    class Handler(BaseHTTPRequestHandler):
        server_version = "TripWire/2"
        sys_version = ""

        def log_message(self, fmt, *args):
            if not quiet:
                print("TripWire HTTP: " + fmt % args)

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            try:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Security-Policy",
                                 "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                 "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def respond(self, status: int, data: Any) -> None:
            self._send(status, json.dumps(data, default=str).encode("utf-8"), "application/json; charset=utf-8")

        def _body(self) -> Dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ApiError(400, "Content-Length must be an integer") from exc
            if length < 0:
                raise ApiError(400, "Content-Length must not be negative")
            if length > MAX_BODY:
                raise ApiError(413, "request body too large")
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ApiError(400, f"invalid JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise ApiError(400, "request body must be a JSON object")
            return payload

        def _guard(self) -> None:
            if self.headers.get("X-TripWire-Client") != "dashboard":
                raise ApiError(403, "missing X-TripWire-Client header")
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).netloc != self.headers.get("Host"):
                raise ApiError(403, "cross-origin request refused")

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/api/state":
                self.respond(200, session.snapshot())
            elif path == "/api/health":
                self.respond(200, {"ok": True, "firewall": session.firewall.mode})
            elif path in ("/", "/index.html"):
                self._send(200, page_path.read_bytes(), "text/html; charset=utf-8")
            else:
                self.respond(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            handler = routes.get(path)
            if handler is None and path.startswith("/api/attack/") and path.count("/") == 3:
                handler = routes["/api/attack/"]
            try:
                if handler is None:
                    raise ApiError(404, "not found")
                self._guard()
                data = self._body()
                result = handler(data, path) or {}
                result["state"] = session.snapshot()
                self.respond(200, result)
            except ApiError as exc:
                self.respond(exc.status, {"error": str(exc)})
            except FirewallError as exc:
                self.respond(409, {"error": str(exc)})
            except (ValueError, TypeError) as exc:
                self.respond(400, {"error": str(exc)})

    return Handler


def run_server(session: Session, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False,
               quiet: bool = True) -> None:
    server = ThreadingHTTPServer((host, port), make_handler(session, quiet=quiet))
    server.daemon_threads = True
    url = f"http://{host}:{server.server_port}"
    print("=" * 64)
    print(f" TripWire security console : {url}")
    print(f" Operator recovery code    : {session.recovery_code}   (never shown in the UI)")
    print(f" Simulated outbox          : {session.outbox.path}")
    print(f" Audit log (HMAC chain)    : {session.audit.path}")
    print(" Press Ctrl+C to stop.")
    print("=" * 64)
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nTripWire stopped.")
    finally:
        session.stop_attacks(wait=1)
        server.server_close()
