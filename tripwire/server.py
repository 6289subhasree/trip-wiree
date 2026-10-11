"""Local HTTP API + dashboard (Python standard library only).

Every dashboard control maps to a POST endpoint that calls the same ``Session`` methods the
tests exercise. Browser-side state is never trusted: the UI re-renders from ``GET /api/state``.

Local hardening: binds to 127.0.0.1 by default, POSTs must carry ``X-TripWire-Client`` (a
custom header forces a CORS pre-flight, which this server never approves) and any ``Origin``
header must match the ``Host`` header. The recovery code is never returned by any endpoint.

Pages: "/" is the built landing page (vantage/out, with its /_next/ and /assets/ files) or, when
that folder is absent, the classic page, which is always at /classic. /demo, /arena, /evidence and
/console are served from this package.

Task mode (PRD 12) adds:

    GET  /api/scenarios                     document scenarios and channel attacks
    POST /api/tasks/start                   {"scenario", "goal"?, "instruction"?}
    GET  /api/tasks/{id}/document           documents with masked canaries and tagged spans
    POST /api/tasks/{id}/agent/run          Agent 1 reads, plans and proposes
    POST /api/gateway/tool-call             one proposal: {"task_id", "tool", "args", ...}
    POST /api/tasks/{id}/approval           {"approval_id", "decision": "approve" | "reject"}
    GET  /api/tasks/{id}/timeline           ordered evidence ledger
    GET  /api/tasks/{id}/report             blast-radius report
    POST /api/tasks/{id}/inject             judge mode: {"instruction", "force"?: {"tool", "destination"?, "record"?}}
    POST /api/replay                        {"scenario", "instruction"?, "force"?}

The same guard, body limit and validation apply. Responses never contain a signing key, the
recovery code or an unmasked canary token.
"""
from __future__ import annotations

import json
import math
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

from .approvals import ApprovalError
from .attacks import SCENARIOS as CHANNEL_ATTACKS
from .firewall import FirewallError
from .scenarios import DOC_SCENARIOS
from .session import Session

MAX_BODY = 4096

# Multi-page web front end (tripwire/web). The original single-page console stays at /console.
WEB_DIR = Path(__file__).with_name("web")
PAGES = {"/classic": "index.html", "/demo": "demo.html", "/arena": "arena.html", "/evidence": "evidence.html"}
STATIC = {"/static/app.css": ("app.css", "text/css; charset=utf-8"),
          "/static/app.js": ("app.js", "text/javascript; charset=utf-8")}
# Landing page: the committed Next.js static export in vantage/out, served on this origin at "/".
# When that folder is absent (no build, or an installed package) "/" serves the classic page instead.
LANDING_DIR = Path(__file__).resolve().parent.parent / "vantage" / "out"
LANDING_ASSET = re.compile(r"^/(?:_next|assets)/[A-Za-z0-9._~/-]+$")
LANDING_PAGE = re.compile(r"^/[A-Za-z0-9_-]{1,64}$")
LANDING_TYPES = {".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".txt": "text/plain; charset=utf-8", ".json": "application/json; charset=utf-8",
                 ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2"}
TASK_PATH = re.compile(r"^/api/tasks/([A-Za-z0-9_-]{1,64})(/document|/timeline|/report|/agent/run|/approval|/inject)?$")


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


def _only(data: Dict[str, Any], *allowed: str) -> None:
    extra = sorted(set(data) - set(allowed))
    if extra:
        raise ValueError(f"unexpected field(s): {', '.join(str(k)[:30] for k in extra[:5])}")


def _opt_text(data: Dict[str, Any], name: str, limit: int) -> Optional[str]:
    value = data.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be 1-{limit} characters of text")
    return value


def landing_asset(root: Path, path: str) -> Optional[Path]:
    """A build asset of the landing page, or None. Known prefixes and file types only, never outside ``root``."""
    if not LANDING_ASSET.match(path) or ".." in path.split("/"):
        return None
    if Path(path).suffix not in LANDING_TYPES:
        return None
    try:
        base, target = root.resolve(), (root / path.lstrip("/")).resolve()
    except (OSError, ValueError):
        return None
    return target if base in target.parents and target.is_file() else None


def landing_page(root: Path, path: str) -> Optional[Path]:
    """A page of the landing build (/chat is chat.html), or None. One plain name, never outside ``root``."""
    if not LANDING_PAGE.match(path):
        return None
    target = root / (path[1:] + ".html")
    return target if target.is_file() else None


def telemetry_summary(s: Session) -> Dict[str, Any]:
    """Counters for the defender and attacker pages. Every one is counted from recorded decisions."""
    entries = list(s.audit.entries)
    decisions = [e.get("data") or {} for e in entries if e.get("kind") == "gateway.decision"]
    tools = [d.get("tool") or {} for d in decisions]
    # Unsafe: an attack message that produced an email, a baseline tool run the protected gateway
    # would have refused, or a chat email sent while the firewall was BYPASSED.
    unsafe = (s.metrics().get("unauthorized_emails", 0)
              + sum(1 for t in tools if t.get("counterfactual") and t.get("executed") and t.get("codes"))
              + sum(1 for e in entries if str(e.get("kind", "")).endswith(".bypassed")))
    return {
        "ok": True,
        "requests": len(decisions),
        "approved": sum(1 for d in decisions if d.get("outcome") == "ACCEPTED"),
        "blocked": sum(1 for d in decisions if d.get("outcome") in ("REJECTED", "BLOCKED")),
        "unsafe_executions": unsafe,
        "intent_mismatches": sum(1 for t in tools if "INTENT_MISMATCH" in (t.get("codes") or [])),
        "signature_failures": sum(1 for d in decisions if d.get("code") == "BAD_MAC"),
        "schema_failures": sum(1 for d in decisions if d.get("code") in ("SCHEMA_INVALID", "PAYLOAD_INVALID")),
        "soc_alerts": sum(1 for r in s.outbox.records
                          if r.get("kind") == "soc_alert" and r.get("status") == "SIMULATED_DELIVERY"),
    }


def telemetry_events(s: Session, limit: int = 200) -> list:
    """The newest audit entries, newest first. Each copy's ``data`` gains the time and action the
    defender page reads; the stored entries and their MACs are not touched."""
    events = []
    for entry in reversed(s.audit.tail(limit)):
        raw = entry.get("data")
        data = dict(raw) if isinstance(raw, dict) else {"value": raw}
        tool = data.get("tool")   # a verdict on gateway decisions, a tool name on approvals and lineage
        data.setdefault("at", entry.get("ts"))
        data.setdefault("action", (tool.get("tool") if isinstance(tool, dict) else tool) or data.get("type"))
        events.append(dict(entry, data=data))
    return events


def attack_runs(s: Session) -> list:
    """The attack log, newest first, with the nested view the attacker page reads."""
    return [dict(row, data={"at": row.get("at"), "action": row.get("scenario"),
                            "decision": row.get("outcome"), "code": row.get("code")})
            for row in list(s.attack_log)]


def scenario_catalogue() -> Dict[str, Any]:
    return {"document": [sc.to_dict() for sc in DOC_SCENARIOS],
            "channel": [{"id": a.id, "title": a.title, "threat_model": a.threat_model, "description": a.description,
                         "expected": a.expected} for a in CHANNEL_ATTACKS]}


def task_get(s: Session, task_id: str, tail: Optional[str]) -> Dict[str, Any]:
    view = s.task_view(task_id)
    if tail == "/document":
        return {"task_id": task_id, "documents": view["documents"], "injected": view["injected"]}
    if tail == "/timeline":
        return {"task_id": task_id, "state": view["state"], "timeline": view["timeline"]}
    if tail == "/report":
        return {"task_id": task_id, "report": view["report"]}
    if tail is None:
        return {"task": view}
    raise ApiError(405, "use POST for this endpoint")


def task_post(s: Session, task_id: str, tail: Optional[str], data: Dict[str, Any]) -> Dict[str, Any]:
    if tail == "/agent/run":
        _only(data)
        decisions = s.run_agent(task_id)
        return {"decisions": [d.to_dict() for d in decisions], "task": s.task_view(task_id)}
    if tail == "/inject":
        _only(data, "instruction", "force")
        s.inject(task_id, data.get("instruction"), data.get("force"))
        return {"task": s.task_view(task_id)}
    if tail == "/approval":
        _only(data, "approval_id", "decision")
        if data.get("decision") not in ("approve", "reject"):
            raise ValueError("decision must be 'approve' or 'reject'")
        s.task_view(task_id)  # 400 for an unknown task before anything else
        item = s.approvals.items.get(data.get("approval_id")) if isinstance(data.get("approval_id"), str) else None
        if item is None or item["task_id"] != task_id:
            raise ApiError(404, "no such approval for this task")
        # The approver is fixed here: this endpoint is the operator's console. A body cannot name one.
        return {"approval": s.decide_approval(item["id"], data["decision"] == "approve", approver="operator"),
                "task": s.task_view(task_id)}
    raise ApiError(405, "use GET for this endpoint")


def build_routes(s: Session) -> Dict[str, Callable[[Dict[str, Any], str], Any]]:
    def task_start(data, _):
        _only(data, "scenario", "goal", "instruction")
        task = s.start_task(data.get("scenario"), goal=_opt_text(data, "goal", 200),
                            instruction=_opt_text(data, "instruction", 300))
        return {"task": s.task_view(task.task_id)}

    def tool_call(data, _):
        _only(data, "task_id", "tool", "args", "purpose", "task_link", "evidence", "resources_requested",
              "destination", "risk_level")
        if not isinstance(data.get("tool"), str) or not isinstance(data.get("args", {}), dict):
            raise ValueError("tool must be text and args an object")
        return {"decision": _decision(s.manual_tool_call(data))}

    def replay(data, _):
        _only(data, "scenario", "instruction", "force")
        return {"replay": s.replay(data.get("scenario"), _opt_text(data, "instruction", 300), data.get("force"))}

    def select(data, _):
        _only(data, "task_id")
        s.task_view(data.get("task_id"))
        s.current_task = data["task_id"]
        return {}


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

    def demo_execute(data, _):
        from .demo_sim import DemoPipeline
        _only(data, "firewall_active", "human_prompt", "attack_active")
        return DemoPipeline.execute(
            bool(data.get("firewall_active", True)),
            str(data.get("human_prompt", "")),
            bool(data.get("attack_active", False))
        )

    def chat(data, _):
        _only(data, "message", "session_id", "attack_simulation")
        return s.chat_request(
            message=str(data.get("message", "")),
            session_id=str(data.get("session_id", "")),
            attack_simulation=bool(data.get("attack_simulation", False))
        )

    def api_firewall_config(data, _):
        mode = "BLOCKING" if data.get("enabled", True) else "NORMAL"
        s.set_firewall(mode)
        return {"enabled": mode == "BLOCKING", "mode": mode}

    return {
        "/api/chat": chat,
        "/api/firewall/config": api_firewall_config,
        "/api/tasks/start": task_start,
        "/api/tasks/select": select,
        "/api/gateway/tool-call": tool_call,
        "/api/replay": replay,
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
        "/api/demo/execute": demo_execute,
        "/api/reset": lambda d, p: s.reset() or {},
        "/api/attack/": attack,  # prefix route
    }


def make_handler(session: Session, quiet: bool = False, landing_dir: Optional[Path] = None):
    routes = build_routes(session)
    landing_dir = LANDING_DIR if landing_dir is None else Path(landing_dir)
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
                                 "script-src 'self' 'unsafe-inline'; media-src 'self' https://d8j0ntlcm91z4.cloudfront.net; frame-ancestors 'none'")
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
            elif path == "/api/status":
                self.respond(200, {
                    "ok": True,
                    "backend": "online",
                    "firewall": session.firewall.mode,
                    "mock_executor": "ready"
                })
            elif path == "/api/firewall/status":
                self.respond(200, {
                    "ok": True,
                    "mode": session.firewall.mode,
                    "enabled": session.firewall.mode == "BLOCKING"
                })
            elif path == "/api/attacks/runs":
                self.respond(200, {"ok": True, "runs": attack_runs(session)})
            elif path == "/api/telemetry/summary":
                self.respond(200, telemetry_summary(session))
            elif path == "/api/telemetry/events":
                self.respond(200, {"ok": True, "events": telemetry_events(session)})
            elif path == "/api/scenarios":
                self.respond(200, scenario_catalogue())
            elif TASK_PATH.match(path):
                task_id, tail = TASK_PATH.match(path).groups()
                try:
                    self.respond(200, task_get(session, task_id, tail))
                except ApiError as exc:
                    self.respond(exc.status, {"error": str(exc)})
                except ValueError as exc:
                    self.respond(404, {"error": str(exc)})
            elif path.startswith("/api/evidence/"):
                trace_id = path.split("/")[-1]
                evidence = next((e for e in session.audit.entries if e.get("data", {}).get("trace_id") == trace_id), None)
                if evidence:
                    self.respond(200, {"evidence": evidence})
                else:
                    self.respond(404, {"error": "Evidence not found"})
            elif path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
            elif path in ("/", "/index.html"):
                built = landing_dir / "index.html"
                page = built if built.is_file() else WEB_DIR / "index.html"
                self._send(200, page.read_bytes(), "text/html; charset=utf-8")
            elif path in PAGES:
                self._send(200, (WEB_DIR / PAGES[path]).read_bytes(), "text/html; charset=utf-8")
            elif (built_page := landing_page(landing_dir, path)) is not None:
                self._send(200, built_page.read_bytes(), "text/html; charset=utf-8")
            elif path == "/console":
                self._send(200, page_path.read_bytes(), "text/html; charset=utf-8")
            elif path in STATIC:
                name, ctype = STATIC[path]
                self._send(200, (WEB_DIR / name).read_bytes(), ctype)
            elif (asset := landing_asset(landing_dir, path)) is not None:
                self._send(200, asset.read_bytes(), LANDING_TYPES[asset.suffix])
            else:
                self.respond(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            handler = routes.get(path)
            if handler is None and path.startswith("/api/attack/") and path.count("/") == 3:
                handler = routes["/api/attack/"]
            task_route = TASK_PATH.match(path) if handler is None else None
            if task_route:
                handler = lambda data, _p: task_post(session, task_route.group(1), task_route.group(2), data)
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
            except ApprovalError as exc:
                self.respond(409, {"error": str(exc), "code": exc.code})
            except (ValueError, TypeError) as exc:
                self.respond(400, {"error": str(exc)})

    return Handler


class ConsoleServer(ThreadingHTTPServer):
    """Refuses a port that another server already holds.

    On Windows ``allow_reuse_address`` lets a second server bind a busy port without any error,
    and the browser then reaches whichever process answers first.
    """
    daemon_threads = True
    allow_reuse_address = os.name != "nt"


def run_server(session: Session, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False,
               quiet: bool = True) -> None:
    try:
        server = ConsoleServer((host, port), make_handler(session, quiet=quiet))
    except OSError as exc:
        raise SystemExit(f"TripWire could not start on {host}:{port}: {exc.strerror or exc}\n"
                         f"Another server is probably using that port. Stop it, or choose another "
                         f"port: python -m tripwire serve --port {port + 35}") from exc
    url = f"http://{host}:{server.server_port}"
    print("=" * 64)
    print(f" TripWire security console : {url}")
    built = (LANDING_DIR / "index.html").is_file()
    print(f" Landing page              : {'vantage/out (built)' if built else 'classic (vantage/out not found)'}")
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
