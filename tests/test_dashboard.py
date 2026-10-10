"""HTTP API: controls must change real backend state, and errors must be explicit."""
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tripwire.server import make_handler
from tests.helpers import CODE, make_session


class DashboardAPITests(unittest.TestCase):
    def setUp(self):
        self.session = make_session(self, auto_lockdown=False)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.session, quiet=True))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def request(self, path, body=None, headers=None):
        data = None if body is None else body.encode() if isinstance(body, str) else json.dumps(body).encode()
        hdrs = {"Content-Type": "application/json", "X-TripWire-Client": "dashboard"}
        hdrs.update(headers or {})
        req = Request(self.base + path, data=data, headers=hdrs)
        try:
            with urlopen(req) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_state_and_threshold_alert_creates_simulated_email(self):
        status, state = self.request("/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(state["firewall"]["mode"], "NORMAL")
        self.assertNotIn(CODE, json.dumps(state))  # recovery code never leaves the backend
        status, result = self.request("/api/telemetry", {"score": 90})
        self.assertEqual(status, 200)
        self.assertEqual(result["decision"]["action"]["email"]["status"], "SIMULATED_DELIVERY")
        self.assertEqual(result["state"]["metrics"]["emails_delivered"], 1)
        self.assertEqual(self.session.outbox.file_count(), 1)

    def test_firewall_toggle_controls_real_enforcement(self):
        self.request("/api/firewall", {"mode": "BLOCKING"})
        self.assertEqual(self.session.firewall.mode, "BLOCKING")
        _, blocked = self.request("/api/alert", {})
        self.assertEqual(blocked["decision"]["outcome"], "BLOCKED")
        self.assertEqual(self.session.outbox.delivered_count, 0)
        self.request("/api/firewall", {"enabled": False})  # legacy toggle shape still works
        self.assertEqual(self.session.firewall.mode, "NORMAL")

    def test_lockdown_and_recovery_flow(self):
        self.request("/api/firewall", {"mode": "LOCKDOWN"})
        status, err = self.request("/api/firewall", {"mode": "NORMAL"})
        self.assertEqual(status, 409)
        status, _ = self.request("/api/recover", {"code": "bad"})
        self.assertEqual(status, 409)
        self.assertEqual(self.session.firewall.mode, "LOCKDOWN")
        status, ok = self.request("/api/recover", {"code": CODE})
        self.assertEqual(status, 200)
        self.assertEqual(ok["state"]["firewall"]["mode"], "NORMAL")

    def test_attack_endpoints_and_sequence(self):
        _, res = self.request("/api/attack/tamper", {})
        self.assertEqual(res["results"][0]["code"], "BAD_MAC")
        status, _ = self.request("/api/attack/doesnotexist", {})
        self.assertEqual(status, 400)
        status, _ = self.request("/api/attack-suite", {"scenarios": ["replay", "stale"]})
        self.assertEqual(status, 200)
        self.request("/api/attack/stop", {})
        self.assertFalse(self.session.attack_run["running"])

    def test_profile_stream_and_audit_endpoints(self):
        _, r = self.request("/api/stream/step", {"stream": "incident"})
        self.assertEqual(r["event"], "failed_login")
        self.request("/api/profile", {"profile": "baseline"})
        self.assertEqual(self.session.gateway.profile, "baseline")
        status, _ = self.request("/api/profile", {"profile": "yolo"})
        self.assertEqual(status, 400)
        _, v = self.request("/api/audit/verify", {})
        self.assertTrue(v["verify"]["ok"])

    def test_reset_preserves_threshold_and_firewall(self):
        self.request("/api/threshold", {"threshold": 40})
        self.request("/api/firewall", {"mode": "BLOCKING"})
        self.request("/api/telemetry", {"score": 90})
        _, reset = self.request("/api/reset", {})
        self.assertEqual(reset["state"]["threshold"], 40)
        self.assertEqual(reset["state"]["firewall"]["mode"], "BLOCKING")
        self.assertEqual(reset["state"]["metrics"]["messages"], 0)
        self.assertEqual(reset["state"]["feed"], [])

    def test_input_validation(self):
        for path, body in (("/api/telemetry", {"score": "high"}), ("/api/telemetry", {"score": 10 ** 1000}),
                           ("/api/threshold", {"threshold": 0}), ("/api/event", {"type": "nuke"}),
                           ("/api/firewall", {"mode": "OFF"})):
            status, err = self.request(path, body)
            self.assertEqual(status, 400, path)
            self.assertIn("error", err)
        status, err = self.request("/api/telemetry", "{broken")
        self.assertEqual(status, 400)
        status, _ = self.request("/api/telemetry", "x" * 5000)
        self.assertEqual(status, 413)

    def test_csrf_guard(self):
        status, _ = self.request("/api/firewall", {"mode": "BLOCKING"}, headers={"X-TripWire-Client": ""})
        self.assertEqual(status, 403)
        status, _ = self.request("/api/firewall", {"mode": "BLOCKING"}, headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        self.assertEqual(self.session.firewall.mode, "NORMAL")

    def test_dashboard_served(self):
        with urlopen(self.base + "/") as response:
            self.assertEqual(response.status, 200)
            self.assertIn(b"TripWire", response.read())

    def test_dashboard_is_single_file_offline_and_never_builds_html_from_strings(self):
        with urlopen(self.base + "/console") as response:
            page = response.read().decode("utf-8")
            csp = response.headers["Content-Security-Policy"]
        self.assertIn("default-src 'self'", csp)
        # offline: no external scripts, styles, fonts or images
        for needle in ("http://", "https://", "//cdn", "@import", "<link", "url("):
            self.assertNotIn(needle, page, needle)
        # server strings are only ever inserted as text nodes
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(sink, page, sink)
        # both modes, the deck footer and the main panels are present
        for needle in ("Invoice task", "Event stream", "CONSTRAIN → ENFORCE → PROVE", "Evidence ledger",
                       "Policy manifest", "Blast radius", "Channel attacks · Agent 3", "Replay: baseline vs protected"):
            self.assertIn(needle, page, needle)
        with urlopen(self.base + "/favicon.ico") as response:
            self.assertEqual(response.status, 204)

    def test_website_pages_and_assets_are_served_offline_and_text_only(self):
        pages = {"/": "Your Gateway Between", "/demo": "Hand a hijacked agent a poisoned invoice",
                 "/arena": "Three agents. One firewall.", "/evidence": "Every decision, on the record."}
        bodies = []
        for path, needle in pages.items():
            with urlopen(self.base + path) as response:
                self.assertEqual(response.status, 200, path)
                self.assertIn("text/html", response.headers["Content-Type"])
                self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
                body = response.read().decode("utf-8")
            self.assertIn(needle, body, path)
            # every page shares the same-origin stylesheet and script, nothing external
            self.assertIn('href="/static/app.css"', body, path)
            self.assertIn('src="/static/app.js"', body, path)
            bodies.append(body)
        for path, ctype in (("/static/app.css", "text/css"), ("/static/app.js", "text/javascript")):
            with urlopen(self.base + path) as response:
                self.assertIn(ctype, response.headers["Content-Type"])
                bodies.append(response.read().decode("utf-8"))
        import re
        for body in bodies:
            self.assertIsNone(re.search(r'(src|href)\s*=\s*"(https?:)?//', body))   # no external loads
            for needle in ("@import", "url(", "//cdn"):
                self.assertNotIn(needle, body)
            for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
                self.assertNotIn(sink, body, sink)
        for missing in ("/static/../server.py", "/static/nope.js", "/demo.html"):
            with self.assertRaises(HTTPError) as ctx:
                urlopen(self.base + missing)
            self.assertEqual(ctx.exception.code, 404, missing)

    def test_snapshot_feeds_both_modes(self):
        _, state = self.request("/api/state")
        for key in ("doc_scenarios", "task", "tasks", "approvals_pending", "replay", "contexts", "tool_executions",
                    "egress", "streams", "events", "scenarios", "feed", "attack_log", "outbox", "metrics"):
            self.assertIn(key, state, key)
        self.assertEqual(len(state["contexts"]), 4)
        self.assertEqual([a["role"] for a in (state["agents"]["monitor"], state["agents"]["validator"],
                                              state["agents"]["adversary"])],
                         ["Intake Agent", "Policy Validator", "Red Team"])


if __name__ == "__main__":
    unittest.main()
