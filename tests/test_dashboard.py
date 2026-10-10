import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tripwire.__main__ import DashboardSession, make_handler


class DashboardAPITests(unittest.TestCase):
    def setUp(self):
        self.session = DashboardSession()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.session))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def request(self, path, body=None):
        data = None if body is None else body.encode() if isinstance(body, str) else json.dumps(body).encode()
        req = Request(self.base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_state_endpoint_and_telemetry_alert(self):
        status, state = self.request("/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(state["accepted"], 0)
        status, result = self.request("/api/telemetry", {"metric": "risk_score", "value": 90})
        self.assertEqual(status, 200)
        self.assertEqual(result["result"]["status"], "ALERT")
        self.assertEqual(result["state"]["alerts"], 1)

    def test_attack_rejection_and_firewall_fail_closed(self):
        _, tampered = self.request("/api/attack/tamper", {})
        self.assertEqual(tampered["result"]["status"], "REJECTED")
        _, replayed = self.request("/api/attack/replay", {})
        self.assertEqual(replayed["result"]["status"], "REJECTED")
        _, forged = self.request("/api/attack/forged", {})
        self.assertEqual(forged["result"]["status"], "REJECTED")
        _, malformed = self.request("/api/attack/malformed", {})
        self.assertEqual(malformed["result"]["status"], "REJECTED")
        self.assertIn("metric", malformed["result"]["detail"])
        _, _ = self.request("/api/firewall", {"enabled": True})
        _, blocked = self.request("/api/telemetry", {"metric": "risk_score", "value": 100})
        self.assertEqual(blocked["result"]["status"], "BLOCKED")
        self.assertEqual(blocked["state"]["alerts"], 0)

    def test_bad_api_input_returns_useful_error(self):
        status, response = self.request("/api/telemetry", {"metric": "", "value": float("nan")})
        self.assertEqual(status, 400)
        self.assertIn("metric", response["error"])

    def test_large_integer_returns_400_instead_of_server_error(self):
        status, response = self.request("/api/telemetry", {"metric": "risk_score", "value": 10**1000})
        self.assertEqual(status, 400)
        self.assertIn("finite number", response["error"])

    def test_threshold_and_reset_preserve_controls(self):
        self.request("/api/threshold", {"threshold": 40})
        self.request("/api/firewall", {"enabled": True})
        self.request("/api/telemetry", {"metric": "risk_score", "value": 90})
        _, reset = self.request("/api/reset", {})
        self.assertEqual(reset["state"]["threshold"], 40)
        self.assertTrue(reset["state"]["firewall"])
        self.assertEqual(reset["state"]["accepted"], 0)
        self.assertEqual(reset["state"]["feed"], [])

    def test_malformed_json_returns_400(self):
        status, response = self.request("/api/telemetry", "{broken")
        self.assertEqual(status, 400)
        self.assertIn("Expecting", response["error"])

    def test_dashboard_served(self):
        with urlopen(self.base + "/") as response:
            self.assertEqual(response.status, 200)
            self.assertIn(b"Security Console", response.read())


if __name__ == "__main__":
    unittest.main()
