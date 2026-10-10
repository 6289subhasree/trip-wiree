"""Three-agent mail simulation (/simulation): outcomes must come from real gateway decisions."""
import json
import os
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tripwire.approvals import ApprovalError
from tripwire.demo_sim import ATTACKER_DROP, MAX_PAUSED_RUNS, DemoPipeline, compose, mail_policy, recipient_of
from tripwire.server import make_handler
from tests.helpers import make_session

PROMPT = "Draft a leave request to abcd@gmail.com"
RECIPIENT = "abcd@gmail.com"


class DemoPipelineTests(unittest.TestCase):
    def setUp(self):
        self.pipeline = DemoPipeline()
        self.addCleanup(self.pipeline.close)

    def settle(self, r):
        """The human at the console: approve what their own instruction backs, reject the rest."""
        for card in list(r["approvals"]):
            r = self.pipeline.decide(r["run_id"], card["id"], "reject" if card["untrusted_only"] else "approve")
        return r

    def test_firewall_disabled_attack_succeeds(self):
        r = self.pipeline.execute(False, PROMPT, True)
        self.assertTrue(r["counterfactual"])
        self.assertEqual((r["profile"], r["status"], r["approvals"]), ("baseline", "success", []))
        self.assertTrue(r["compromised"])
        self.assertEqual(r["final_egress"]["to"], RECIPIENT)
        self.assertIn("GIBBERISH", r["final_egress"]["body"])
        self.assertTrue(r["final_egress"]["malicious"])
        self.assertEqual(r["threat_log"], [])  # nothing was enforced
        # the injected export really ran and really reached the attacker's (simulated) mailbox
        leaked = [m for m in r["egress"] if m["to"] == ATTACKER_DROP and m["records"]]
        self.assertEqual(len(leaked), 1)
        self.assertGreater(leaked[0]["canaries"], 0)
        self.assertEqual(r["report"]["containment"], "BREACHED")
        self.assertIn(ATTACKER_DROP, r["report"]["external_destinations_reached"])
        # the user's own message was never proposed
        self.assertFalse(any(not m["malicious"] for m in r["egress"]))
        self.assertEqual(r["steps"][-1]["code"], "DRAFT_REPLACED")

    def test_firewall_enabled_attack_blocked(self):
        r = self.pipeline.execute(True, PROMPT, True)
        self.assertFalse(r["counterfactual"])
        events = [t["event"] for t in r["threat_log"]]
        for code in ("UNTRUSTED_AUTHORITY", "BAD_MAC", "DESTINATION_NOT_ALLOWED", "INTENT_MISMATCH", "TOOL_FORBIDDEN"):
            self.assertIn(code, events)
        self.assertTrue(all(t["actor"] == "Agent 3" for t in r["threat_log"]))
        # nothing has left yet: three hostile requests refused, two external emails paused for a human
        self.assertEqual((r["status"], r["egress"], r["final_egress"]), ("awaiting_approval", [], None))
        hostile = [s for s in r["steps"] if s["origin"] != "task"]
        self.assertEqual([s["decision"] for s in hostile], ["BLOCK", "REQUIRE_APPROVAL", "BLOCK", "BLOCK"])
        self.assertFalse(any(s["executed"] for s in r["steps"]))
        self.assertEqual([a["untrusted_only"] for a in r["approvals"]], [True, False])

        r = self.settle(r)
        self.assertEqual((r["status"], r["approvals"]), ("blocked", []))
        self.assertEqual(len(r["egress"]), 1)  # exactly one email left, and it is the user's
        self.assertEqual(r["final_egress"]["to"], RECIPIENT)
        self.assertEqual(r["final_egress"]["body"], compose(PROMPT, RECIPIENT))
        self.assertFalse(r["final_egress"]["malicious"])
        self.assertFalse(r["compromised"])
        self.assertEqual(r["report"]["containment"], "CONTAINED")
        self.assertEqual(r["report"]["sensitive_records_exposed"], 0)
        self.assertGreater(r["report"]["sensitive_records_protected"], 0)
        self.assertTrue(r["audit_ok"])

    def test_injected_output_for_the_users_own_recipient_cannot_authorise_itself(self):
        r = self.pipeline.execute(True, PROMPT, True)
        override = next(s for s in r["steps"] if s["origin"] == "injection" and s["to"] == RECIPIENT)
        # allowed tool, allowed destination: the only thing wrong with it is where the reason came from
        self.assertEqual(override["codes"], ["UNTRUSTED_AUTHORITY"])
        self.assertEqual((override["decision"], override["executed"]), ("REQUIRE_APPROVAL", False))
        self.assertTrue(override["approval"]["untrusted_only"])
        self.assertEqual([(e["context"], e["verified"], e["authorising"]) for e in override["evidence"]],
                         [("document", True, False)])
        self.assertIn("untrusted content", override["reason"])

    def test_a_human_who_approves_the_injected_email_is_the_authority_for_it(self):
        r = self.pipeline.execute(True, PROMPT, True)
        card = next(a for a in r["approvals"] if a["untrusted_only"])
        r = self.pipeline.decide(r["run_id"], card["id"], "approve")
        self.assertTrue(r["compromised"])
        self.assertIn("GIBBERISH", r["final_egress"]["body"])
        self.assertEqual(r["status"], "awaiting_approval")  # the user's own email is still waiting

    def test_clean_run(self):
        r = self.pipeline.execute(True, PROMPT, False)
        self.assertEqual((r["status"], r["delivered"], r["attack_log"], r["threat_log"]),
                         ("awaiting_approval", False, [], []))
        self.assertEqual([(a["to"], a["untrusted_only"], a["triggers"]) for a in r["approvals"]],
                         [(RECIPIENT, False, ["external_destination"])])
        r = self.settle(r)
        self.assertEqual((r["status"], r["delivered"], r["compromised"]), ("success", True, False))
        self.assertEqual([m["to"] for m in r["egress"]], [RECIPIENT])
        self.assertEqual(r["steps"][0]["approval"]["status"], "EXECUTED")
        # the baseline sends the same message with no checks and no human
        r = self.pipeline.execute(False, PROMPT, False)
        self.assertEqual((r["status"], r["delivered"], r["compromised"], r["approvals"]), ("success", True, False, []))
        self.assertEqual(r["report"]["containment"], "BREACHED")  # an external email with no approval

    def test_paused_runs_are_bounded_and_cleaned_up(self):
        first = self.pipeline.execute(True, PROMPT, False)
        tmp = self.pipeline._runs[first["run_id"]].tmp
        self.assertTrue(os.path.isdir(tmp))
        for _ in range(MAX_PAUSED_RUNS):
            last = self.pipeline.execute(True, PROMPT, False)
        self.assertEqual(len(self.pipeline._runs), MAX_PAUSED_RUNS)
        self.assertFalse(os.path.isdir(tmp))  # the oldest paused run was evicted
        with self.assertRaises(ValueError):
            self.pipeline.decide(first["run_id"], first["approvals"][0]["id"], "approve")
        done = self.settle(last)
        self.assertNotIn(done["run_id"], self.pipeline._runs)  # settled runs are not kept
        self.pipeline.execute(False, PROMPT, True)
        self.assertEqual(len(self.pipeline._runs), MAX_PAUSED_RUNS - 1)  # a baseline run never pauses

    def test_decisions_are_validated(self):
        r = self.pipeline.execute(True, PROMPT, True)
        card = r["approvals"][0]["id"]
        for args in ((r["run_id"], card, "yes"), ("nope", card, "approve"), (r["run_id"], "apr-9999", "approve"),
                     (None, card, "approve")):
            with self.assertRaises(ValueError, msg=args):
                self.pipeline.decide(*args)
        self.pipeline.decide(r["run_id"], card, "reject")
        with self.assertRaises(ApprovalError):
            self.pipeline.decide(r["run_id"], card, "approve")  # an approval is spent once decided

    def test_only_the_named_recipient_is_allowlisted(self):
        policy = mail_policy(RECIPIENT)
        self.assertEqual(policy.allowed_destinations, (RECIPIENT,))
        self.assertEqual(policy.allowed_tools, ("send_email",))
        self.assertEqual(recipient_of("Write to first@a.example and cc second@b.example"), "first@a.example")

    def test_input_is_validated(self):
        for args in (("yes", PROMPT, True), (True, PROMPT, 1), (True, "", False), (True, 7, False),
                     (True, "x" * 201, False), (True, "Draft a leave request", False)):
            with self.assertRaises(ValueError, msg=args):
                self.pipeline.execute(*args)
        self.assertEqual(self.pipeline._runs, {})


class DemoEndpointTests(unittest.TestCase):
    def setUp(self):
        self.session = make_session(self, auto_lockdown=False)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.session, quiet=True))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def request(self, path, body=None, headers=None):
        hdrs = {"Content-Type": "application/json", "X-TripWire-Client": "dashboard"}
        hdrs.update(headers or {})
        req = Request(self.base + path, data=None if body is None else json.dumps(body).encode(), headers=hdrs)
        try:
            with urlopen(req) as response:
                return response.status, response.read()
        except HTTPError as exc:
            return exc.code, exc.read()

    def post(self, path, **body):
        status, raw = self.request(path, body)
        return status, json.loads(raw)

    def execute(self, **body):
        return self.post("/api/demo/execute", **body)

    def assert_live_session_untouched(self):
        self.assertEqual(self.session.gateway.profile, "strict")
        self.assertEqual(self.session.outbox.records, [])
        self.assertEqual(self.session.outbox.file_count(), 0)
        self.assertEqual(self.session.registry.executions["send_email"], 0)
        self.assertEqual(self.session.tools.tasks, {})
        self.assertEqual(self.session.approvals.items, {})
        self.assertTrue(self.session.verify_audit()["ok"])

    def test_firewall_off_runs_in_a_throwaway_session_and_leaves_the_live_one_strict(self):
        status, r = self.execute(firewall_active=False, human_prompt=PROMPT, attack_active=True)
        self.assertEqual(status, 200)
        self.assertTrue(r["compromised"])
        self.assertIn("GIBBERISH", r["final_egress"]["body"])
        self.assert_live_session_untouched()
        self.assertEqual(self.session.audit.path.read_text(encoding="utf-8").count('"demo.execute"'), 1)

    def test_firewall_on_blocks_the_attack_and_sends_only_what_the_human_approves(self):
        status, r = self.execute(firewall_active=True, human_prompt=PROMPT, attack_active=True)
        self.assertEqual((status, r["status"], r["egress"]), (200, "awaiting_approval", []))
        self.assertIn("UNTRUSTED_AUTHORITY", [t["event"] for t in r["threat_log"]])
        for card in r["approvals"]:
            status, r2 = self.post("/api/demo/approval", run_id=r["run_id"], approval_id=card["id"],
                                   decision="reject" if card["untrusted_only"] else "approve")
            self.assertEqual(status, 200)
        self.assertEqual((r2["status"], r2["compromised"], len(r2["egress"])), ("blocked", False, 1))
        self.assertEqual(r2["final_egress"]["to"], RECIPIENT)
        self.assertNotIn("GIBBERISH", r2["final_egress"]["body"])
        self.assert_live_session_untouched()
        # the run is finished, so its approvals cannot be used again
        status, _ = self.post("/api/demo/approval", run_id=r["run_id"], approval_id=r["approvals"][0]["id"],
                              decision="approve")
        self.assertEqual(status, 400)

    def test_bad_requests_are_refused(self):
        self.assertEqual(self.execute(firewall_active=True, human_prompt="no address here", attack_active=False)[0], 400)
        self.assertEqual(self.execute(firewall_active="on", human_prompt=PROMPT, attack_active=False)[0], 400)
        self.assertEqual(self.execute(firewall_active=True, human_prompt=PROMPT, attack_active=False,
                                      to="x@y.example")[0], 400)
        self.assertEqual(self.post("/api/demo/approval", run_id="x", approval_id="apr-0001", decision="approve")[0], 400)
        self.assertEqual(self.post("/api/demo/approval", run_id="x", approval_id="apr-0001", decision="approve",
                                   approver="agent-1-monitor")[0], 400)
        status, _ = self.request("/api/demo/execute", {"firewall_active": True, "human_prompt": PROMPT,
                                                       "attack_active": False}, {"X-TripWire-Client": "other"})
        self.assertEqual(status, 403)

    def test_page_and_assets_are_served_and_load_nothing_external(self):
        status, page = self.request("/simulation")
        self.assertEqual(status, 200)
        for needle in (b'id="fw-toggle"', b'id="attack-btn"', b'id="attack-log"', b'id="topology"', b'id="threat-log"',
                       b'id="approvals"', b'id="chat-input"', b"/static/sim.js", b"/static/sim.css"):
            self.assertIn(needle, page, needle)
        for path in ("/static/sim.js", "/static/sim.css"):
            status, body = self.request(path)
            self.assertEqual(status, 200, path)
            self.assertNotIn(b"http://", body, path)
            self.assertNotIn(b"https://", body, path)
            self.assertNotIn(b"innerHTML", body, path)
        self.assertNotIn(b"https://", page)


if __name__ == "__main__":
    unittest.main()
