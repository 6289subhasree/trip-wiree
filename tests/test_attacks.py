"""Every attack scenario against the strict gateway, the baseline comparison, and the bounded runner."""
import time
import unittest

from tripwire.attacks import ATTACKER_MAILBOX, MAX_MESSAGES, SCENARIOS
from tests.helpers import make_session

EXPECTED = {
    "malformed": {"SCHEMA_INVALID", "OVERSIZE"},
    "forged_sender": {"BAD_MAC"},
    "tamper": {"BAD_MAC"},
    "replay": {"REPLAY"},
    "stale": {"STALE"},
    "reorder": {"SEQUENCE_REGRESSION"},
    "unauthorized_action": {"UNAUTHORIZED_ROUTE"},
    "recipient_injection": {"PAYLOAD_INVALID"},
}


class StrictAttackTests(unittest.TestCase):
    def setUp(self):
        self.s = make_session(self, auto_lockdown=False)
        self.s.report_score(90)  # one legitimate alert to sniff/replay
        self.legit_mail = self.s.outbox.delivered_count

    def test_each_scenario_is_detected_with_expected_code(self):
        for sid, codes in EXPECTED.items():
            rows = self.s.run_attack(sid)
            self.assertTrue(rows, sid)
            self.assertEqual({r["code"] for r in rows}, codes, sid)
            self.assertTrue(all(r["outcome"] == "REJECTED" and r["detected"] for r in rows), sid)
        self.assertEqual(self.s.outbox.delivered_count, self.legit_mail)
        self.assertEqual(self.s.metrics()["unauthorized_emails"], 0)
        self.assertFalse(any(ATTACKER_MAILBOX in r["to"] for r in self.s.outbox.records))

    def test_flood_is_bounded_and_rate_limited(self):
        rows = self.s.run_attack("flood")
        self.assertLessEqual(len(rows), MAX_MESSAGES)
        self.assertIn("RATE_LIMITED", {r["code"] for r in rows})
        self.assertEqual(sum(r["email"] for r in rows), 0)

    def test_probe_is_blocked_while_engaged_and_skipped_when_normal(self):
        self.assertEqual(self.s.run_attack("probe_while_blocked")[0]["outcome"], "SKIPPED")
        self.s.set_firewall("BLOCKING")
        rows = self.s.run_attack("probe_while_blocked")
        self.assertEqual(rows[0]["code"], "FIREWALL_BLOCKING")
        self.assertEqual(self.s.outbox.delivered_count, self.legit_mail)

    def test_unknown_scenario(self):
        with self.assertRaises(ValueError):
            self.s.run_attack("nmap")


class BaselineComparisonTests(unittest.TestCase):
    def test_baseline_profile_is_actually_vulnerable(self):
        s = make_session(self, auto_lockdown=False)
        s.set_profile("baseline")
        s.report_score(90)
        for sid in ("forged_sender", "unauthorized_action", "recipient_injection", "replay"):
            s.run_attack(sid)
        m = s.metrics()
        self.assertGreaterEqual(m["unauthorized_emails"], 4)
        self.assertTrue(any(ATTACKER_MAILBOX in r["to"] for r in s.outbox.records))
        self.assertTrue(any(e["kind"] == "gateway.profile" for e in s.audit.entries))

    def test_baseline_still_honours_the_firewall(self):
        s = make_session(self, auto_lockdown=False)
        s.set_profile("baseline")
        s.set_firewall("BLOCKING")
        s.run_attack("forged_sender")
        self.assertEqual(s.outbox.delivered_count, 0)


class SequenceRunnerTests(unittest.TestCase):
    def wait(self, s, timeout=10):
        deadline = time.time() + timeout
        while s.attack_run["running"] and time.time() < deadline:
            time.sleep(0.01)
        self.assertFalse(s.attack_run["running"])

    def test_full_sequence_runs_bounded_and_ends_in_lockdown(self):
        s = make_session(self, attack_delay_s=0.05)
        s.report_score(90)
        s.start_attack_sequence()
        with self.assertRaises(ValueError):
            s.start_attack_sequence()
        self.wait(s)
        self.assertEqual(s.attack_run["done"], len(SCENARIOS))
        self.assertEqual(s.firewall.mode, "LOCKDOWN")
        self.assertTrue(s.firewall.automatic)
        self.assertIsNotNone(s.attack_run["lockdown_after_s"])
        m = s.metrics()
        self.assertEqual(m["unauthorized_emails"], 0)
        self.assertEqual(s.outbox.delivered_count, 1)
        self.assertLessEqual(m["attack_attempts"], len(SCENARIOS) * MAX_MESSAGES)

    def test_stop_interrupts_sequence(self):
        s = make_session(self, attack_delay_s=0.5)
        s.start_attack_sequence()
        time.sleep(0.1)
        s.stop_attacks()
        self.assertFalse(s.attack_run["running"])
        self.assertTrue(s.attack_run["stopped"])
        self.assertLess(s.attack_run["done"], len(SCENARIOS))


if __name__ == "__main__":
    unittest.main()


class GuidedDemoRegressionTests(unittest.TestCase):
    def test_guided_demo_sequence_yields_no_unauthorized_email(self):
        """Mirrors the dashboard's guided demo. Regression: a message blocked during BLOCKING
        used to be replayable after release and produced an unauthorized email."""
        s = make_session(self)
        for _ in range(3):
            s.stream_step("baseline")
        s.reset_streams()
        for _ in range(5):
            s.stream_step("incident")
        self.assertEqual(s.outbox.delivered_count, 1)
        s.run_attack("tamper")
        s.run_attack("forged_sender")
        s.set_firewall("BLOCKING")
        self.assertEqual(s.send_alert().outcome, "BLOCKED")
        s.set_firewall("NORMAL")
        for sc in SCENARIOS:
            s.run_attack(sc.id)
        m = s.metrics()
        self.assertEqual(m["unauthorized_emails"], 0)
        self.assertEqual(s.outbox.delivered_count, 1)
        self.assertEqual(s.firewall.mode, "LOCKDOWN")
        self.assertTrue(s.audit.verify()["ok"])
        passed = [r for r in s.attack_log if r["outcome"] == "ACCEPTED"]
        self.assertTrue(all(r["scenario"] == "flood" for r in passed))
