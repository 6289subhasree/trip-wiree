"""End-to-end workflow, firewall state machine, outbox side effects, audit chain, concurrency."""
import threading
import unittest

from tripwire.firewall import FirewallError
from tripwire.protocol import VALIDATOR, ALERT
from tripwire.risk import STREAMS, simulate
from tests.helpers import CODE, FakeClock, make_session


class ThresholdWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.s = make_session(self, auto_lockdown=False)

    def test_risk_model_is_deterministic(self):
        self.assertEqual(simulate(STREAMS["incident"]), simulate(STREAMS["incident"]))
        self.assertLess(max(simulate(STREAMS["baseline"])), 70)
        scores = simulate(STREAMS["incident"])
        self.assertLess(scores[3], 70)
        self.assertGreaterEqual(scores[4], 70)

    def test_below_at_and_above_threshold(self):
        below = self.s.report_score(69.9)
        self.assertEqual(below.message_type, "telemetry.report")
        at = self.s.report_score(70)
        self.assertEqual(at.message_type, "alert.request")
        self.assertIsNotNone(at.action)
        self.assertEqual(at.action.email["status"], "SIMULATED_DELIVERY")
        above = self.s.report_score(90)  # same open incident: no duplicate alert
        self.assertEqual(above.message_type, "telemetry.report")
        self.assertEqual(self.s.outbox.delivered_count, 1)
        self.assertEqual(self.s.outbox.file_count(), 1)

    def test_incident_stream_delivers_exactly_one_email_with_correlation(self):
        results = [self.s.stream_step("incident") for _ in STREAMS["incident"]]
        alerts = [r["decision"] for r in results if r["decision"].message_type == "alert.request"]
        self.assertEqual(len(alerts), 1)
        mail = [r for r in self.s.outbox.records if r["status"] == "SIMULATED_DELIVERY"]
        self.assertEqual(len(mail), 1)
        self.assertEqual(mail[0]["correlation_id"], alerts[0].correlation_id)
        self.assertEqual(mail[0]["to"], ["soc-oncall@tripwire.invalid"])
        self.assertTrue(mail[0]["simulated"])
        with self.assertRaises(ValueError):
            self.s.stream_step("incident")

    def test_validator_refuses_alert_below_threshold(self):
        self.s.report_score(10)
        d = self.s.send_alert()
        self.assertEqual(d.code, "VALIDATOR_REFUSED")
        self.assertIsNone(d.action)
        self.assertEqual(self.s.outbox.delivered_count, 0)
        self.assertEqual(self.s.outbox.records[-1]["status"], "REJECTED")

    def test_one_email_per_incident_action_policy(self):
        self.s.report_score(90)
        corr = self.s.monitor.incident
        again = self.s.legit(self.s.monitor.alert(corr))
        self.assertEqual(again.action.code, "ACTION_DENIED")
        self.assertEqual(self.s.outbox.delivered_count, 1)

    def test_threshold_is_tunable_and_validated(self):
        self.s.set_threshold(40)
        self.assertEqual(self.s.report_score(45).message_type, "alert.request")
        for bad in (0, 101, "70", True, float("nan")):
            with self.assertRaises(ValueError):
                self.s.set_threshold(bad)


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.s = make_session(self, auto_lockdown=False)

    def test_blocking_denies_all_traffic_and_email(self):
        self.s.set_firewall("BLOCKING")
        d = self.s.report_score(95)
        self.assertEqual((d.outcome, d.code), ("BLOCKED", "FIREWALL_BLOCKING"))
        self.assertEqual(self.s.send_alert().outcome, "BLOCKED")
        self.assertEqual(self.s.validator.handled, 0)
        self.assertEqual(self.s.outbox.delivered_count, 0)
        self.assertEqual(self.s.outbox.file_count(), 0)
        self.assertIn("BLOCKED", {r["status"] for r in self.s.outbox.records})

    def test_messages_blocked_by_firewall_cannot_be_reinjected_after_release(self):
        self.s.report_score(90)
        self.s.set_firewall("BLOCKING")
        wire = self.s.monitor.alert()
        import copy
        self.assertEqual(self.s.legit(copy.deepcopy(wire)).outcome, "BLOCKED")
        self.s.set_firewall("NORMAL")
        self.assertEqual(self.s.attack(wire, "reinject").code, "REPLAY")  # burned while blocked
        self.assertEqual(self.s.outbox.delivered_count, 1)
        self.assertEqual(self.s.send_alert().outcome, "ACCEPTED")  # fresh traffic still works

    def test_forged_messages_while_blocked_do_not_burn_legit_sequence(self):
        self.s.set_firewall("BLOCKING")
        forged = self.s.adversary.signer.sign(VALIDATOR, ALERT, {"risk_score": 90, "threshold": 70, "signals": [],
                                              "summary": "x"}, sender_id="agent-1-monitor", sequence_number=10**9)
        self.assertEqual(self.s.attack(forged, "t").would_fail, "BAD_MAC")
        self.s.set_firewall("NORMAL")
        self.assertEqual(self.s.report_score(10).outcome, "ACCEPTED")

    def test_blocking_release_without_code_but_lockdown_needs_code(self):
        self.s.set_firewall("BLOCKING")
        self.s.set_firewall("NORMAL")
        self.s.set_firewall("LOCKDOWN")
        with self.assertRaises(FirewallError):
            self.s.set_firewall("NORMAL")
        with self.assertRaises(FirewallError):
            self.s.set_firewall("BLOCKING")
        with self.assertRaises(FirewallError):
            self.s.recover("wrong")
        self.assertEqual(self.s.firewall.mode, "LOCKDOWN")
        self.s.recover(CODE)
        self.assertEqual(self.s.firewall.mode, "NORMAL")

    def test_recovery_is_throttled_after_repeated_failures(self):
        self.s.set_firewall("LOCKDOWN")
        for _ in range(5):
            with self.assertRaises(FirewallError):
                self.s.recover("nope")
        with self.assertRaisesRegex(FirewallError, "too many"):
            self.s.recover(CODE)  # even the right code waits out the cooldown
        self.assertEqual(self.s.firewall.mode, "LOCKDOWN")

    def test_reset_does_not_bypass_lockdown(self):
        self.s.set_firewall("LOCKDOWN")
        self.s.reset()
        self.assertEqual(self.s.firewall.mode, "LOCKDOWN")
        self.assertEqual(self.s.report_score(99).outcome, "BLOCKED")

    def test_transitions_are_audited_and_distinguish_automatic(self):
        self.s.set_firewall("BLOCKING")
        self.s.set_firewall("NORMAL")
        kinds = [e for e in self.s.audit.entries if e["kind"] == "firewall.transition"]
        self.assertEqual([e["data"]["to_mode"] for e in kinds], ["BLOCKING", "NORMAL"])
        self.assertTrue(all(e["data"]["automatic"] is False for e in kinds))


class AutoLockdownTests(unittest.TestCase):
    def test_attack_pressure_triggers_automatic_lockdown(self):
        s = make_session(self, auto_lockdown=True, lockdown_threshold=100)
        s.run_attack("forged_sender")   # 40
        s.run_attack("tamper")          # 80
        self.assertEqual(s.firewall.mode, "NORMAL")
        s.run_attack("replay")          # 115 -> lockdown
        self.assertEqual(s.firewall.mode, "LOCKDOWN")
        self.assertTrue(s.firewall.automatic)
        self.assertEqual(s.report_score(99).outcome, "BLOCKED")
        self.assertEqual(s.outbox.delivered_count, 0)
        s.recover(CODE)
        self.assertEqual(s.gateway.pressure(), 0)
        self.assertEqual(s.report_score(99).action.email["status"], "SIMULATED_DELIVERY")

    def test_pressure_decays(self):
        clock = FakeClock()
        s = make_session(self, clock=clock, lockdown_threshold=1000)
        s.run_attack("forged_sender")
        before = s.gateway.pressure()
        clock.advance(120)
        self.assertAlmostEqual(s.gateway.pressure(), before / 2, places=3)


class AuditTests(unittest.TestCase):
    def test_chain_verifies_and_detects_tampering(self):
        s = make_session(self)
        s.report_score(90)
        s.run_attack("tamper")
        self.assertTrue(s.audit.verify()["ok"])
        seq = s.tamper_audit()["tampered_seq"]
        result = s.audit.verify()
        self.assertFalse(result["ok"])
        self.assertEqual(result["broken_at"], seq)

    def test_deleting_an_entry_is_detected(self):
        s = make_session(self)
        s.report_score(90)
        del s.audit.entries[2]
        self.assertFalse(s.audit.verify()["ok"])

    def test_every_decision_is_audited_with_correlation(self):
        s = make_session(self)
        d = s.report_score(90)
        audited = [e["data"] for e in s.audit.entries if e["kind"] == "gateway.decision"]
        self.assertEqual({a["correlation_id"] for a in audited}, {d.correlation_id})
        self.assertEqual(len(audited), 2)  # alert.request + action.email.send
        self.assertTrue(any(e["kind"] == "email.delivered" for e in s.audit.entries))


class ConcurrencyTests(unittest.TestCase):
    def test_no_email_after_blocking_transition_under_concurrency(self):
        s = make_session(self, auto_lockdown=False)
        s.gateway.email_limit = 10_000
        s.gateway.rate_capacity = 10_000
        barrier = threading.Barrier(9)

        def sender():
            barrier.wait()
            for _ in range(40):
                s.legit(s.monitor.alert())  # each alert is a new incident

        def operator():
            barrier.wait()
            s.set_firewall("BLOCKING")

        threads = [threading.Thread(target=sender) for _ in range(8)] + [threading.Thread(target=operator)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        transition = next(e["seq"] for e in s.audit.entries if e["kind"] == "firewall.transition")
        deliveries = [e["seq"] for e in s.audit.entries if e["kind"] == "email.delivered"]
        self.assertTrue(all(seq < transition for seq in deliveries))
        after = [e for e in s.audit.entries if e["seq"] > transition and e["kind"] == "gateway.decision"]
        self.assertTrue(after)
        self.assertTrue(all(e["data"]["outcome"] == "BLOCKED" for e in after))
        self.assertEqual(len(deliveries), s.outbox.file_count())

    def test_concurrent_replay_is_accepted_once(self):
        s = make_session(self, auto_lockdown=False)
        wire = s.monitor.signer.sign(VALIDATOR, ALERT, {"risk_score": 90, "threshold": 70, "signals": [],
                                                        "summary": "x"})
        import copy
        results = []
        threads = [threading.Thread(target=lambda: results.append(s.submit(copy.deepcopy(wire), "legit").outcome))
                   for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count("ACCEPTED"), 1)
        self.assertEqual(s.outbox.delivered_count, 1)


if __name__ == "__main__":
    unittest.main()
