"""Protocol + gateway validation: every check is exercised with a real side-effect assertion."""
import copy
import unittest

from tripwire.protocol import (ALERT, EMAIL_ACTION, EMAIL_SEND, MONITOR, TELEMETRY, VALIDATOR, resign)
from tests.helpers import FakeClock, make_session


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.s = make_session(self, clock=self.clock, auto_lockdown=False)

    def telemetry(self, score=10):
        return self.s.monitor.signer.sign(VALIDATOR, TELEMETRY, {"risk_score": score, "signals": [], "source": "t"})

    def test_valid_telemetry_is_accepted_and_delivered(self):
        d = self.s.legit(self.telemetry())
        self.assertEqual((d.outcome, d.code), ("ACCEPTED", "OK"))
        self.assertEqual(self.s.validator.handled, 1)
        self.assertEqual(self.s.outbox.delivered_count, 0)

    def test_tampered_payload_is_rejected_without_delivery(self):
        wire = self.telemetry()
        wire["payload"]["risk_score"] = 99
        d = self.s.attack(wire, "t")
        self.assertEqual(d.code, "BAD_MAC")
        self.assertEqual(self.s.validator.handled, 0)

    def test_tampered_header_fields_are_covered_by_mac(self):
        for field, value in (("receiver_id", EMAIL_ACTION), ("correlation_id", "x"), ("timestamp", 1.0),
                             ("sequence_number", 999)):
            wire = self.telemetry()
            wire[field] = value
            self.assertEqual(self.s.attack(wire, "t").code, "BAD_MAC", field)

    def test_forged_sender_with_attacker_key_is_rejected(self):
        wire = self.s.adversary.signer.sign(VALIDATOR, TELEMETRY, {"risk_score": 1, "signals": [], "source": "x"},
                                            sender_id=MONITOR)
        self.assertEqual(self.s.attack(wire, "t").code, "BAD_MAC")
        # even re-signing a sniffed legit message with the attacker key fails
        self.assertEqual(self.s.attack(resign(self.telemetry(), self.s.adversary.key), "t").code, "BAD_MAC")

    def test_unregistered_sender_is_rejected(self):
        wire = self.s.adversary.signer.sign(VALIDATOR, TELEMETRY, {"risk_score": 1, "signals": [], "source": "x"})
        self.assertEqual(self.s.attack(wire, "t").code, "UNKNOWN_SENDER")

    def test_replay_is_rejected(self):
        wire = self.telemetry()
        self.assertEqual(self.s.legit(copy.deepcopy(wire)).outcome, "ACCEPTED")
        self.assertEqual(self.s.attack(wire, "t").code, "REPLAY")
        self.assertEqual(self.s.validator.handled, 1)

    def test_stale_and_future_messages_are_rejected(self):
        old = self.s.monitor.signer.sign(VALIDATOR, TELEMETRY, {"risk_score": 1, "signals": [], "source": "x"},
                                         timestamp=self.clock.now - 31)
        self.assertEqual(self.s.attack(old, "t").code, "STALE")
        future = self.s.monitor.signer.sign(VALIDATOR, TELEMETRY, {"risk_score": 1, "signals": [], "source": "x"},
                                            timestamp=self.clock.now + 60)
        self.assertEqual(self.s.attack(future, "t").code, "FUTURE_TIMESTAMP")

    def test_freshness_window_boundary(self):
        wire = self.telemetry()
        self.clock.advance(30)
        self.assertEqual(self.s.legit(wire).outcome, "ACCEPTED")

    def test_out_of_order_sequence_is_rejected(self):
        first, second = self.telemetry(), self.telemetry()
        self.assertEqual(self.s.legit(second).outcome, "ACCEPTED")
        self.assertEqual(self.s.attack(first, "t").code, "SEQUENCE_REGRESSION")

    def test_schema_violations(self):
        cases = [
            "not an object", {}, {**self.telemetry(), "extra": 1},
            {**self.telemetry(), "sequence_number": True}, {**self.telemetry(), "nonce": "xyz"},
            {**self.telemetry(), "timestamp": float("nan")},
        ]
        for wire in cases:
            self.assertEqual(self.s.attack(wire, "t").code, "SCHEMA_INVALID", repr(wire)[:60])

    def test_oversize_unknown_type_and_version(self):
        big = self.s.monitor.signer.sign(VALIDATOR, TELEMETRY, {"risk_score": 1, "signals": [], "source": "x",
                                                                "pad": "A" * 5000})
        self.assertEqual(self.s.attack(big, "t").code, "OVERSIZE")
        odd = self.s.monitor.signer.sign(VALIDATOR, "shell.exec", {})
        self.assertEqual(self.s.attack(odd, "t").code, "UNKNOWN_MESSAGE_TYPE")
        v1 = self.telemetry()
        v1["protocol_version"] = 1
        self.assertEqual(self.s.attack(v1, "t").code, "UNSUPPORTED_VERSION")

    def test_route_policy_blocks_privilege_escalation(self):
        direct = self.s.monitor.signer.sign(EMAIL_ACTION, EMAIL_SEND, {
            "template": "threshold_alert", "incident_id": "i", "risk_score": 100, "summary": "s"})
        self.assertEqual(self.s.attack(direct, "t").code, "UNAUTHORIZED_ROUTE")
        wrong_receiver = self.s.monitor.signer.sign(MONITOR, TELEMETRY, {"risk_score": 1, "signals": [], "source": "x"})
        self.assertEqual(self.s.attack(wrong_receiver, "t").code, "UNAUTHORIZED_ROUTE")
        self.assertEqual(self.s.outbox.delivered_count, 0)

    def test_payload_schema_is_strict(self):
        injected = self.s.monitor.signer.sign(VALIDATOR, ALERT, {
            "risk_score": 100, "threshold": 70, "signals": [], "summary": "s", "to": ["x@evil.invalid"]})
        self.assertEqual(self.s.attack(injected, "t").code, "PAYLOAD_INVALID")
        bad_score = self.s.monitor.signer.sign(VALIDATOR, TELEMETRY, {"risk_score": 101, "signals": [], "source": "x"})
        self.assertEqual(self.s.attack(bad_score, "t").code, "PAYLOAD_INVALID")
        self.assertEqual(self.s.outbox.delivered_count, 0)

    def test_rate_limit_per_sender(self):
        outcomes = [self.s.legit(self.telemetry()).code for _ in range(15)]
        self.assertEqual(outcomes.count("OK"), 12)
        self.assertEqual(outcomes.count("RATE_LIMITED"), 3)
        self.clock.advance(1)  # refills 2 tokens
        self.assertEqual(self.s.legit(self.telemetry()).code, "OK")

    def test_forged_traffic_cannot_drain_a_legit_senders_budget(self):
        for _ in range(20):
            forged = self.s.adversary.signer.sign(VALIDATOR, TELEMETRY, {"risk_score": 1, "signals": [], "source": "x"},
                                                  sender_id=MONITOR)
            self.s.attack(forged, "t")
        self.assertEqual(self.s.legit(self.telemetry()).outcome, "ACCEPTED")

    def test_same_wire_gets_same_decision_regardless_of_origin_label(self):
        a, b = self.telemetry(), None
        b = copy.deepcopy(a)
        b["payload"]["risk_score"] = 50
        self.assertEqual(self.s.submit(copy.deepcopy(b), "legit").code, "BAD_MAC")
        self.assertEqual(self.s.submit(copy.deepcopy(b), "attack:x").code, "BAD_MAC")


if __name__ == "__main__":
    unittest.main()
