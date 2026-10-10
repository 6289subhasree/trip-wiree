import tempfile
import unittest
from pathlib import Path

from tripwire.agents import AdversaryAgent, RelayAgent, SentinelAgent
from tripwire.firewall import Firewall
from tripwire.notifications import JsonlOutbox
from tripwire.protocol import SignedProtocol


class TripWireTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.protocol = SignedProtocol(b"test-secret", allowed_senders={"sentinel"})
        self.firewall = Firewall()
        self.outbox = JsonlOutbox(str(Path(self.temp.name) / "outbox.jsonl"))
        self.sentinel = SentinelAgent(self.protocol)
        self.relay = RelayAgent(self.protocol, self.firewall, self.outbox)

    def test_threshold_crossing_creates_alert(self):
        result = self.relay.receive(self.sentinel.report("risk_score", 80), 75)
        self.assertEqual(result.status, "ALERT")
        self.assertTrue(result.alert_sent)
        self.assertEqual(self.outbox.count(), 1)

    def test_below_threshold_does_not_alert(self):
        result = self.relay.receive(self.sentinel.report("risk_score", 20), 75)
        self.assertEqual(result.status, "ACCEPTED")
        self.assertEqual(self.outbox.count(), 0)

    def test_tampering_is_rejected(self):
        envelope = self.sentinel.report("risk_score", 20)
        result = self.relay.receive(AdversaryAgent.tamper_value(envelope, 100), 75)
        self.assertEqual(result.status, "REJECTED")
        self.assertIn("signature mismatch", result.detail)

    def test_replay_is_rejected(self):
        envelope = self.sentinel.report("risk_score", 20)
        self.assertEqual(self.relay.receive(envelope, 75).status, "ACCEPTED")
        result = self.relay.receive(AdversaryAgent.replay(envelope), 75)
        self.assertEqual(result.status, "REJECTED")
        self.assertIn("replay", result.detail)

    def test_firewall_blocks_messages_and_alerts(self):
        self.firewall.enable("attack simulation")
        result = self.relay.receive(self.sentinel.report("risk_score", 100), 75)
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(self.outbox.count(), 0)

    def test_forged_sender_is_rejected(self):
        envelope = self.sentinel.report("risk_score", 20)
        result = self.relay.receive(AdversaryAgent.forge_sender(envelope, "attacker"), 75)
        self.assertEqual(result.status, "REJECTED")
        self.assertIn("sender", result.detail)


if __name__ == "__main__":
    unittest.main()
