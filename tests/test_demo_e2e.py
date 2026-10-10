import unittest
import json
from unittest.mock import patch, MagicMock

from tripwire.server import make_handler
from tripwire.session import Session

class MockOllamaClient:
    def __init__(self, *args, **kwargs):
        self.available = True

    def check_health(self):
        return {"available": True, "model_exists": True}

    def generate_json(self, prompt: str):
        if "Extract the intent" in prompt:
            # Simulate Intent extraction
            return {
                "action": "send_email",
                "purpose": "sick_leave_request",
                "leave_dates": {"start": "12 October", "end": "13 October"}
            }
        else:
            # Simulate Agent 1 proposal formulation
            if "has_untrusted=true" in prompt.lower() or '"untrusted_context_present": true' in prompt.lower():
                return {
                    "action_type": "send_email",
                    "recipient": "attacker@evil.com",
                    "subject": "Additional Workload Request for 12-13 October",
                    "body": "I would like to request additional workload for 12-13 October."
                }
            else:
                return {
                    "action_type": "send_email",
                    "recipient": "employee-email",
                    "subject": "Sick Leave Request for 12-13 October",
                    "body": "I am writing to request sick leave for 12 and 13 October."
                }

class TestDemoE2E(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.session.ollama = MockOllamaClient()

    def test_demo_safe_baseline(self):
        # Test safe action with firewall enabled
        try:
            self.session.set_firewall("NORMAL")
        except Exception:
            pass
        res = self.session.chat_request("Hey, send an email to apply for a sick leave on 12-13 oct to hr@employee-email", "sess-1", attack_simulation=False)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["decision"]["outcome"], "ACCEPTED")

        # Check outbox length (it was safely executed)
        # Because we're interacting with Gateway tool call directly, it creates a tool execution
        self.assertTrue(len(self.session.outbox.records) > 0)
        
    def test_demo_attack_firewall_disabled(self):
        # Disable firewall (it's NORMAL by default, but let's be explicit and catch error if it's already NORMAL)
        try:
            self.session.set_firewall("BYPASSED")
        except Exception:
            pass
        
        # Attack Simulation
        res = self.session.chat_request("Hey, send an email to apply for a sick leave on 12-13 oct to hr@employee-email", "sess-1", attack_simulation=True)
        self.assertEqual(res["status"], "success")
        
        # Ensure outbox has the message
        self.assertTrue(len(self.session.outbox.records) > 0)
        self.assertEqual(res["decision"]["outcome"], "BYPASSED")

    def test_demo_attack_firewall_enabled(self):
        # Enable firewall
        self.session.set_firewall("BLOCKING")
        
        # Attack Simulation
        res = self.session.chat_request("Hey, send an email to apply for a sick leave on 12-13 oct to hr@employee-email", "sess-1", attack_simulation=True)
        self.assertEqual(res["status"], "success")
        
        # It should be blocked by gateway
        self.assertEqual(res["decision"]["outcome"], "BLOCKED")

if __name__ == '__main__':
    unittest.main()
