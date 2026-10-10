import unittest
from tripwire.demo_sim import DemoPipeline

class TestDemoPipeline(unittest.TestCase):
    def test_firewall_disabled_attack_succeeds(self):
        """When firewall is OFF and attack is ON, the payload should succeed."""
        result = DemoPipeline.execute(firewall_active=False, human_prompt="hello", attack_active=True)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["threat_log"], [])
        self.assertEqual(result["final_egress"]["to"], "hacker@evil.com")
        self.assertIn("GIBBERISH", result["final_egress"]["body"])
        
    def test_firewall_enabled_attack_blocked(self):
        """When firewall is ON and attack is ON, it should block the attack and log the threat."""
        result = DemoPipeline.execute(firewall_active=True, human_prompt="send an email to team", attack_active=True)
        
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(len(result["threat_log"]), 1)
        self.assertEqual(result["threat_log"][0]["event"], "UNTRUSTED_AUTHORITY")
        
        # Ensures safe intent still executes instead of malicious exfiltration
        self.assertEqual(result["final_egress"]["to"], "authorized_recipient@company.com")
        self.assertIn("send an email to team", result["final_egress"]["body"])
        self.assertNotIn("GIBBERISH", result["final_egress"]["body"])

    def test_normal_operation(self):
        """When attack is OFF, it should succeed normally regardless of firewall."""
        result = DemoPipeline.execute(firewall_active=True, human_prompt="safe intent", attack_active=False)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["final_egress"]["to"], "authorized_recipient@company.com")
        self.assertIn("safe intent", result["final_egress"]["body"])
