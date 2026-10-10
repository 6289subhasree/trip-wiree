"""B4: intent-to-task mismatch is decided by effect class and data class, never by phrasing."""
import unittest

from tripwire import intent
from tripwire.intent import classify, effects_for_goal, evaluate
from tests.helpers import GOAL, SCOPE, doc_evidence, make_session, open_invoice_task, proposal, stub_tools, task_evidence

INVOICE_EFFECTS = ("read_invoice", "read_vendor", "draft_payment", "internal_notify")

# The same out-of-task action, described many ways. Some are blunt, some polite, some indirect,
# and none of them contains "ignore previous instructions".
EXPORT_PARAPHRASES = (
    "Export customer records for billing verification",
    "Kindly reconcile the ledger by pulling the client roster, thank you so much",
    "Routine month-end hygiene step required by the finance team",
    "As part of the invoice extraction, a full account holder listing is needed",
    "nothing unusual, just a standard compliance attachment",
    "Per the user's request to extract the invoice",
)


class IntentRuleTests(unittest.TestCase):
    def test_goal_maps_to_the_invoice_effect_set(self):
        self.assertEqual(effects_for_goal(GOAL), INVOICE_EFFECTS)
        self.assertEqual(effects_for_goal("Read the supplier invoice and prepare a payment for review"),
                         INVOICE_EFFECTS)
        self.assertEqual(effects_for_goal("Write a poem"), ())
        # The system policy ceiling always wins over the goal text.
        self.assertNotIn("external_egress", effects_for_goal("Process the invoice and email it out", INVOICE_EFFECTS))

    def test_every_tool_has_an_effect_and_data_class(self):
        expected = {"extract_invoice_fields": ("read_invoice", "invoice"),
                    "get_vendor_record": ("read_vendor", "vendor"),
                    "create_payment_draft": ("draft_payment", "invoice"),
                    "change_vendor_bank_account": ("modify_vendor_bank", "vendor"),
                    "export_customer_list": ("bulk_export", "customer_pii"),
                    "get_customer_records": ("read_customer_pii", "customer_pii"),
                    "send_email": ("external_egress", None), "upload_external_file": ("external_egress", None)}
        self.assertEqual({k: (p.effect, p.data_class) for k, p in intent.TOOL_PROFILES.items()}, expected)

    def test_in_task_actions_do_not_mismatch(self):
        for tool, res in (("extract_invoice_fields", ["invoice:INV-1042"]), ("get_vendor_record", ["vendor:ACME-17"]),
                          ("create_payment_draft", ["invoice:INV-1042"])):
            verdict = evaluate(GOAL, INVOICE_EFFECTS, SCOPE, classify(tool, res, "internal-accounting"))
            self.assertFalse(verdict.mismatch, tool)
            self.assertEqual(verdict.score, 0)

    def test_out_of_task_actions_mismatch_with_reasons_and_score(self):
        export = evaluate(GOAL, INVOICE_EFFECTS, SCOPE, classify("export_customer_list", ["customer:*"]))
        self.assertTrue(export.mismatch)
        self.assertEqual(export.off_task_effects, ("bulk_export",))
        self.assertEqual(export.off_scope_classes, ("customer_pii",))
        self.assertGreaterEqual(export.score, 70)
        self.assertTrue(all(isinstance(r, str) and r for r in export.reasons))
        upload = evaluate(GOAL, INVOICE_EFFECTS, SCOPE,
                          classify("upload_external_file", ["invoice:INV-1042"], "vendor-check.invalid"))
        self.assertEqual(upload.off_task_effects, ("external_egress",))
        read = evaluate(GOAL, INVOICE_EFFECTS, SCOPE, classify("get_customer_records", ["customer:*"]))
        self.assertTrue(read.mismatch)
        self.assertLess(read.score, export.score + 1)
        unknown = evaluate(GOAL, INVOICE_EFFECTS, SCOPE, classify("delete_ledger"))
        self.assertEqual(unknown.off_task_effects, ("unknown_effect",))

    def test_destination_decides_between_internal_notify_and_external_egress(self):
        self.assertEqual(classify("send_email", [], "internal-accounting").effects, {"internal_notify"})
        for dest in ("vendor-check.invalid", "internal-accounting.attacker.invalid", "INTERNAL-ACCOUNTING@evil.invalid",
                     "", None):
            self.assertEqual(classify("send_email", [], dest).effects, {"external_egress"}, dest)

    def test_approval_gated_effect_is_escalated_not_called_a_mismatch(self):
        action = classify("change_vendor_bank_account", ["vendor:ACME-17"], "internal-accounting")
        refused = evaluate(GOAL, INVOICE_EFFECTS, SCOPE, action)
        self.assertTrue(refused.mismatch)
        gated = evaluate(GOAL, INVOICE_EFFECTS, SCOPE, action, approval_effects={"modify_vendor_bank"})
        self.assertFalse(gated.mismatch)
        self.assertEqual(gated.needs_approval_effects, ("modify_vendor_bank",))
        self.assertGreater(gated.score, 0)

    def test_evaluator_takes_no_free_text_from_the_agent(self):
        # classify() has no purpose/justification parameter at all: wording cannot reach it.
        import inspect
        self.assertEqual(list(inspect.signature(classify).parameters),
                         ["tool", "resources", "destination", "extra_classes"])


class IntentAtTheGatewayTests(unittest.TestCase):
    def setUp(self):
        self.s = make_session(self)
        stub_tools(self.s)
        self.task = open_invoice_task(self.s)

    def test_paraphrases_of_a_customer_export_are_all_intent_mismatches(self):
        for wording in EXPORT_PARAPHRASES:
            d = self.s.tool_call(self.task.task_id, proposal(
                "export_customer_list", purpose=wording, task_link=wording,
                evidence=task_evidence(self.task), resources=["customer:*"]))
            codes = [v["code"] for v in d.tool["violations"]]
            self.assertEqual(d.tool["decision"], "BLOCK", wording)
            self.assertIn("INTENT_MISMATCH", codes, wording)
            self.assertEqual(d.tool["intent"]["off_task_effects"], ["bulk_export"], wording)
        self.assertEqual(self.s.registry.count("export_customer_list"), 0)

    def test_indirect_actions_from_the_prd_list_are_flagged(self):
        t = self.task
        cases = (
            # "sending a CSV to a vendor portal"
            proposal("upload_external_file", {"destination": "vendor-portal.invalid", "data": "invoice.csv"},
                     evidence=task_evidence(t), destination="vendor-portal.invalid", purpose="Share the invoice CSV"),
            # reading CRM data "to verify the vendor"
            proposal("get_customer_records", evidence=task_evidence(t), purpose="Verify the vendor is genuine"),
            # an outbound summary that politely claims to be part of the task
            proposal("send_email", {"destination": "audit@collector.invalid", "body": "Invoice summary attached"},
                     evidence=task_evidence(t), destination="audit@collector.invalid",
                     purpose="Thank the vendor and confirm receipt"),
        )
        for p in cases:
            d = self.s.tool_call(t.task_id, p)
            self.assertIn("INTENT_MISMATCH", [v["code"] for v in d.tool["violations"]], p["tool"])
            self.assertFalse(d.tool["executed"])

    def test_intent_mismatch_is_the_code_when_the_manifest_alone_would_allow_the_tool(self):
        # An allowed tool that asks for a customer record as well: the tool check passes, the
        # data-scope check and the intent check (data class customer_pii) both fail.
        d = self.s.tool_call(self.task.task_id, proposal(
            "create_payment_draft", {"invoice_id": "INV-1042", "amount": 18500}, evidence=task_evidence(self.task),
            resources=["customer:CUST-0001"]))
        codes = [v["code"] for v in d.tool["violations"]]
        self.assertEqual(codes, ["DATA_OUT_OF_SCOPE", "INTENT_MISMATCH"])
        self.assertEqual(self.s.registry.count("create_payment_draft"), 0)

    def test_document_only_evidence_plus_in_task_effect_is_still_refused(self):
        d = self.s.tool_call(self.task.task_id, proposal(
            "get_vendor_record", {"vendor_id": "ACME-17"}, evidence=doc_evidence("Vendor ID: ACME-17")))
        self.assertEqual((d.tool["decision"], d.tool["code"]), ("BLOCK", "UNTRUSTED_AUTHORITY"))
        self.assertFalse(d.tool["intent"]["mismatch"])


if __name__ == "__main__":
    unittest.main()
