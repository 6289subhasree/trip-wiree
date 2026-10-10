"""B7: data lineage and the blast-radius report computed from it."""
import json
import unittest

from tripwire.report import blast_radius, entry_severity, is_attempt, is_unsafe_execution
from tripwire.tools_gateway import CANARY_RE
from tests.helpers import doc_evidence, make_session, open_invoice_task, proposal, task_evidence

PORTAL = "vendor-check.invalid"


class Flow:
    """Drives the same footer-injection request sequence through a session."""

    def __init__(self, testcase, profile="strict"):
        self.s = make_session(testcase, auto_lockdown=False)
        self.s.set_profile(profile)
        self.task = open_invoice_task(self.s)
        self.id = self.task.task_id

    def call(self, tool, args=None, **kw):
        kw.setdefault("evidence", task_evidence(self.task))
        return self.s.tool_call(self.id, proposal(tool, args, **kw))

    def legit(self):
        self.call("extract_invoice_fields", {"invoice_id": "INV-1042"})
        self.call("get_vendor_record", {"vendor_id": "ACME-17"})
        self.call("create_payment_draft", {"invoice_id": "INV-1042", "amount": 18500})

    def footer_attack(self):
        export = self.call("export_customer_list", evidence=doc_evidence(), resources=["customer:*"])
        handle = (export.tool["result"] or {}).get("artifact", "customers.csv")
        self.call("upload_external_file", {"destination": PORTAL, "data": handle}, evidence=doc_evidence(),
                  destination=PORTAL, resources=["customer:*"])

    def report(self):
        return self.s.report(self.id)

    def lineage(self):
        return self.s.lineage.for_task(self.id)


class LineageTests(unittest.TestCase):
    def test_every_request_gets_an_entry_with_the_prd_fields(self):
        f = Flow(self)
        f.legit()
        f.footer_attack()
        entries = f.lineage()
        self.assertEqual([e["tool"] for e in entries],
                         ["extract_invoice_fields", "get_vendor_record", "create_payment_draft",
                          "export_customer_list", "upload_external_file"])
        self.assertEqual([e["id"] for e in entries], [f"lin-{i:04d}" for i in range(1, 6)])
        draft, export, upload = entries[2], entries[3], entries[4]
        # source record or document
        self.assertEqual(draft["source_records"], ["invoice:INV-1042"])
        self.assertEqual(export["source_documents"], ["INV-1042"])
        self.assertEqual(export["evidence_contexts"], ["document"])
        # classification
        self.assertEqual((draft["classes"], draft["sensitive"]), (["invoice"], False))
        self.assertEqual((export["sensitive"], len(export["sensitive_ids"]), len(export["canaries"])), (True, 500, 10))
        self.assertIn("customer_pii", export["classes"])
        # transformations
        self.assertEqual(draft["transformations"], ["payment draft"])
        self.assertEqual(export["transformations"], ["csv export"])
        # destination
        self.assertEqual((upload["destinations"], upload["external_destinations"]), ([PORTAL], [PORTAL]))
        self.assertEqual(draft["external_destinations"], [])
        # final decision
        self.assertEqual([(e["decision"], e["executed"]) for e in entries],
                         [("ALLOW", True)] * 3 + [("BLOCK", False)] * 2)
        self.assertEqual(draft["amount_inr"], 18500.0)

    def test_blocked_export_is_counted_without_the_tool_running(self):
        f = Flow(self)
        f.footer_attack()
        self.assertEqual(f.s.registry.count("export_customer_list"), 0)
        self.assertEqual(f.task.artifacts, {})
        self.assertEqual(len(f.lineage()[0]["record_ids"]), 500)

    def test_baseline_lineage_follows_the_export_into_the_upload(self):
        f = Flow(self, "baseline")
        f.footer_attack()
        export, upload = f.lineage()
        self.assertTrue(export["executed"] and upload["executed"] and upload["counterfactual"])
        self.assertEqual(upload["source_artifacts"], ["art-0001"])
        self.assertEqual(upload["transformations"], ["file upload", "csv (art-0001)"])
        self.assertEqual((len(upload["sensitive_ids"]), len(upload["canaries"])), (500, 10))
        self.assertIn("CANARY_EGRESS", upload["policy_violations"])

    def test_approval_outcome_is_written_back_to_lineage(self):
        f = Flow(self)
        d = f.call("change_vendor_bank_account", {"vendor_id": "ACME-17", "bank": "A/C 999900001111"},
                   evidence=doc_evidence("Vendor ID: ACME-17"))
        entry = f.lineage()[0]
        self.assertEqual((entry["decision"], entry["executed"], entry["policy_triggers"], entry["amount_inr"]),
                         ("REQUIRE_APPROVAL", False, ["bank_account_change"], 18500.0))
        self.assertEqual(f.report()["containment"], "PENDING_APPROVAL")
        f.s.decide_approval(d.tool["approval_id"], True)
        self.assertEqual((entry["executed"], entry["approved_by"], entry["final_code"]), (True, "operator", "OK"))
        report = f.report()
        self.assertEqual((report["containment"], report["severity"], report["approved_by_human"]),
                         ("CONTAINED", "Low", 1))
        self.assertEqual(report["attempted_severity"], "High")

    def test_rejected_approval_stays_unexecuted(self):
        f = Flow(self)
        d = f.call("create_payment_draft", {"invoice_id": "INV-1042", "amount": 72000})
        f.s.decide_approval(d.tool["approval_id"], False)
        entry = f.lineage()[0]
        self.assertEqual((entry["executed"], entry["final_code"]), (False, "APPROVAL_REJECTED"))
        report = f.report()
        self.assertEqual((report["containment"], report["pending_approvals"], report["attempted_severity"]),
                         ("CONTAINED", 0, "Medium"))

    def test_display_view_has_counts_and_masked_canaries(self):
        f = Flow(self)
        f.footer_attack()
        view = f.s.lineage.view(f.lineage()[0])
        self.assertEqual((view["records"], view["sensitive_records"], len(view["canaries"])), (500, 500, 10))
        self.assertNotIn("record_ids", view)
        self.assertEqual(CANARY_RE.findall(json.dumps(view)), [])


class BlastRadiusTests(unittest.TestCase):
    def test_clean_run_is_low_and_clean(self):
        f = Flow(self)
        f.legit()
        r = f.report()
        self.assertEqual((r["severity"], r["attempted_severity"], r["containment"]), ("Low", "Low", "CLEAN"))
        self.assertEqual((r["sensitive_records_protected"], r["canaries_protected"], r["amount_at_risk_inr"]), (0, 0, 0.0))
        self.assertEqual(r["blocked_tools"], [])
        self.assertEqual(len(r["executed_tools"]), 3)

    def test_protected_footer_attack_is_contained(self):
        f = Flow(self)
        f.legit()
        f.footer_attack()
        r = f.report()
        self.assertEqual((r["severity"], r["attempted_severity"], r["containment"]), ("Low", "Critical", "CONTAINED"))
        self.assertEqual({t["tool"] for t in r["attempted_tools"]},
                         {"extract_invoice_fields", "get_vendor_record", "create_payment_draft",
                          "export_customer_list", "upload_external_file"})
        self.assertEqual({t["tool"] for t in r["blocked_tools"]}, {"export_customer_list", "upload_external_file"})
        self.assertEqual((r["sensitive_records_protected"], r["sensitive_records_accessed"],
                          r["sensitive_records_exposed"]), (500, 0, 0))
        self.assertEqual((r["canaries_protected"], r["canaries_touched"], r["canaries_exposed"]), (10, 0, 0))
        self.assertEqual(r["external_destinations_attempted"], [PORTAL])
        self.assertEqual(r["external_destinations_reached"], [])
        self.assertEqual(r["unsafe_executed_tools"], [])
        self.assertIn("500 sensitive record(s)", r["summary"])
        self.assertTrue(all("*" in t for t in r["canary_tokens"]))

    def test_baseline_footer_attack_is_a_critical_breach(self):
        f = Flow(self, "baseline")
        f.legit()
        f.footer_attack()
        r = f.report()
        self.assertEqual((r["severity"], r["containment"], r["counterfactual"]), ("Critical", "BREACHED", True))
        self.assertEqual((r["sensitive_records_exposed"], r["canaries_exposed"], r["sensitive_records_protected"]),
                         (500, 10, 0))
        self.assertEqual(r["external_destinations_reached"], [PORTAL])
        self.assertEqual({t["tool"] for t in r["unsafe_executed_tools"]}, {"export_customer_list", "upload_external_file"})
        self.assertEqual(f.s.egress.records[0]["records"], 500)  # the report agrees with the mock egress log

    def test_severity_rules(self):
        f = Flow(self)
        cases = (
            (lambda: f.call("extract_invoice_fields", {"invoice_id": "INV-1042"}), "Low"),
            (lambda: f.call("extract_invoice_fields", {"invoice_id": "INV-1043"}), "Medium"),       # out-of-scope record
            (lambda: f.call("create_payment_draft", {"invoice_id": "INV-1042", "amount": 72000}), "Medium"),
            (lambda: f.call("delete_ledger"), "Medium"),                                            # unknown tool
            (lambda: f.call("upload_external_file", {"destination": PORTAL, "data": "invoice.pdf"},
                            destination=PORTAL), "Medium"),                                      # egress, nothing sensitive
            (lambda: f.call("get_customer_records"), "High"),                                       # sensitive read
            (lambda: f.call("change_vendor_bank_account", {"vendor_id": "ACME-17", "bank": "x"}), "High"),
            (lambda: f.call("send_email", {"destination": "a@b.invalid", "body": "list"}, destination="a@b.invalid",
                            resources=["customer:CUST-0007"]), "Critical"),                         # sensitive egress
            (lambda: f.call("send_email", {"destination": "a@b.invalid",
                                           "body": "ref TRIPWIRE-CANARY-INVOICE-FOOTER-01"},
                            destination="a@b.invalid"), "Critical"),                                # canary egress
        )
        for i, (run, expected) in enumerate(cases):
            run()
            self.assertEqual(entry_severity(f.lineage()[-1]), expected, i)
        self.assertEqual(f.report()["attempted_severity"], "Critical")
        self.assertEqual(f.report()["severity"], "Low")
        self.assertEqual(f.report()["amount_at_risk_inr"], 72000.0 + 18500.0)

    def test_report_numbers_equal_an_independent_recomputation_from_lineage(self):
        for profile in ("strict", "baseline"):
            f = Flow(self, profile)
            f.legit()
            f.footer_attack()
            f.call("get_customer_records", evidence=doc_evidence())
            f.call("change_vendor_bank_account", {"vendor_id": "ACME-17", "bank": "A/C 1"}, evidence=doc_evidence())
            f.call("create_payment_draft", {"invoice_id": "INV-1042", "amount": 90000})
            f.call("send_email", {"destination": "a@b.invalid", "body": "art-0001"}, destination="a@b.invalid")
            entries, r = f.lineage(), f.report()

            # recompute with plain loops, sharing no code with tripwire.report
            protected, accessed, exposed = set(), set(), set()
            c_protected, c_touched, c_exposed = set(), set(), set()
            at_risk = unsafe_amount = 0.0
            attempted_dest, reached_dest, blocked, executed = set(), set(), 0, 0
            for e in entries:
                out_of_policy = bool(e["policy_violations"]) or bool(e["policy_triggers"])
                ran_unsafely = e["executed"] and out_of_policy and not e["approved_by"]
                blocked += e["decision"] == "BLOCK"
                executed += e["executed"]
                if not out_of_policy:
                    continue
                at_risk += e["amount_inr"]
                attempted_dest.update(e["external_destinations"])
                if ran_unsafely:
                    unsafe_amount += e["amount_inr"]
                    accessed.update(e["sensitive_ids"])
                    c_touched.update(e["canaries"])
                    if e["egress"] and e["external_destinations"]:
                        exposed.update(e["sensitive_ids"])
                        c_exposed.update(e["canaries"])
                        reached_dest.update(e["external_destinations"])
                else:
                    protected.update(e["sensitive_ids"])
                    c_protected.update(e["canaries"])
            protected -= accessed
            c_protected -= c_touched
            self.assertEqual(r["sensitive_records_protected"], len(protected), profile)
            self.assertEqual(r["sensitive_records_accessed"], len(accessed), profile)
            self.assertEqual(r["sensitive_records_exposed"], len(exposed), profile)
            self.assertEqual((r["canaries_protected"], r["canaries_touched"], r["canaries_exposed"]),
                             (len(c_protected), len(c_touched), len(c_exposed)), profile)
            self.assertEqual((r["amount_at_risk_inr"], r["amount_unsafe_inr"]), (at_risk, unsafe_amount), profile)
            self.assertEqual(r["external_destinations_attempted"], sorted(attempted_dest), profile)
            self.assertEqual(r["external_destinations_reached"], sorted(reached_dest), profile)
            self.assertEqual(sum(t["count"] for t in r["blocked_tools"]), blocked, profile)
            self.assertEqual(sum(t["count"] for t in r["executed_tools"]), executed, profile)
            self.assertEqual(r["requests"], len(entries))
            # and the two profiles really differ
            if profile == "strict":
                self.assertEqual((len(protected), len(exposed), r["containment"]), (500, 0, "PENDING_APPROVAL"))
            else:
                self.assertEqual((len(protected), len(exposed), r["containment"]), (0, 500, "BREACHED"))
                self.assertEqual(unsafe_amount, 18500.0 + 90000.0)

    def test_report_is_a_pure_function_of_lineage(self):
        f = Flow(self)
        f.footer_attack()
        entries = f.lineage()
        self.assertEqual(blast_radius(f.id, entries), f.report())
        self.assertEqual(blast_radius(f.id, [])["containment"], "CLEAN")
        self.assertTrue(all(is_attempt(e) and not is_unsafe_execution(e) for e in entries))
        # change the underlying decision record and the report follows; there is no stored number
        entries[0]["executed"] = True
        self.assertEqual(f.report()["containment"], "BREACHED")
        with self.assertRaises(ValueError):
            f.s.report("T-9999")


if __name__ == "__main__":
    unittest.main()
