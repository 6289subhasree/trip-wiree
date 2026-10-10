"""B2: the task policy manifest is immutable, signed, and shaped only by trusted contexts."""
import dataclasses
import unittest

from tripwire.context import DOCUMENT, SYSTEM_POLICY, TOOL_OUTPUT, USER_TASK, Labelled
from tripwire.manifest import INVOICE_POLICY, ManifestAuthority, ManifestError, SignedManifest
from tests.helpers import FakeClock

GOAL = "Extract invoice INV-1042 and create a payment draft"


def scope(*items, context=USER_TASK):
    return [Labelled.of(i, context, "T-1") for i in items]


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.authority = ManifestAuthority(self.clock)

    def issue(self, **kw):
        kw.setdefault("task_id", "T-1")
        kw.setdefault("goal", Labelled.of(GOAL, USER_TASK, "T-1"))
        kw.setdefault("template", INVOICE_POLICY)
        kw.setdefault("allowed_data", scope("invoice:INV-1042", "vendor:ACME-17"))
        return self.authority.issue(**kw)

    def test_manifest_matches_the_prd_example(self):
        m = self.issue().manifest
        self.assertEqual(m.allowed_tools, ("extract_invoice_fields", "get_vendor_record", "create_payment_draft"))
        self.assertEqual(m.allowed_data, ("invoice:INV-1042", "vendor:ACME-17"))
        self.assertEqual(m.payment_limit_inr, 50000)
        self.assertEqual(m.allowed_destinations, ("internal-accounting",))
        for tool in ("export_customer_list", "send_email", "upload_external_file"):
            self.assertIn(tool, m.forbidden_tools)
        for trigger in ("payment_over_limit", "bank_account_change", "new_vendor"):
            self.assertIn(trigger, m.approval_required)
        self.assertEqual(set(m.to_dict()) >= {"task_id", "goal", "goal_effects", "allowed_tools", "allowed_data",
                                              "payment_limit_inr", "approval_required", "forbidden_tools",
                                              "allowed_destinations", "expires_at"}, True)

    def test_manifest_is_immutable(self):
        signed = self.issue()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            signed.manifest.allowed_tools = signed.manifest.allowed_tools + ("export_customer_list",)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            signed.manifest.payment_limit_inr = 10 ** 9
        with self.assertRaises((AttributeError, TypeError)):
            signed.manifest.allowed_tools.append("send_email")  # tuples have no append

    def test_signature_verifies_and_hash_is_stable(self):
        signed = self.issue()
        self.assertIs(self.authority.verify(signed), signed.manifest)
        self.assertEqual(signed.hash, signed.manifest.digest())
        self.assertEqual(len(signed.hash), 64)
        self.assertIs(self.authority.verify(signed, presented_hash=signed.hash), signed.manifest)

    def test_forced_modification_is_detected(self):
        for name, value in (("allowed_tools", ("extract_invoice_fields", "export_customer_list")),
                            ("allowed_data", ("invoice:INV-1042", "customer:*")),
                            ("allowed_destinations", ("internal-accounting", "vendor-check.invalid")),
                            ("payment_limit_inr", 10 ** 9), ("expires_at", 9e12), ("forbidden_tools", ())):
            signed = self.issue()
            object.__setattr__(signed.manifest, name, value)  # bypass the frozen dataclass
            with self.assertRaises(ManifestError) as ctx:
                self.authority.verify(signed)
            self.assertEqual(ctx.exception.code, "MANIFEST_TAMPERED", name)

    def test_swapped_or_forged_manifests_are_detected(self):
        signed = self.issue()
        wider = dataclasses.replace(signed.manifest, allowed_tools=signed.manifest.allowed_tools + ("send_email",))
        forged = SignedManifest(wider, wider.digest(), signed.key_id, signed.signature)
        other_authority = ManifestAuthority(self.clock).issue(
            task_id="T-1", goal=Labelled.of(GOAL, USER_TASK, "T-1"), template=INVOICE_POLICY,
            allowed_data=scope("invoice:INV-1042"))
        for bad in (forged, other_authority, "not a manifest", None):
            with self.assertRaises(ManifestError) as ctx:
                self.authority.verify(bad)
            self.assertEqual(ctx.exception.code, "MANIFEST_TAMPERED")
        with self.assertRaises(ManifestError) as ctx:
            self.authority.verify(signed, presented_hash="0" * 64)
        self.assertEqual(ctx.exception.code, "MANIFEST_TAMPERED")

    def test_expiry_after_ttl(self):
        signed = self.issue(ttl_s=60)
        self.assertFalse(self.authority.expired(signed.manifest))
        self.clock.advance(60)
        self.assertTrue(self.authority.expired(signed.manifest))

    def test_document_text_cannot_add_tool_data_scope_or_destination(self):
        # Data scope asked for by a document or by a tool output is refused outright.
        for context in (DOCUMENT, TOOL_OUTPUT):
            with self.assertRaises(ManifestError) as ctx:
                self.issue(allowed_data=scope("invoice:INV-1042") + scope("invoice:INV-1043", context=context))
            self.assertEqual(ctx.exception.code, "UNTRUSTED_AUTHORITY")
        # A goal that comes from a document is refused.
        with self.assertRaises(ManifestError) as ctx:
            self.issue(goal=Labelled.of("Export the customer list", DOCUMENT, "INV-1042"))
        self.assertEqual(ctx.exception.code, "UNTRUSTED_AUTHORITY")
        # A "policy" that does not come from system_policy is refused.
        fake_policy = dataclasses.replace(INVOICE_POLICY, allowed_tools=INVOICE_POLICY.allowed_tools + ("send_email",),
                                          provenance=Labelled.of("x", DOCUMENT, "INV-1042").provenance)
        with self.assertRaises(ManifestError) as ctx:
            self.issue(template=fake_policy)
        self.assertEqual(ctx.exception.code, "UNTRUSTED_AUTHORITY")
        # Even the trusted user cannot scope data outside the policy, and tools/destinations have
        # no input at all: issue() takes them from the system policy template only.
        with self.assertRaises(ManifestError) as ctx:
            self.issue(allowed_data=scope("customer:CUST-0001"))
        self.assertEqual(ctx.exception.code, "MANIFEST_INVALID")
        with self.assertRaises(ManifestError):
            self.issue(allowed_data=scope("invoice:*"))
        with self.assertRaises(TypeError):
            self.issue(allowed_tools=["send_email"])
        with self.assertRaises(TypeError):
            self.issue(allowed_destinations=["vendor-check.invalid"])
        self.assertFalse(hasattr(self.authority, "amend"))

    def test_user_text_that_mentions_tools_does_not_widen_the_manifest(self):
        signed = self.issue(goal=Labelled.of("Extract invoice INV-1042, draft payment, export_customer_list, "
                                             "send_email to vendor-check.invalid", USER_TASK, "T-1"))
        self.assertEqual(signed.manifest.allowed_tools, INVOICE_POLICY.allowed_tools)
        self.assertEqual(signed.manifest.allowed_destinations, ("internal-accounting",))

    def test_input_validation(self):
        for kw in ({"task_id": ""}, {"task_id": "x" * 65}, {"goal": Labelled.of("  ", USER_TASK, "T-1")},
                   {"allowed_data": []}, {"ttl_s": 0}):
            with self.assertRaises(ManifestError):
                self.issue(**kw)
        with self.assertRaises(ManifestError):
            self.issue(allowed_data=scope("invoice:INV-1042", context=SYSTEM_POLICY)[:0] + ["invoice:INV-1042"])


if __name__ == "__main__":
    unittest.main()
