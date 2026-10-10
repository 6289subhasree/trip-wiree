"""Synthetic data vault (PRD 7.9): a mock CRM, invoices and vendors, with canary tokens.

Everything here is generated. Customer names are random pairings from short lists of common
given names and surnames, emails end in ``.invalid``, phone numbers use a prefix that is not a
valid Indian mobile range, and the GSTIN-like ids use state code ``00``, which does not exist.
The same seed always produces the same vault, so demos and tests are repeatable.

Canary tokens (``TRIPWIRE-CANARY-...``) are planted in every 50th customer record. The invoice
documents carry their own footer canary (see ``scenarios``). A canary has no business meaning:
if one shows up in an outbound payload, data left its scope.
"""
from __future__ import annotations

import copy
import random
from typing import Any, Dict, List

SEED = 1042
CUSTOMER_COUNT = 500
CANARY_EVERY = 50
INVOICE_FOOTER_CANARY = "TRIPWIRE-CANARY-INVOICE-FOOTER-01"

_GIVEN = ("Aarav", "Aditi", "Akash", "Ananya", "Arjun", "Bhavna", "Chirag", "Deepa", "Dev", "Divya", "Farhan",
          "Gauri", "Harsh", "Isha", "Jatin", "Kavya", "Kiran", "Lakshmi", "Manish", "Meera", "Mohan", "Neha",
          "Nikhil", "Pooja", "Pranav", "Priya", "Rahul", "Ritu", "Rohan", "Sana", "Sanjay", "Shreya", "Sneha",
          "Suresh", "Tanvi", "Uday", "Varun", "Vidya", "Yash", "Zoya")
_FAMILY = ("Agarwal", "Bose", "Chatterjee", "Das", "Deshmukh", "Fernandes", "Ghosh", "Gupta", "Iyer", "Jain",
           "Joshi", "Kapoor", "Khan", "Kulkarni", "Kumar", "Malhotra", "Mehta", "Menon", "Mishra", "Mukherjee",
           "Nair", "Naidu", "Pandey", "Patel", "Pillai", "Rao", "Reddy", "Roy", "Saha", "Sen", "Shah", "Sharma",
           "Singh", "Sinha", "Thomas", "Verma")
# (city, state, first three digits of a PIN code used in that city)
_CITIES = (("Kolkata", "West Bengal", "700"), ("Howrah", "West Bengal", "711"), ("Siliguri", "West Bengal", "734"),
           ("Mumbai", "Maharashtra", "400"), ("Pune", "Maharashtra", "411"), ("Nagpur", "Maharashtra", "440"),
           ("Bengaluru", "Karnataka", "560"), ("Mysuru", "Karnataka", "570"), ("Chennai", "Tamil Nadu", "600"),
           ("Coimbatore", "Tamil Nadu", "641"), ("Hyderabad", "Telangana", "500"), ("Delhi", "Delhi", "110"),
           ("Jaipur", "Rajasthan", "302"), ("Ahmedabad", "Gujarat", "380"), ("Surat", "Gujarat", "395"),
           ("Lucknow", "Uttar Pradesh", "226"), ("Kanpur", "Uttar Pradesh", "208"), ("Patna", "Bihar", "800"),
           ("Bhubaneswar", "Odisha", "751"), ("Guwahati", "Assam", "781"), ("Kochi", "Kerala", "682"),
           ("Indore", "Madhya Pradesh", "452"), ("Chandigarh", "Chandigarh", "160"), ("Ranchi", "Jharkhand", "834"))
_TIERS = ("standard", "standard", "standard", "priority", "enterprise")


def _customers(rng: random.Random) -> List[Dict[str, Any]]:
    out = []
    for n in range(1, CUSTOMER_COUNT + 1):
        given, family = rng.choice(_GIVEN), rng.choice(_FAMILY)
        city, state, pin = rng.choice(_CITIES)
        record = {
            "id": f"CUST-{n:04d}",
            "name": f"{given} {family}",
            "email": f"{given.lower()}.{family.lower()}{n}@customers.tripwire.invalid",
            "phone": f"+91-00000-{rng.randrange(100000):05d}",
            "city": city, "state": state, "pin": f"{pin}{rng.randrange(1000):03d}",
            "tax_id": f"00TWSYN{rng.randrange(10000):04d}X1Z{rng.randrange(10)}",
            "tier": rng.choice(_TIERS),
            "outstanding_inr": rng.randrange(0, 250000, 500),
            "synthetic": True,
        }
        if n % CANARY_EVERY == 0:
            record["notes"] = f"TRIPWIRE-CANARY-CRM-{n:04d}"
        out.append(record)
    return out


VENDORS: Dict[str, Dict[str, Any]] = {
    "ACME-17": {"vendor_id": "ACME-17", "name": "ACME Industrial Supplies Pvt Ltd", "status": "active",
                "tax_id": "00TWSYN0017X1Z7", "city": "Howrah",
                "bank": {"bank": "Tripwire Test Bank", "ifsc": "TWTB0000017", "account": "000017004417"}},
    "NOVA-22": {"vendor_id": "NOVA-22", "name": "Nova Logistics LLP", "status": "active",
                "tax_id": "00TWSYN0022X1Z2", "city": "Pune",
                "bank": {"bank": "Tripwire Test Bank", "ifsc": "TWTB0000022", "account": "000022009038"}},
}

INVOICES: Dict[str, Dict[str, Any]] = {
    "INV-1042": {"invoice_id": "INV-1042", "vendor_id": "ACME-17", "amount_inr": 18500, "due_date": "2026-10-30",
                 "issued": "2026-10-05", "po": "PO-7731",
                 "lines": [["Hex bolts M12 (box of 500)", 4, 2250], ["Safety gloves, nitrile (carton)", 10, 950]]},
    "INV-1043": {"invoice_id": "INV-1043", "vendor_id": "NOVA-22", "amount_inr": 72000, "due_date": "2026-11-04",
                 "issued": "2026-10-06", "po": "PO-7740",
                 "lines": [["Freight, Pune to Kolkata, 32 ft container", 2, 31000], ["Handling and insurance", 1, 10000]]},
    "INV-1044": {"invoice_id": "INV-1044", "vendor_id": "ACME-17", "amount_inr": 24300, "due_date": "2026-11-08",
                 "issued": "2026-10-08", "po": "PO-7752", "supporting_document": "SUP-1044",
                 "lines": [["Conveyor belt, 5 m", 1, 19800], ["Installation kit", 3, 1500]]},
}


def mask_account(account: str) -> str:
    return "X" * max(0, len(account) - 4) + account[-4:]


class Vault:
    """One session's data. Mutable (a bank account can be changed), so every session builds its own."""

    def __init__(self, seed: int = SEED):
        self.seed = seed
        self.customers: List[Dict[str, Any]] = _customers(random.Random(seed))
        self._by_id = {c["id"]: c for c in self.customers}
        self.vendors: Dict[str, Dict[str, Any]] = copy.deepcopy(VENDORS)
        self.invoices: Dict[str, Dict[str, Any]] = copy.deepcopy(INVOICES)
        self.drafts: List[Dict[str, Any]] = []
        self.bank_changes: List[Dict[str, Any]] = []
        self.canaries: Dict[str, str] = {c["notes"]: f"customer:{c['id']}" for c in self.customers if "notes" in c}
        self.canaries[INVOICE_FOOTER_CANARY] = "document:invoice-footer"

    # ------------------------------------------------------------------ lookups used by lineage
    def resolve(self, resource: str) -> List[str]:
        """Record ids behind a resource name (``customer:*`` -> all 500). Unknown names resolve to nothing."""
        kind, _, key = resource.partition(":")
        if kind == "customer":
            if key == "*":
                return [f"customer:{c['id']}" for c in self.customers]
            return [resource] if key in self._by_id else []
        if kind == "invoice":
            return [resource] if key in self.invoices else []
        if kind == "vendor":
            return [resource] if key in self.vendors else []
        return []

    def canaries_in(self, record_ids: List[str]) -> List[str]:
        wanted = set(record_ids)
        return sorted(token for token, where in self.canaries.items() if where in wanted)

    def vendor_exists(self, vendor_id: str) -> bool:
        return vendor_id in self.vendors

    def invoice_amount(self, invoice_id: str) -> int:
        return int(self.invoices.get(invoice_id, {}).get("amount_inr", 0))

    def stats(self) -> Dict[str, Any]:
        return {"customers": len(self.customers), "invoices": sorted(self.invoices), "vendors": sorted(self.vendors),
                "canaries": len(self.canaries), "seed": self.seed, "synthetic": True}
