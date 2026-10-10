"""Task policy manifest (PRD 7.3): the signed, immutable capability for one task.

A manifest is created once, at task start, from two trusted inputs only:

* the *system policy* template for the kind of task (which tools, limits and destinations a
  task of that kind may ever get), and
* the *user-assigned task* (the goal text and the records the user pointed the agent at).

It is then HMAC-signed with a key that only the gateway holds. The gateway re-verifies the
signature on every tool request, so editing the manifest in memory, swapping in another
manifest or presenting a different hash all end in ``MANIFEST_TAMPERED``. There is no API to
amend a manifest: document text, tool output and agent messages have no path to add a tool,
a data scope or a destination.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field, fields
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from .context import SYSTEM_POLICY, USER_TASK, Labelled, Provenance
from .intent import effects_for_goal
from .protocol import MAC_ALGORITHM, ProtocolError, canonical_bytes, compute_mac

DEFAULT_PAYMENT_LIMIT_INR = 50000
DEFAULT_TTL_S = 15 * 60

# Approval triggers (PRD 7.8)
PAYMENT_OVER_LIMIT = "payment_over_limit"
BANK_ACCOUNT_CHANGE = "bank_account_change"
NEW_VENDOR = "new_vendor"
EXTERNAL_DESTINATION = "external_destination"


class ManifestError(ProtocolError):
    """Manifest could not be issued or failed verification. ``code`` is stable."""


@dataclass(frozen=True)
class PolicyTemplate:
    """System policy for one kind of task. This is the ceiling for any manifest of that kind."""
    id: str
    goal_effects: Tuple[str, ...]
    allowed_tools: Tuple[str, ...]
    forbidden_tools: Tuple[str, ...]
    allowed_destinations: Tuple[str, ...]
    approval_required: Tuple[str, ...]
    data_prefixes: Tuple[str, ...]
    payment_limit_inr: int = DEFAULT_PAYMENT_LIMIT_INR
    provenance: Provenance = field(default=Provenance(SYSTEM_POLICY, "policy"), compare=False)


INVOICE_POLICY = PolicyTemplate(
    id="invoice-intake-v1",
    goal_effects=("read_invoice", "read_vendor", "draft_payment", "internal_notify"),
    allowed_tools=("extract_invoice_fields", "get_vendor_record", "create_payment_draft"),
    forbidden_tools=("export_customer_list", "get_customer_records", "send_email", "upload_external_file"),
    allowed_destinations=("internal-accounting",),
    approval_required=(PAYMENT_OVER_LIMIT, BANK_ACCOUNT_CHANGE, NEW_VENDOR, EXTERNAL_DESTINATION),
    data_prefixes=("invoice:", "vendor:"),
)

CHAT_POLICY = PolicyTemplate(
    id="chat-assistant-v1",
    goal_effects=("external_egress", "internal_notify"),
    allowed_tools=("send_email", "get_vendor_record"),
    forbidden_tools=("export_customer_list", "get_customer_records", "upload_external_file"),
    allowed_destinations=("internal-accounting", "employee-email", "kumarayush.professional@gmail.com"),
    approval_required=(),
    data_prefixes=("sys-doc-",),
)


@dataclass(frozen=True)
class Manifest:
    task_id: str
    goal: str
    goal_effects: Tuple[str, ...]
    allowed_tools: Tuple[str, ...]
    allowed_data: Tuple[str, ...]
    payment_limit_inr: int
    approval_required: Tuple[str, ...]
    forbidden_tools: Tuple[str, ...]
    allowed_destinations: Tuple[str, ...]
    expires_at: float
    issued_at: float = 0.0
    policy_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            out[f.name] = list(value) if isinstance(value, (tuple, list)) else value
        return out

    def digest(self) -> str:
        return hashlib.sha256(canonical_bytes(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class SignedManifest:
    manifest: Manifest
    hash: str
    key_id: str
    signature: str = field(repr=False)

    def to_dict(self) -> Dict[str, Any]:
        """Safe to show: the signature is a MAC, the key never leaves the authority."""
        return {"manifest": self.manifest.to_dict(), "hash": self.hash, "key_id": self.key_id,
                "alg": MAC_ALGORITHM, "signature": self.signature}


class ManifestAuthority:
    """Gateway-side issuer and verifier. Holds the manifest signing key."""

    def __init__(self, clock: Callable[[], float] = time.time, key: Optional[bytes] = None):
        self._key = key or secrets.token_bytes(32)
        self._clock = clock
        self.key_id = "gateway-manifest#" + secrets.token_hex(4)

    def _sign(self, manifest: Manifest) -> str:
        return compute_mac(self._key, {"key_id": self.key_id, "manifest": manifest.to_dict()})

    @staticmethod
    def _require_authority(item: Labelled, what: str) -> None:
        if not isinstance(item, Labelled):
            raise ManifestError("UNTRUSTED_AUTHORITY", f"{what} must carry provenance")
        if not item.provenance.can_authorize:
            raise ManifestError("UNTRUSTED_AUTHORITY",
                                f"{what} comes from '{item.provenance.context}' ({item.provenance.trust}); "
                                f"only system_policy and user_task can shape a manifest")

    def issue(self, *, task_id: str, goal: Labelled, template: PolicyTemplate,
              allowed_data: Sequence[Labelled], ttl_s: float = DEFAULT_TTL_S) -> SignedManifest:
        """Create and sign the manifest for one task.

        ``goal`` must come from the user task. Every entry of ``allowed_data`` must come from the
        user task or the system policy and must fit the template's data prefixes. Tools,
        destinations, limits and approval rules come from the template only.
        """
        if not isinstance(template, PolicyTemplate) or template.provenance.context != SYSTEM_POLICY:
            raise ManifestError("UNTRUSTED_AUTHORITY", "policy template must come from system_policy")
        self._require_authority(goal, "task goal")
        if goal.provenance.context != USER_TASK:
            raise ManifestError("UNTRUSTED_AUTHORITY", "task goal must come from the user task")
        if not isinstance(task_id, str) or not 0 < len(task_id) <= 64:
            raise ManifestError("MANIFEST_INVALID", "task id must be 1-64 characters")
        if not goal.text.strip() or len(goal.text) > 200:
            raise ManifestError("MANIFEST_INVALID", "task goal must be 1-200 characters")
        if not 0 < float(ttl_s) <= 24 * 3600:
            raise ManifestError("MANIFEST_INVALID", "ttl must be between 1 second and 24 hours")
        scope = []
        for item in allowed_data:
            self._require_authority(item, f"data scope '{getattr(item, 'text', item)}'")
            if not any(item.text.startswith(p) and len(item.text) > len(p) for p in template.data_prefixes):
                raise ManifestError("MANIFEST_INVALID",
                                    f"data scope '{item.text[:40]}' is outside policy '{template.id}'")
            if "*" in item.text:
                raise ManifestError("MANIFEST_INVALID", "wildcard data scopes are not allowed")
            scope.append(item.text)
        if not scope:
            raise ManifestError("MANIFEST_INVALID", "a task needs at least one record in scope")
        now = self._clock()
        manifest = Manifest(
            task_id=task_id, goal=goal.text.strip(), goal_effects=self._effects(goal.text, template),
            allowed_tools=tuple(template.allowed_tools), allowed_data=tuple(dict.fromkeys(scope)),
            payment_limit_inr=int(template.payment_limit_inr), approval_required=tuple(template.approval_required),
            forbidden_tools=tuple(template.forbidden_tools), allowed_destinations=tuple(template.allowed_destinations),
            expires_at=now + float(ttl_s), issued_at=now, policy_id=template.id)
        return SignedManifest(manifest, manifest.digest(), self.key_id, self._sign(manifest))

    @staticmethod
    def _effects(goal_text: str, template: PolicyTemplate) -> Tuple[str, ...]:
        """Effects this goal needs, never more than the policy template allows."""
        effects = effects_for_goal(goal_text, ceiling=template.goal_effects)
        if not effects:
            raise ManifestError("MANIFEST_INVALID", f"goal does not describe a task that policy "
                                                    f"'{template.id}' covers")
        return effects

    def verify(self, signed: Any, presented_hash: Optional[str] = None) -> Manifest:
        """Return the manifest if it is exactly what this authority signed, else raise."""
        if not isinstance(signed, SignedManifest) or not isinstance(signed.manifest, Manifest):
            raise ManifestError("MANIFEST_TAMPERED", "not a signed manifest")
        try:
            digest, expected = signed.manifest.digest(), self._sign(signed.manifest)
        except (TypeError, ValueError) as exc:
            raise ManifestError("MANIFEST_TAMPERED", "manifest is not canonical") from exc
        if signed.key_id != self.key_id or not hmac.compare_digest(expected, str(signed.signature)):
            raise ManifestError("MANIFEST_TAMPERED", "manifest signature does not verify (modified after issue)")
        if not hmac.compare_digest(digest, str(signed.hash)):
            raise ManifestError("MANIFEST_TAMPERED", "manifest hash does not match its content")
        if presented_hash is not None and not hmac.compare_digest(digest, str(presented_hash)):
            raise ManifestError("MANIFEST_TAMPERED", "request presents a different manifest hash")
        return signed.manifest

    def expired(self, manifest: Manifest) -> bool:
        return self._clock() >= manifest.expires_at
