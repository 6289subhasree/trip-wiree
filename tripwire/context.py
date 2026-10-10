"""Trust-labelled contexts and provenance (PRD 7.2).

Every piece of text the system handles, and every action an agent proposes, carries a
``Provenance`` record saying which context it came from. Only two contexts can authorise a
tool call:

    system_policy   trusted               can authorise
    user_task       trusted within policy can authorise (inside the system policy)
    document        untrusted evidence    can NOT authorise
    tool_output     data only             can NOT authorise

The instruction detector at the bottom of this module tags imperative sentences in untrusted
content as ``untrusted_instruction``. It exists for display and logging ONLY. No enforcement
decision reads its output: the gateway decides from the manifest, the data scope, the effect
class of the requested tool and the verified provenance of the evidence. A sentence the
detector misses is blocked exactly like one it catches (see tests/test_capability.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

SYSTEM_POLICY = "system_policy"
USER_TASK = "user_task"
DOCUMENT = "document"
TOOL_OUTPUT = "tool_output"

TRUSTED = "trusted"
TRUSTED_WITHIN_POLICY = "trusted_within_policy"
UNTRUSTED_EVIDENCE = "untrusted_evidence"
DATA_ONLY = "data_only"


@dataclass(frozen=True)
class ContextSpec:
    name: str
    label: str
    trust: str
    can_authorize: bool


CONTEXTS: Dict[str, ContextSpec] = {
    SYSTEM_POLICY: ContextSpec(SYSTEM_POLICY, "System policy", TRUSTED, True),
    USER_TASK: ContextSpec(USER_TASK, "User-assigned task", TRUSTED_WITHIN_POLICY, True),
    DOCUMENT: ContextSpec(DOCUMENT, "Document / webpage content", UNTRUSTED_EVIDENCE, False),
    TOOL_OUTPUT: ContextSpec(TOOL_OUTPUT, "Tool output / retrieved record", DATA_ONLY, False),
}

UNTRUSTED_INSTRUCTION = "untrusted_instruction"


def can_authorize(context: str) -> bool:
    spec = CONTEXTS.get(context)
    return bool(spec and spec.can_authorize)


@dataclass(frozen=True)
class Provenance:
    """Where a piece of text or a proposed action came from.

    ``trust`` is derived from ``context`` and cannot be chosen independently, so nobody can
    build a "trusted document" record.
    """
    context: str
    source_id: str
    span: Optional[Tuple[int, int]] = None
    trust: str = ""

    def __post_init__(self) -> None:
        spec = CONTEXTS.get(self.context)
        if spec is None:
            raise ValueError(f"unknown context {self.context!r}")
        if not isinstance(self.source_id, str) or not self.source_id:
            raise ValueError("provenance needs a source id")
        if self.trust not in ("", spec.trust):
            raise ValueError(f"context '{self.context}' always has trust '{spec.trust}'")
        object.__setattr__(self, "trust", spec.trust)
        if self.span is not None:
            start, end = self.span
            if not (isinstance(start, int) and isinstance(end, int) and 0 <= start <= end):
                raise ValueError("span must be (start, end) character offsets")
            object.__setattr__(self, "span", (start, end))

    @property
    def can_authorize(self) -> bool:
        return CONTEXTS[self.context].can_authorize

    def to_dict(self) -> Dict[str, Any]:
        return {"context": self.context, "id": self.source_id, "trust": self.trust,
                "span": list(self.span) if self.span else None}

    @classmethod
    def from_wire(cls, data: Any) -> "Provenance":
        """Parse the ``source`` object carried in a tool request. Raises ``ValueError``."""
        if not isinstance(data, dict):
            raise ValueError("source must be an object")
        span = data.get("span")
        if span is not None:
            if not (isinstance(span, (list, tuple)) and len(span) == 2
                    and all(isinstance(n, int) and not isinstance(n, bool) for n in span)):
                raise ValueError("span must be [start, end]")
            span = (span[0], span[1])
        return cls(str(data.get("context", "")), str(data.get("id", "")), span)


@dataclass(frozen=True)
class Labelled:
    """A piece of text together with its provenance."""
    text: str
    provenance: Provenance

    @classmethod
    def of(cls, text: str, context: str, source_id: str,
           span: Optional[Tuple[int, int]] = None) -> "Labelled":
        return cls(text, Provenance(context, source_id, span))


# ---------------------------------------------------------------------------
# Instruction detector (display and logging only; never used to decide)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class InstructionSpan:
    start: int
    end: int
    text: str
    reasons: Tuple[str, ...]
    tag: str = UNTRUSTED_INSTRUCTION

    def to_dict(self) -> Dict[str, Any]:
        return {"start": self.start, "end": self.end, "text": self.text, "tag": self.tag,
                "reasons": list(self.reasons)}


_IMPERATIVES = frozenset("""
    export upload send email forward transfer change update replace retrieve fetch ignore disregard
    delete create add summarize summarise download post share copy wire attach include append
    override bypass approve grant disable read collect gather extract dump list submit
""".split())
# Words that may come directly before a clause-initial imperative ("please export", "you must send").
_LEADERS = frozenset("please kindly now then also and must should shall immediately first next to".split())
_ADDRESS = re.compile(r"\b(?:ai|agent|assistant|system|model|bot)\b|\byou\s+(?:must|should|shall|are\s+required)\b",
                      re.IGNORECASE)
_OVERRIDE = re.compile(r"\b(?:ignore|disregard|override|bypass|forget)\b[^.!?\n]{0,40}"
                       r"\b(?:instruction|instructions|rule|rules|policy|policies|approval|limit)\b", re.IGNORECASE)
_TARGET = re.compile(r"\b(?:customers?|crm|records?|list|bank|account|portal|csv|credentials?|password|database|"
                     r"files?|vendor|payment|approval|invoices?)\b", re.IGNORECASE)
_LINK = re.compile(r"https?://\S+|\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b|\b[\w-]+(?:\.[\w-]+)*\.(?:invalid|example|com|net|org|io|in)\b",
                   re.IGNORECASE)
_SENTENCE = re.compile(r"[^.!?\n]+(?:[.!?]+(?=\s|$)|\.(?=\w)[^.!?\n]*)*[.!?]*")
_WORD = re.compile(r"[A-Za-z']+")


def _clause_imperative(sentence: str) -> Optional[str]:
    """Return the first imperative verb that starts a clause, if any."""
    for clause in re.split(r"[,;:]|\band\b|\bthen\b", sentence, flags=re.IGNORECASE):
        words = [w.lower() for w in _WORD.findall(clause)]
        while words and words[0] in _LEADERS:
            words.pop(0)
        if words and words[0] in _IMPERATIVES:
            return words[0]
        # "you must export ..." / "the agent should upload ..."
        for i, word in enumerate(words[:-1]):
            if word in ("must", "should", "shall") and words[i + 1] in _IMPERATIVES:
                return words[i + 1]
    return None


def detect_instructions(text: str) -> List[InstructionSpan]:
    """Tag sentences in untrusted content that look like instructions to the agent.

    Heuristic: a clause-initial imperative verb together with a tool/data noun, a link or a
    direct address to the agent; or an explicit "ignore the rules" phrase. It is intentionally
    simple and it WILL miss rephrased instructions. That is acceptable because nothing is
    enforced from this output.
    """
    spans: List[InstructionSpan] = []
    for match in _SENTENCE.finditer(text):
        raw = match.group(0)
        sentence = raw.strip()
        if len(sentence) < 8:
            continue
        reasons: List[str] = []
        verb = _clause_imperative(sentence)
        if verb:
            if _TARGET.search(sentence):
                reasons.append("names a tool or data target")
            if _LINK.search(sentence):
                reasons.append("names a destination (URL, domain or email)")
            if _ADDRESS.search(sentence):
                reasons.append("addresses the agent directly")
            if reasons:
                reasons.insert(0, f"imperative verb '{verb}'")
        if _OVERRIDE.search(sentence):
            reasons.append("asks to override rules or approval")
        if reasons:
            start = match.start() + (len(raw) - len(raw.lstrip()))
            spans.append(InstructionSpan(start, start + len(sentence), sentence, tuple(reasons)))
    return spans
