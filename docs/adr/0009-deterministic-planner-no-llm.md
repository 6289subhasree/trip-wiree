# ADR 0009: Agent 1 plans with a deterministic rule set; there is no LLM

Status: accepted (hackathon build)

## Context

The PRD (7.1, 11) suggests an LLM for field extraction and for generating proposed tool calls. The build has three hard constraints: Python standard library only, fully offline on a venue laptop, and no API keys or paid services. A hosted model breaks all three. A local model breaks the first and adds a large download.

What the demo has to show is not that a model can be fooled. That is well known. It has to show that when the agent *is* fooled, the tool does not run.

## Decision

Agent 1 uses `DeterministicPlanner` (`tripwire/planner.py`) behind a small `Planner` interface:

```python
class Planner:
    name: str
    def plan(self, *, task_id, goal, documents, primary) -> list[dict]: ...
```

The planner is rule-based and deliberately naive. It plans the legitimate invoice steps, and it also follows instructions it finds in the document, citing the document sentence as its only evidence. That stands in for a hijacked model. It is the component being contained, not a defence.

No code path calls a model, opens a socket to one, or reads an API key. A test parses every module's imports and fails on any LLM, HTTP-client or ML library.

## Consequences

- The demo is repeatable: the same document always produces the same proposals, so tests can assert exact decisions.
- The planner's "understanding" is a handful of regular expressions. It follows a narrower range of phrasings than a real model would. A judge's sentence that the planner does not understand produces no proposal, and the UI then shows that the agent did not act on it. That is honest but less dramatic than a model would be.
- The planner and the display-only instruction detector share no code, so one can follow a sentence the other does not tag. A test pins such a case to show that enforcement does not depend on detection.
- Field extraction is pattern matching on a fixed invoice layout, not general document understanding.

## Limitations (stated plainly)

- This build does not measure how well the controls hold against a real LLM's behaviour. The gateway is model-agnostic by design, since it only sees structured proposals, but that claim is argued, not demonstrated, here.
- The intent check is rule-based (effect class and data class). It is not the "richer LLM-based evaluator" the PRD lists as a nice-to-have.

## Future work

Plug a local model in behind `Planner` (for example through a subprocess, so the core stays dependency-free). Nothing in the gateway, the manifest or the tests would change: the model's output would be parsed into the same proposal dictionaries and submitted as `tool.request` envelopes. The model must never be given tool handles.
