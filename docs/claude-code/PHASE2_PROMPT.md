# Trip-Wire Phase 2: PRD capability layer + deck-aligned redesign

You are working in the Trip-Wire repository. Read `CLAUDE.md` first and follow its hard rules (stdlib only, offline, synthetic data, no AI attribution trailers, frequent detailed commits and a push after every phase).

Also read: `README.md`, `ARCHITECTURE.md`, `docs/DEMO.md`, every module in `tripwire/`, and `tests/`. Then **verify the starting state** before changing anything: run the full suite (expect 54 passing), run `python -m tripwire demo`, check `git status` and `git log -5`, and report what you find. If reality differs from this prompt, trust the code and tell me.

## 0. Why this phase exists

Today the repo is a working three-agent communication firewall: a monitor, a validator and an adversary; a default-deny gateway; a NORMAL/BLOCKING/LOCKDOWN firewall; HMAC envelopes; a mock email action; an HMAC-chained audit log; and 10 attack scenarios. It shares the PRD's mechanism (*one server-side gateway; authority comes from policy, never from content; every decision is audited; a red-team baseline vs a protected run*). But it is missing the PRD's **task-scoped capability layer** and its **document-injection story**, and the UI doesn't match Team HELLCODE's deck.

Goal: keep the three-agent story (it's our differentiator) **and** implement the PRD features on top of the existing gateway, then rebuild the UI in the deck's visual language. Don't throw away working code. Extend it.

## 1. Target narrative (the three agents, PRD-aligned)

| Agent | New role | Talks to |
|---|---|---|
| **Agent 1 · Intake Agent** (evolves `EventMonitor`) | Given a task ("Extract invoice INV-1042 and create a payment draft"), reads an **untrusted document**, extracts fields, scores document risk, and *proposes* structured tool calls with justifications. It is deliberately naive: it will propose whatever the document tells it to. That simulates a hijacked LLM. | Gateway only |
| **Agent 2 · Policy Validator** (evolves `Validator`) | Holds the **task policy manifest**, checks each proposal semantically (intent to task, evidence source), owns the **approval queue**, and raises the SOC alert when the risk threshold (default 70) is crossed. | Gateway only |
| **Agent 3 · Red Team** (existing `Adversary`) | Keeps all 10 protocol attacks, and gains the 3 PRD document scenarios plus **judge-supplied custom instructions** injected into the document. | Gateway only |

**Keep the original three-agent event mode fully working.** Agent 1's existing event-stream mode (the `baseline`/`incident` streams, the risk model `score = min(100, 0.8·prev + weight)`, the threshold-70 alert, Agent 2's validation and the internal alert email) must remain intact *alongside* the new invoice/document mode. Both modes must be selectable in the UI, demonstrable end to end, and covered by tests. All 10 existing channel attacks, the firewall states, auto-lockdown, recovery, the baseline profile and the audit chain stay. Do not delete or weaken any existing test.

The email alert from the original spec stays: crossing the threshold makes Agent 2 request `send_email` to the **internal, allowlisted** SOC destination. That is the one email that is *allowed*. Any external email is blocked.

## 2. Backend work packages (do them in order; commit after each)

Keep everything in `tripwire/` as small modules with explicit interfaces. Every package gets tests.

### B1 · Trust-labelled context model (`tripwire/context.py`)
- Four contexts, per PRD §7.2: `system_policy` (trusted, can authorise), `user_task` (trusted within policy), `document` (untrusted evidence, can't authorise), `tool_output` (data only, can't authorise).
- A `Provenance` record attached to every piece of text and every proposed action: `source` (context and id), `trust`, `span` (character offsets in the document when relevant).
- An instruction detector that tags imperative sentences in untrusted content as `untrusted_instruction`, using structural and verb-based heuristics (imperatives addressed to the agent, tool or destination nouns, URLs or emails). **Detection is for display and logging only. Enforcement must never depend on it.** Add a test that a novel, oddly phrased instruction which the detector *misses* is still blocked by B3/B4.

### B2 · Task policy manifest (`tripwire/manifest.py`)
- Immutable dataclass matching PRD §7.3: `task_id, goal, goal_effects, allowed_tools, allowed_data, payment_limit_inr (50000), approval_required, forbidden_tools, allowed_destinations, expires_at`.
- Created at task start, **HMAC-signed by the gateway** (reuse the protocol primitives), with its hash shown in the UI and written to the audit log. Any modification attempt gives `MANIFEST_TAMPERED`.
- Expiry: the manifest dies on task completion or after N minutes, and later tool calls give `CAPABILITY_EXPIRED`.
- A manifest can only be created from `user_task` and `system_policy` contexts. A test must prove that document text cannot add a tool, data scope or destination.

### B3 · Capability tool gateway (extend `tripwire/gateway.py` or add `tripwire/tools_gateway.py`)
- New protocol message type `tool.request`, sent Agent 1 → gateway. It carries the PRD §7.6 justification: `tool, args, purpose, task_link, evidence (with provenance), resources_requested, destination, risk_level`. Add it to `ROUTES` and give it a strict payload schema.
- Decision ∈ `ALLOW | BLOCK | REQUIRE_APPROVAL`, with stable codes:
  `TOOL_NOT_IN_MANIFEST`, `TOOL_FORBIDDEN`, `DATA_OUT_OF_SCOPE`, `DESTINATION_NOT_ALLOWED`, `INTENT_MISMATCH`, `UNTRUSTED_AUTHORITY` (the justification cites only document or tool-output evidence as its reason to act), `PAYMENT_OVER_LIMIT`, `APPROVAL_REQUIRED`, `CAPABILITY_EXPIRED`, `CANARY_EGRESS`.
- Order: firewall → envelope checks (existing) → manifest validity → tool allowed/forbidden → data scope → destination → intent-to-task → evidence provenance → thresholds → approval rules → execute.
- **Blocked tools never execute.** Prove it with a per-tool execution counter and a test.
- Everything runs under `Firewall.lock` like the existing pipeline.

### B4 · Intent-to-task mismatch (`tripwire/intent.py`)
- Deterministic and explainable. Map each tool to an **effect class** (`read_invoice, read_vendor, draft_payment, modify_vendor_bank, read_customer_pii, bulk_export, external_egress, internal_notify`) and a **data class** (`invoice, vendor, customer_pii, canary`).
- Map the task goal to an allowed effect set (an invoice task allows `read_invoice, read_vendor, draft_payment, internal_notify`).
- A mismatch is decided by *effect and data class*, **not by phrases**. So "export customer records for billing verification" is still `bulk_export + customer_pii`, which gives `INTENT_MISMATCH`. Return a score (0-100) and the reasons. Test it with several paraphrases, including polite and indirect ones.

### B5 · Mock enterprise tools + synthetic vault (`tripwire/tools.py`, `tripwire/vault.py`)
- All 8 PRD §7.5 tools, each deterministic and returning JSON: `extract_invoice_fields, get_vendor_record, create_payment_draft, change_vendor_bank_account, export_customer_list, get_customer_records, send_email, upload_external_file`. `send_email` and `upload_external_file` **only ever write to the mock outbox or egress log**.
- Vault: **500 synthetic customer records** generated deterministically (fixed seed; Indian names, cities and PIN codes, fake GSTIN-like ids, *no real people*), 3 invoices (INV-1042 ₹18,500 normal; INV-1043 ₹72,000 over the limit; INV-1044 with a linked "supporting document"), and 2 vendors.
- **Canary tokens** (`TRIPWIRE-CANARY-…`) seeded into sensitive records and into the invoice footer. Any read, transform, include, email or upload of canary-tagged data is tracked, and any canary in an egress payload gives `CANARY_EGRESS`.

### B6 · Human approval boundary (`tripwire/approvals.py`)
- `REQUIRE_APPROVAL` creates a pending approval: requested action, justification, evidence source with provenance, affected data, risk, and expiry. The tool **does not run** while the approval is pending.
- `approve(id, approver)` / `reject(id, approver)`. Only the operator (dashboard, same CSRF guard) can decide. **An agent message can never approve**; prove that with a test where Agent 1 or the red team tries to submit an approval. Approved calls re-check the manifest and firewall at execution time; a LOCKDOWN after approval still blocks.
- Approval triggers per PRD §7.8: payment above ₹50,000, bank-account change, new vendor, any outbound email or upload to a non-internal destination.

### B7 · Data lineage + blast radius (`tripwire/lineage.py`, `tripwire/report.py`)
- Lineage for every data-bearing action: source record or document, classification, transformations (summary, CSV, draft), requested destination, final decision.
- A blast-radius report per run, per PRD §7.14: severity (Low/Medium/High/Critical, with documented rules), attempted tools, blocked tools, sensitive records protected (count), canaries touched or protected, ₹ amount at risk, attempted external destinations, and final containment status. Compute it **from lineage and gateway decisions**, never hand-entered.

### B8 · Scenarios + replay (`tripwire/scenarios.py`)
- The PRD §7.11 scenarios as document fixtures, each with the attack text and the expected outcome:
  1. **Invoice Footer Injection:** CRM export and external upload get blocked.
  2. **Vendor Bank-Change Fraud:** gets `REQUIRE_APPROVAL`, never an automatic change.
  3. **Cross-Document Exfiltration:** unrelated retrieval and the outbound email get blocked.
  Plus **Clean invoice** (the happy path) and **Over-limit invoice** (gets approval).
- **Judge mode:** an API that inserts a custom malicious sentence into the selected document. Controls must hold whenever the requested action is out of scope (PRD §16).
- **Red-team replay:** the same scenario run through (a) the `baseline` profile, labelled *"counterfactual red-team simulation"*, and (b) the protected gateway. Return both timelines and both blast-radius reports for a side-by-side view.
- Keep all 10 existing protocol attacks. They are now the "channel attacks" next to the "document attacks".

### B9 · No LLM / no API (decided)
**Skip any LLM adapter entirely.** No API keys, no paid or external services, no network calls. Agent 1 uses only a `DeterministicPlanner` (rule-based, deliberately naive, follows document instructions), behind a small `Planner` interface so a local model could be plugged in later. Document this as a limitation and future work in an ADR.

### B10 · API (extend `tripwire/server.py`)
Add the PRD §12 endpoints and keep the existing ones working:
`GET /api/scenarios`, `POST /api/tasks/start`, `GET /api/tasks/{id}/document`, `POST /api/tasks/{id}/agent/run`, `POST /api/gateway/tool-call`, `POST /api/tasks/{id}/approval`, `GET /api/tasks/{id}/timeline`, `GET /api/tasks/{id}/report`, `POST /api/tasks/{id}/inject` (judge mode), `POST /api/replay`.
Same CSRF/Origin guard, body limits and input validation. The snapshot must never include keys, the recovery code or full canary values (show them masked).

**Non-functional (PRD §10):** a decision appears in the timeline within 1 s of a request, and each scenario completes in under 90 s. Add a timing assertion in tests.

## 3. Frontend redesign (`tripwire/dashboard.html`, single file, offline)

The current UI looks generic and AI-made. Rebuild it to match **Team HELLCODE's deck**.

**Identity:** near-black `#0b0708` / `#120a0b`, crimson `#c8102e` (violations and brand marks only), bone white `#efe9e4` text, muted `#8a7f7a`, and a single desaturated green `#5f8f6e` for ALLOW. Headlines in an editorial serif (stack: `"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif`; no web fonts, the venue may be offline). Body in `"Segoe UI",system-ui`. The ledger in `Consolas,ui-monospace`. Use the deck's **red square section numbers** ("01", "02") and the **red corner flag** mark. Footer strip: `TRIPWIRE | CONSTRAIN → ENFORCE → PROVE`.

**Anti-"AI look" rules (enforce strictly):**
- No glow blobs, radial gradients, glassmorphism, emoji, sparkles or gradient-bordered cards.
- No uniform grid of identical rounded cards. Use a newspaper-like grid with hairline 1px rules, 2px corner radius at most, and real typographic hierarchy (serif display, small-caps labels, tabular numbers).
- Colour has meaning: crimson = blocked or violation, amber `#c98a1a` = pending approval, green = allowed. Nothing decorative.
- Motion only where state changes (a row slides into the ledger, the decision stamp appears). No looping animations except a slow LOCKDOWN indicator.
- Write copy like a security product, not marketing: short, specific labels with codes visible.

**Layout (PRD §9, extended for three agents):**
- **Top bar:** brand, task id and goal, firewall state (NORMAL / BLOCKING / LOCKDOWN), profile (Protected / Replay-baseline), and the manifest hash.
- **Left (≈30%) · Document:** render the invoice as a paper sheet (white page, real invoice layout, ₹ amounts). **Highlight untrusted instruction spans** inline (crimson underline plus a margin note "UNTRUSTED · cannot grant authority"). Scenario picker and the judge's "Insert instruction" box sit above it.
- **Centre (≈40%) · Agent pathway + evidence ledger:** a compact horizontal lane diagram (Agent 1 → Gateway → Agent 2 → Tools/Outbox, with Agent 3 entering the gateway) whose edges reflect the last real decision. Below it, the streaming **evidence ledger** (monospace, timestamped). Each row has: time, source context and trust, proposed action, decision stamp (ALLOW / BLOCK / APPROVAL), code, reason, risk, data scope. Clicking a row expands lineage and justification JSON.
- **Right (≈30%) · Policy manifest:** the signed manifest as a readable spec sheet (tools ✓/✗, data scope, ₹ limit, destinations, approval rules, expiry), with live capability status. Below it, the firewall controls and the recovery code input.
- **Approval card:** an inline card (not a browser dialog) with action, justification, evidence source, affected data, risk, and Approve/Reject. It shows exactly the PRD §7.8 fields.
- **Bottom band:** extracted invoice fields, the payment draft, the **blast-radius report** (severity word set large in serif, then the numbers), and the outbox (simulated, with the internal SOC alert distinct from blocked externals).
- **Replay view:** a toggle that splits the centre into *Baseline (counterfactual)* | *Protected*, showing the same scenario side by side with both blast-radius severities.
- **Channel attacks** (the existing 10) move to a collapsible "Channel attacks · Agent 3" drawer.
- Responsive down to 1280 px for the projector; usable at 390 px.
- All server strings are HTML-escaped. Never render document text as HTML.

Verify in a real browser (`python -m tripwire serve --open`). Check: no console errors, every control changes backend state, and screenshots at 1440 px and 1280 px look like the deck.

## 4. Tests (add; never weaken existing ones)
At minimum, test: manifest immutability and signature; document text cannot expand capabilities; each PRD acceptance criterion in §13 (1-8) as its own named test; the blocked-tool execution counter stays at 0; approvals can't be self-approved by agents; approval followed by LOCKDOWN still blocks; canary egress is detected; intent mismatch on paraphrases; the judge's custom instruction holds; replay shows baseline harm vs protected containment; blast-radius numbers equal recomputation from lineage; API validation and CSRF on the new endpoints; timing (decision within 1 s). Keep the whole suite deterministic and offline.

## 5. Docs + deck alignment
- Update `README.md`, `ARCHITECTURE.md` (new pipeline stages, trust contexts, manifest, approvals, lineage, blast-radius rules, honest limitations), `docs/DEMO.md` (new 3-minute script following PRD §15 *and* the three-agent pathway), and add ADRs for the manifest/capability gateway and the deterministic planner + optional LLM.
- Create `docs/DECK_NOTES.md` listing the slide edits the team should make so the deck matches the real build. Known mismatches: slide 4 claims React + Flask + PostgreSQL + scikit-learn ML + Docker, but the build is stdlib Python with a single-file UI and no ML; and the spelling "TRIPWARE" appears on slides 2-3. Propose accurate replacement text. Don't add technologies just to match a slide.

## 6. Phases, commits and pushes
- **Phase A (backend core):** B1-B4 (plus a regression check that event mode still works). Commit per package; push when the phase is green.
- **Phase B (data + approvals):** B5-B7.
- **Phase C (scenarios + API):** B8-B10.
- **Phase D (UI redesign)** + browser verification.
- **Phase E (docs + deck notes + final verification).**
After each phase: run the full suite, run `python -m tripwire demo`, commit, `git push origin main`, and tell me what changed, the test count, and anything you couldn't do. If something fails, diagnose the real error; don't skip or loosen a test to get green. Ask me only for decisions that change security behaviour or the architecture.

## 7. Definition of done
- All three agents are visible and doing distinct jobs; every agent action goes through the gateway.
- The PRD §13 acceptance criteria 1-8 each pass as tests and are demonstrable in the UI.
- The judge can type a new malicious sentence and the out-of-scope action is still blocked.
- The replay view shows baseline harm vs protected containment, computed from real runs.
- The UI matches the deck and doesn't look template-generated.
- The suite is green, the demo script works end to end on Windows, and everything is pushed to `origin/main` with detailed commits authored by the repo owner and no AI trailers.
