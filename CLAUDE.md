# CLAUDE.md: Trip-Wire repository guide

Project: **Trip-Wire**, Team HELLCODE's entry for HackInverse 1.0 (hackday 11 Oct 2026, JIS University).
Repo: https://github.com/6289subhasree/trip-wiree (branch `main`). Owner: Subhasree.

## What this is
A runtime containment layer for AI agents. Core principle (from the PRD): **untrusted content may supply evidence, but it can never grant authority.** Every message and every consequential tool call passes through one server-side gateway that can ALLOW, BLOCK or REQUIRE_APPROVAL. Three agents make up the story: an intake agent, a policy validator and a red-team adversary.

## Hard rules
- **Python standard library only** (3.10+). No pip dependencies, no build step, no CDN. It must run offline on a Windows venue laptop.
- **Never send real email or make external network calls** by default. Every external destination is simulated.
- **Synthetic data only.** No real people, customers or credentials. Never commit secrets. Keys are generated per process.
- The insecure `baseline`/replay profile is a labelled counterfactual. It must never become the default.
- Never fake results. Metrics, timelines and badges must come from recorded backend decisions. Don't make UI-only "blocked" states.
- **Git:** commit as the configured user (Subhasree). **Do not add `Co-Authored-By` or any AI attribution trailers.** Use Conventional Commits with descriptive bodies (Problem / Changes / Security / Validation). Commit after each completed work package with tests green. Push to `origin main` after each phase. Never force-push, rewrite published history or delete branches.

## Commands (PowerShell, repo root)
```powershell
python -m unittest discover -t . -s tests -v   # full suite; must stay green
python -m tripwire serve --open                 # console at http://127.0.0.1:8765
python -m tripwire demo                         # scripted terminal story (event mode)
python -m tripwire invoice-demo                 # PRD demo script (task mode)
python -m tripwire attack-demo                  # strict vs baseline matrix
```
Set `$env:TRIPWIRE_RECOVERY_CODE="TW-JUDGE-42"` for a predictable lockdown recovery code.

## Layout
- `tripwire/protocol.py`: envelope v2, per-agent HMAC keys, route table, strict payload schemas
- `tripwire/gateway.py`: default-deny pipeline, action policy, intrusion pressure, audit and outbox hooks
- `tripwire/tools_gateway.py`, `manifest.py`, `context.py`, `intent.py`: capability gateway, signed manifest, trust contexts, intent check
- `tripwire/approvals.py`, `lineage.py`, `report.py`: approval queue, data lineage, blast-radius report
- `tripwire/vault.py`, `tools.py`, `planner.py`, `scenarios.py`: synthetic data, mock tools, naive planner, document scenarios
- `tripwire/firewall.py`: NORMAL / BLOCKING / LOCKDOWN + recovery code
- `tripwire/agents.py`, `risk.py`, `attacks.py`: agents, risk model, adversary scenarios
- `tripwire/notifications.py`: mock email; `audit.py`: HMAC-chained audit log
- `tripwire/demo_sim.py`: three-agent mail simulation behind `/simulation` (`web/sim.html`, `sim.css`, `sim.js`); runs in throwaway sessions
- `tripwire/session.py`: wiring, metrics, attack runner; `server.py`: stdlib HTTP API; `dashboard.html`: UI
- `vantage/`: landing page source (Next.js static export). `vantage/out/` is the committed build that `server.py` serves at `/`; the runtime still needs only Python. After editing it: `cd vantage; npm run build`, then commit `out/`. The old page stays at `/classic`
- `tests/`: unittest suite (`tests/helpers.py` has `make_session`, `FakeClock`)
- `docs/`: DEMO.md, DECK_NOTES.md, adr/, reference/ (PRD, deck), screenshots/, claude-code/ (build prompts)

## Conventions
- The gateway is the only enforcement point. Agents produce envelopes and requests; they never call tools or each other.
- Every rejection has a stable UPPER_SNAKE code and a human reason.
- All gateway work happens under `Firewall.lock`. Keep side effects inside that lock.
- Tests assert real side effects (outbox file, tool execution log, audit order), not just HTTP status codes.
