# Contributing to TripWire

Thanks for helping improve this local-first security demonstration. Keep changes understandable to reviewers and preserve its defensive, local-only scope.

## Development workflow

1. Start from an up-to-date `main` branch or a focused feature branch. Do not rewrite published history or discard another contributor's work.
2. Read [`ARCHITECTURE.md`](ARCHITECTURE.md), the relevant source modules, and nearby tests before changing behaviour.
3. Keep protocol and business checks in Python. Validate all browser/API inputs on the server. Avoid adding external services or attack traffic.
4. Add regression tests for changed security behaviour, API validation, state changes, and failure paths.
5. Run the exact local checks listed below and inspect `git diff --check` and `git status` before committing.
6. Update the README for user-facing launch/usage changes and the architecture guide for changes to trust boundaries, data flow, validation order, API behaviour, or security assumptions.

## Tests and local checks

From the repository root in PowerShell:

```powershell
python -m unittest discover -s tests -v
python -m tripwire --demo
python -m tripwire --attack-demo
git diff --check
```

For dashboard changes, start `python -m tripwire serve`, open `http://127.0.0.1:8765`, and verify the affected control in a browser. Keep the server on loopback. If browser testing was not performed, describe the HTTP/API or automated checks that were performed instead.

GitHub Actions runs the unit suite and demo smoke command across the supported Python versions in `.github/workflows/tests.yml`. Do not describe a local run as a CI result.

## Commits

Use concise Conventional Commit subjects, for example:

- `feat(dashboard): add threshold activity controls`
- `fix(protocol): serialize replay checks`
- `docs(architecture): describe trust boundaries`
- `test(api): cover invalid telemetry requests`

Group related changes into a coherent commit. Use a descriptive body for meaningful changes, with sections such as `Problem`, `Changes`, `Security`, `Validation`, and `Limitations`. Report only tests that actually ran. Do not create artificial milestones, empty commits, or commits with falsified timestamps.

## Architectural decisions

When a change alters a lasting architectural trade-off, add or update a record in [`docs/adr/`](docs/adr/). An ADR should include context, the decision, trade-offs, and consequences. New records document decisions as of their actual addition; do not backdate them or imply that they existed earlier. Keep the architecture guide synchronized with implemented behaviour and label proposed work as future work.

## Security and scope

Do not add network scanning, external attack behaviour, malware, real email delivery, public listeners by default, embedded production credentials, or paid/cloud dependencies. Treat the built-in HMAC key and unauthenticated local HTTP API as demo-only. If a vulnerability is found, include a regression test and explain any residual limitation.
