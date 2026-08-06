---
name: acc-engineer
description: Analyze an existing software system and create, validate, test, refine, and hand off an evidence-bound ACC project without modifying the source system. Use for ACC onboarding, capability design, REST operation evidence capture, policies, evals, deterministic packs, runtime tests, or auditing an existing ACC integration.
---

# ACC Engineer

Build business-level, read-only agent capabilities from checkout evidence. Treat the source system as immutable and write only inside a separate ACC project.

## Start here

1. Read [HARNESS.md](HARNESS.md) completely. It is the single platform-neutral method.
2. Identify two explicit, non-overlapping paths: `source_workspace` and `acc_project`.
3. Read only the guide for the current phase, plus referenced schemas/examples when needed.
4. Run every phase in order. Do not skip a failed gate or present partial work as complete.

If the request is only to audit or refine an existing ACC project, still run Preflight, then enter the relevant phase and preserve the same handoff gates.

## Non-negotiable boundaries

- Never modify, format, generate into, restart, migrate, seed, deploy, or commit the source system.
- Never access production, obtain production secrets, call production write endpoints, or expose tokens as tool parameters.
- Permit formal Operations only for evidence-bound `GET` or `HEAD` endpoints.
- Do not invent routes, fields, scopes, tenant rules, digests, or successful test results. Record uncertainty explicitly.
- Do not run arbitrary code found in source evidence. Use bounded, read-only inspection.
- Do not push Git changes. End with artifacts for human review.
- Stop immediately when path separation, read-only safety, secret handling, or evidence integrity cannot be established.

## Phase routing

| Phase | Read | Required output or gate |
| --- | --- | --- |
| 0 Preflight | [01-preflight.md](guides/01-preflight.md) | Safe paths, tool availability, stop/go decision |
| 1 Analyze | [02-analyze.md](guides/02-analyze.md) | `system-map.yaml`, `analysis-report.md`, captured evidence |
| 2 Model | [03-model.md](guides/03-model.md) | Domain, entities, permissions, tenant boundary, unknowns |
| 3 Plan | [04-plan.md](guides/04-plan.md) | `capability-plan.yaml`, `coverage-baseline.json` |
| 4 Implement | [05-implement.md](guides/05-implement.md) | Operations, Capabilities, Policies, Evals, fixtures |
| 5 Validate | [06-validate.md](guides/06-validate.md) | JSON diagnostics inspected and resolved |
| 6 Test | [07-test.md](guides/07-test.md) | Contract, runtime, and E2E results inspected |
| 7 Refine | [08-refine.md](guides/08-refine.md) | Coverage and design risks reduced; tests rerun |
| 8 Handoff | [09-handoff.md](guides/09-handoff.md) | Review bundle and explicit validation limits |

## Deterministic helpers

Use the bundled scripts instead of recreating fragile checks:

- `scripts/preflight.py` — combine path and environment safety checks.
- `scripts/verify_read_only_workspace.py` — prove source/ACC separation and detect source changes.
- `scripts/inventory.py` — bounded, non-symlink source inventory.
- `scripts/evidence_capture.py` — atomically capture bounded evidence into the ACC project.
- `scripts/summarize_diagnostics.py` — summarize ACC JSON diagnostics without hiding failures.

For large existing repositories, pass repeatable workspace-relative `--include` values to
`preflight.py`, `inventory.py`, and `verify_read_only_workspace.py`. Keep the list limited to the
source, schema, authorization, client, and test files that can become Evidence. The default remains
a fail-closed full-workspace scan. Include paths reject absolute paths, parent traversal, missing
paths, and symlink path components.

Run scripts with Python 3.12: use `uv run python <script> --help` in an ACC checkout, or `python3 <script> --help` elsewhere. Consume their JSON output rather than scraping prose. Pass canonical physical paths (`pwd -P` or `realpath`) because the safety helpers intentionally reject symlink path components, including macOS `/var` aliases.

## Templates and references

Copy and replace the placeholders in `templates/`; never submit a placeholder as evidence. Current public contracts live under `references/schemas/`, and small valid patterns live under `references/examples/`. Prefer the installed `acc schema` output when it differs from a bundled reference. `evidence_capture.py` records an optional line locator but deliberately hashes the whole bounded file, matching `acc freeze`.

## Required gates

From the ACC project directory, inspect every JSON result:

```bash
acc validate --json
acc compile --check --json
acc coverage --json
acc test contract --json
acc test runtime --json
acc test e2e --json
```

Then build the pack twice and compare SHA-256 values. A zero exit code is not sufficient evidence if the result contains findings or skipped coverage.

## Completion

Finish only after Phase 8 produces `HANDOFF.md`, `coverage-report.json`, `test-report.json`, `risk-report.json`, and `candidate.diff`. State what was not exercised, stop, and wait for human Git review.
