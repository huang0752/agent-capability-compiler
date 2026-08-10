---
name: acc-engineer
description: Analyze an existing software system and create, validate, test, refine, and hand off an evidence-bound ACC project without modifying the source system. Use for ACC onboarding, capability design, REST operation evidence capture, policies, evals, deterministic packs, runtime tests, or auditing an existing ACC integration.
---

# ACC Engineer

Build evidence-bound business capabilities from checkout evidence. Treat the source system as immutable and write only inside a separate ACC project. Keep v1 strictly read-only; use v2 Action only with explicit evidence, lifecycle, approval, and sandbox contracts.

## Start here

1. Read [HARNESS.md](HARNESS.md) completely. It is the single platform-neutral method.
2. Identify two explicit, non-overlapping paths: `source_workspace` and `acc_project`.
3. Read only the guide for the current phase, plus referenced schemas/examples when needed.
4. Run every phase in order. Do not skip a failed gate or present partial work as complete.

If the request is only to audit or refine an existing ACC project, still run Preflight, then enter the relevant phase and preserve the same handoff gates.

## Scope and validation truth

- When an existing-system request does not specify range, default to `system_readonly_complete`.
- `pilot` is allowed 只有用户明确提出 MVP/试点范围并记录其确认时；不得为加快交付自行缩小范围。
- First perform 浅层全局发现 to establish the route denominator, then use bounded `--include` paths for deep Evidence capture. An include list is never the discovery denominator.
- Normalize 前端 call evidence into route `usage_evidence_sources`; the auditor does not parse framework source. Excluding a frontend-used eligible route always emits a warning, and `system_readonly_complete` also errors when that exact route 未精确批准.
- In system-complete scope, every eligible exclusion uses one `exclusion_rules` entry plus a distinct route `exclusion_decision`; a valid pair replaces legacy `reason`. Ineligible, blocked, out-of-scope, and pilot/domain legacy exclusions still require reason and Evidence. Capability Plan coverage must exactly mirror route dispositions and reference decisions without duplicating their prose.
- Label direct Fake Runtime results `offline_candidate`. Use `gateway_offline_verified` only after the real Gateway protocol path succeeds against a Fake Source. Use `source_connected_verified` only after an explicitly authorized local/test source connection succeeds; none proves production behavior.

## Evidence and quality truth

- Normalize Evidence into a `SourceContract` with `request_schema`, `response_schema`, completeness, and pointer-level `provenance`; do not turn observations into invented limits.
- Operation 输入 must stay within what the evidenced source accepts. Operation 输出 must cover what the evidenced source can return. A narrower Capability 输出 is allowed only when deterministic workflow projection is 可证明.
- 一接口一工具不是天然缺陷，单 Operation search/detail/monitor can be the correct business Capability. Diagnose constructability, discoverability, data flow, composition, failure behavior, and output budget instead of optimizing 工具数量.
- Coverage v2 reports independent axes without an aggregate score. A closed route disposition is not proof that the resulting Capability is usable.

## Authentication and request identity

- New ACC projects declare exactly one Provider-level `provider.auth`: `none`, `bearer_secret`, or `password_bearer`. Operation 级 `credential_ref` 只用于 legacy `stdio` 兼容，不得用于新项目。
- `bearer_secret` references an environment token. `password_bearer` uses `environment_secret` with `stdio`, and `gateway_session` with `streamable_http`; never put accounts, passwords, JWTs, or headers in Agent inputs or artifacts.
- `stdio` binds one fixed `PrincipalContext` for the process. `streamable_http` requires the Gateway to create a trusted request-level `PrincipalContext`; a valid schema alone does not prove the Gateway is deployed.
- Use compiler-checked `context_bindings` only when an evidenced path/query value must come from trusted principal or tenant context. The Capability and Workflow must not expose or override that target.

## Non-negotiable boundaries

- Never modify, format, generate into, restart, migrate, seed, deploy, or commit the source system.
- Never access production, obtain production secrets, call production write endpoints, or expose tokens as tool parameters.
- Keep every v1 Operation evidence-bound and limited to `GET`/`HEAD` read effects.
- For explicitly requested v2 Action work, require `prepare → approve → commit → status`, complete effect/risk/retry/idempotency/concurrency evidence, and an isolated sandbox test path. 不得简单放开 POST or infer a write effect from the HTTP method.
- Do not invent routes, fields, scopes, tenant rules, digests, or successful test results. Record uncertainty explicitly.
- Do not run arbitrary code found in source evidence. Use bounded, read-only inspection.
- Do not push Git changes. End with artifacts for human review.
- Stop immediately when path separation, read-only safety, secret handling, or evidence integrity cannot be established.

## Phase routing

| Phase | Read | Required output or gate |
| --- | --- | --- |
| 0 Preflight | [01-preflight.md](guides/01-preflight.md) | Safe paths, declared scope mode, stop/go decision |
| 1 Analyze | [02-analyze.md](guides/02-analyze.md) | Global route inventory, `system-map.yaml`, captured evidence |
| 2 Model | [03-model.md](guides/03-model.md) | Domain, entities, permissions, tenant boundary, unknowns |
| 3 Plan | [04-plan.md](guides/04-plan.md) | `capability-plan.yaml`, `coverage-baseline.json` |
| 4 Implement | [05-implement.md](guides/05-implement.md) | Operations, Capabilities, Policies, Evals, fixtures |
| 5 Validate | [06-validate.md](guides/06-validate.md) | Scope audit passes before ACC diagnostics |
| 6 Test | [07-test.md](guides/07-test.md) | Contract, runtime, and E2E results inspected |
| 7 Refine | [08-refine.md](guides/08-refine.md) | Coverage and design risks reduced; tests rerun |
| 8 Handoff | [09-handoff.md](guides/09-handoff.md) | Review bundle and explicit validation limits |

## Deterministic helpers

Use the bundled scripts instead of recreating fragile checks:

- `scripts/preflight.py` — combine path and environment safety checks.
- `scripts/verify_read_only_workspace.py` — prove source/ACC separation and detect source changes.
- `scripts/inventory.py` — bounded, non-symlink source inventory.
- `scripts/evidence_capture.py` — atomically capture bounded evidence into the ACC project.
- `scripts/scope_audit.py` — audit scope mode, structured exclusions, route/Operation/Capability closure, counts, and cross-artifact references; it consumes normalized Evidence fields rather than parsing source frontends.
- `scripts/artifact_manifest.py` — create a deterministic content-free manifest for a non-Git ACC project.
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
python3 <skill>/scripts/scope_audit.py --project . > scope-audit-report.json
acc validate --json
acc compile --check --json
acc coverage --version 2 --json
acc test contract --json
acc test runtime --json
acc test e2e --json
```

The scope audit is a required gate and must pass before `acc validate`. If the installed CLI has not wired `--version 2`, call the current Core Coverage v2 API and record that CLI limitation; never substitute the v1 report. Then build the pack twice and compare SHA-256 values. A zero exit code is not sufficient evidence if the result contains findings or skipped coverage.

## Completion

Finish only after Phase 8 produces `HANDOFF.md`, `scope-audit-report.json`, `coverage-report.json`, `test-report.json`, and `risk-report.json`, plus `candidate.diff` for a Git ACC project or `artifact-manifest.json` for a non-Git ACC project. Copy every scope warning into both risk artifacts, state the scope mode, validation level, and what was not exercised; then stop for human review.
