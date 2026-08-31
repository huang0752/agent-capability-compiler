---
name: acc-engineer
description: Analyze an existing software system and create, validate, test, refine, and hand off an evidence-bound ACC project without modifying the source system. Use for ACC onboarding, capability design, REST operation evidence capture, policies, evals, deterministic packs, runtime tests, or auditing an existing ACC integration.
---

# ACC Engineer

Build evidence-bound business capabilities from checkout evidence. Treat the source system as immutable and write only inside a separate ACC project. ACC accepts only current format `2`; old-format documents must be rejected instead of migrated implicitly.

## Start here

1. Read [HARNESS.md](HARNESS.md) completely. It is the single platform-neutral method.
2. Identify two explicit, non-overlapping paths: `source_workspace` and `acc_project`.
3. Read only the guide for the current phase, plus referenced schemas/examples when needed.
4. Run every phase in order. Do not skip a failed gate or present partial work as complete.

If the request is only to audit or refine an existing ACC project, still run Preflight, then enter the relevant phase and preserve the same handoff gates.

## Scope and validation truth

- When an existing-system request does not specify range, default to `system_complete`.
- `pilot` is allowed 只有用户明确提出 MVP/试点范围并记录其确认时；不得为加快交付自行缩小范围。
- `system_complete` means the complete evidenced business surface, not a Read-only subset: inventory Read, Create, Update, Delete, transition, execute, and composite intents across backend routes and client interactions. HTTP methods are discovery signals only; Evidence determines kind and effect.
- Missing write-sandbox authorization or incomplete effect/risk/retry/idempotency/concurrency/approval/outcome Evidence never removes an Action from that denominator. Keep it `undetermined` and `blocked_on_evidence`; a system-complete project cannot be `complete` while any such Action or composite intent remains blocked.
- An eligible Action intent cannot be closed by an exclusion decision. A duplicate route may be `composed` only when its replacement materializes the same business mutation through the full Action lifecycle. Only independently evidenced objective ineligibility can remove an Action from the eligible surface; a user preference for Read-only delivery requires `pilot` or remains deferred, not a completed `system_complete` claim.
- First perform 浅层全局发现 to establish the route denominator, then use bounded `--include` paths for deep Evidence capture. An include list is never the discovery denominator.
- Keep route usage and client interaction as two facts: route `usage_evidence_sources` records observed calls, while `ui-interaction-inventory.yaml` independently records evidenced business interactions. Framework adapters normalize Evidence; Core and auditors never execute or parse client code. Excluding a frontend-used eligible route always emits a warning, and `system_complete` also errors when that exact route 未精确批准.
- In system-complete scope, every permitted eligible Read exclusion uses one `exclusion_rules` entry plus a distinct route `exclusion_decision`; a valid pair replaces `reason`. Eligible Action intent cannot use this mechanism to close scope. Ineligible, blocked, out-of-scope, and pilot/domain exclusions still require reason and Evidence. Capability Plan coverage must exactly mirror route dispositions and reference decisions without duplicating their prose.
- Label direct Fake Runtime results `offline_candidate`. Use `gateway_offline_verified` only after the real Gateway protocol path succeeds against a Fake Source. Use `source_connected_verified` only after an explicitly authorized local/test source connection succeeds; none proves production behavior.

## Domain wizard

Run the system-complete denominator as a domain wizard, not an interface questionnaire:

1. Perform a 全局浅扫 and create the complete Candidate Ledger, `DomainMap`, dependency order, and initial `intent-plan.yaml` before any domain deep scan.
2. 一次只激活一个依赖已就绪的大领域；never activate a dependent domain merely because its routes are easy to inspect.
3. Before deep inspection, ask the user to confirm only the business goals, risk boundary, write-sandbox authorization, and `DomainPolicy`. The user does not choose a tool quota, route grouping, or ordinary candidate disposition. 绝不把全部 route 交给用户选择；未授权写测试只会阻断对应 Action，不会把它从全局分母删除。
4. Deep-scan only the active domain. The Coding Agent acts as the AI Domain Intent Planner: it revises `intent-plan.yaml`, automatically models every 证据清晰 candidate, derives Capability boundaries and quantity from Evidence, and retains uncertain facts as typed gaps.
5. 一次只问一个 exception: evidence conflict, business ambiguity, high-risk policy choice, or missing user-controlled test boundary. Do not ask the user to classify ordinary routes.
6. Review every 独立轴 and bind the versioned `DomainDecision` to the confirmed `DomainPolicy`, Evidence snapshot, and any explicit exception/high-risk decision. Do not ask the user to approve an AI-selected tool count. Continue only with the next dependency-ready domain.

## AI Domain Intent Planner

The Planner is a compile-time responsibility of the Coding Agent; ACC Core and Runtime remain model-free. It must:

- account for every discovered route and client interaction before proposing intent boundaries;
- decide `single_operation`, parameterized, or deterministic composite boundaries from evidenced user goals, resources, selector/data flow, permission, risk, approval, idempotency, concurrency, outcome, output, and failure semantics;
- preserve independently useful search/detail/monitor intents and merge only when the claimed equivalence or composition dependency has Evidence;
- emit `materialize`, `compose`, `blocked_on_evidence`, or objectively evidenced ineligibility without hiding denominator entries;
- treat `capability_count` and `projected_mcp_tool_count` as derived observations after materialization, never quotas or optimization targets.

Fixed tool-count goals, route-per-tool generation, evidence-free merging, and a catch-all `manage` Capability are invalid planning shortcuts. Deterministic audits verify accounting, references, safety, and contradictions; they do not manufacture business semantics or replace Planner Evidence.

The 源 JWT and source interface make the 最终裁决 on authorization. `Scope 只能收窄` what a deployment may attempt; it never grants a source permission. Action `approval 不是授权`: it confirms this exact prepared execution and cannot replace upstream authorization.

## Evidence and quality truth

- Normalize Evidence into a `SourceContract` with `request_schema`, `response_schema`, completeness, and pointer-level `provenance`; do not turn observations into invented limits.
- Normalize client surfaces, events, bindings, defaults, options, conditions, related data, states, and unknowns into the UI inventory, then adopt them through an `InteractionContract`. A hidden/disabled control is not authorization. 前端默认值或前端条件不能冒充 `SourceContract` authority; conflicts remain explicit.
- Operation 输入 must stay within what the evidenced source accepts. Operation 输出 must cover what the evidenced source can return. A narrower Capability 输出 is allowed only when deterministic workflow projection is 可证明.
- 一接口一工具不是天然缺陷，单 Operation search/detail/monitor can be the correct business Capability. Diagnose constructability, discoverability, data flow, composition, failure behavior, and output budget instead of optimizing 工具数量.
- Coverage retains nine source/capability axes, ten interaction axes, and twelve independent Domain/Action axes without an aggregate score. Route closure, candidate safety, interaction fidelity, source connection, and real client conformance remain distinct facts.

## Authentication and request identity

- ACC projects declare exactly one Provider-level `provider.auth`: `none`, `bearer_secret`, or `password_bearer`. Operation 不得保存 `credential_ref`。
- `bearer_secret` references an environment token. `password_bearer` uses `environment_secret` with `stdio`, and `gateway_session` with `streamable_http`; never put accounts, passwords, JWTs, or headers in Agent inputs or artifacts.
- `stdio` binds one fixed `PrincipalContext` for the process. `streamable_http` requires the Gateway to create a trusted request-level `PrincipalContext`; a valid schema alone does not prove the Gateway is deployed.
- Use compiler-checked `context_bindings` only when an evidenced path/query value must come from trusted principal or tenant context. The Capability and Workflow must not expose or override that target.

## Non-negotiable boundaries

- Never modify, format, generate into, restart, migrate, seed, deploy, or commit the source system.
- Never access production, obtain production secrets, call production write endpoints, or expose tokens as tool parameters.
- Keep every Read Operation evidence-bound with an explicit `read` effect; do not infer business effect from the HTTP method.
- For every discovered or selected Action, require `prepare → approve → commit → status`, complete effect/risk/retry/idempotency/concurrency/outcome evidence, trusted approval provenance, and an explicitly authorized isolated sandbox test path. Until then it must remain `blocked_on_evidence`; 不得简单放开 POST、静默排除 Action、从 HTTP method 推断 effect，或把 Read-only 子集宣称为 system complete。
- Only for an explicitly authorized local/development source may a low-risk Action with honest `concurrency: not_supported`, `runtime_deduplicate`, and `retry: never` use `local_development_state_guard`. Start it only with both `--development-actions` and `--local-development-action-guards`. Treat its bounded process-local lock and sealed-input pre-commit re-read as protection among cooperating ACC calls, never as source atomicity or production conflict-control Evidence.
- Do not invent routes, fields, scopes, tenant rules, digests, or successful test results. Record uncertainty explicitly.
- Do not run arbitrary code found in source evidence. Use bounded, read-only inspection.
- Do not push Git changes. End with artifacts for human review.
- Stop immediately when path separation, read-only safety, secret handling, or evidence integrity cannot be established.

## Phase routing

| Phase | Read | Required output or gate |
| --- | --- | --- |
| 0 Preflight | [01-preflight.md](guides/01-preflight.md) | Safe paths, declared scope mode, stop/go decision |
| 1 Analyze | [02-analyze.md](guides/02-analyze.md) | Route and interaction inventories, initial `intent-plan.yaml`, `system-map.yaml`, captured evidence |
| 2 Model | [03-model.md](guides/03-model.md) | Domain, entities, permissions, tenant boundary, unknowns |
| 3 Plan | [04-plan.md](guides/04-plan.md) | Evidence-finalized `intent-plan.yaml`, `capability-plan.yaml`, `coverage-baseline.json` |
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
- `scripts/scope_audit.py` — audit scope mode, structured exclusions, route/Operation/Capability closure, counts, and cross-artifact references.
- `scripts/interaction_audit.py` — audit normalized UI inventory structure, Evidence, and route/interaction cross-references without parsing a client framework.
- `scripts/artifact_manifest.py` — create a deterministic content-free manifest for a non-Git ACC project.
- `scripts/summarize_diagnostics.py` — summarize ACC JSON diagnostics without hiding failures.

For large existing repositories, pass repeatable workspace-relative `--include` values to
`preflight.py`, `inventory.py`, and `verify_read_only_workspace.py`. Keep the list limited to the
source, schema, authorization, client, and test files that can become Evidence. The default remains
a fail-closed full-workspace scan. Include paths reject absolute paths, parent traversal, missing
paths, and symlink path components.

Run scripts with Python 3.12: use `uv run python <script> --help` in an ACC checkout, or `python3 <script> --help` elsewhere. Consume their JSON output rather than scraping prose. Pass canonical physical paths (`pwd -P` or `realpath`) because the safety helpers intentionally reject symlink path components, including macOS `/var` aliases.

## Templates and references

Copy and replace the placeholders in `templates/`; never submit a placeholder as evidence. `templates/intent-plan.yaml` is a platform-neutral planning contract, and `references/examples/evidence-derived-intent-plan.yaml` demonstrates evidence-derived boundaries without a tool quota. Current public contracts live under `references/schemas/`, and small valid patterns live under `references/examples/`. Prefer the installed `acc schema` output when it differs from a bundled reference. `evidence_capture.py` records an optional line locator but deliberately hashes the whole bounded file, matching `acc freeze`.

## Required gates

From the ACC project directory, inspect every JSON result:

```bash
python3 <skill>/scripts/scope_audit.py --project . > scope-audit-report.json
python3 <skill>/scripts/interaction_audit.py --project . --output interaction-audit-report.json
acc validate --json
acc compile --check --json
acc coverage --json
acc test contract --json
acc test runtime --json
acc test e2e --json
```

The scope audit and, when client surfaces exist, interaction audit are required gates before `acc validate`. Coverage reports ten core axes, including `tool_portfolio`, plus `surface_disposition`, `interaction_trace`, `input_binding_fidelity`, `default_provenance`, `option_resolution`, `condition_coverage`, `related_data_graph`, `state_scenarios`, `presentation_projection`, and `client_adapter_evidence`; it never generates a total score. The portfolio axis audits review budget, same-intent overlap, isolated mutations, and materialized-route reachability without equating routes to tools or hiding blocked denominator entries. Then build the pack twice and compare SHA-256 values. A zero exit code is not sufficient evidence if the result contains findings or skipped coverage.

For `system_complete`, interpret route closure separately from executable release readiness. The
scope result exposes `release_readiness` with deterministic `discovery_complete`,
`executable_ready`, `blocked`, and `unknown` counts. A known, classified route may remain
`blocked_on_evidence` and produce `status: limited` without reopening the discovery denominator;
it is not executable and must not appear in an Operation or Capability. Missing or unknown routes,
blocked routes smuggled into executable traces, and planned/composed routes that are not eligible
remain errors. `limited` is a truthful handoff state, not production readiness.

## Completion

Finish only after Phase 8 produces the Evidence-finalized `intent-plan.yaml`, `HANDOFF.md`, `scope-audit-report.json`, applicable `interaction-audit-report.json`, `coverage-report.json`, `test-report.json`, and `risk-report.json`, plus `candidate.diff` for a Git ACC project or `artifact-manifest.json` for a non-Git ACC project. A `system_complete` finish requires the complete Read/Create/Update/Delete/transition/execute/composite business surface to be materialized or objectively ineligible, with zero `blocked_on_evidence`, deferred Action intent, or eligible Action exclusion. Copy every audit warning into both risk artifacts; state route and interaction scope plus independently proven verification levels. `headless_verified`, `source_connected_verified`, and `client_adapter_verified` never imply one another; then stop for human review.
