# ACC Engineer Harness

This is the single platform-neutral operating method for ACC onboarding. Platform integrations may point here but must not fork it.

## Contract

Inputs:

- an explicit existing-system checkout, `source_workspace`;
- a distinct writable `acc_project` directory;
- a user goal describing useful business capabilities;
- only test/local credentials supplied through environment references.

Outputs are confined to `acc_project`. The source checkout is evidence, never an implementation target.

## Invariants

1. Resolve both paths before reading broadly. Reject equality, nesting in either direction, `..`, and symlink ambiguity.
2. Capture a source snapshot before work and verify it again before handoff.
3. Read bounded regular files only. Do not follow repository symlinks or inspect common secret files.
4. Evidence precedes every formal Operation. Unknown facts remain unknown.
5. Read Operations are atomic `GET`/`HEAD` REST calls. Action Operations require explicit effect and safety evidence. 一接口一工具不是天然缺陷; choose Capability boundaries from business intent and data flow, not tool count.
6. Runtime behavior is deterministic and model-free. Credentials stay in SecretRef/environment boundaries.
7. Permission, tenant, disclosure, timeout, and response-size controls are testable contracts.
8. Failures remain visible in diagnostics and handoff artifacts.
9. Default unspecified existing-system scope to `system_complete`; use `pilot` only after explicit user MVP confirmation is recorded.
9a. `system_complete` covers the full business surface: Read, Create, Update, Delete, transition, execute, and composite intents. It is not synonymous with every route being classified or with a Read-only delivery.
10. Separate 浅层全局发现 from bounded deep Evidence includes, and never use `--include` as the discovery denominator.
11. Authentication belongs to `provider.auth`: `none`, `bearer_secret`, or `password_bearer`; Operation 不得保存 `credential_ref`, and account/password/JWT values never enter project files.
12. Request identity comes only from immutable `PrincipalContext`. `context_bindings` inject trusted principal/tenant values into evidenced path/query inputs and cannot be supplied by an Agent or Workflow.
13. Frontend route usage is normalized into `usage_evidence_sources`; client business semantics are separately normalized into `ui-interaction-inventory.yaml` and adopted through an `InteractionContract`.
14. Scope Inventory is the only authority for exclusion rules, route decisions, Evidence, replacement closure, and exact user approval. Capability Plan stores references, not duplicate free-text exclusion facts.
15. Convert captured Evidence into `SourceContract` request/response schemas and pointer-level `provenance`. Operation 输入 is an evidenced safe subset; Operation 输出 covers evidenced source responses; Capability 输出 may narrow only through a 可证明 deterministic projection.
16. Every Capability plan records selector acquisition, an empty success path where list/search can legitimately return nothing, failure isolation, and output budget. Producer edges must make required selectors constructible.
17. Coverage keeps route disposition, Operation trace, scenarios, constructability, discoverability, composition, schema fidelity, output budget, and live observations independent; it does not generate an aggregate score or equate route closure with usability.
18. An Action uses `prepare → approve → commit → status`, complete safety contracts, trusted approval handles, and isolated sandbox validation; 不得简单放开 POST.
18a. Missing sandbox authorization or Action safety Evidence forces `eligibility=undetermined` and `disposition=blocked_on_evidence`. It blocks domain and system completion; it does not justify `excluded`, `ineligible`, or disappearance from the denominator.
18b. In `system_complete`, an eligible Action intent cannot be completed by exclusion. Route composition is valid only when the replacement preserves the same mutation intent and full Action lifecycle; otherwise choose an explicitly confirmed `pilot` or report the system as incomplete.
19. Client discovery records surfaces, events, bindings, defaults, options, conditions, related data, states, and unknowns. A hidden/disabled control 不是授权；前端默认值和前端条件不得冒充 `SourceContract`。
20. 全局浅扫先建立 Candidate Ledger、`DomainMap` 和依赖顺序；领域深扫不能反向缩小全局分母。
21. 一次只激活一个依赖已就绪的领域。先确认业务目标和 `DomainPolicy`，再深扫并自动处理证据清晰候选；绝不把全部 route 交给用户选择。
22. 一次只问一个异常、冲突、高风险策略或用户控制的测试边界；普通证据清晰候选不占用用户决策。
23. 每个领域结束时逐项复核独立轴并确认版本化 `DomainDecision`，然后才进入下一个领域。
24. 源 JWT/接口最终裁决源权限；Scope 只能收窄；Action approval 不是授权，只确认本次 prepared execution。
25. The Coding Agent is the AI Domain Intent Planner. It emits and revises `intent-plan.yaml`; ACC Core and Runtime never call an LLM.
26. Capability quantity is an Evidence-derived result. Fixed tool quotas, route-per-tool defaults, evidence-free merging, and catch-all management tools are prohibited.
27. The user confirms `DomainPolicy`, user-controlled test boundaries, and exceptional/high-risk choices only; the Planner owns ordinary intent grouping and never asks the user to set a tool count.
28. Every denominator route appears in an intent candidate or remains explicitly blocked. If a route belongs to multiple intents, `IntentRelationship` must explain the shared boundary with Evidence; merge/split/compose rationale must address permission, risk, data flow, and failure semantics.

## State machine

Advance only when the current gate passes:

```text
PREFLIGHT -> GLOBAL_ANALYZE -> INTENT_PLAN -> DOMAIN_POLICY -> DOMAIN_DEEP_SCAN -> DOMAIN_REVIEW
          -> (NEXT_READY_DOMAIN | MODEL -> PLAN -> IMPLEMENT)
          -> VALIDATE -> TEST -> REFINE -> HANDOFF -> STOP
```

On path separation, source immutability, secret, or production-access safety failure, transition to `STOP` and report the blocker. On candidate Evidence or sandbox-authorization failure, keep that candidate `blocked_on_evidence`, stop its Implement/Test path, and continue only safe discovery; do not advance the affected domain or claim system completion. On a validation or test failure, stay in that phase, fix only the ACC project, and rerun the focused gate before later gates.

## Phase protocol

### 0. Preflight

Canonicalize both paths with `pwd -P` or `realpath`. Declare `system_complete` by default; `pilot` requires explicit user MVP wording and recorded confirmation. Record that the default denominator includes Read/Create/Update/Delete/transition/execute/composite intents. For a new target, create the distinct project directory with `acc init <acc_project>`, enter it, then run `acc doctor --json`; do not run Doctor against an uninitialized empty directory. Run the bundled preflight and read-only verification scripts with Python 3.12. Confirm checkout identity, separate paths, route discovery inputs, test discoverability, and absence of likely production secrets. Record a source snapshot. Missing write-sandbox authorization blocks discovered Actions but does not stop read-only global discovery or remove them from the denominator. Stop only the unsafe Action implementation/test path on that blocker.

### 1. Analyze

Perform shallow global discovery across route registrations, OpenAPI, and client surfaces to establish the complete route/interaction denominator, Candidate Ledger, `DomainMap`, dependency order, and initial `intent-plan.yaml`. Do not offer the route list as user choices. The Coding Agent proposes initial intent boundaries without a fixed quantity goal and accounts for every route; uncertain boundaries remain gaps. Activate exactly one dependency-ready domain, confirm only its business goals and `DomainPolicy`, and only then use repeatable workspace-relative `--include` paths for that domain's deep Evidence inspection. Normalize calls into route usage and client semantics independently; UI evidence cannot upgrade authorization or `SourceContract` authority. Automatically model evidence-clear candidates and ask one question at a time only for exceptions or high-risk choices.

### 2. Model

Normalize only the active, policy-confirmed domain: entities, relations, Read and Action operations, source authorization boundary, tenant derivation, interaction dependency graph, existing tests, and uncertainty. Add `scope_route_ids` to every candidate Operation and retain route `interaction_ids`. Source JWT remains final; Scope and approval add restrictions rather than authority. Do not add speculative abstractions.

### 3. Plan

Present the active domain's independent axes and versioned candidate dispositions. Finalize `intent-plan.yaml` from Evidence: choose single, parameterized, or composite boundaries; record merge/split/compose rationale; and derive the portfolio without a quota. Bind its `DomainDecision` to the previously confirmed `DomainPolicy` and any explicit exception/high-risk decision; do not ask the user to approve tool quantity or ordinary route grouping. User deferral remains distinct from an evidence blocker. Only accepted, evidenced candidates enter Capability Plan. A system-complete DomainDecision cannot be completed while an Action is deferred, excluded, or blocked; lack of write-sandbox authorization remains `blocked_on_evidence`. After a domain is policy-bound and reviewed, continue with the next dependency-ready domain; never batch all route decisions into one prompt. The final Plan closes the Read/Create/Update/Delete/transition/execute/composite business surface plus both route and interaction denominators, and keeps credentials, tenant identity, and server-derived values out of agent inputs.

### 4. Implement

Write only under `acc_project`, and implement only planned/composed routes and evidenced interaction adoptions: Evidence, SourceContracts, Operations, Capabilities, InteractionContracts, Policies, Evals, and fixtures. Prove schema fidelity, output projection, and every adopted default/binding/condition. Select Provider auth from evidence; trusted values stay outside public inputs. Action definitions retain `prepare → approve → commit → status`. Freeze evidence digests from exact source material. No source-system edits or generated artifacts outside the project.

### 5. Validate

Run `scope_audit.py` first, then `interaction_audit.py` when a client surface was discovered; retain both reports. Only after they have no errors run `validate`, `compile --check`, and `coverage`. Inspect every independent source and interaction axis; warning-only is non-blocking but remains a handoff risk.

For `system_complete`, require exact discovery denominator closure and inspect the structured
`release_readiness` result independently. A `limited` result may contain known, classified,
explicitly non-executable `blocked` routes while `unknown` remains zero; those routes stay outside
Operations and Capabilities and are listed as handoff blockers. Missing/unclassified routes,
smuggled executable traces, or unresolved routes selected as planned/composed still fail closed.

### 6. Test

Run contract and direct Fake Runtime suites as `offline_candidate`; record `headless_verified` only when every required normalized interaction scenario passes. Keep Gateway/Fake Source protocol evidence distinct. `source_connected_verified` requires an authorized local/test source run, while `client_adapter_verified` requires the real client adapter to replay the same contract successfully. None implies another. Exercise defaults, options, cascades, related data, states, permissions, identity, and the Action lifecycle without exposing secrets.

### 7. Refine

Compare the ten core axes, including `tool_portfolio`, and ten interaction axes independently: `surface_disposition`, `interaction_trace`, `input_binding_fidelity`, `default_provenance`, `option_resolution`, `condition_coverage`, `related_data_graph`, `state_scenarios`, `presentation_projection`, and `client_adapter_evidence`. Do not generate a total score. Reconcile `intent-plan.yaml` route coverage, `IntentRelationship` Evidence, and boundary rationale against the materialized portfolio. Detect route-per-tool generation, fixed-count optimization, evidence-free merges, catch-all tools, portfolio explosion, same-intent overlap, isolated mutations, under-covered materialized routes, orphaned interactions, unproven defaults, unsafe conditions, broken related-data graphs, frontend-used exclusions, and denominator distortion. Rerun both audits, validation, and tests after each material change.

### 8. Handoff

Verify the source snapshot is unchanged. Build the pack twice and compare digests. Deliver the Evidence-finalized `intent-plan.yaml` and every blocked boundary; report derived Capability/MCP counts separately from the strict plan artifact. State route scope, interaction scope, full business-surface disposition, and each independently proven verification level. Never label `system_complete` complete when any eligible Action/composite intent is excluded, deferred, or `blocked_on_evidence`. A source-connected result never becomes client-adapter proof. Produce review artifacts with exact commands/results, limitations, and risks. Do not commit or push unless separately requested; stop for human review.

## Handoff truth rules

- `HANDOFF.md` summarizes outcomes and validation limits without claiming deployment.
- `coverage-report.json` is copied from current structured coverage output.
- `test-report.json` identifies each suite and real pass/fail counts.
- `risk-report.json` includes unresolved evidence, auth, tenant, schema, runtime, deployment risks, and every scope-audit warning; `HANDOFF.md` repeats those warnings for human review.
- A Git `candidate.diff` contains only ACC project changes; a non-Git `artifact-manifest.json` records sorted file hashes without file content. Neither substitutes for source verification.
- `system_complete` is a completion claim only when every discovered business intent is materialized or objectively ineligible. Read closure, structured exclusions, or a user choice not to authorize write testing cannot substitute for unresolved Action evidence.

Never label a skipped test as passed, a placeholder digest as evidence, or a local result as production proof.
