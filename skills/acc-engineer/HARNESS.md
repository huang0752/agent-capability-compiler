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
10. Separate 浅层全局发现 from bounded deep Evidence includes, and never use `--include` as the discovery denominator.
11. Authentication belongs to `provider.auth`: `none`, `bearer_secret`, or `password_bearer`; Operation 不得保存 `credential_ref`, and account/password/JWT values never enter project files.
12. Request identity comes only from immutable `PrincipalContext`. `context_bindings` inject trusted principal/tenant values into evidenced path/query inputs and cannot be supplied by an Agent or Workflow.
13. Frontend route usage is normalized into `usage_evidence_sources`; client business semantics are separately normalized into `ui-interaction-inventory.yaml` and adopted through an `InteractionContract`.
14. Scope Inventory is the only authority for exclusion rules, route decisions, Evidence, replacement closure, and exact user approval. Capability Plan stores references, not duplicate free-text exclusion facts.
15. Convert captured Evidence into `SourceContract` request/response schemas and pointer-level `provenance`. Operation 输入 is an evidenced safe subset; Operation 输出 covers evidenced source responses; Capability 输出 may narrow only through a 可证明 deterministic projection.
16. Every Capability plan records selector acquisition, an empty success path where list/search can legitimately return nothing, failure isolation, and output budget. Producer edges must make required selectors constructible.
17. Coverage keeps route disposition, Operation trace, scenarios, constructability, discoverability, composition, schema fidelity, output budget, and live observations independent; it does not generate an aggregate score or equate route closure with usability.
18. An Action uses `prepare → approve → commit → status`, complete safety contracts, trusted approval handles, and isolated sandbox validation; 不得简单放开 POST.
19. Client discovery records surfaces, events, bindings, defaults, options, conditions, related data, states, and unknowns. A hidden/disabled control 不是授权；前端默认值和前端条件不得冒充 `SourceContract`。

## State machine

Advance only when the current gate passes:

```text
PREFLIGHT -> ANALYZE -> MODEL -> PLAN -> IMPLEMENT
          -> VALIDATE -> TEST -> REFINE -> HANDOFF -> STOP
```

On a safety or evidence failure, transition to `STOP` and report the blocker. On a validation or test failure, stay in that phase, fix only the ACC project, and rerun the focused gate before later gates.

## Phase protocol

### 0. Preflight

Canonicalize both paths with `pwd -P` or `realpath`. Declare `system_complete` by default; `pilot` requires explicit user MVP wording and recorded confirmation. For a new target, create the distinct project directory with `acc init <acc_project>`, enter it, then run `acc doctor --json`; do not run Doctor against an uninitialized empty directory. Run the bundled preflight and read-only verification scripts with Python 3.12. Confirm checkout identity, separate paths, route discovery inputs, test discoverability, and absence of likely production secrets. Record a source snapshot. Stop on ambiguity or risk.

### 1. Analyze

Perform shallow global discovery across route registrations, OpenAPI, and client surfaces to establish `scope-inventory.yaml` and `ui-interaction-inventory.yaml`. Normalize calls into route usage, then independently normalize surfaces/events/bindings/defaults/options/conditions/related data/states/unknowns with immutable Evidence. The auditors do not parse or execute framework source. Only then use repeatable workspace-relative `--include` paths for deep Evidence inspection. Bind every interface and permission claim to a locator plus digest and normalize source contracts separately; UI evidence cannot upgrade authorization or `SourceContract` authority. Produce a system map and analysis report; list gaps.

### 2. Model

Normalize only the observed domain: entities, relations, Read and Action operations, permission scopes, tenant derivation, interaction dependency graph, existing tests, and uncertainty. Add `scope_route_ids` to every candidate Operation and retain route `interaction_ids`. Separate upstream authorization from UI visibility and ACC output disclosure. Do not add speculative abstractions.

### 3. Plan

Assign every eligible route and high-value interaction a traceable disposition, adoption, or evidence-backed omission. System-complete exclusions keep their structured approval rules. Capability Plan closes over both denominators, records interaction dependencies, and never counts unresolved items as complete. Design business capabilities with explicit selector acquisition, defaults/options provenance, conditional input construction, empty success path, failure isolation, and output budget. Keep credentials, tenant identity, and server-derived values out of agent inputs. Require positive and permission-negative Evals where applicable. Do not advance with unresolved scope.

### 4. Implement

Write only under `acc_project`, and implement only planned/composed routes and evidenced interaction adoptions: Evidence, SourceContracts, Operations, Capabilities, InteractionContracts, Policies, Evals, and fixtures. Prove schema fidelity, output projection, and every adopted default/binding/condition. Select Provider auth from evidence; trusted values stay outside public inputs. Action definitions retain `prepare → approve → commit → status`. Freeze evidence digests from exact source material. No source-system edits or generated artifacts outside the project.

### 5. Validate

Run `scope_audit.py` first, then `interaction_audit.py` when a client surface was discovered; retain both reports. Only after they have no errors run `validate`, `compile --check`, and `coverage`. Inspect every independent source and interaction axis; warning-only is non-blocking but remains a handoff risk.

### 6. Test

Run contract and direct Fake Runtime suites as `offline_candidate`; record `headless_verified` only when every required normalized interaction scenario passes. Keep Gateway/Fake Source protocol evidence distinct. `source_connected_verified` requires an authorized local/test source run, while `client_adapter_verified` requires the real client adapter to replay the same contract successfully. None implies another. Exercise defaults, options, cascades, related data, states, permissions, identity, and the Action lifecycle without exposing secrets.

### 7. Refine

Compare the nine existing axes and ten interaction axes independently: `surface_disposition`, `interaction_trace`, `input_binding_fidelity`, `default_provenance`, `option_resolution`, `condition_coverage`, `related_data_graph`, `state_scenarios`, `presentation_projection`, and `client_adapter_evidence`. Do not generate a total score. Detect orphaned interactions, unproven defaults, unsafe conditions, broken related-data graphs, frontend-used exclusions, and denominator distortion. Rerun both audits, validation, and tests after each material change.

### 8. Handoff

Verify the source snapshot is unchanged. Build the pack twice and compare digests. State route scope, interaction scope, and each independently proven verification level. A source-connected result never becomes client-adapter proof. Produce review artifacts with exact commands/results, limitations, and risks. Do not commit or push unless separately requested; stop for human review.

## Handoff truth rules

- `HANDOFF.md` summarizes outcomes and validation limits without claiming deployment.
- `coverage-report.json` is copied from current structured coverage output.
- `test-report.json` identifies each suite and real pass/fail counts.
- `risk-report.json` includes unresolved evidence, auth, tenant, schema, runtime, deployment risks, and every scope-audit warning; `HANDOFF.md` repeats those warnings for human review.
- A Git `candidate.diff` contains only ACC project changes; a non-Git `artifact-manifest.json` records sorted file hashes without file content. Neither substitutes for source verification.

Never label a skipped test as passed, a placeholder digest as evidence, or a local result as production proof.
