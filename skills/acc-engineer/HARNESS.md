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
13. Frontend usage is normalized into `usage_evidence_sources`; excluding such a route always warns, and system-complete scope treats an unapproved exact route as an error.
14. Scope Inventory is the only authority for exclusion rules, route decisions, Evidence, replacement closure, and exact user approval. Capability Plan stores references, not duplicate free-text exclusion facts.
15. Convert captured Evidence into `SourceContract` request/response schemas and pointer-level `provenance`. Operation 输入 is an evidenced safe subset; Operation 输出 covers evidenced source responses; Capability 输出 may narrow only through a 可证明 deterministic projection.
16. Every Capability plan records selector acquisition, an empty success path where list/search can legitimately return nothing, failure isolation, and output budget. Producer edges must make required selectors constructible.
17. Coverage keeps route disposition, Operation trace, scenarios, constructability, discoverability, composition, schema fidelity, output budget, and live observations independent; it does not generate an aggregate score or equate route closure with usability.
18. An Action uses `prepare → approve → commit → status`, complete safety contracts, trusted approval handles, and isolated sandbox validation; 不得简单放开 POST.

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

Perform shallow global discovery across route registrations, OpenAPI, and client surfaces to establish `scope-inventory.yaml`. Normalize frontend usage Evidence into route fields; the scope auditor does not parse Vue, React, or other framework source. Only then use repeatable workspace-relative `--include` paths for deep Evidence inspection of relevant controllers, services, models, auth, tests, and docs. Bind every interface and permission claim to a locator plus digest, then normalize it into `SourceContract` `request_schema`, `response_schema`, completeness, and pointer-level `provenance`. Produce a system map and analysis report; list gaps.

### 2. Model

Normalize only the observed domain: entities, relations, read operations, permission scopes, tenant derivation, existing tests, and uncertainty. Add `scope_route_ids` to every candidate Operation so it traces to discovered routes. Separate upstream authorization from ACC output disclosure. Do not add speculative abstractions.

### 3. Plan

Assign every eligible discovered route exactly one disposition: `planned`, `composed`, `excluded`, or `blocked_on_evidence`; `out_of_scope` is valid only where the declared mode permits it. System-complete exclusions require a structured rule and distinct route decision, which replace a free-text route reason only when valid; subjective and frontend-used exclusions require exact route approval. Ineligible, blocked, out-of-scope, and pilot/domain exclusions keep reason plus Evidence. Capability Plan route lists and decision pointers exactly close over Inventory without duplicate free text. Never count `blocked_on_evidence` as complete. Reconcile the `source_scope` baseline, then design business capabilities with explicit selector acquisition, empty success path, failure isolation, and output budget. Keep credentials, tenant identity, and server-derived values out of agent inputs. Require positive and permission-negative Evals where applicable. Do not advance with unresolved scope.

### 4. Implement

Write only under `acc_project`, and implement only routes disposed as `planned` or `composed`: Evidence, SourceContracts, Operations, Capabilities, CapabilityQuality, Policies, Evals, and fixtures. Prove Operation schema fidelity and every Capability output projection. Select Provider auth from evidence: `none`, environment-backed `bearer_secret`, or `password_bearer`; new Operations never carry `credential_ref`. For `stdio`, password login uses `environment_secret`; `streamable_http` requires `gateway_session`. Add `context_bindings` only for evidenced trusted path/query inputs and keep those targets out of Capability inputs and Workflow arguments. Freeze evidence digests from exact source material. No source-system edits or generated artifacts outside the project.

### 5. Validate

Run `scope_audit.py --project <acc_project>` first and retain `scope-audit-report.json`. Only after it has no errors run `validate`, `compile --check`, and `coverage` with `--json`. Inspect `ok`, diagnostics, and findings: warning-only is non-blocking but every warning remains a handoff risk. Fix one diagnostic class at a time and rerun from the scope audit.

### 6. Test

Run contract and direct Fake Runtime suites as `offline_candidate`. Label the real Gateway protocol path against a Fake Source `gateway_offline_verified`. Exercise normal, empty, 404, insufficient scope, cross-tenant, redaction, timeout, response-too-large, error mapping, MCP list, and MCP call behavior. Test `PrincipalContext`, effective scopes, Provider auth, and every declared `context_bindings` target without exposing identity or credentials through MCP tools. Treat `stdio` as one fixed identity; do not claim `streamable_http` until its Gateway request identity path is actually exercised. A `source_connected_verified` result additionally requires explicit local/test connection authorization and a successful source-connected run; never infer it from Fake tests.

### 7. Refine

Compare all Coverage axes independently: route disposition, Operation trace, scenario coverage, constructability, discoverability graph, composition, schema fidelity, output budget, and live observations. Do not generate a total score. Detect duplicate decisions, whole-domain zero capability, frontend-used exclusions, and the high-exclusion heuristic (eligible `>= 10`, excluded `>= 70%`). Remove orphaned or duplicate definitions, correct evidence-unsupported schemas, and add missing valuable or negative coverage. Rerun scope audit, validation, and tests after each material change.

### 8. Handoff

Verify the source snapshot is unchanged. Build the pack twice and compare digests. State the scope mode and validation level. Produce review artifacts with exact commands/results, paths, limitations, and risks. For a Git ACC project provide `candidate.diff`; for a non-Git project generate `artifact-manifest.json` with the bundled deterministic helper. Do not commit or push unless separately requested; stop for human review.

## Handoff truth rules

- `HANDOFF.md` summarizes outcomes and validation limits without claiming deployment.
- `coverage-report.json` is copied from current structured coverage output.
- `test-report.json` identifies each suite and real pass/fail counts.
- `risk-report.json` includes unresolved evidence, auth, tenant, schema, runtime, deployment risks, and every scope-audit warning; `HANDOFF.md` repeats those warnings for human review.
- A Git `candidate.diff` contains only ACC project changes; a non-Git `artifact-manifest.json` records sorted file hashes without file content. Neither substitutes for source verification.

Never label a skipped test as passed, a placeholder digest as evidence, or a local result as production proof.
