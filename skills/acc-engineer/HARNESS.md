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
5. Operations are atomic, read-only REST calls; Capabilities are business-level compositions, not one-interface-one-tool mirrors.
6. Runtime behavior is deterministic and model-free. Credentials stay in SecretRef/environment boundaries.
7. Permission, tenant, disclosure, timeout, and response-size controls are testable contracts.
8. Failures remain visible in diagnostics and handoff artifacts.
9. Default unspecified existing-system scope to `system_readonly_complete`; use `pilot` only after explicit user MVP confirmation is recorded.
10. Separate 浅层全局发现 from bounded deep Evidence includes, and never use `--include` as the discovery denominator.
11. Authentication belongs to `provider.auth`: `none`, `bearer_secret`, or `password_bearer`; Operation 级 `credential_ref` 只用于 legacy `stdio`, and account/password/JWT values never enter project files.
12. Request identity comes only from immutable `PrincipalContext`. `context_bindings` inject trusted principal/tenant values into evidenced path/query inputs and cannot be supplied by an Agent or Workflow.

## State machine

Advance only when the current gate passes:

```text
PREFLIGHT -> ANALYZE -> MODEL -> PLAN -> IMPLEMENT
          -> VALIDATE -> TEST -> REFINE -> HANDOFF -> STOP
```

On a safety or evidence failure, transition to `STOP` and report the blocker. On a validation or test failure, stay in that phase, fix only the ACC project, and rerun the focused gate before later gates.

## Phase protocol

### 0. Preflight

Canonicalize both paths with `pwd -P` or `realpath`. Declare `system_readonly_complete` by default; `pilot` requires explicit user MVP wording and recorded confirmation. For a new target, create the distinct project directory with `acc init <acc_project>`, enter it, then run `acc doctor --json`; do not run Doctor against an uninitialized empty directory. Run the bundled preflight and read-only verification scripts with Python 3.12. Confirm checkout identity, separate paths, route discovery inputs, test discoverability, and absence of likely production secrets. Record a source snapshot. Stop on ambiguity or risk.

### 1. Analyze

Perform shallow global discovery across route registrations, OpenAPI, and client surfaces to establish `scope-inventory.yaml`. Only then use repeatable workspace-relative `--include` paths for deep Evidence inspection of relevant controllers, services, models, auth, tests, and docs. Bind every interface and permission claim to a locator plus digest. Produce a system map and analysis report; list gaps.

### 2. Model

Normalize only the observed domain: entities, relations, read operations, permission scopes, tenant derivation, existing tests, and uncertainty. Add `scope_route_ids` to every candidate Operation so it traces to discovered routes. Separate upstream authorization from ACC output disclosure. Do not add speculative abstractions.

### 3. Plan

Assign every eligible discovered route exactly one disposition: `planned`, `composed`, `excluded`, or `blocked_on_evidence`; `out_of_scope` is valid only where the declared mode permits it. Reconcile the `source_scope` baseline before designing the smallest valuable business capabilities. Keep credentials, tenant identity, and server-derived values out of agent inputs. Require positive and permission-negative Evals where applicable. Do not advance with unresolved scope.

### 4. Implement

Write only under `acc_project`, and implement only routes disposed as `planned` or `composed`: Evidence, Operations, Capabilities, Policies, Evals, and fixtures. Select Provider auth from evidence: `none`, environment-backed `bearer_secret`, or `password_bearer`; new Operations never carry `credential_ref`. For `stdio`, password login uses `environment_secret`; `streamable_http` requires `gateway_session`. Add `context_bindings` only for evidenced trusted path/query inputs and keep those targets out of Capability inputs and Workflow arguments. Freeze evidence digests from exact source material. No source-system edits or generated artifacts outside the project.

### 5. Validate

Run `scope_audit.py --project <acc_project>` first and retain `scope-audit-report.json`. Only after it passes run `validate`, `compile --check`, and `coverage` with `--json`. Inspect `ok`, diagnostics, and findings. Fix one diagnostic class at a time and rerun from the scope audit.

### 6. Test

Run contract, Fake Runtime, and Fake E2E suites and label the result `offline_candidate`. Exercise normal, empty, 404, insufficient scope, cross-tenant, redaction, timeout, response-too-large, error mapping, MCP list, and MCP call behavior. Test `PrincipalContext`, effective scopes, Provider auth, and every declared `context_bindings` target without exposing identity or credentials through MCP tools. Treat `stdio` as one fixed identity; do not claim `streamable_http` until its Gateway request identity path is actually exercised. A `source_connected_verified` result additionally requires explicit local/test connection authorization and a successful source-connected run; never infer it from Fake tests.

### 7. Refine

Compare three layers independently: source-route disposition coverage, Operation-to-source trace coverage, and Capability/Eval scenario coverage. Remove orphaned or duplicate definitions, tighten broad schemas, and add missing valuable or negative coverage. Rerun scope audit, validation, and tests after each material change.

### 8. Handoff

Verify the source snapshot is unchanged. Build the pack twice and compare digests. State the scope mode and validation level. Produce review artifacts with exact commands/results, paths, limitations, and risks. For a Git ACC project provide `candidate.diff`; for a non-Git project generate `artifact-manifest.json` with the bundled deterministic helper. Do not commit or push unless separately requested; stop for human review.

## Handoff truth rules

- `HANDOFF.md` summarizes outcomes and validation limits without claiming deployment.
- `coverage-report.json` is copied from current structured coverage output.
- `test-report.json` identifies each suite and real pass/fail counts.
- `risk-report.json` includes unresolved evidence, auth, tenant, schema, runtime, and deployment risks.
- A Git `candidate.diff` contains only ACC project changes; a non-Git `artifact-manifest.json` records sorted file hashes without file content. Neither substitutes for source verification.

Never label a skipped test as passed, a placeholder digest as evidence, or a local result as production proof.
