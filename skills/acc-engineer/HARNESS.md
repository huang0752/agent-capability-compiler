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

## State machine

Advance only when the current gate passes:

```text
PREFLIGHT -> ANALYZE -> MODEL -> PLAN -> IMPLEMENT
          -> VALIDATE -> TEST -> REFINE -> HANDOFF -> STOP
```

On a safety or evidence failure, transition to `STOP` and report the blocker. On a validation or test failure, stay in that phase, fix only the ACC project, and rerun the focused gate before later gates.

## Phase protocol

### 0. Preflight

Canonicalize both paths with `pwd -P` or `realpath`. For a new target, create the distinct project directory with `acc init <acc_project>`, enter it, then run `acc doctor --json`; do not run Doctor against an uninitialized empty directory. Run the bundled preflight and read-only verification scripts with Python 3.12. For a large checkout, pass the same repeatable, workspace-relative `--include` boundaries to Preflight, Inventory, and both source-snapshot calls; do not broaden the scan merely to include generated dependencies, repository metadata, local environments, or binary assets that cannot become Evidence. Confirm checkout identity, separate paths, OpenAPI/test discoverability, and absence of likely production secrets in the intended inputs. Record a source snapshot. Stop on ambiguity or risk.

### 1. Analyze

Inspect README, routes/controllers, services, models, auth and tenant middleware, frontend API clients, OpenAPI, tests, SOPs, and sample data. Bind every interface and permission claim to a file/line, JSON Pointer, or OpenAPI operation plus digest. Produce a system map and analysis report; list gaps.

### 2. Model

Normalize only the observed domain: entities, relations, read operations, permission scopes, tenant derivation, existing tests, and uncertainty. Separate upstream authorization from ACC output disclosure. Do not add speculative abstractions.

### 3. Plan

Design the smallest valuable business capabilities. Combine related operations when the user goal needs context. Keep credentials, tenant identity, and server-derived values out of agent inputs. Require at least one positive Eval per capability and a permission-negative Eval for protected capabilities. When the user goal or security evidence is incomplete, emit a plan with `status: blocked_on_evidence` and do not advance.

### 4. Implement

Write only under `acc_project`: Evidence, Operations, Capabilities, Policies, Evals, and test fixtures. Use current schemas and templates. Freeze evidence digests from exact source material. No source-system edits or generated artifacts outside the project.

### 5. Validate

Run `validate`, `compile --check`, and `coverage` with `--json`. Inspect `ok`, `diagnostics`, and findings. Fix one diagnostic class at a time and rerun it. Never suppress a validator or widen a schema merely to make it pass.

### 6. Test

Run contract, runtime, and E2E suites. Exercise normal, empty, 404, insufficient scope, cross-tenant, redaction, timeout, response-too-large, error mapping, MCP list, and MCP call behavior as applicable. Inspect results, calls, output schemas, forbidden fields, and stable errors.

### 7. Refine

Compare System Map, Operations, Capabilities, and Evals. Remove orphaned or duplicate definitions; tighten broad schemas; replace one-interface-one-tool designs with useful compositions; add missing high-value and negative coverage. Rerun validation and all tests after each material change.

### 8. Handoff

Verify the source snapshot is unchanged. Build the pack twice and compare digests. Produce the five review artifacts, including exact commands/results, source/ACC paths, evidence limitations, remaining risks, and a candidate diff. Do not commit or push unless the user separately requests it; stop for human review.

## Handoff truth rules

- `HANDOFF.md` summarizes outcomes and validation limits without claiming deployment.
- `coverage-report.json` is copied from current structured coverage output.
- `test-report.json` identifies each suite and real pass/fail counts.
- `risk-report.json` includes unresolved evidence, auth, tenant, schema, runtime, and deployment risks.
- `candidate.diff` contains only ACC project changes and is never a substitute for source verification.

Never label a skipped test as passed, a placeholder digest as evidence, or a local result as production proof.
