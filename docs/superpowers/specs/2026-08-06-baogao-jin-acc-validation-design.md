# Baogao Jin ACC Validation Design

## Outcome

Use `/Users/chou/code/baogao-jin` as an existing, immutable source system to validate the complete ACC Engineer workflow against a realistic multi-user FastAPI application. The result is an independent ACC project that compiles a small, evidence-bound business capability slice into a deterministic Capability Pack and exposes it through the generic MCP stdio Runtime.

This is a validation of Agent Capability Compiler, not a modification or deployment of Baogao Jin.

## Workspace boundaries

- Source workspace: `/Users/chou/code/baogao-jin`.
- ACC project: `/Users/chou/code/baogao-jin-acc`.
- The two canonical paths must be distinct and non-nested.
- Baogao Jin is read-only evidence. Do not modify, format, generate into, install dependencies in, start, restart, migrate, seed, test, commit, or deploy it.
- Record Baogao Jin's initial Git commit and dirty-worktree state before analysis, then verify that exact baseline again at handoff.
- Write all Evidence, Operations, Capabilities, Policies, Evals, fixtures, build output, and handoff artifacts only inside the ACC project.
- Do not access production services, production data, or production credentials.

## Representative business slice

The first validation slice models an authenticated user's customer context rather than the external public-query integration.

Candidate read-only operations are limited to existing `GET` endpoints supported by source, schema, authorization, tenant, and test evidence:

1. Read the current authenticated user, tenant membership, permissions, and menu context.
2. Search customers visible to that user.
3. Read one visible customer's overview.
4. List reports and certificate records visible for that customer when the user's permissions allow them.

The Analyze phase may narrow or block any candidate whose path, response schema, permission requirement, tenant/data-space behavior, or error behavior lacks sufficient evidence. It must not replace an unsupported candidate with an invented route.

The planned business capabilities are:

- `inspect_current_access`: explain the current test identity's effective user, tenant, and read permissions without exposing the JWT or internal secret material.
- `search_visible_customers`: return only customers visible to the authenticated test user.
- `get_customer_document_context`: compose a visible customer overview with only the report and certificate summaries authorized for that user.

## Authentication and multi-user model

Baogao Jin remains the authority for authentication, tenant membership, custom-role permissions, and data-space access.

- The MCP Runtime does not accept usernames, passwords, JWTs, tenant IDs, permission grants, or base URLs as tool arguments.
- Login is outside the ACC MVP because Baogao Jin's login is a write-method operation and ACC formal Operations support only `GET` and `HEAD`.
- Each test identity receives a JWT before Runtime startup through an environment-backed SecretRef.
- The first version runs one MCP stdio Runtime process per test identity. It does not multiplex multiple users through one shared credential.
- Runtime scope and tenant configuration must match the identity under test. They are defense-in-depth policy inputs, not replacements for Baogao Jin's authorization checks.
- No administrator or all-powerful shared JWT is used to simulate ordinary users.

At minimum, test identities should represent:

1. A user with the required customer and document read permissions.
2. A user missing at least one document read permission.
3. A user in a different tenant or data space for negative isolation tests.

Only local or isolated test credentials may be used. If suitable identities cannot be provided safely, live E2E validation is reported as blocked while deterministic fake-system tests remain eligible to run.

## Evidence and modelling

Run the ACC Engineer state machine in order:

`PREFLIGHT -> ANALYZE -> MODEL -> PLAN -> IMPLEMENT -> VALIDATE -> TEST -> REFINE -> HANDOFF`

Analysis must cross-check route definitions, response schemas, shared authentication dependencies, permission catalog entries, tenant/data-space helpers, frontend API clients, and existing static tests. Every formal Operation must bind method, path, parameters, output fields, permissions, tenant boundary, effects, and expected errors to captured Evidence with stable digests.

Facts, conflicts, and unknowns remain separate. Existing Baogao Jin worktree changes are user-owned and must not be interpreted as stable released behavior without corroborating evidence.

## Runtime data flow

1. The host starts one generic ACC MCP stdio Runtime for a test identity.
2. Runtime resolves the Baogao Jin test base URL and JWT from environment references.
3. An Agent calls a business capability without receiving or supplying credentials.
4. Runtime validates the capability input, injects runtime-only policy context, and executes only compiled `GET` Operations against the fixed test origin.
5. Baogao Jin validates the JWT, tenant membership, permissions, and data-space access.
6. ACC validates upstream response schemas, maps errors, applies output allowlists and redaction, and returns bounded structured MCP output.

The Runtime must never dynamically create routes, change origins, perform login, retry through a different identity, or widen access after a permission failure.

## Error and disclosure contracts

The Pack and tests must distinguish at least:

- missing or invalid JWT;
- insufficient permission;
- hidden cross-tenant or cross-space resource;
- resource not found;
- empty customer or document result;
- upstream timeout;
- oversized response;
- invalid JSON or output-schema mismatch.

Capability output must omit credentials, authorization headers, password hashes, internal secret fields, and unnecessary tenant/data-space identifiers. A denied document sub-operation must not silently produce a result that implies the user has complete document visibility.

## Test strategy

The ACC project must pass the deterministic gates from its own directory:

```bash
acc doctor --json
acc validate --json
acc compile --check --json
acc coverage --json
acc test contract --json
acc test runtime --json
acc test e2e --json
```

Contract and Runtime tests use ACC-owned fixtures and a fake REST boundary to cover normal, empty, 401, 403, 404, cross-tenant/data-space, timeout, oversized-response, schema-error, MCP tool-list, and MCP tool-call behavior without running Baogao Jin.

Live E2E is optional and may target only an already available local or isolated Baogao Jin test service. It must not start Baogao Jin, mutate its database, call write endpoints, or use production configuration. Skipped or blocked live E2E is reported honestly and is not labelled as passed.

Build the final `.accpkg` twice from unchanged inputs and compare SHA-256 digests.

## Deliverables and completion

The independent ACC project must contain:

- `preflight-report.json` and `source-baseline.json`;
- `system-map.yaml`, `analysis-report.md`, and captured `evidence/`;
- `capability-plan.yaml` and `coverage-baseline.json`;
- evidence-bound Operations, Capabilities, Policies, Evals, and fixtures;
- `HANDOFF.md`, `coverage-report.json`, `test-report.json`, `risk-report.json`, and `candidate.diff`;
- a deterministic Capability Pack when all required compile and pack gates pass.

Completion means the ACC workflow and its validation limits are demonstrated. It does not mean Baogao Jin was changed, deployed, production-tested, or certified secure. The process stops for human Git review and does not push changes.
