# ACC Engineer handoff: Synthetic FastAPI CRM

## Outcome

This candidate is ready for human Git review. It exposes three read-only capabilities from six
evidence-bound REST Operations:

- `search_customers` searches tenant-visible customers.
- `get_customer_context` composes customer, contacts, followups, and todos through four lower-level
  Operations; contact email is masked and tenant fields are removed.
- `find_overdue_followups` returns open followups before an explicit deterministic date.

The source system is `../system`; the isolated ACC project is this directory. Runtime configuration
uses Provider-level `bearer_secret` through the `CRM_DEMO_TOKEN` environment reference, plus
`CRM_BASE_URL`, deployment scopes, and tenant context. All six Operations omit
`credential_ref`. Credential values, tenant, base URL, and authorization headers are not Agent tool
inputs.

All six Operations declare the trusted `tenant_id -> tenant_context.tenant_id` context binding;
tenant identity is restored from the fixed stdio `PrincipalContext`, never accepted from Agent
input. `streamable_http` Gateway and request-level multi-user identity were not exercised by this
example.

## Evidence and source integrity

Routes, auth/scope/tenant rules, strict response models, and source tests are referenced by file,
line locator, and whole-file SHA-256 digest. `acc freeze <operation> --json` refreshed every formal
Operation. Final read-only verification matched the Phase 0 snapshot:

`sha256:fc9ef130276ca53951bf651ed6718469bf3db7267e499277e2072d945cb5c498`

- Original source-system changes after baseline: **0**
- Formal Operations without Evidence: **0**
- Invented endpoints: **0**
- Write Operations: **0**
- Runtime LLM calls: **0**

## Final validation

- `acc validate --json`: 3 capabilities, 9 evals, 6 operations, 3 policies; no diagnostics.
- `acc compile --check --json`: passed; IR SHA-256
  `da3598860f83cc01fd0824f68ba8ca6a7862e5f89700c7594891edf4d6de4258`.
- `acc coverage --json`: no orphan Operations or missing eval/permission-negative coverage; two
  low-risk one-interface heuristics are retained and explained in `risk-report.json`.
- Contract, Runtime, and E2E suites: each 9/9 passed against the local synthetic CRM.
- Pack built twice byte-identically on 2026-08-06: SHA-256
  `6d13a596446fa7dd7cbe34d7345fd642d75bfca918fff7825de91686a18d97b5`.
- Repository on 2026-08-06: 720 tests passed; Ruff lint, changed-file format checks, and strict
  mypy for 102 files passed. Repository-wide Ruff format remains open on nine files outside this
  migration, including the immutable synthetic source and separate scope-governance work.
- Independent source system: 34 tests passed; Ruff and strict mypy passed.
- Real MCP stdio initialized, listed all three tools, and called `get_customer_context` without a
  token in tool arguments or stderr.
- Stable 404, 403, timeout, and response-too-large mappings were exercised.

See `coverage-report.json`, `test-report.json`, and `risk-report.json` for machine-readable detail.

## Validation limits

Validation level is `source_connected_verified` only for the explicitly started local synthetic CRM;
the ACC Contract suite and isolated fixture coverage are also `offline_candidate`. No production
system, credential, deployment, write path, rate limit, availability target, `streamable_http`
Gateway, or unrelated source checkout was tested. The FastAPI source generates OpenAPI at runtime
rather than storing it as a checked-in file. Timeout and oversize responses were simulated at the
generic HTTP transport boundary. These are documented limits, not production assurances.

## Human review order

1. Review `system-map.yaml`, `analysis-report.md`, and `evidence/` against `../system`.
2. Review Operations, Policies, and the composed `get_customer_context` workflow.
3. Review all nine Evals and the machine-readable reports.
4. Review the Git diff, rerun the commands in `../README.md`, and decide whether to merge.

No deployment or push was performed.
