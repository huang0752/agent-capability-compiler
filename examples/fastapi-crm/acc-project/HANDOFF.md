# ACC Engineer handoff: Synthetic FastAPI CRM

## Outcome

This candidate is ready for human Git review. It exposes three read-only capabilities from six
evidence-bound REST Operations:

- `search_customers` searches tenant-visible customers.
- `get_customer_context` composes customer, contacts, followups, and todos through four lower-level
  Operations; contact email is masked and tenant fields are removed.
- `find_overdue_followups` returns open followups before an explicit deterministic date.

`ui-interaction-inventory.yaml` truthfully declares interaction scope `none`. The source contains
FastAPI routes and API tests, but no applicable browser, mobile, desktop, command, or other client
surface. Its evidence sources and rationale record that boundary; surfaces, interactions, and
summary counts are empty, and there are no InteractionContracts. API route tests are not presented
as UI or client interaction evidence. `evidence/client-surface-inventory.json` binds this claim to a
read-only scan of the bounded `../system` tree: all regular files are included except named generated
cache directories and Python bytecode, and the sorted relative-file list has a deterministic digest.

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

Fresh maintained-example gates passed with the interaction scope declared as `none`:

- `interaction_audit.py`: 0 surfaces, 0 interactions, 0 contracts, 0 unresolved.
- `scope_audit.py`: 6 eligible routes, all 6 composed, 0 unresolved.
- `acc validate --json`: valid with 3 Capabilities, 6 Operations, 3 Policies, and 9 Evals.
- `acc compile --check --json`: compiled IR SHA-256
  `092159d28fe79dbf9c1e8809e261567ae3fb45849756db88ee74d86346be9f75`.
- `acc coverage --json`: all six eligible routes traced; all ten interaction axes report the
  evidence-backed `explicit_none` state rather than inferring a client surface.
- Two independent Pack builds were byte-identical at SHA-256
  `54661a1b2ef94bc000588b79a5d6c8f576940b7f84fa6c1c071be130621583b9`.
- `tests/e2e/test_fastapi_crm_example.py`: 12 passed.

Validation, compilation, coverage, and packing retain 25 explicit
`ACC_CAPABILITY_OUTPUT_BOUND_UNKNOWN` warnings for string fields without proven maximum lengths.
Historical repository-wide pass counts and earlier Pack hashes are intentionally not retained as
current evidence.

See `coverage-report.json`, `test-report.json`, and `risk-report.json` for machine-readable detail.

## Validation limits

Validation level is `source_connected_verified` only for the explicitly started local synthetic CRM;
the ACC Contract suite and isolated fixture coverage are also `offline_candidate`. No production
system, credential, deployment, write path, rate limit, availability target, `streamable_http`
Gateway, or unrelated source checkout was tested. The FastAPI source generates OpenAPI at runtime
rather than storing it as a checked-in file. Timeout and oversize responses were simulated at the
generic HTTP transport boundary. These are documented limits, not production assurances.

`headless_verified` is 未验证 because there is no applicable interaction surface or scenario to run.
`client_adapter_verified` is also 未验证 because this source has no real client adapter.
`source_connected_verified` applies only to the local API connection and does not imply either
interaction level.

## Human review order

1. Review `system-map.yaml`, `analysis-report.md`, `evidence/`, and the interaction-scope `none`
   rationale in `ui-interaction-inventory.yaml` against `../system`.
2. Review Operations, Policies, and the composed `get_customer_context` workflow.
3. Review all nine Evals and machine-readable reports.
4. Review the Git diff, rerun the commands in `../README.md`, and decide whether to merge.

No deployment or push was performed.
