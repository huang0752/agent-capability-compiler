# Synthetic FastAPI CRM analysis

## Scope and evidence

The source workspace is the frozen, independent `../system` directory. It contains six FastAPI
business routes, strict response models, fixed synthetic records, explicit Bearer authorization,
and route tests. Evidence metadata in `evidence/` records whole-file SHA-256 digests with bounded
line locators; no source content or credential value is copied into an Operation.

## Confirmed facts

- Every business route is `GET`; the source tests assert POST, PUT, PATCH, and DELETE return 405.
- Authentication uses a Bearer token. Each token resolves to a tenant and a fixed set of read scopes.
- Every request requires `tenant_id`; it must equal the token-derived tenant before scope checks.
- Customer, contact, followup, and todo output fields are declared by strict Pydantic models.
- A customer lookup that is missing or belongs to another tenant returns 404 without revealing
  cross-tenant existence.
- Overdue followups use an explicit `as_of` query date, avoiding server-clock nondeterminism.
- The demo strings documented by the source are local test credentials, not production secrets.

## Candidate model

Six evidence-backed atomic Operations support three useful capabilities. `get_customer_context`
combines four Operations so an Agent receives one coherent customer view instead of four interface
tools. Search and overdue followups remain focused discovery capabilities because their query and
result semantics are already business-level.

The runtime must inject tenant context and resolve the credential from `CRM_DEMO_TOKEN`; neither is
an Agent input. ACC policy independently enforces the same scope/tenant boundary and strips
`tenant_id` from disclosed output. Contact email is masked by policy in the composed context.

## Conflicts and unknowns

No conflict was found between routes, models, README, and tests. Runtime-generated OpenAPI is
verified by source tests but no checked-in OpenAPI document exists. No production deployment,
production credential, rate limit, or availability guarantee is claimed; these do not block the
local synthetic example.

## Analyze gate

All six formal Operation candidates have method, path, parameters, response fields, scope, tenant,
error, and read-effect evidence. Formal Operations without evidence: 0. Invented endpoints: 0.
