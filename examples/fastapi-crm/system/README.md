# Synthetic FastAPI CRM

This directory is a self-contained, read-only source-system simulation. It does not import ACC.
All records are synthetic and all business routes support `GET` only.

## Demo Bearer tokens

| Token | Tenant | Scopes |
| --- | --- | --- |
| `demo-tenant-a-reader` | `tenant-a` | customer, contact, followup and todo read |
| `demo-tenant-a-customer-reader` | `tenant-a` | customer read only |
| `demo-tenant-b-reader` | `tenant-b` | customer, contact, followup and todo read |

These fixed strings are test credentials, not production secrets. Every request supplies a
`tenant_id` query parameter that must equal the tenant derived from the token. Overdue queries also
require an explicit `as_of=YYYY-MM-DD`, so results never depend on the server clock.

## Verify

From this directory:

```bash
uv run --isolated pytest -q
uv run --isolated ruff check .
uv run --isolated mypy
```
