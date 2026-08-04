# FastAPI CRM end-to-end example

This example demonstrates ACC against an independent, synthetic, read-only CRM:

- `system/` is the pre-existing FastAPI source system and contains no ACC import.
- `acc-project/` is the separate evidence-bound integration generated with the ACC Engineer Skill.
- `../../tests/e2e/test_fastapi_crm_example.py` exercises the real HTTP boundary, deterministic
  Pack construction, generic Runtime, policy filtering, stable faults, and MCP stdio list/call.

All records and demo Bearer values are synthetic. Nothing here is a production credential or
deployment configuration.

## Run the source-system checks

From `system/`:

```bash
PYTHONDONTWRITEBYTECODE=1 uv run --isolated pytest -q -p no:cacheprovider
uv run --isolated ruff check --no-cache .
uv run --isolated mypy --cache-dir=../../../.mypy_cache/fastapi-crm-system
```

## Run ACC against the local CRM

Start the local source system from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=examples/fastapi-crm/system/src \
uv run uvicorn fastapi_crm_system:app --host 127.0.0.1 --port 8000
```

In another shell:

```bash
cd examples/fastapi-crm/acc-project
export CRM_BASE_URL=http://127.0.0.1:8000
export CRM_DEMO_TOKEN=demo-tenant-a-reader

uv run acc validate --json
uv run acc compile --check --json
uv run acc coverage --json
uv run acc test contract --json
uv run acc test runtime --json
uv run acc test e2e --json
uv run acc pack --output build/fastapi-crm.accpkg --json

ACC_GRANTED_SCOPES="customer.read contact.read followup.read todo.read" \
ACC_TENANT_ID=tenant-a \
uv run acc run build/fastapi-crm.accpkg
```

The MCP tools expose only capability inputs. Base URL, credential, scopes, and tenant context remain
runtime configuration; they are not tool arguments or Pack secrets.
