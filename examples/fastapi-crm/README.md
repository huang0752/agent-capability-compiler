# FastAPI CRM end-to-end example

This example demonstrates ACC against an independent, synthetic, read-only CRM:

- `system/` is the pre-existing FastAPI source system and contains no ACC import.
- `acc-project/` is the separate evidence-bound integration generated with the ACC Engineer Skill.
- `../../tests/e2e/test_fastapi_crm_example.py` exercises the real HTTP boundary, deterministic
  Pack construction, generic Runtime, policy filtering, stable faults, and MCP stdio list/call.

All records and demo Bearer values are synthetic. Nothing here is a production credential or
deployment configuration.

The ACC project declares the demo token once as Provider-level `bearer_secret` authentication.
`CRM_DEMO_TOKEN` is an environment-variable reference in `project.yaml`; its value never enters the
Pack, an Operation, or an MCP tool argument. The six Operations intentionally contain no legacy
`credential_ref`.

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

This command uses MCP `stdio`, so one fixed `PrincipalContext` is created when the process starts.
The example does not expose `streamable_http`; that transport requires the separate multi-user
Gateway and request-level identities. Fake contract/runtime/E2E results are `offline_candidate`.
The repository E2E test may be called `source_connected_verified` only after it actually connects
to this local synthetic CRM and succeeds. Neither level proves production behavior or validates an
unrelated source checkout or online system.

For new integrations, Provider authentication is one of `none`, `bearer_secret`, or
`password_bearer`. Runtime supports compiler-checked `context_bindings` sourced from
`PrincipalContext`, but this CRM candidate does not declare one. Its hidden `tenant_id` is still
injected by the legacy required-tenant Policy compatibility path from the fixed stdio tenant
context. This proves backward-compatible tenant isolation, not the explicit binding contract;
account credentials, JWTs, and tenant identifiers still must not become Agent inputs.
