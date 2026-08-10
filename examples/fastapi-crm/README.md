# FastAPI CRM end-to-end example

This example demonstrates ACC against an independent, synthetic, read-only CRM:

- `system/` is the pre-existing FastAPI source system and contains no ACC import.
- `acc-project/` is the separate evidence-bound integration generated with the ACC Engineer Skill.
- `../../tests/e2e/test_fastapi_crm_example.py` exercises the real HTTP boundary, deterministic
  Pack construction, generic Runtime, policy filtering, stable faults, and MCP stdio list/call.

All records and demo Bearer values are synthetic. Nothing here is a production credential or
deployment configuration.

The maintained ACC project truthfully declares interaction scope `none`. The synthetic source tree
contains FastAPI routes and API tests, but no browser, mobile, desktop, command, or other applicable
client surface. `evidence/client-surface-inventory.json` records the bounded, read-only source-tree
scan with explicit cache/bytecode exclusions, a sorted relative-file inventory, and its deterministic
digest. Therefore `ui-interaction-inventory.yaml` has an evidence-bound rationale with empty
surfaces, interactions, and summary counts, and the project contains no InteractionContract. The
API tests remain valid route evidence; they are not client interaction evidence. 这不代表真实前端、
headless interaction runner 或 client adapter 已验证。

The ACC project declares the demo token once as Provider-level `bearer_secret` authentication.
`CRM_DEMO_TOKEN` is an environment-variable reference in `project.yaml`; its value never enters the
Pack, an Operation, or an MCP tool argument. The six Operations contain no per-Operation credential
input.

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

The interaction inventory is validated only as an honest `none` declaration.
`headless_verified` requires declared interaction scenarios to run through the headless evaluator,
and `client_adapter_verified` requires replay through a real client adapter. This example claims
neither level; source-connected API evidence does not imply client interaction conformance.

For new integrations, Provider authentication is one of `none`, `bearer_secret`, or
`password_bearer`. Runtime supports compiler-checked `context_bindings` sourced from
`PrincipalContext`; this CRM candidate declares `tenant_id` bindings on all six Operations. The
fixed stdio Principal supplies that trusted tenant value, while account credentials, JWTs, and
tenant identifiers remain outside Agent inputs.
