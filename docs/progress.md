# ACC MVP Progress

| Milestone | Status | Verification |
| --- | --- | --- |
| 0 — workspace and architecture | Complete | `uv lock --check`; Ruff format/lint; mypy (28 files); pytest (4 passed) |
| 1 — core models and validation | Complete | Ruff format/lint; mypy (37 files); pytest (73 passed); CLI/schema smoke |
| 2 — compiler and pack | Complete | Ruff format/lint; mypy (46 files); pytest (113 passed); deterministic/safety cases |
| 3 — generic runtime | Complete | Ruff format/lint; mypy (56 files); pytest (182 passed); real MCP stdio handshake |
| 4 — eval and testkit | Complete | Ruff format/lint; mypy (77 files); pytest (252 passed); runtime and pack/MCP E2E CLI |
| 5 — engineer skill | Complete | skill-creator validation; Ruff/mypy; pytest (274 passed); independent Phase 0–3 forward test |
| 6 — CRM acceptance | Complete | ACC gates 9/9 each; source 34 passed; repository 281 passed; deterministic Pack and real MCP stdio |
| 7 — generic auth, identity, and scope governance | Complete | Provider auth, PrincipalContext, structured scope audit, stdio/source contracts |
| 8 — optional multi-user HTTP Gateway | Complete | 1100 passed; Ruff; mypy; Schema/CRM compile; Skill validation; independent security reviews |

This file records fresh command evidence at each milestone. A status changes to complete only after its focused tests, the full test suite, lint, type checking, diff review, and milestone commit have succeeded.

## Verification log

### 2026-08-04 — Milestone 0

- `uv sync --frozen --all-packages --group dev`
- `uv lock --check`
- `uv run --frozen ruff format --check .` — 38 files already formatted
- `uv run --frozen ruff check .` — all checks passed
- `uv run --frozen mypy packages tests` — 28 source files, no issues
- `uv run --frozen pytest` — 4 passed

### 2026-08-04 — Milestone 1

- TDD red evidence: model tests initially 25 failed; IO tests initially 19 failed; CLI tests initially 7 failed; project validation initially failed import
- `uv run --frozen acc schema --output schemas --json` — six Draft 2020-12 schemas exported
- `uv run --frozen acc --help` — `init`, `doctor`, `schema`, and `validate` registered
- `uv run --frozen ruff format --check .` — 47 files already formatted
- `uv run --frozen ruff check .` — all checks passed
- `uv run --frozen mypy packages tests` — 37 source files, no issues
- `uv run --frozen pytest` — 73 passed

### 2026-08-04 — Milestone 2

- TDD red evidence: compiler API missing; Pack API missing; analysis APIs missing; M2 CLI commands missing; protected output and nested-source cases reproduced
- `uv run --frozen ruff format --check .` — 56 files already formatted
- `uv run --frozen ruff check .` — all checks passed
- `uv run --frozen mypy packages tests` — 46 source files, no issues
- `uv run --frozen pytest` — 113 passed
- Pack tests build identical archives twice and verify lock coverage, traversal, symlink, duplicate, unknown-entry, checksum, size, and protected-output rejection
- `uv run --frozen acc --help` — `compile`, `coverage`, `diff`, `freeze`, and `pack` registered

### 2026-08-04 — Milestone 3

- TDD red evidence: runtime loader, credentials, ten workflow actions, HTTP provider, policy enforcement, MCP adapter, and `run` command were each introduced from failing tests
- `uv run acc schema --output schemas --json` — refreshed project and operation schemas for strict environment references and query mappings
- `uv run ruff format --check packages tests` — 56 files already formatted
- `uv run ruff check packages tests` — all checks passed
- `uv run mypy packages tests` — 56 source files, no issues
- `uv run pytest -q` — 182 passed
- The MCP integration test launches `acc run <pack>`, completes an SDK stdio handshake, and lists the compiled capability with empty stderr
- Runtime tests cover verified pack loading, stable errors, secret redaction, all ten workflow actions, schema checks, fixed-origin GET/HEAD requests, bounded responses, tenant/scope policy, output filtering, and protocol-safe errors

### 2026-08-04 — Milestone 4

- TDD red evidence: contract/runtime Eval APIs, Adapter SDK contracts, Fake REST transport, faults, assertions, recorder interoperability, adapter scaffolding, and all three `acc test` suites began from focused failing tests
- `uv lock --check` — lockfile is current after direct PyYAML/jsonschema dependencies
- `uv run ruff format --check packages tests` — 77 files already formatted
- `uv run ruff check packages tests` — all checks passed
- `uv run mypy packages tests` — 77 source files, no issues
- `uv run pytest -q` — 252 passed
- `acc test contract --json` statically checks bindings, schemas, operation dependencies, positive cases, and permission-negative coverage
- `acc test runtime --json` executes both expected-success and expected-403 cases against a real local HTTP boundary; `acc test e2e --json` additionally verifies a generated pack and calls through the MCP adapter
- Testkit tests cover FastAPI and no-socket transports, fixture loading, deterministic 403/404/timeout/oversize faults, call recording, MCP stdio client cleanup, output/error/forbidden-field assertions, and domain-neutral example data
- Adapter SDK tests cover strict GET/HEAD contracts, health metadata, safe paths, exact route registration, write-route rejection, YAML loading, generated scaffolds, and a deployable domain-neutral fake adapter

### 2026-08-04 — Milestone 5

- Initialized `skills/acc-engineer` with the canonical `skill-creator` script and generated deterministic `agents/openai.yaml` metadata
- Implemented the platform-neutral `HARNESS.md`, nine phase guides, eight templates, focused schema/example references, and five standalone JSON safety scripts
- Added thin Codex and Claude Code installers/commands that delegate to the single Skill/Harness method and refuse overwrite
- `quick_validate.py skills/acc-engineer` — `Skill is valid!`
- `uv run pytest tests/unit/skill -q` — 22 passed
- `uv run ruff format --check .` — 116 files already formatted
- `uv run ruff check .` — all checks passed
- `uv run mypy packages tests skills/acc-engineer/scripts` — 88 source files, no issues
- `uv run pytest -q` — 274 passed
- Independent minimal-context forward test completed Phases 0–3 against an unfamiliar read-only adapter package, produced a source-stable blocked plan, and correctly refused implementation without user-goal/auth/scope/tenant evidence
- Forward-test findings were incorporated: explicit `acc init` cold start, Python 3 invocation, canonical macOS paths, preflight/coverage-baseline templates, conditional permission-negative/empty scenarios, blocked-plan semantics, and whole-file evidence digest documentation

### 2026-08-04 — Milestone 6

- Applied `skills/acc-engineer` through Preflight, Analyze, Model, Plan, Implement, Validate, Test, Refine, and Handoff against an independent synthetic FastAPI CRM
- Source system: six GET-only routes, Bearer auth, four read scopes, token/request tenant equality, strict response models, synthetic A/B tenant data, runtime OpenAPI checks, and 34 passing isolated tests
- ACC project: six frozen evidence-bound Operations, three Policies, nine Evals, and three business capabilities; `get_customer_context` composes customer, contacts, followups, and todos
- `acc validate --json` and `acc compile --check --json` passed; Coverage has no orphans or missing eval/permission-negative coverage and retains two documented low-risk one-interface heuristics
- Contract, Runtime, and E2E CLI suites each passed 9/9 against the real local CRM HTTP boundary
- E2E tests verify policy-before-public-schema validation, masked contact email, omitted tenant fields, stable 404/403/timeout/oversize errors, SecretRef isolation, and real MCP stdio list/call
- Two CLI-built Packs were byte-identical with SHA-256 `d6670760bc1d690f6e34e57cc9dff029c258f91a4912486fd7032345724fc6ae`
- Final source snapshot matched the Preflight digest with zero source changes; formal Operations without Evidence: 0; invented endpoints: 0; runtime LLM calls: 0
- `uv lock --check`; Ruff format/lint; strict mypy; repository `pytest -q` — 281 passed

### 2026-08-06 — Milestone 7

- Added strict Provider auth contracts for `none`, `bearer_secret`, and `password_bearer`; legacy Operation-level credentials remain a dedicated `stdio` compatibility path rather than the default example.
- Added immutable request identity through `PrincipalContext`, trusted `context_bindings`, effective-Scope intersection, and a fixed principal for `stdio`.
- The `streamable_http` schema accepts only the Gateway-session authentication combination. The executable Gateway itself is recorded separately under Milestone 8.
- Migrated the synthetic FastAPI CRM example to Provider-level `bearer_secret` and removed credentials from all six Operations.
- Fake Runtime/Fake E2E remains `offline_candidate`; `source_connected_verified` requires a separately authorized and successful local/test source connection. This milestone does not assert production behavior or validation of any unrelated source system.
- Provider-auth/stdio/CRM/Skill focused regression: 85 passed; local synthetic CRM source: 34 passed; repository: 720 passed.
- `acc validate` and `acc compile --check` passed; with the local synthetic CRM running, ACC Contract, Runtime, and E2E suites each passed 9/9. This is `source_connected_verified` for that synthetic test source only.
- Strict mypy passed for 102 source files; Ruff lint and the changed-file format check passed; Skill quick validation reported `Skill is valid!`.
- Structured scope governance now requires an explicit coverage mode, route inventory, evidence/disposition closure, planned/composed Operation closure, and honest `offline_candidate` versus `source_connected_verified` handoff labels.
- The generic-auth and scope-governance work subsequently passed its repository gates before Gateway implementation began; historical focused counts above remain evidence for the auth migration rather than a claim about the newer Gateway tree.

### 2026-08-06 — Milestone 8

- `acc run` 现在会将 `runtime.transport: [streamable_http]` Pack 分派到可选的 Starlette/Uvicorn Gateway。ACC 仍是 compiler 与 Generic Runtime；Gateway 是运行时适配层，不是 Web 控制面，也不替代源系统的用户、角色、租户或数据权限。
- Gateway v1 明确是单进程实现，要求 `workers=1`。它校验精确 Host/Origin allowlist、loopback/TLS 部署规则、请求体大小、会话 TTL、最大会话数，以及不高于 Gateway TTL 的有限 MCP idle timeout。
- 每个用户只在 `POST /runtime/sessions` 一次性提交 identity/password。密码在源登录交换后丢弃，源 JWT 只保留在进程内，客户端收到独立的短期 opaque Gateway token，Store 只用其摘要索引。MCP tool 拒绝凭据和身份覆盖参数。
- 每个已认证 HTTP 请求都重新解析 `PrincipalContext`。A/B/C 的 Gateway 与 MCP Session 相互独立；MCP Session owner 绑定阻止跨 token 的 POST/GET/DELETE/SSE 访问。有效 Scope 是映射后的源 Scope 与部署 ceiling 的交集，源系统仍会授权每次 REST 调用。
- `DELETE /runtime/sessions/current`、过期、重启和源 401 都会使受影响的 Gateway 授权路径失效。源 401 只将当前用户标记为 `reauth_required`。MCP SDK 1.29 没有立即终止单个底层 Streamable HTTP 传输的公开 manager API，因此已有 SSE/传输受配置的 idle timeout 上限约束，但被撤销 token 不能授权新请求。
- 仓库包含一个领域中立的多用户 Fake 源 E2E，以及 CRM、Warehouse 和 `baogao-jin` 的代表性 Provider 配置夹具。这些 Fake 结果都是 `offline_candidate`，不暗示已验证任何生产源。
- 最新聚焦验证命令为 `uv run --frozen pytest -q tests/unit/runtime/gateway tests/integration/runtime/test_gateway_http.py tests/e2e/test_multi_user_http_gateway.py tests/unit/testkit/test_mcp_client.py tests/unit/core/test_cli.py`，已通过。
- 最终仓库门禁：`uv run --frozen pytest -q` 为 1100 passed，仅有既有 Starlette TestClient 弃用警告；Ruff format/check 检查 168 个文件通过；mypy 检查 122 个源码文件通过。
- `acc schema`、FastAPI CRM `acc validate` 与 `acc compile --check` 均通过，Skill quick validation 返回 `Skill is valid!`。Gateway 认证、MCP owner、Testkit、ASGI 生命周期、CLI factory 和多用户 E2E 的最终独立复审均为 0 Critical / 0 Important。

### `baogao-jin` 当前验证边界

- `/Users/chou/code/baogao-jin` 仍是已有只读源系统，本仓库流程不修改它。
- 当前 Gateway 回归用通用 Fake 源验证 A/B/C 隔离，同时保留一个 `baogao-jin-fake-email-password` 认证配置夹具；二者都只是 `offline_candidate`，不使用真实 `baogao-jin` 账号、JWT、服务状态或生产数据。
- 目前记录的源码审阅仅支持三个只读 GET 表面：`/api/me`、`/api/customers/search` 和 `/api/customers/{id}/overview`。overview 响应包含摘要统计，不包含文档列表。在收集新的路由、Schema、权限和测试证据前，不宣称更广的文档/报告能力。
- 未来的 `source_connected_verified` 需要用户明确授权，并成功连接已启动的本地或隔离测试服务；不能从源码阅读或 Fake 测试推导。
