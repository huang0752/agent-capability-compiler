# ACC Development Progress

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
| 9 — quality contracts and Coverage | Complete | current-format SourceContract, CapabilityQuality, Scope callability, independent base-quality Coverage, full release gates |
| 10 — Action and Live validation | In progress | compiler-proven Gateway MCP lifecycle is offline verified; production durable Store, approval issuer, audit backend, and source-connected sandbox remain pending |
| 11 — interaction conformance | Complete | platform-neutral sidecars, static proof, Runtime manifest, Testkit evaluator, ten interaction axes, seven cross-industry fixtures, and full release gates |
| 12 — AI domain-guided discovery | Complete | current-format domain contracts, deterministic Core/CLI, Skill flow, Runtime strategies, 7 cross-industry fixtures, reproducible Schema/Pack, and full release gates |

This file records fresh command evidence at each milestone. A status changes to complete only after its focused tests, the full test suite, lint, type checking, diff review, and milestone commit have succeeded.

## Current-format boundary — 2026-08-10

- Project、Operation、Capability、IR 与 Pack 只接受当前格式 `2`；旧格式在解析边界稳定拒绝。部署仍默认 `allowed_effects={read}`。
- 全局 AI 扫描由 ACC Engineer Skill 所在的 Coding Agent 执行；ACC Core 与 Runtime 都不调用 LLM。当前仓库实现的是结构化输入、确定性闭包和失败关闭，不宣称生产 AI 扫描已经验证。
- 新的领域向导先生成 DomainMap 和完整 Candidate Ledger，再按依赖与显式优先顺序一次处理一个已就绪领域。用户确认业务目标与策略，不逐条选择 route；证据清晰项自动处理，例外一次只问一个问题。unknown 候选不能被伪装为 ineligible 或消失。
- DomainDecision 按 revision 版本化，并绑定 Candidate Ledger、领域候选、Evidence 和依赖快照。Evidence 变化通过 DomainChangeRequest 精确重开受影响领域，不覆盖历史确认。
- 源 JWT 与源 API 是最终授权者，ACC Scope 只能收窄。DomainDecision、部署 allowlist 与 Action approval 均不授予源权限；登录前未知权限保持 unknown，最终 REST 请求仍由源系统鉴权。
- Core 已加入平台中立的 SourceContract/provenance、CapabilityQuality、Schema fidelity、constructability/discoverability/composition、保守输出预算，以及十个独立交互 Coverage 轴。Coverage 不生成总分，route disposition closure 不代表 Capability usable。
- Coverage 另有十二个相互独立的领域与 Action Coverage 轴，分别保留业务目标、候选分类、安全语义、身份授权、Action 生命周期、冲突控制、幂等、结果解析、验证等级、跨领域依赖和用户决策事实；没有总分或 deployable/usable 推断。
- Runtime/CLI 已加入路径感知 Scope callability：空 deployment ceiling 默认拒绝，确定不可调用项可由 strict mode 阻止启动，登录前未知的源权限保持 unknown。
- Action 已有严格模型、编译证明、Pack/Loader 合同、部署策略、Runtime Coordinator、审批协议和显式开发/测试内存 Store。状态机为 `prepare → approve → commit → status`，不能简化为允许 `POST`。
- Action semantics 已由 SourceContract 可信 Evidence 逐字段绑定，并在 compiler IR 与 Runtime 之间做摘要证明。乐观并发要求可信 token/precondition；服务端状态谓词策略与状态幂等、`retry: never` 和 `status_query` 成组验证。Gateway 只从当前 Pack IR 与同一 Provider 构造 Coordinator，缺少显式部署依赖时拒绝 Action Pack；DeploymentPolicy 禁止的能力不会出现在 tools/list 或公开 manifest。既有业务 prepare、外部 approval handle、commit/status 与 A/B 会话隔离由官方 MCP SDK 在 Fake Source 上验证；服务端状态策略的终态短路、一次 mutation 和未知结果 replay 目前由独立 Runtime/Fake Provider 测试验证。
- 普通 Generic Runtime 的 `tools()`/`call()` 仍不能直连 Action。生产 durable Store、可信审批签发服务、集中审计后端和 source-connected 隔离沙箱仍由部署者提供，因此 M10 保持 In progress，当前结论是 `gateway_offline_verified`，不是生产 Action 可用性声明。
- Live 验证术语分为 `offline_candidate`、`gateway_offline_verified` 和 `source_connected_verified`。历史里程碑使用的旧二层标签保留为当时记录，不自动升级为更高等级；新报告必须依据实际传输和源连接重新判定。
- 交互验证事实分为 `contract_declared`、`static_verified`、`headless_verified`、`runtime_offline_verified`、`source_connected_verified` 和 `client_adapter_verified`。源连通与真实客户端适配验证相互独立；required scenario 未执行、失败或跳过时不得升级为 verified。
- 当前完整门禁：`uv run --frozen pytest -q` 为 1763 passed（仅 1 条既有 Starlette 弃用警告）；Ruff format/check 检查 271 个文件通过；mypy 检查 213 个源码文件通过。双次导出的 16 份公开 Schema 与仓库逐字节一致。CRM Read、Finance 乐观并发 Action、Content 服务端状态谓词 Action 的双 Pack 均字节一致，SHA-256 分别为 `eacd5f4ca429cca7547029a0f9381d9b9bf092d305d745602742241babe2a590`、`2f3dc5ef768c5c6eac113c22d2c7108a643be0d590c401c2bc37d28aace6e760`、`19cea9a8594716c0edf51ceb20c6d2cf7e9decb7ca7d563e629c44c6825094b1`，JWT-like、Bearer value、private-key 和 raw-confirmation sentinel 扫描均无命中。FastAPI CRM 的 validate、compile、coverage 与双 Pack 也通过，Pack SHA-256 为 `7944a3fdc2ea03c4d373242c416d0780b8c24d4960d7e0367431b8dacb7c3f04`。

### 2026-08-10 — Milestone 12

- ACC Engineer Skill 完成平台中立的全局浅扫、领域分组、单领域业务目标确认、证据清晰候选自动处理、单例外问题与版本化 DomainDecision 循环；Core/Runtime 不调用 LLM。
- DomainMap、CapabilityCandidateLedger、DomainDecision、DomainChangeRequest、readiness、Evidence 影响图和十二个独立领域与 Action Coverage 轴已纳入当前格式合同。`acc domains status/show/review/impact` 只执行确定性类型化逻辑。
- 源 JWT 与源 API 保持最终权限权威；ACC Scope、部署 allowlist、DomainDecision 与 Action approval 只能收窄，不能授予源权限。
- Action 同时支持证据化乐观并发与服务端状态谓词策略；状态查询参数只来自编译证明的 Capability 输入或 Policy 公开的已密封 preview，歧义结果保持 `outcome_unknown` 且不重放 mutation。
- 7 类完整 current-format fixture 覆盖 CRM、ERP、财务、内容、任务、权限和移动端；13 个跨行业正反例通过，生产代码没有项目专属分支。
- `uv lock --check`、Ruff format/check、严格 mypy、1763 项 pytest、Skill quick validation、双次 16 Schema 对比、3 类代表 Pack 和 FastAPI CRM 确定性构建全部通过。生产 AI 扫描和生产源 Action 仍不在本里程碑的验证声明内。

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

- Added strict Provider auth contracts for `none`, `bearer_secret`, and `password_bearer`; Operation-level credentials have since been removed from the current format.
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
- 当前 Gateway 明确是单进程实现，要求 `workers=1`。它校验精确 Host/Origin allowlist、loopback/TLS 部署规则、请求体大小、会话 TTL、最大会话数，以及不高于 Gateway TTL 的有限 MCP idle timeout。
- 每个用户只在 `POST /runtime/sessions` 一次性提交 identity/password。密码在源登录交换后丢弃，源 JWT 只保留在进程内，客户端收到独立的短期 opaque Gateway token，Store 只用其摘要索引。MCP tool 拒绝凭据和身份覆盖参数。
- 每个已认证 HTTP 请求都重新校验 Gateway Session，每次工具执行再恢复并绑定 `PrincipalContext`。A/B/C 的 Gateway 与 MCP Session 相互独立；MCP Session owner 绑定阻止跨 token 的 POST/GET/DELETE/SSE 访问。有效 Scope 是映射后的源 Scope 与部署 ceiling 的交集，源系统仍会授权每次 REST 调用。
- `DELETE /runtime/sessions/current`、过期、重启和源 401 都会使受影响的 Gateway 授权路径失效。源 401 只将当前用户标记为 `reauth_required`。MCP SDK 1.29 没有立即终止单个底层 Streamable HTTP 传输的公开 manager API，因此已有 SSE/传输受配置的 idle timeout 上限约束，但被撤销 token 不能授权新请求。
- 仓库包含一个领域中立的多用户 Fake 源 E2E，以及多种代表性 Provider 认证形状夹具。这些历史 Fake 结果使用当时的 `offline_candidate` 标签，不暗示已验证任何生产源。
- 最新聚焦验证命令为 `uv run --frozen pytest -q tests/unit/runtime/gateway tests/integration/runtime/test_gateway_http.py tests/e2e/test_multi_user_http_gateway.py tests/unit/testkit/test_mcp_client.py tests/unit/core/test_cli.py`，已通过。
- 最终仓库门禁：`uv run --frozen pytest -q` 为 1100 passed，仅有既有 Starlette TestClient 弃用警告；Ruff format/check 检查 168 个文件通过；mypy 检查 122 个源码文件通过。
- `acc schema`、FastAPI CRM `acc validate` 与 `acc compile --check` 均通过，Skill quick validation 返回 `Skill is valid!`。Gateway 认证、MCP owner、Testkit、ASGI 生命周期、CLI factory 和多用户 E2E 的最终独立复审均为 0 Critical / 0 Important。
