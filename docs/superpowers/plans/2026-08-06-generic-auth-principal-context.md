# 通用认证与 PrincipalContext 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 ACC 增加与业务系统无关的 Provider 级认证、可信请求身份上下文和上下文绑定，同时保持现有 stdio Pack 可迁移运行。

**Architecture:** Core 只描述严格的认证与绑定合同；Runtime 用不可变 `PrincipalContext` 计算有效 scope，并通过 Auth Strategy 获取请求头；Operation 不接触密码或 JWT。旧的 Operation 级 `credential_ref` 只作为 stdio 兼容合同，Gateway 配置从一开始就被限制为 `password_bearer + gateway_session`，实际 HTTP 服务留给第三阶段。

**Tech Stack:** Python 3.12、Pydantic v2、httpx、MCP Python SDK、pytest、JSON Schema、ruff、mypy。

---

## 固定合同

认证联合类型固定为：

```yaml
provider:
  kind: http
  base_url_ref: TARGET_BASE_URL
  auth:
    kind: password_bearer
    credentials:
      kind: gateway_session
    login_path: /api/auth/login
    identity_field: username
    password_field: password
    token_pointer: /access_token
    token_type_pointer: /token_type
    expires_in_pointer: /expires_in
    scopes_pointer: /permissions
    principal_pointer: /user/id
    tenant_pointer: /tenant
    scope_mapping:
      customer:read: [customer.read]
```

`none` 不带 credential source；`bearer_secret` 使用 `environment_secret`；`password_bearer` 在 stdio 使用 environment username/password refs，在 streamable HTTP 使用 `gateway_session`。Runtime transport 仍是长度为 1 的数组。stdio 未提供源权限时，`source_scopes` 记为 unavailable，`effective_scopes` 只取部署 ceiling；一旦源权限可得，则为映射结果与 ceiling 的交集。旧的 `granted_scopes` 参数等价于部署 ceiling，旧的 `tenant_id` 转成 `{"tenant_id": value}`。stdio principal 默认 `stdio-local`，可由新增的 `ACC_PRINCIPAL_ID` 部署环境变量覆盖，绝不从工具参数推断。

### Task 1: 建立 Core 认证与绑定合同

**Files:**

- Modify: `packages/acc-core/src/acc_core/models/__init__.py`
- Modify: `packages/acc-core/src/acc_core/validation/project.py`
- Modify: `packages/acc-core/src/acc_core/compiler/ir.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Regenerate: `schemas/project.schema.json`
- Regenerate: `schemas/operation.schema.json`
- Test: `tests/unit/core/test_models.py`
- Test: `tests/unit/core/test_project_validation.py`
- Test: `tests/unit/compiler/test_compiler.py`
- Test: `tests/unit/core/test_cli.py`

- [ ] 先写失败测试：三种 auth union、两种 credential source、安全相对 login path、合法 JSON Pointer、`timeout_seconds`、`max_response_bytes`、`retry_on_unauthorized` 的默认值和边界、transport/source 组合、旧合同 warning、`context_bindings` 目标和不可公开/覆盖规则。
- [ ] 运行红灯：

```bash
uv run --frozen pytest -q tests/unit/core/test_models.py -k "auth or credential or transport or context"
uv run --frozen pytest -q tests/unit/core/test_project_validation.py
uv run --frozen pytest -q tests/unit/compiler/test_compiler.py -k context_binding
```

- [ ] 在模型中增加 `NoAuthConfig`、`BearerSecretAuthConfig`、`PasswordBearerAuthConfig`、`EnvironmentSecretCredentials`、`GatewaySessionCredentials`；扩展 transport；令 `HttpOperation.credential_ref` 可选；给 `Operation` 增加 `context_bindings: dict[str, str]`。
- [ ] 在 project 交叉校验中保证：无 provider auth 的旧项目仍要求 operation credential；新 auth 禁止 operation credential；streamable HTTP 只接受 password bearer + gateway session；stdio 不接受 gateway session。
- [ ] 编译器验证 binding 目标是已声明且最终映射到 path/query 的 Operation input，Capability input 和 workflow arguments 都不能提供该字段；若 streamable HTTP Capability 的有效 Policy/Operation scopes 非空，则 `password_bearer` 必须声明 `scopes_pointer` 和非空 `scope_mapping`，否则阻断编译，避免只相信 deployment ceiling。
- [ ] 用 CLI 生成 schema，而不是手改：

```bash
uv run --frozen acc schema --output schemas --json
uv run --frozen pytest -q tests/unit/core/test_models.py tests/unit/core/test_project_validation.py tests/unit/compiler/test_compiler.py tests/unit/core/test_cli.py
git commit --only -m 'feat(core): 定义通用认证与上下文绑定合同' -- packages/acc-core/src/acc_core/models/__init__.py packages/acc-core/src/acc_core/validation/project.py packages/acc-core/src/acc_core/compiler/ir.py packages/acc-core/src/acc_core/cli/main.py schemas/project.schema.json schemas/operation.schema.json tests/unit/core/test_models.py tests/unit/core/test_project_validation.py tests/unit/compiler/test_compiler.py tests/unit/core/test_cli.py
```

### Task 2: 实现不可变 PrincipalContext

**Files:**

- Create: `packages/acc-runtime/src/acc_runtime/context.py`
- Modify: `packages/acc-runtime/src/acc_runtime/__init__.py`
- Create: `tests/unit/runtime/test_context.py`

- [ ] 写失败测试，覆盖 scope mapping、ceiling 交集、未映射权限丢弃、unavailable 兼容语义、深层 tenant path、防御性复制和不公开 auth state。
- [ ] 运行红灯：`uv run --frozen pytest -q tests/unit/runtime/test_context.py`。
- [ ] 实现 frozen dataclass `PrincipalContext`，字段固定为 `principal_id`、`gateway_session_id`、`target_system_id`、`source_scopes`、`deployment_scope_ceiling`、`effective_scopes`、`tenant_context`、`auth_state_handle`；集合转 frozenset，对象深拷贝后只读包装。
- [ ] 提供纯函数 `map_effective_scopes()` 与受限 `resolve_context_binding()`，允许 `principal_id`、`tenant_context.*` 和固定元数据，禁止 token/password/header 路径。
- [ ] 运行绿灯并提交：

```bash
uv run --frozen pytest -q tests/unit/runtime/test_context.py
git commit --only -m 'feat(runtime): 增加可信请求身份上下文' -- packages/acc-runtime/src/acc_runtime/context.py packages/acc-runtime/src/acc_runtime/__init__.py tests/unit/runtime/test_context.py
```

### Task 3: 实现 CredentialSource 与 Auth Strategy

**Files:**

- Create: `packages/acc-runtime/src/acc_runtime/auth/__init__.py`
- Create: `packages/acc-runtime/src/acc_runtime/auth/errors.py`
- Create: `packages/acc-runtime/src/acc_runtime/auth/credentials.py`
- Create: `packages/acc-runtime/src/acc_runtime/auth/strategies.py`
- Modify: `packages/acc-runtime/src/acc_runtime/credentials/__init__.py`
- Create: `tests/unit/runtime/test_auth.py`

- [ ] 写失败测试：none、bearer secret、password login body、各 Pointer、提前刷新、并发 single-flight、4xx/5xx/超时/超限/非 JSON/缺 token/非法 expiry、禁重定向以及日志脱敏。
- [ ] 运行红灯：`uv run --frozen pytest -q tests/unit/runtime/test_auth.py`。
- [ ] 定义 `CredentialSource` 与 `HttpAuthStrategy` Protocol；实现 environment source、none、bearer secret、password bearer。Token 状态按 `auth_state_handle` 索引并受异步锁保护，不使用全局单 token。
- [ ] 登录使用独立的无 Cookie client 或每请求显式清空 cookie，`follow_redirects=False`；只发送配置声明的 identity/password 两字段；错误统一为 `ACC_RUNTIME_AUTH_*` 安全结构。
- [ ] 运行绿灯并提交：

```bash
uv run --frozen pytest -q tests/unit/runtime/test_auth.py
git commit --only -m 'feat(runtime): 实现受限 HTTP 认证策略' -- packages/acc-runtime/src/acc_runtime/auth packages/acc-runtime/src/acc_runtime/credentials/__init__.py tests/unit/runtime/test_auth.py
```

### Task 4: HttpProvider 接入认证并限制 401 重放

**Files:**

- Modify: `packages/acc-runtime/src/acc_runtime/providers/http.py`
- Modify: `packages/acc-runtime/src/acc_runtime/providers/__init__.py`
- Modify: `tests/unit/runtime/test_http_policy.py`
- Create: `tests/unit/runtime/test_http_auth.py`

- [ ] 写失败测试：策略头注入、旧 credential 兼容、首次 401 使状态失效并最多重放一次、第二次 401、禁止重定向、最终 URL 固定 Origin、A/B auth state 与 cookie 不串用。
- [ ] 运行红灯：`uv run --frozen pytest -q tests/unit/runtime/test_http_policy.py tests/unit/runtime/test_http_auth.py`。
- [ ] 构造器接收 auth strategy；新合同从策略取 header，旧合同转成兼容 bearer 策略；401 仅对可续期的 environment source 允许同一 Principal 重认证一次，第二次返回 `ACC_RUNTIME_AUTH_UNAUTHORIZED`；gateway one-shot source 不重登，只进入 `reauth_required`。
- [ ] timeout/oversize 安全 details 增加 `phase: login|operation`，任何 details 不包含 URL 查询、header、token 或用户名。
- [ ] 运行绿灯并提交：

```bash
uv run --frozen pytest -q tests/unit/runtime/test_http_policy.py tests/unit/runtime/test_http_auth.py
git commit --only -m 'feat(runtime): 将认证策略接入 HTTP Provider' -- packages/acc-runtime/src/acc_runtime/providers/http.py packages/acc-runtime/src/acc_runtime/providers/__init__.py tests/unit/runtime/test_http_policy.py tests/unit/runtime/test_http_auth.py
```

### Task 5: GenericRuntime 增加请求级上下文入口

**Files:**

- Modify: `packages/acc-runtime/src/acc_runtime/runtime.py`
- Modify: `packages/acc-runtime/src/acc_runtime/__init__.py`
- Modify: `tests/unit/runtime/test_runtime.py`
- Modify: `tests/unit/runtime/test_mcp.py`

- [ ] 写失败测试：`call_with_context()` 使用显式 Principal；旧 `call()` 固定绑定；业务参数不能覆盖 binding；Policy 只读 effective scopes；tools 不暴露 Principal/JWT/credential。
- [ ] 运行红灯：`uv run --frozen pytest -q tests/unit/runtime/test_context.py tests/unit/runtime/test_runtime.py tests/unit/runtime/test_mcp.py`。
- [ ] 新增 `call_with_context(capability_id, arguments, principal_context)`；旧二参数 `call()` 只使用构造时绑定 context。旧 granted scopes/tenant 参数在构造时转换，不能在调用时换身份。
- [ ] `_PolicyOperationCaller` 在鉴权前从 binding 注入可信值，并在发现调用参数包含绑定字段时拒绝，而非 setdefault。
- [ ] 运行绿灯并提交：

```bash
uv run --frozen pytest -q tests/unit/runtime/test_context.py tests/unit/runtime/test_runtime.py tests/unit/runtime/test_mcp.py
git commit --only -m 'feat(runtime): 按请求身份执行能力调用' -- packages/acc-runtime/src/acc_runtime/runtime.py packages/acc-runtime/src/acc_runtime/__init__.py tests/unit/runtime/test_runtime.py tests/unit/runtime/test_mcp.py
```

### Task 6: 完成 stdio 组合根与示例迁移

**Files:**

- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Modify: `tests/integration/test_cli_milestone2.py`
- Create: `tests/e2e/test_generic_auth_stdio.py`
- Modify: `examples/fastapi-crm/acc-project/project.yaml`
- Modify: `examples/fastapi-crm/acc-project/operations/crm.find_overdue_followups.yaml`
- Modify: `examples/fastapi-crm/acc-project/operations/crm.get_customer.yaml`
- Modify: `examples/fastapi-crm/acc-project/operations/crm.list_customer_contacts.yaml`
- Modify: `examples/fastapi-crm/acc-project/operations/crm.list_customer_followups.yaml`
- Modify: `examples/fastapi-crm/acc-project/operations/crm.list_customer_todos.yaml`
- Modify: `examples/fastapi-crm/acc-project/operations/crm.search_customers.yaml`
- Modify: `examples/fastapi-crm/README.md`
- Modify: `README.md`
- Modify: `docs/architecture/adr/003-generic-runtime.md`
- Modify: `docs/progress.md`

- [ ] 写 stdio E2E，覆盖首次登录、缓存、401 重登、第二次 401、stderr/Pack secret 扫描；保留独立 legacy fixture。
- [ ] 让 `acc run` 只为 stdio 建立固定 Principal；streamable HTTP 在本阶段返回稳定“需 Gateway”配置错误。
- [ ] 把 CRM 示例迁到 provider bearer secret，移除六个 Operation 的 credential ref；文档解释旧合同迁移。
- [ ] 运行阶段门禁并提交：

```bash
uv run --frozen pytest -q tests/integration/test_cli_milestone2.py tests/e2e/test_fastapi_crm_example.py tests/e2e/test_generic_auth_stdio.py
uv run --frozen acc validate examples/fastapi-crm/acc-project --json
uv run --frozen acc compile examples/fastapi-crm/acc-project --check --json
git commit --only -m 'docs: 迁移示例到 Provider 级认证' -- packages/acc-core/src/acc_core/cli/main.py tests/integration/test_cli_milestone2.py tests/e2e/test_generic_auth_stdio.py examples/fastapi-crm README.md docs/architecture/adr/003-generic-runtime.md docs/progress.md
```

### Task 7: 完整验证

- [ ] 运行：

```bash
uv run --frozen pytest -q
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy packages tests skills/acc-engineer/scripts
uv run python /Users/chou/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/acc-engineer
```

- [ ] 检查没有业务系统名称进入 `packages/acc-core` 或 `packages/acc-runtime`，没有密码、JWT、Cookie 或 Authorization 出现在 IR、MCP tools、错误、日志、fixture snapshot、Coverage、Test、Handoff、Artifact Manifest 和 Pack。
- [ ] 仅提交 ACC 路径；不修改 `/Users/chou/code/baogao-jin`，不处理 `.understand-anything/`。
