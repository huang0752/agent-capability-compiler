# 多用户 Streamable HTTP Gateway 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 提供一个单进程多用户 ACC Gateway，使 A/B/C 各自登录源系统、获得独立 Gateway Session 和 MCP Session，并在每次请求中恢复可信 Principal、执行权限交集和源系统权限校验。

**Architecture:** Gateway 自己只持有短期会话，不成为业务权限源。登录密码一次性换取源 token 后立即丢弃；客户端持有 256-bit opaque Gateway token，服务端只按 SHA-256 摘要索引。官方 `StreamableHTTPSessionManager` 负责 MCP 协议会话，并以 Gateway session id 作为认证 subject 绑定 owner；ACC Store 管 Gateway Session，Runtime 的 `call_with_context()` 执行业务能力。

**Tech Stack:** Python 3.12、MCP SDK 1.29+、Starlette、Uvicorn、httpx、anyio、pytest。

---

## 前置条件与固定边界

开始本计划前，通用认证与 PrincipalContext、结构化范围治理两份计划都必须完成各自全部任务和最终发布门禁，形成可发布增量。第一阶段 Auth Strategy 必须提供按 `auth_state_handle` 隔离的 one-shot 登录结果，本计划不得复制登录实现。

Gateway v1 只支持单进程内存 Store；CLI 禁止多 worker。Host 必须精确 allowlist；Origin 缺失可以接受，但存在时必须精确匹配；禁止通配符。非 loopback 明文监听拒绝启动。Gateway Session 默认 3600 秒、最大 86400 秒，且不得超过源 token 到期时间；容量满时拒绝创建，不驱逐活跃会话。

### Task 1: 锁定依赖并定义 Gateway 配置合同

**Files:**

- Modify: `packages/acc-runtime/pyproject.toml`
- Modify: `uv.lock`
- Create: `packages/acc-runtime/src/acc_runtime/gateway/__init__.py`
- Create: `packages/acc-runtime/src/acc_runtime/gateway/models.py`
- Create: `tests/unit/runtime/gateway/test_models.py`

- [ ] 写失败测试：TTL 默认/上下限、容量正数、Host/Origin 非空精确值且拒绝 `*`、监听安全约束、Session create request 只接受 identity/password。
- [ ] 运行红灯：`uv run --frozen pytest -q tests/unit/runtime/gateway/test_models.py`。
- [ ] 将 MCP 依赖下限提高到实际使用完整 API 的 `mcp>=1.29,<2`，显式增加 `starlette` 与 `uvicorn` 直接依赖并更新 lock。
- [ ] 实现严格 Pydantic 模型 `GatewaySettings`、`SessionCreateRequest`、`SessionCreateResponse`、`GatewaySessionRecord`、`GatewaySessionStatus`。
- [ ] 运行绿灯并提交：

```bash
uv lock
uv run --frozen pytest -q tests/unit/runtime/gateway/test_models.py
git commit --only -m 'feat(gateway): 定义多用户网关配置合同' -- packages/acc-runtime/pyproject.toml uv.lock packages/acc-runtime/src/acc_runtime/gateway/__init__.py packages/acc-runtime/src/acc_runtime/gateway/models.py tests/unit/runtime/gateway/test_models.py
```

### Task 2: 实现内存 Session Store 与登录服务

**Files:**

- Create: `packages/acc-runtime/src/acc_runtime/gateway/sessions.py`
- Create: `packages/acc-runtime/src/acc_runtime/gateway/service.py`
- Create: `tests/unit/runtime/gateway/test_sessions.py`
- Create: `tests/unit/runtime/gateway/test_service.py`

- [ ] 写 Store 失败测试：`secrets.token_bytes(32)` 生成 URL-safe opaque token、record 只存 SHA-256 digest、TTL/容量/撤销/过期/reauth、并发创建注销、A/B/C 分别解析。
- [ ] 写 Service 失败测试：密码只传给 one-shot login 一次且不保留，登录结果生成 Principal、映射 source scopes 与 ceiling，会话 TTL 截断到源 token 到期，401 只标记对应会话 reauth；缺少 `principal_pointer` 时生成仅在该 Gateway Session 内稳定、跨新会话不同的匿名 principal id。
- [ ] 运行红灯：

```bash
uv run --frozen pytest -q tests/unit/runtime/gateway/test_sessions.py tests/unit/runtime/gateway/test_service.py
```

- [ ] 实现 `GatewaySessionStore` Protocol 和 `InMemoryGatewaySessionStore`：`create`、`resolve_token`、`resolve_session_id`、`revoke`、`mark_reauth_required`、`purge_expired`、`close`。锁内只做内存状态变更，不在锁内访问源系统。
- [ ] 实现 `GatewaySessionService.create_session()` 和 `delete_current()`；任何 repr、异常或日志不得含明文 Gateway token、源 token、password。
- [ ] 运行绿灯并提交：

```bash
uv run --frozen pytest -q tests/unit/runtime/gateway/test_sessions.py tests/unit/runtime/gateway/test_service.py
git commit --only -m 'feat(gateway): 隔离用户登录与短期会话' -- packages/acc-runtime/src/acc_runtime/gateway/sessions.py packages/acc-runtime/src/acc_runtime/gateway/service.py tests/unit/runtime/gateway/test_sessions.py tests/unit/runtime/gateway/test_service.py
```

### Task 3: 将 Gateway Bearer 绑定到 MCP Session owner

**Files:**

- Create: `packages/acc-runtime/src/acc_runtime/gateway/auth.py`
- Modify: `packages/acc-runtime/src/acc_runtime/mcp/server.py`
- Modify: `packages/acc-runtime/src/acc_runtime/mcp/__init__.py`
- Create: `tests/unit/runtime/gateway/test_auth.py`
- Create: `tests/unit/runtime/gateway/test_mcp_context.py`
- Modify: `tests/unit/runtime/test_mcp.py`

- [ ] 写失败测试：缺失/伪造/过期/撤销/reauth token 不认证；token A 不能恢复 B；SDK `AccessToken` 固定 `client_id=project_id`、`claims={"iss": "acc-gateway"}`、`subject=gateway_session_id`。MCP SDK 1.29 的 issuer 来自 claims，不得传不存在的 `issuer` 构造参数。
- [ ] 写 MCP 适配失败测试：Principal 只从 auth context/resolver 来，arguments 中的 principal/scope/credential 被忽略或拒绝；stdio 二参数 Protocol 行为不变。
- [ ] 运行红灯：

```bash
uv run --frozen pytest -q tests/unit/runtime/gateway/test_auth.py tests/unit/runtime/gateway/test_mcp_context.py tests/unit/runtime/test_mcp.py
```

- [ ] 实现 `GatewayTokenVerifier(TokenVerifier)` 与 resolver；新增 `ContextualMcpRuntime` 和 `PrincipalCapabilityMcpServer`，调用 `GenericRuntime.call_with_context()`。
- [ ] 只使用 SDK 公开 API，不读取 `_session_owners`、`_server_instances` 等私有属性，也不维护第二份 MCP owner map。
- [ ] 运行绿灯并提交：

```bash
uv run --frozen pytest -q tests/unit/runtime/gateway/test_auth.py tests/unit/runtime/gateway/test_mcp_context.py tests/unit/runtime/test_mcp.py
git commit --only -m 'feat(gateway): 绑定网关身份与 MCP 会话' -- packages/acc-runtime/src/acc_runtime/gateway/auth.py packages/acc-runtime/src/acc_runtime/mcp/server.py packages/acc-runtime/src/acc_runtime/mcp/__init__.py tests/unit/runtime/gateway/test_auth.py tests/unit/runtime/gateway/test_mcp_context.py tests/unit/runtime/test_mcp.py
```

### Task 4: 增加最小化审计

**Files:**

- Create: `packages/acc-runtime/src/acc_runtime/gateway/audit.py`
- Modify: `packages/acc-runtime/src/acc_runtime/runtime.py`
- Create: `tests/unit/runtime/gateway/test_audit.py`
- Modify: `tests/unit/runtime/test_runtime.py`

- [ ] 写失败测试：session create/delete、事件时间戳、Project、Capability、实际执行 Operation 集合、结果类别、耗时；workflow 分支只记录真正调用的 Operation；成功、policy deny、upstream deny、internal error 分类稳定。
- [ ] 运行红灯：`uv run --frozen pytest -q tests/unit/runtime/gateway/test_audit.py tests/unit/runtime/test_runtime.py -k audit`。
- [ ] 实现 `AuditEvent`、`AuditSink`、`LoggingAuditSink`、`AuditCollector`。Principal/session 只记录带部署 salt 的摘要；API 不接受请求体、响应体、Authorization 或 Secret。
- [ ] 在 `_PolicyOperationCaller.call()` 边界采集实际 operation id，在 `call_with_context()` 完成时提交；stdio 默认 no-op。
- [ ] 运行绿灯并提交：

```bash
uv run --frozen pytest -q tests/unit/runtime/gateway/test_audit.py tests/unit/runtime/test_runtime.py
git commit --only -m 'feat(gateway): 记录最小化能力执行审计' -- packages/acc-runtime/src/acc_runtime/gateway/audit.py packages/acc-runtime/src/acc_runtime/runtime.py tests/unit/runtime/gateway/test_audit.py tests/unit/runtime/test_runtime.py
```

### Task 5: 组装受保护的 ASGI Gateway

**Files:**

- Create: `packages/acc-runtime/src/acc_runtime/gateway/security.py`
- Create: `packages/acc-runtime/src/acc_runtime/gateway/app.py`
- Create: `tests/unit/runtime/gateway/test_security.py`
- Create: `tests/integration/runtime/test_gateway_http.py`

- [ ] 写 security 测试：Host 不允许返回 421；Origin 存在且不允许返回 403；所有路径有 body size 上限；session 创建路由无 MCP bearer 但仍受 Host/Origin/容量保护。
- [ ] 写真实 ASGI 生命周期集成测试：`POST /runtime/sessions`、`POST/GET/DELETE /mcp`、SSE 恢复逐请求认证、`DELETE /runtime/sessions/current`；token B 携 token A 的 `MCP-Session-Id` 返回 404；注销后失效；关闭并重新创建 app/store 后旧 Gateway token 和 MCP Session 全部失效。
- [ ] 运行红灯：

```bash
uv run --frozen pytest -q tests/unit/runtime/gateway/test_security.py tests/integration/runtime/test_gateway_http.py
```

- [ ] `create_gateway_app()` 用 Starlette 组装路由和 lifespan；lifespan 进入 `StreamableHTTPSessionManager.run()`。中间件顺序为请求安全 → AuthenticationMiddleware → AuthContextMiddleware → RequireAuthMiddleware → MCP manager；session login/delete 按各自认证要求独立路由。
- [ ] 把相同精确 allowlist 转成 SDK `TransportSecuritySettings` 形成第二层校验。不要关闭 SDK 的 session owner binding。
- [ ] 运行绿灯并提交：

```bash
uv run --frozen pytest -q tests/unit/runtime/gateway/test_security.py tests/integration/runtime/test_gateway_http.py
git commit --only -m 'feat(gateway): 提供受保护的 Streamable HTTP 服务' -- packages/acc-runtime/src/acc_runtime/gateway/security.py packages/acc-runtime/src/acc_runtime/gateway/app.py tests/unit/runtime/gateway/test_security.py tests/integration/runtime/test_gateway_http.py
```

### Task 6: 增加 CLI 和 HTTP Testkit

**Files:**

- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Modify: `tests/unit/core/test_cli.py`
- Modify: `tests/integration/test_cli_milestone2.py`
- Create: `packages/acc-testkit/src/acc_testkit/mcp_client/streamable_http.py`
- Modify: `packages/acc-testkit/src/acc_testkit/mcp_client/__init__.py`
- Modify: `packages/acc-testkit/src/acc_testkit/__init__.py`
- Modify: `tests/unit/testkit/test_mcp_client.py`

- [ ] 写 CLI 失败测试：按 Pack 唯一 transport 自动分派；Gateway 参数含 host/port/allowed-host/allowed-origin/TTL/max sessions；非 loopback 明文、多个 worker、缺 allowlist 均拒绝；stdio 回归。
- [ ] 写 Testkit 失败测试：使用官方 `streamable_http_client`，注入 Gateway bearer，支持 list/call，并暴露 session id 仅供断言。
- [ ] 运行红灯：

```bash
uv run --frozen pytest -q tests/unit/core/test_cli.py tests/integration/test_cli_milestone2.py tests/unit/testkit/test_mcp_client.py
```

- [ ] 提取 `_run_stdio_runtime()` 和 `_run_streamable_http_gateway()`；`--scope` 在 Gateway 明确解释为 deployment ceiling。实现 `McpStreamableHttpTestClient`，不重复实现协议。
- [ ] 运行绿灯并提交：

```bash
uv run --frozen pytest -q tests/unit/core/test_cli.py tests/integration/test_cli_milestone2.py tests/unit/testkit/test_mcp_client.py
git commit --only -m 'feat(gateway): 接入 CLI 与 HTTP 测试客户端' -- packages/acc-core/src/acc_core/cli/main.py tests/unit/core/test_cli.py tests/integration/test_cli_milestone2.py packages/acc-testkit/src/acc_testkit/mcp_client/streamable_http.py packages/acc-testkit/src/acc_testkit/mcp_client/__init__.py packages/acc-testkit/src/acc_testkit/__init__.py tests/unit/testkit/test_mcp_client.py
```

### Task 7: A/B/C 端到端隔离与发布门禁

**Files:**

- Create: `tests/e2e/test_multi_user_http_gateway.py`
- Modify: `README.md`
- Modify: `docs/architecture/adr/003-generic-runtime.md`
- Modify: `docs/progress.md`

- [ ] 构建 Fake 登录/业务服务：A/B/C 返回不同 principal、source scopes、tenant 和 source token；三方并发建立 Gateway/MCP sessions。
- [ ] 断言同一 Capability 只返回各自可见数据；所有 token/MCP session 交叉组合拒绝；A 不能用 arguments 覆盖 tenant/actor；source 401 只令对应用户 reauth；stdio 与 HTTP 对相同 context 结果一致。
- [ ] 扫描 tools/list、structured error、审计、日志、repr、Coverage、Test、Handoff、Artifact Manifest 和 Pack，确认无 password、source token、Gateway token、Authorization、Cookie。
- [ ] 增加跨样例回归：CRM 旧 Operation Bearer 与新 Provider Bearer；通用 Warehouse fixture 的 `none` 与 Bearer；`baogao-jin` Fake email/password 登录和 A/B/C 隔离。所有 Fake 结果标记为 `offline_candidate`；只有另行授权且实际连接隔离源系统后才可标记 `source_connected_verified`。
- [ ] 记录单进程限制、TLS/反向代理边界、会话失效语义和部署示例并提交：

```bash
uv run --frozen pytest -q tests/e2e/test_multi_user_http_gateway.py
git commit --only -m 'test(gateway): 验证多用户端到端身份隔离' -- tests/e2e/test_multi_user_http_gateway.py README.md docs/architecture/adr/003-generic-runtime.md docs/progress.md
```

- [ ] 最终执行：

```bash
uv run --frozen pytest -q
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy packages tests skills/acc-engineer/scripts
```

- [ ] 检查 Runtime/Gateway 无 `baogao-jin`、CRM、Warehouse 专用分支；跨样例只存在于测试 fixture；不修改源系统和 `.understand-anything/`。
