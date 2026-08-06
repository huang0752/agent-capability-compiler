# ACC 通用认证与范围治理设计

## 目标

扩展 Agent Capability Compiler，使其继续保持固定、可审计的 Generic Runtime，同时能够覆盖常见前后端分离系统的用户态认证、单用户 stdio 与多用户 HTTP Gateway，并阻止“完整盘点后用模板理由批量排除大多数路由”造成的虚假范围完整。

本设计只修改 `/Users/chou/code/agent-capability-compiler`。`baogao-jin`、CRM 与 Warehouse 仅作为测试系统或夹具，不接受系统专用运行时代码。

## 产品边界

ACC 当前面向可证据化的 HTTP REST 读取系统：正式 Operation 仍只允许 `GET` 和 `HEAD`。认证握手与 Gateway 会话创建是 Runtime 基础设施行为，不是 Agent 可调用的 Operation，也不改变 Capability 的只读效果。

本次支持三种内置认证策略：

- `none`：无需认证的只读系统。
- `bearer_secret`：从 SecretRef 读取现成 Bearer Token。
- `password_bearer`：使用 SecretRef 中的用户标识和密码调用固定登录端点，在进程内保存 Bearer Token。

Runtime 支持两种部署模式：

- `stdio`：启动时绑定一个固定 Principal，适合本地个人 Agent。
- `streamable_http`：一个 Gateway 进程承载多个 Principal，每个请求从可信 Gateway 会话凭证解析身份，适合 A、B、C 多用户同时使用。

为保持 Project Schema 兼容，`runtime.transport` 继续是长度为 1 的数组，只把允许值从 `stdio` 扩展为 `stdio | streamable_http`。一个编译 Pack 选择一种 transport，不在同一进程同时开启两种；“双模式一致性”通过使用相同 Capability 定义分别编译两种部署配置验证。

OAuth2 Authorization Code、浏览器交互登录、SAML、GraphQL、gRPC、WebSocket 和任意客户代码插件不进入本次实现。后续认证方式通过新增受限判别分支扩展，不通过动态导入客户代码扩展。

## 方案选择

### 采用：Generic Runtime 内置受限认证策略

认证配置进入严格的 Project Contract。Runtime 根据经过编译和校验的声明创建认证策略，并把获取的认证头交给固定 HTTP Provider。该方案保留 Pack 的可移植性、统一错误语义和 Secret 脱敏，也符合 ADR 003 的单一 Generic Runtime 决策。

### 不采用：外部认证代理

外部代理能减少 Runtime 改动，但会把一个完整接入拆成两个部署物，并使 Pack 无法表达自身认证需求。它仍可作为未来部署方式，但不是本次默认模型。

### 不采用：任意插件注册表

动态加载客户认证代码会扩大执行面、破坏确定性并造成版本漂移，与 ADR 003 冲突。

## Project 与 Operation Contract

`provider` 增加可选的 `auth` 判别联合。缺少 `auth` 时进入旧版兼容模式，继续使用每个 Operation 的 `credential_ref`。

```yaml
provider:
  kind: http
  base_url_ref: BAOGAO_BASE_URL
  auth:
    kind: password_bearer
    login_path: /api/auth/login
    credentials:
      kind: environment_secret
      identity_ref: BAOGAO_USER_EMAIL
      password_ref: BAOGAO_USER_PASSWORD
    identity_field: email
    password_field: password
    token_pointer: /data/access_token
    token_type_pointer: /data/token_type
    expires_in_pointer: /data/expires_in
    principal_pointer: /data/user/id
    scopes_pointer: /data/permissions
    timeout_seconds: 10
    max_response_bytes: 65536
    retry_on_unauthorized: true
```

契约规则：

- `login_path` 必须是固定 Origin 下的安全相对路径，不得包含查询、片段、反斜杠或路径穿越。
- `password_bearer.credentials` 是严格判别联合：stdio 使用 `environment_secret` 并提供 `identity_ref`、`password_ref`；HTTP 多用户使用 `gateway_session` 且不得出现环境凭据引用。
- `identity_ref`、`password_ref` 和 `token_ref` 只接受现有环境变量 SecretRef 命名规则。
- JSON Pointer 必须是合法的绝对 Pointer；Token 必须解析为非空字符串。
- `principal_pointer`、`scopes_pointer` 和 `tenant_pointer` 可选；存在时分别解析公开用户标识、字符串权限数组和租户上下文。Pointer 的原始登录响应不得进入编译产物或日志。
- `token_type_pointer` 缺省时使用 `Bearer`；存在时只接受大小写不敏感的 `bearer`。
- `expires_in_pointer` 可选；存在时必须解析为正整数秒。刷新提前量取 `30 秒` 与有效期 `10%` 中的较小值，Runtime 在 `expires_at - margin` 后重新认证。
- `retry_on_unauthorized` 只允许布尔值；启用且 CredentialSource 可续期时，每次业务调用遇到第一个 401 最多清除 Token、重新登录并重放一次。one-shot Gateway 会话不自动重登。
- 登录响应 `max_response_bytes` 默认 64 KiB，允许范围为 1 字节至 1 MiB。
- `password_bearer`、`bearer_secret` 和 `none` 下 Operation 必须省略 `credential_ref`；只有缺少 `provider.auth` 的旧版兼容模式继续要求 Operation 级 `credential_ref`，禁止同时存在两个互相竞争的 Token 来源。
- 登录请求体只包含声明的 identity/password 字段，不允许任意 Header、动态 URL、附加模板或 Agent 输入。

`bearer_secret` 把 Token 引用提升到 Provider：

```yaml
auth:
  kind: bearer_secret
  token_ref: CRM_USER_TOKEN
```

HTTP 多用户使用同一个 `password_bearer` 协议，但凭据来源改为：

```yaml
credentials:
  kind: gateway_session
```

Contract 交叉校验 `runtime.transport` 与凭据来源：v1 的 `streamable_http` 只允许 `password_bearer + gateway_session`；`none`、`bearer_secret` 和 `password_bearer + environment_secret` 只允许 stdio。固定服务 Principal 的 HTTP Token 签发不进入 v1，避免出现没有合法 Gateway Session 的半认证模式。

旧 Pack 不立即失效。没有 `provider.auth` 的 Project 保持当前按 Operation `credential_ref` 注入 Bearer 的行为；校验器给出迁移提示而不是错误。新 Pack 不再重复声明 Operation 级 Token。

## Runtime 组件边界

### `PrincipalContext`

定义请求级、不可由 Agent 修改的身份上下文：

```text
principal_id
gateway_session_id
target_system_id
source_scopes
deployment_scope_ceiling
effective_scopes
tenant_context（可选）
auth_state_handle
```

`PrincipalContext` 只能由可信 transport/session resolver 创建。Capability 输入、MCP Schema 和模型输出中不得出现 Gateway `principal_id`、JWT 或 Credential 名称。普通业务接口仍可以合法使用名为 `user_id`、`tenant_id` 的资源过滤字段；编译器不按字段名称猜测身份语义，而通过显式 `context_bindings` 区分受信任上下文与业务输入。

stdio 在进程启动时创建一个固定 Principal；HTTP Gateway 在每次请求入口验证 Gateway 会话凭证并解析 Principal。内部核心使用 `call_with_context(capability_id, arguments, principal_context)`；现有 `call(capability_id, arguments)` 保持兼容，它只调用实例构造时绑定的固定 Principal，供 stdio 和现有嵌入代码使用。HTTP Gateway 不使用这个二参数 facade。

### `HttpAuthStrategy`

定义内部 Protocol，只负责返回当前请求所需的认证 Header，并在明确的 401 反馈后决定是否刷新。它不接触 Capability、Operation 参数或 MCP。

### `NoAuthStrategy`

返回空认证 Header，不读取环境变量。

### `BearerSecretAuthStrategy`

通过现有 SecretRef 解析器读取 Token。Token 不缓存到日志或公共错误中。

### `PasswordBearerAuthStrategy`

使用与业务 HTTP 请求相同的固定 Base URL 和受控 HTTP transport。首次需要认证时执行登录；Token、类型和单调时钟到期点仅存于进程内。

认证与业务请求都禁用 HTTP Redirect。每个 Principal 的 Auth State 拥有独立且默认禁用 Cookie 持久化的请求上下文；`Set-Cookie` 不得从登录响应进入其他 Principal 的请求。底层连接池可以共享，但 Header、Cookie Jar、认证状态和请求对象不能共享可变身份数据。每次响应处理后仍校验最终 URL 与配置 Origin 一致。未来 Cookie/Session auth 必须使用每 Principal 独立 Cookie Jar，不能复用 Bearer 策略的无 Cookie 路径。

并发首次调用通过异步锁合并成一次登录。等待者复用同一结果。登录失败后不保留半成品状态。

认证策略接收受限 `CredentialSource`：stdio 的环境 SecretRef 是可重复读取的 renewable source；HTTP Gateway 会话创建请求是 one-shot source。401 重试只在 CredentialSource 可续期时采用单飞语义：只有仍持有失败 Token 的调用负责刷新，其他调用复用新 Token，每次业务调用最多重放一次。one-shot Gateway source 不保留密码，401 直接把会话标记为 `reauth_required`。

### `HttpProvider`

继续负责固定 Origin、GET/HEAD、参数编码、超时、响应上限、JSON 与 Schema 校验。它不理解登录响应，只向 Auth Strategy 请求 Header 并反馈 401。

### `GenericRuntime`

根据 Project Contract 创建 Auth Strategy 和 HttpProvider。内部 `call_with_context` 显式接收受信任的 `PrincipalContext`，Policy、认证状态、租户上下文和审计字段均从该上下文派生。外部注入自定义 `OperationProvider` 的测试与嵌入场景继续工作；旧二参数 `call` 通过 Bound Runtime 固定上下文兼容，不允许在调用时切换 Principal。

## 多用户 HTTP Gateway

### 身份来源

Gateway 身份不能由 Agent、自然语言或工具参数推断。Streamable HTTP 请求必须携带 Gateway 自己签发的高熵、不透明 Session Token；Gateway 只根据该 Token 的服务端会话记录恢复 `PrincipalContext`。

Source JWT 不能直接充当 Gateway Session Token，避免把目标系统凭据扩散到 Agent 宿主和 MCP 调用层。

### 会话创建

Gateway 提供与 MCP 工具面分离的 `POST /runtime/sessions`。`password_bearer` 项目接受通用字段 `identity` 与 `password`，在 TLS 边界内完成一次源系统登录。成功后：

1. Gateway 创建随机 256-bit Session Token，只向调用方返回一次。
2. 服务端只保存 Session Token 的 SHA-256 摘要，不保存明文 Gateway Token。
3. 会话绑定唯一 `principal_id`、目标 ACC Project、独立 Auth State、Scope 与租户上下文。
4. Agent 后续只携带 Gateway Session Token 调用 MCP，不再接触账号、密码或 Source JWT。

会话入口不是 MCP Tool，不会出现在 `tools/list`。

客户端随后通过 `Authorization: Bearer <gateway-session-token>` 调用 `/mcp` Streamable HTTP 端点。`DELETE /runtime/sessions/current` 注销当前会话。非 loopback 部署必须使用 TLS；Runtime 不提供明文公网监听的安全承诺。

HTTP 多用户 v1 只允许 `password_bearer + gateway_session` 建立动态用户会话。`none`、`bearer_secret` 和环境账号密码仍是 stdio 模式；其他 HTTP 认证协议必须通过未来新增的受限 auth kind 和明确 Token 签发契约表达。

如果登录响应配置了 `principal_pointer`，Gateway 使用该公开值建立 Principal；否则生成仅在该会话内稳定的匿名 Principal ID。若 Capability Policy 需要 Scope，HTTP 多用户项目必须配置 `scopes_pointer` 并从登录响应取得源权限数组；不允许由会话创建请求自行声明 Scope。`tenant_pointer` 存在时同理从受信任登录响应取得，不能由 Agent 或客户端覆盖。

源系统权限代码不能自动等同于 ACC Scope。Project 必须声明 `scope_mapping`，把允许映射的 source permission 映射到 ACC Scope；未映射权限一律丢弃。部署侧另行提供不可由用户改变的 `deployment_scope_ceiling`。最终 `effective_scopes = mapped_source_scopes ∩ deployment_scope_ceiling`，Policy 只读取 effective scopes。目标源系统仍使用 Source JWT 做最终授权。

stdio 兼容模式在进程启动时固定构造 Principal：旧部署没有源权限探测时，`source_scopes` 标记为 unavailable，`effective_scopes` 等于现有部署 Scope ceiling；如果配置了可信登录/身份响应 Scope，则同样执行显式 mapping 与交集。任何模式都不能用 Agent 输入扩大 ceiling。

### 凭据保留

HTTP Gateway v1 在源系统登录成功后不持久化用户密码。Source JWT 与必要的认证状态只保存在该会话的进程内内存中；Gateway 重启后所有会话失效。

如果源 JWT 过期或返回 401，Gateway 将会话标记为 `reauth_required`，要求用户重新通过受信任会话入口认证。Gateway v1 不为了自动重登而长期保存用户密码。stdio 模式仍可从固定 SecretRef 重新认证，因为 Secret 由启动环境负责托管。

未来如需 Gateway 自动重登，必须接入独立 Credential Vault 契约，不得把明文密码写入 Pack、数据库或普通缓存。

### 会话生命周期

- 默认 Gateway 会话 TTL 为 1 小时，配置上限为 24 小时。
- 如果源 Token 的已知剩余寿命更短，会话到期时间不得超过源 Token 到期时间。
- 会话注销、过期、Gateway 重启或源系统明确 401 后，后续 MCP 请求返回稳定的重新认证错误。
- 内存会话存储必须有可配置容量上限；达到上限时拒绝新会话，不静默驱逐活跃身份。
- 同一用户可以建立多个独立会话，但每个会话有不同 Gateway Token 与 Auth State。

### 请求绑定与防串号

每次 MCP 调用按以下固定顺序执行：

1. Transport 验证 Gateway Session Token。
2. Session Resolver 恢复 `PrincipalContext`。
3. Runtime 根据 `principal_id + target_system_id + gateway_session_id` 取得隔离 Auth State。
4. ACC Policy 做能力级预检查。
5. HttpProvider 使用该会话的 Source JWT 调用目标系统。
6. 目标系统按自己的用户、角色、租户和数据范围做最终权限裁决。
7. Gateway 记录不含 Secret 的审计事件。

任何来自 MCP 参数的值都不能覆盖声明为 `context_bindings` 的 Principal 字段。Token、Credential Ref 和 Gateway Principal ID 永远不是公共输入。这避免用户 A 诱导 Agent 覆盖受信任绑定而形成混淆代理攻击，同时保留合法的业务资源 ID 查询。

### Operation 上下文绑定

需要把 Principal/Tenant 注入上游请求的 Operation 必须显式声明 `context_bindings`：

```yaml
context_bindings:
  tenant_id: tenant_context.tenant_id
  actor_id: principal_id
```

左侧是 Operation input property，右侧只能引用 `PrincipalContext` 允许公开给 Provider 的固定字段路径。编译器验证：

- binding 目标存在于 Operation input Schema，并最终映射到 path/query 参数；
- Capability Workflow 不得给该 input property 传值；
- 该字段不得出现在 Capability 公共输入 Schema；
- Runtime 在 Operation 输入校验前注入值，调用参数和 Agent 输入不能覆盖；
- 普通未绑定的 `user_id`、`tenant_id` 仍按业务参数处理，不被名称规则误杀。

### Streamable HTTP 会话绑定

`POST /mcp` 初始化成功后，Gateway 将 MCP Session ID 绑定到当前 Gateway Session Token 摘要和 PrincipalContext 标识。后续所有 `POST /mcp`、`GET /mcp`、`DELETE /mcp`、SSE 建连与恢复请求都必须重新验证 Gateway Token，并检查其与 MCP Session ID 的绑定；Token 缺失、Principal 不同或会话已失效时立即拒绝。

Gateway 对每个 HTTP 请求执行配置化 `Origin` allowlist 和 `Host` allowlist 检查。非浏览器客户端缺少 Origin 时仍必须通过 Gateway Token 与 Host 校验；出现 Origin 时不得使用通配符。监听地址、公开 Host 和目标系统 Origin 都由部署配置固定，不能从请求 Header 推导，以降低 DNS rebinding 风险。

### 审计事件

Gateway 对每次会话和工具调用记录结构化审计元数据：时间、匿名化 principal 标识、session 标识摘要、Project、Capability、Operation 集合、结果类别和延迟。审计不得包含账号密码、Source JWT、Gateway Token、Authorization Header、完整请求体或完整响应体。

## 多用户与 Secret 边界

stdio Runtime 进程只对应一个身份配置；HTTP Gateway 进程可以承载多个身份，但每个请求必须绑定一个隔离的 `PrincipalContext`。用户名或邮箱、密码、JWT、Base URL、租户 ID 和权限上下文都不进入工具参数。

多个 stdio 用户通过多个独立进程运行；多个 HTTP 用户通过独立 Gateway 会话运行。Runtime 不提供 `select_user`、`switch_tenant` 或动态 Credential 名称输入。

以下位置不得出现 Secret 值：

- Pack 和编译 IR；
- MCP `tools/list` 与 `tools/call` Schema；
- 正常输出、结构化错误 details、异常字符串和日志；
- Coverage、Test、Handoff 与 Artifact Manifest；
- 录制测试快照。

认证错误只暴露稳定错误码、阶段和可公开的状态信息，不返回登录响应体。

## 认证错误模型

新增稳定错误类别：

- `ACC_RUNTIME_AUTH_CONFIGURATION_INVALID`：编译后认证配置非法。
- `ACC_RUNTIME_AUTH_SECRET_MISSING`：所需 SecretRef 未解析。
- `ACC_RUNTIME_AUTH_LOGIN_FAILED`：登录返回非成功状态。
- `ACC_RUNTIME_AUTH_RESPONSE_INVALID`：登录响应不是合规 JSON，或 Token/类型/有效期不符合契约。
- `ACC_RUNTIME_AUTH_UNAUTHORIZED`：刷新后业务请求仍为 401。
- `ACC_GATEWAY_SESSION_INVALID`：Gateway Session Token 不存在或校验失败。
- `ACC_GATEWAY_SESSION_EXPIRED`：Gateway 会话已过期。
- `ACC_GATEWAY_REAUTH_REQUIRED`：Source Token 失效，需要重新登录。
- `ACC_GATEWAY_SESSION_CAPACITY_REACHED`：会话容量达到配置上限。

超时和响应上限沿用现有 HTTP Runtime 错误语义，但 details 增加公开的 `phase: login|operation`，不得包含 URL 查询、请求体、响应体或 Secret。

登录响应上限采用独立且较小的固定默认值，并设置可校验的上限，防止认证端点返回超大内容。

## 范围清单结构化排除

`scope-inventory.yaml` 增加顶层 `exclusion_rules`。eligible 路由使用 `disposition: excluded` 时必须通过 `exclusion_rule_id` 引用一条规则；不再只靠自由文本 `reason` 表示完整决策。

```yaml
exclusion_rules:
  - id: binary-downloads
    category: binary_or_download
    route_ids:
      - reports.download
      - objects.download
    rationale: 返回二进制或短期下载地址，不属于结构化 Agent 输出
    evidence_sources:
      - openapi
      - frontend-download-client
    capability_ids: []
```

规则只复用技术类别和共同约束，不能替代逐路由决策。每个 eligible excluded route 还必须包含：

```yaml
exclusion_decision:
  rationale: 该路由仅返回短期下载 URL，业务信息已由 reports.summary 覆盖
  evidence_sources: [report-route, frontend-download-client]
  replacement_route_ids: [reports.summary]
  capability_ids: [review_reports]
```

首版类别为：

- `binary_or_download`
- `sensitive_configuration`
- `alternate_identity_boundary`
- `unsafe_dynamic_authorization`
- `unavailable_or_disabled`
- `operational_polling`
- `duplicate_or_subsumed`
- `low_business_value`

结构规则：

- rule ID、类别、非空 rationale、route IDs 和 Evidence 均必填。
- 每个排除路由只能属于一条规则；规则中的每个 route ID 必须存在并确实为 excluded。
- 每个 eligible excluded route 必须有自己的非空 rationale 和 Evidence；共享规则的 rationale 不能替代 route-level decision。
- eligible 路由使用 `duplicate_or_subsumed` 时，逐路由 `exclusion_decision` 必须提供至少一个真实 `capability_id` 和一个或多个 `replacement_route_ids`。替代路由必须为 planned/composed，且 Capability 的 Operation 依赖可追溯到这些替代路由。被排除路由本身不伪装成 Operation 依赖。
- `low_business_value` 与 `operational_polling` 属于主观排除。`system_readonly_complete` 下必须在 `scope.exclusion_approval` 记录用户明确批准原文和精确 route IDs；没有批准时审计失败。批准不能用“用户要求完整分析”或 Agent 自己的判断代替。
- 技术上不适合作为正式 Operation 的下载、敏感配置、替代身份、动态鉴权或停用路由，应优先标为 ineligible，而不是通过 eligible exclusion 降低覆盖分母。
- ineligible 路由仍需排除理由和 Evidence，但可继续使用简化的 route-level reason；它不进入 eligible 覆盖分母。
- `blocked_on_evidence` 仍不能在 `system_readonly_complete` 中伪装成完成。

## 范围诊断语义

新增以下 error 级诊断：

- `ACC_SCOPE_EXCLUSION_RULE_REQUIRED`
- `ACC_SCOPE_EXCLUSION_RULE_UNKNOWN`
- `ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH`
- `ACC_SCOPE_EXCLUSION_EVIDENCE_REQUIRED`
- `ACC_SCOPE_SUBSUMED_CAPABILITY_REQUIRED`
- `ACC_SCOPE_OPERATION_ROUTE_TRACE_REQUIRED`
- `ACC_SCOPE_ROUTE_EXCLUSION_DECISION_REQUIRED`
- `ACC_SCOPE_EXCLUSION_APPROVAL_REQUIRED`
- `ACC_SCOPE_EXCLUSION_DECISION_REUSED`
- `ACC_SCOPE_DOMAIN_ZERO_CAPABILITY`
- `ACC_SCOPE_FRONTEND_USED_ROUTE_EXCLUDED`

新增 warning 级诊断：

- `ACC_SCOPE_EXCLUSION_TEMPLATE_REUSED`：多个规则跨域重复使用高度相同的共享 rationale，但逐路由决策仍有效。
- `ACC_SCOPE_HIGH_EXCLUSION_RATIO`：eligible 路由达到足够样本量后出现异常高排除比例。

Warning 不单独使审计失败，但必须保留在 JSON、风险报告和 Handoff。高排除率只是启发式风险信号，不是正确性阈值；不同系统不因固定百分比被武断拒绝。

以下情况为 error/release gate，而不是 warning：

- eligible 路由缺逐路由决策或多条路由复用同一句决策；
- 有前端调用证据的 eligible 路由被排除，但没有逐路由用户批准；
- 具有 eligible 路由的整个业务域没有 planned/composed 路由，且这些路由未全部通过可验证的 `duplicate_or_subsumed` 指向其他域能力；
- 主观类别排除没有精确 route-level 用户批准。

为支持 warning，审计结果把 `diagnostics` 分为 error 与 warning：有 error 时 `ok: false` 并返回失败退出码；只有 warning 时 `ok: true`，退出码为 0，但调用方不得丢弃 warning。

## Operation 与 Capability 溯源

System Map 的每个 candidate Operation 必须包含非空 `scope_route_ids`。审计器验证：

- route ID 存在；
- route disposition 为 planned 或 composed；
- route 上的 `operation_id` 与 candidate Operation ID 一致；
- Capability Plan 的依赖 Operation 存在于 System Map；
- `duplicate_or_subsumed` 规则引用的 Capability 存在，且通过 `replacement_route_ids` 形成可验证的替代路由依赖闭包；普通 `scope_route_ids` 仍只能指向 planned/composed 路由。

这保证“一个业务 Capability 组合多个底层接口”是可追溯的，而不是用一句“已被能力覆盖”跳过路由。

## 前端使用证据

范围发现继续保持平台中立。OpenAPI 或后端注册建立正式路由分母；前端 API 客户端只作为使用证据，不替代分母。

路由可声明 `usage_evidence_sources`。只要存在前端调用证据，排除时产生 warning，要求 Handoff 解释为什么用户可见功能没有进入 Agent 能力；在 `system_readonly_complete` 下缺少逐路由用户批准时，同时触发前述 error/release gate。审计器不解析 Vue、React 或具体框架；发现器负责把源码证据归一为该字段。

## 兼容与迁移

认证迁移分两步：

1. 当前 Project 没有 `provider.auth` 时继续按旧语义运行，并产生非阻断迁移提示。
2. 新建模板和示例改用 Provider 级 `auth`；后续主版本再考虑移除 Operation `credential_ref`。

范围清单属于 Skill 交付契约而非 Pack Runtime Schema。已有 pilot/domain 项目可继续读取旧 `reason`；只有 `system_readonly_complete` 的 eligible excluded 路由强制结构化规则。这样修复完整性漏洞，同时避免无条件破坏旧试点产物。

## 测试策略

所有行为采用测试驱动开发，每项先观察精确失败，再实现最小通过代码。

### Contract

- 三种 auth 判别分支的合法与非法配置。
- 登录路径、SecretRef、JSON Pointer、超时、响应上限和冲突 Token 来源。
- 旧 Project/Operation 合同继续通过。

### Runtime

- 静态 Bearer 与无认证请求。
- 密码登录成功、Token 注入及登录响应不泄露。
- Token 有效期缓存和提前刷新。
- 并发首次调用只登录一次。
- 首次 401 刷新并重放一次；第二次 401 不循环。
- 登录 4xx/5xx、超时、超限、非 JSON、缺 Token、错误 token type 和非法 expires_in。
- 日志、异常、录制调用和 MCP stderr 的 Secret 扫描。

### HTTP Gateway

- A/B/C 三个会话同时调用，分别使用自己的 Source JWT。
- A 的请求不能通过工具参数、Header 混淆或并发竞争取得 B/C 的 Auth State。
- A/B/C 登录响应设置不同 Cookie 时，Bearer 请求仍不携带或串用任何登录 Cookie。
- Gateway Session Token 只返回一次，服务端只保存摘要。
- MCP Session ID 与 Gateway Session/Principal 强绑定；POST、GET、DELETE 和 SSE 恢复全部逐次认证。
- Origin/Host allowlist、禁重定向与最终 Origin 复核覆盖 DNS rebinding 和跨 Origin 风险。
- 会话过期、注销、源系统 401、进程重启和容量上限。
- Gateway 模式不持久化密码；401 后进入 `reauth_required`。
- stdio 与 HTTP Gateway 对同一 Capability 产生一致的业务输出和 Policy 结果。
- Streamable HTTP MCP 的 `tools/list`、`tools/call` 和错误响应不泄露 Principal、Gateway Token 或 Source JWT。
- 审计事件包含调用归属和结果类别，但不包含请求/响应正文与 Secret。
- source scopes 经过显式 mapping 后与 deployment ceiling 取交集；客户端不能声明或扩大 Scope。

### 范围审计

- 合法结构化批量排除。
- 未知规则、悬空 route、缺 Evidence、重复归属。
- subsumed Capability 的正反例和 Operation route trace。
- 模板理由复用、整域零能力、前端使用路由排除、高排除率 warning。
- 只有 warning 时 `ok: true` 且 diagnostics 被保留。
- pilot、domain_complete 与旧清单兼容回归。

### 跨样例回归

- CRM：旧 Operation 级 Bearer 和新 Provider 级 Bearer 均可运行。
- Warehouse：`none` 或 Bearer 场景不依赖特定业务域名称。
- `baogao-jin`：使用本地 Fake 登录服务验证 email/password JWT 交换、A/B/C Gateway 会话隔离、stdio 401 重登和 Gateway 401 后重新认证；不读取真实账号，不修改源系统。

### 发布门禁

运行完整 pytest、Ruff、mypy、Skill `quick_validate.py`，并检查编译、打包和 MCP stdio 回归。任何真实源系统连接另行标记为 `source_connected_verified`，Fake 服务只标记 `offline_candidate`。

## 交付与非目标

完成后交付：

- 更新后的 Project/Operation Schema、编译与 Runtime；
- 请求级 `PrincipalContext`、内存 Gateway Session Store 与 Streamable HTTP MCP；
- 结构化 Scope Audit 和模板；
- CRM、Warehouse、`baogao-jin` Fake 测试覆盖；
- ADR/README/Skill 指南同步；
- 迁移说明与稳定诊断码。

本次不生成 127 个报告金 MCP，不替报告金决定最终业务能力数量，不读取真实账号密码，不连接生产，也不修改任何被分析系统。

## 分阶段实施边界

该设计包含三个可独立验证但顺序相关的子项目，分别编写实施计划：

1. **通用认证与 PrincipalContext**：Project Contract、Auth Strategy、Scope mapping、请求级 Runtime 上下文、Bound Runtime facade 和 stdio 兼容。
2. **结构化范围治理**：Exclusion Rules、Operation 路由溯源、warning 语义和 Skill/模板更新。
3. **多用户 HTTP Gateway**：Streamable HTTP transport、会话入口、内存 Session Store、MCP Session 绑定、Origin/Host 防护、请求解析、审计和 A/B/C 隔离测试。

顺序必须为 1 → 2 → 3。子项目 1 和 2 分别形成可发布、可回归的软件增量；子项目 3 建立在 PrincipalContext 之上。任何阶段都不得通过报告金专用分支或动态客户插件绕过通用契约。
