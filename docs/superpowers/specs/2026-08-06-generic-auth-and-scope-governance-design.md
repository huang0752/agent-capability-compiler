# ACC 通用认证与范围治理设计

## 目标

扩展 Agent Capability Compiler，使其继续保持固定、可审计的 Generic Runtime，同时能够覆盖常见前后端分离系统的用户态认证，并阻止“完整盘点后用模板理由批量排除大多数路由”造成的虚假范围完整。

本设计只修改 `/Users/chou/code/agent-capability-compiler`。`baogao-jin`、CRM 与 Warehouse 仅作为测试系统或夹具，不接受系统专用运行时代码。

## 产品边界

ACC 当前面向可证据化的 HTTP REST 读取系统：正式 Operation 仍只允许 `GET` 和 `HEAD`。认证握手是 Runtime 基础设施行为，不是 Agent 可调用的 Operation，也不改变 Capability 的只读效果。

本次支持三种内置认证策略：

- `none`：无需认证的只读系统。
- `bearer_secret`：从 SecretRef 读取现成 Bearer Token。
- `password_bearer`：使用 SecretRef 中的用户标识和密码调用固定登录端点，在进程内保存 Bearer Token。

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
    identity_ref: BAOGAO_USER_EMAIL
    password_ref: BAOGAO_USER_PASSWORD
    identity_field: email
    password_field: password
    token_pointer: /data/access_token
    token_type_pointer: /data/token_type
    expires_in_pointer: /data/expires_in
    timeout_seconds: 10
    max_response_bytes: 65536
    retry_on_unauthorized: true
```

契约规则：

- `login_path` 必须是固定 Origin 下的安全相对路径，不得包含查询、片段、反斜杠或路径穿越。
- `identity_ref`、`password_ref` 和 `token_ref` 只接受现有环境变量 SecretRef 命名规则。
- JSON Pointer 必须是合法的绝对 Pointer；Token 必须解析为非空字符串。
- `token_type_pointer` 缺省时使用 `Bearer`；存在时只接受大小写不敏感的 `bearer`。
- `expires_in_pointer` 可选；存在时必须解析为正整数秒。刷新提前量取 `30 秒` 与有效期 `10%` 中的较小值，Runtime 在 `expires_at - margin` 后重新认证。
- `retry_on_unauthorized` 只允许布尔值；启用时，每次业务调用遇到第一个 401 最多清除 Token、重新登录并重放一次。
- 登录响应 `max_response_bytes` 默认 64 KiB，允许范围为 1 字节至 1 MiB。
- `password_bearer`、`bearer_secret` 和 `none` 下 Operation 必须省略 `credential_ref`；只有缺少 `provider.auth` 的旧版兼容模式继续要求 Operation 级 `credential_ref`，禁止同时存在两个互相竞争的 Token 来源。
- 登录请求体只包含声明的 identity/password 字段，不允许任意 Header、动态 URL、附加模板或 Agent 输入。

`bearer_secret` 把 Token 引用提升到 Provider：

```yaml
auth:
  kind: bearer_secret
  token_ref: CRM_USER_TOKEN
```

旧 Pack 不立即失效。没有 `provider.auth` 的 Project 保持当前按 Operation `credential_ref` 注入 Bearer 的行为；校验器给出迁移提示而不是错误。新 Pack 不再重复声明 Operation 级 Token。

## Runtime 组件边界

### `HttpAuthStrategy`

定义内部 Protocol，只负责返回当前请求所需的认证 Header，并在明确的 401 反馈后决定是否刷新。它不接触 Capability、Operation 参数或 MCP。

### `NoAuthStrategy`

返回空认证 Header，不读取环境变量。

### `BearerSecretAuthStrategy`

通过现有 SecretRef 解析器读取 Token。Token 不缓存到日志或公共错误中。

### `PasswordBearerAuthStrategy`

使用与业务 HTTP 请求相同的固定 Base URL 和受控 `httpx.AsyncClient`。首次需要认证时执行登录；Token、类型和单调时钟到期点仅存于进程内。

并发首次调用通过异步锁合并成一次登录。等待者复用同一结果。登录失败后不保留半成品状态。

401 重试采用单飞语义：只有仍持有失败 Token 的调用负责刷新；其他调用如果观察到 Token 已更新，直接复用新 Token。每次业务调用最多重放一次，第二次 401 原样映射为稳定认证错误。

### `HttpProvider`

继续负责固定 Origin、GET/HEAD、参数编码、超时、响应上限、JSON 与 Schema 校验。它不理解登录响应，只向 Auth Strategy 请求 Header 并反馈 401。

### `GenericRuntime`

根据 Project Contract 创建 Auth Strategy 和 HttpProvider。外部注入自定义 `OperationProvider` 的测试与嵌入场景继续工作。

## 多用户与 Secret 边界

一个 Runtime/MCP 进程只对应一个身份配置。用户名或邮箱、密码、JWT、Base URL、租户 ID 和权限上下文都不进入工具参数。

多个用户通过多个独立进程或宿主级隔离实例运行。Runtime 不提供 `select_user`、`switch_tenant` 或动态 Credential 名称输入。

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
- eligible 路由使用 `duplicate_or_subsumed` 时必须提供至少一个真实 `capability_id`，且该 Capability 的 Operation 依赖最终可追溯到相关路由。
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

新增 warning 级诊断：

- `ACC_SCOPE_EXCLUSION_TEMPLATE_REUSED`：多个规则跨域重复使用高度相同的 rationale。
- `ACC_SCOPE_DOMAIN_ZERO_CAPABILITY`：具有 eligible 路由的完整业务域没有 planned/composed 路由。
- `ACC_SCOPE_FRONTEND_USED_ROUTE_EXCLUDED`：有前端调用证据的路由被排除。
- `ACC_SCOPE_HIGH_EXCLUSION_RATIO`：eligible 路由达到足够样本量后出现异常高排除比例。

Warning 不单独使审计失败，但必须保留在 JSON、风险报告和 Handoff。高排除率只是启发式风险信号，不是正确性阈值；不同系统不因固定百分比被武断拒绝。

为支持 warning，审计结果把 `diagnostics` 分为 error 与 warning：有 error 时 `ok: false` 并返回失败退出码；只有 warning 时 `ok: true`，退出码为 0，但调用方不得丢弃 warning。

## Operation 与 Capability 溯源

System Map 的每个 candidate Operation 必须包含非空 `scope_route_ids`。审计器验证：

- route ID 存在；
- route disposition 为 planned 或 composed；
- route 上的 `operation_id` 与 candidate Operation ID 一致；
- Capability Plan 的依赖 Operation 存在于 System Map；
- `duplicate_or_subsumed` 规则引用的 Capability 存在，且具有可验证的路由依赖闭包。

这保证“一个业务 Capability 组合多个底层接口”是可追溯的，而不是用一句“已被能力覆盖”跳过路由。

## 前端使用证据

范围发现继续保持平台中立。OpenAPI 或后端注册建立正式路由分母；前端 API 客户端只作为使用证据，不替代分母。

路由可声明 `usage_evidence_sources`。只要存在前端调用证据，排除时产生 warning，要求 Handoff 解释为什么用户可见功能没有进入 Agent 能力。审计器不解析 Vue、React 或具体框架；发现器负责把源码证据归一为该字段。

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
- `baogao-jin`：使用本地 Fake 登录服务验证 email/password JWT 交换、多用户进程隔离和 401 重登；不读取真实账号，不修改源系统。

### 发布门禁

运行完整 pytest、Ruff、mypy、Skill `quick_validate.py`，并检查编译、打包和 MCP stdio 回归。任何真实源系统连接另行标记为 `source_connected_verified`，Fake 服务只标记 `offline_candidate`。

## 交付与非目标

完成后交付：

- 更新后的 Project/Operation Schema、编译与 Runtime；
- 结构化 Scope Audit 和模板；
- CRM、Warehouse、`baogao-jin` Fake 测试覆盖；
- ADR/README/Skill 指南同步；
- 迁移说明与稳定诊断码。

本次不生成 127 个报告金 MCP，不替报告金决定最终业务能力数量，不读取真实账号密码，不连接生产，也不修改任何被分析系统。
