# Agent Capability Compiler (ACC)

ACC 是一个**零代码侵入式 Agent 能力接入工具链**。它帮助 Coding Agent 从已有系统的源码、接口文档、权限规则和测试中提取有证据支持的业务能力，将其编译为可重复构建的 Capability Pack，再由固定的通用 Runtime 通过 MCP 暴露给 Agent。

ACC 不修改已有业务系统，不要求业务系统嵌入 Agent SDK 或接入 MCP。运行时只访问已有 REST API，或访问独立部署的旁路 Adapter。

> [!IMPORTANT]
> 已完成的本地端到端验收只证明对应的本地合同，不代表生产发布、生产安全认证，也不代表任何未连接业务系统的源码或在线数据已经验证。请结合[开发状态](#开发状态)、示例交接报告和后续发布说明判断使用范围。

## 为什么需要 ACC

直接让模型观察系统并临时拼接请求，难以保证权限、证据和行为可重复。ACC 将接入过程拆成两个边界清晰的阶段：

- **编译期有 AI**：Codex、Claude Code 等宿主负责分析、规划、创建能力定义、运行测试并根据诊断修复。
- **运行期无 AI**：ACC Runtime 只执行已经校验和编译的 Pack；不调用 LLM，不生成代码，不临时构造未知请求。

完整链路如下：

```text
已有系统源码 / OpenAPI / 权限规则 / 测试（只读）
                         │
                         ▼
              Codex / Claude Code 等宿主
                         │ 加载 ACC Engineer Skill
                         ▼
  Scope Inventory / Evidence / SourceContract / CapabilityQuality
                 Operation / Capability / Policy / Eval
                         │
                         ▼
          ACC Core：校验、编译、测试、确定性打包
                         │
                         ▼
                  Capability Pack (.accpkg)
                         │
                         ▼
              ACC Generic Runtime（无 LLM）
                         │
             ┌───────────┴───────────┐
             │ MCP stdio             │ streamable_http
             ▼                       ▼
       本地单身份 Agent       可选多用户 Gateway
                         │
                         ▼
             原系统 REST API / 独立 Adapter
```

## 产品边界

ACC 负责：

- 稳定的 `acc` CLI、Schema 和结构化诊断；
- Evidence 绑定、引用检查、Policy 校验和 Workflow 编译；
- SourceContract、CapabilityQuality、Eval、九轴 Coverage 和可重复构建的 Capability Pack；
- 固定通用 Runtime、MCP stdio、REST Provider、Provider 级认证和 SecretRef；
- Adapter SDK 基础契约、测试工具和 Fake Adapter；
- 面向 Coding Agent 的 ACC Engineer Skill。

ACC **不**负责：

- 集成 OpenAI、Anthropic 或其他模型 SDK；
- 模型选择、Token 管理、上下文压缩、Agent Loop、模型重试或计费；
- 修改原系统代码、数据库结构、认证逻辑或部署；
- 在 Runtime 中动态生成代码、HTTP 请求或工作流；
- 生产级 Action 审批 UI、durable Action Store、集中审计控制面，以及插件市场、Kubernetes、Helm、OCI、SOAP、gRPC、数据库 Adapter、消息队列、RPA 或浏览器录制。

当前唯一格式为 `2`。稳定可执行入口支持证据绑定的 Read Operation、Capability Pack、MCP stdio 和多用户 `streamable_http` Gateway。Action 已具备模型、编译证明、Pack/Loader 合同和直接 Runtime 状态机基础，但尚未接入通用 MCP 工具面，也没有生产 durable Store/审批签发实现。Gateway 是 Generic Runtime 的可选运行时适配层：它负责 HTTP 身份、会话隔离和请求级 `PrincipalContext`，不是用户/租户管理平台、权限源或 SaaS 控制面。

## 架构

仓库由四个可独立测试的 Python 包和一套平台中立的 Engineer Skill 组成：

| 组件 | 职责 |
| --- | --- |
| `acc-core` | 数据模型、JSON Schema、CLI、Evidence、校验器、编译器、Coverage、Eval、Pack |
| `acc-runtime` | Pack Loader、MCP stdio、Workflow 执行、REST Provider、Provider 级认证、`PrincipalContext`、Policy、结构化错误 |
| `acc-adapter-sdk` | Adapter Contract、Server 基础骨架、测试工具和 Fake Adapter 示例 |
| `acc-testkit` | Fake REST System、MCP 测试客户端、E2E 断言、故障模拟和示例数据 |
| `skills/acc-engineer` | `preflight → analyze → model → plan → implement → validate → test → refine → handoff` |

核心原则：

1. **Skill-first**：AI 能力由 Coding Agent 宿主提供，ACC 本身不集成模型。
2. **AI 负责创造，ACC 负责约束**：分析和候选定义可以由 Agent 完成，最终有效性由确定性工具验证。
3. **通用 Runtime**：每个系统只生成数据化的 Pack，不复制一套 Runtime 源码。
4. **证据先于约束**：Evidence 通过 SourceContract provenance 支持 Operation Schema；观测样本不能证明业务上界。
5. **默认拒绝写**：Action 只有同时通过 effect/risk、部署 allowlist、Scope、审批、幂等和并发门禁才可能执行。
6. **原系统源码只读**：所有生成物写入独立 ACC 项目；Engineer Skill 最终停在人工 Git Review 之前。

详细设计决策见 `docs/architecture/adr/`。

## 快速开始

### 环境要求

- Python 3.12
- [`uv`](https://docs.astral.sh/uv/)
- Git

### 从源码准备开发环境

```bash
git clone <your-fork-or-repository-url> agent-capability-compiler
cd agent-capability-compiler
uv sync --all-packages --group dev
uv run acc --help
```

当前格式的接入流程如下：

```bash
# 在独立目录创建 ACC 项目；不要在原系统目录中生成文件
mkdir my-system-acc
cd my-system-acc
acc init

# 检查环境和只读边界
acc doctor --json

# 校验、编译和查看覆盖率
acc validate --json
acc compile --check --json
acc coverage --json

# 执行契约、Runtime 和端到端测试
acc test contract --json
acc test runtime --json
acc test e2e --json

# 生成 Pack，并由通用 Runtime 以 MCP stdio 方式运行
acc pack --json
acc run example-crm-0.1.0.accpkg
```

以上命令均已在当前检出版本实现；开发仓库中可以统一写成 `uv run acc ...`。Coverage 只提供当前九轴报告，并要求项目根存在合法 `scope-inventory.yaml`。

### 运行多用户 Gateway

仅当 Pack 声明 `runtime.transport: [streamable_http]`，且 Provider 使用 `password_bearer + gateway_session` 时，`acc run` 才会启动 Gateway。最小的本机明文示例是：

```bash
uv run acc run build/my-system.accpkg \
  --host 127.0.0.1 \
  --port 8000 \
  --allowed-host 127.0.0.1:8000 \
  --allowed-origin http://127.0.0.1:3000 \
  --scope customer.read \
  --session-ttl 3600 \
  --max-sessions 1000 \
  --mcp-idle-timeout 60 \
  --body-limit 4194304 \
  --workers 1
```

`--allowed-host` 至少给出一个精确值；`--allowed-origin` 也是精确清单，不支持通配符。端口、TTL、容量、MCP idle timeout 和请求体上限均由部署方显式限定。Gateway 只支持单进程 `--workers 1`，因为 Gateway Session 与 MCP Session 均是进程内状态。明文 HTTP 只允许绑定 loopback；绑定非 loopback IP 必须同时提供 `--tls-certfile` 和 `--tls-keyfile`，或在受信反向代理后仅监听 loopback。

Gateway 的 `acc run` 不加 `--json` 时启动并持续服务；加 `--json` 时只加载 Pack、验证 Gateway 组合并返回脱敏配置，不启动监听器。

客户端先向 `POST /runtime/sessions` 一次性提交当前用户的账号和密码，然后用响应中的 opaque Gateway token 作为 `Authorization: Bearer ...` 调用 `/mcp`。密码在登录边界使用后即丢弃；源 JWT 只存在当前进程的认证状态中；客户端持有的是另一枚短期、不透明 Gateway token，服务端会话索引只保存其摘要。用户 A/B/C 各自登录，得到独立 Gateway Session 和独立 MCP Session；Agent 无需再把用户标识放入工具参数。

```json
{
  "identity": "user@example.test",
  "password": "<one-shot secret>"
}
```

`DELETE /runtime/sessions/current` 会使当前 Gateway token 立即无效。MCP SDK 1.29 没有按单个 Gateway Session 立即 terminate 底层 Streamable HTTP 传输的公开管理 API，因此已建立的 SSE/传输实例会在有限 `--mcp-idle-timeout` 内回收；它在此期间也无法通过失效 token 成功执行新请求。源系统返回 401 时，只把对应 Gateway Session 标记为需重新认证，其他用户会话不受影响。

## CLI 契约

当前 CLI 命令面如下：

```text
acc init
acc doctor
acc schema
acc validate
acc compile
acc coverage
acc diff
acc freeze
acc test
acc pack
acc run
acc adapter init
```

所有命令都必须支持 `--json`。成功输出：

```json
{
  "ok": true,
  "command": "validate",
  "result": {},
  "diagnostics": []
}
```

失败输出仍保持同一结构，并提供可供 Coding Agent 定位和修复的稳定诊断：

```json
{
  "ok": false,
  "command": "validate",
  "result": null,
  "diagnostics": [
    {
      "code": "ACC_OPERATION_EVIDENCE_MISSING",
      "severity": "error",
      "message": "Operation requires at least one evidence reference.",
      "path": "operations/crm.get_customer.yaml",
      "pointer": "/evidence"
    }
  ]
}
```

稳定退出码：

| 退出码 | 含义 |
| ---: | --- |
| `0` | 成功 |
| `2` | CLI 用法错误 |
| `3` | Schema 或输入错误 |
| `4` | 编译错误 |
| `5` | 测试错误 |
| `6` | Pack 或 Runtime 错误 |

MCP 模式下，协议消息只写 stdout；日志只写 stderr。

## ACC 项目格式

`acc init` 创建的项目由声明式文件组成。一个最小项目预期如下：

```text
my-system-acc/
├── project.yaml
├── operations/
│   └── crm.get_customer.yaml
├── capabilities/
│   └── get_customer_context.yaml
├── policies/
│   └── crm-sales-read.yaml
├── evals/
│   ├── get-customer-context-normal.yaml
│   └── get-customer-context-cross-tenant-denied.yaml
├── evidence/
└── fixtures/
```

### Project

Project 绑定只读源码工作区和 HTTP Provider，但只保存凭据引用。当前合同如下：

```yaml
schema_version: "2"
project:
  id: example-crm
  version: 0.1.0
source_workspace:
  path: ../system
  mode: read_only
runtime:
  transport: [stdio]
provider:
  kind: http
  base_url_ref: CRM_BASE_URL
  auth:
    kind: bearer_secret
    token_ref: CRM_USER_TOKEN
quality:
  profile: standard
```

认证是 Provider 合同，不是 Operation 参数。新项目按目标系统选择以下互斥配置：

- `none`：源系统不要求认证，不携带 credential source。
- `bearer_secret`：从 `token_ref` 指向的部署环境变量读取既有 Bearer Secret；适合本地 `stdio` 的服务账号或测试账号。
- `password_bearer`：调用配置的登录端点换取 JWT。`stdio` 只能使用环境中的账号/密码引用；`streamable_http` 只能使用 Gateway 会话提交的一次性登录材料，Pack 不保存用户账密或 JWT。

Operation 不得保存 `credential_ref`；认证只能通过 `provider.auth` 表达。Project 必须选择质量 profile，并为每个 Operation 配套 SourceContract、为每个 Capability 配套 CapabilityQuality。旧格式文档和 Pack 会被稳定拒绝，不做隐式迁移。

### Operation、Evidence 与 SourceContract

Operation 是已有系统的原子 HTTP 操作。Read 必须显式声明 `effect: read`；`POST` 等非安全方法若用于查询，还必须提供证据分类，不能只凭 HTTP 方法猜测效果。正式 Operation 必须绑定 Evidence：

```yaml
schema_version: "2"
id: crm.get_customer
title: 获取客户资料
kind: read
input_schema:
  type: object
  additionalProperties: false
  required: [customer_id]
  properties:
    customer_id: {type: string}
output_schema:
  type: object
  additionalProperties: false
  required: [id, name]
  properties:
    id: {type: string}
    name: {type: string}
http:
  method: GET
  path: /customers/{customer_id}
  path_parameters:
    customer_id: customer_id
  scopes: [customer.read]
  timeout_seconds: 15
  max_response_bytes: 1048576
safety:
  effect: read
evidence:
  - source_id: crm-backend
    locator: app/api/customers.py#L42-L68
    digest: sha256:<content-digest>
```

Evidence 可以定位到文件和行号、JSON Pointer 或 OpenAPI Operation，并携带内容摘要。ACC 不允许用常识或模型猜测补全路径、字段、Scope 或租户规则。

SourceContract 将证据归一化为 `request_schema`、`response_schema`、完整性和 JSON Pointer 级 provenance。Action Operation 还必须提供证据绑定的 `action_semantics`，逐字段证明 method、effect、risk、reversibility、retry、idempotency 与 concurrency；仅运行观测不能作为安全降级依据。Operation 输入必须是源系统可接受请求的安全子集；Operation 输出必须覆盖源系统可能返回的响应。无法证明的 Schema 关系报告 `unknown`，证据冲突报告错误；运行观测不能用来伪造 `maxItems`、`maxLength` 等上界。

如果源接口需要可信身份或租户值，Operation 用 `context_bindings` 声明注入位置，例如把 `tenant_id` 绑定到 `tenant_context.tenant_id`。绑定值只能由 Runtime 的不可变 `PrincipalContext` 提供，Agent 输入和 Workflow 参数都不能覆盖；Provider 还必须通过 `context_binding_allowlist` 显式允许租户路径。`PrincipalContext` 保存 principal、目标系统、有效 Scope 和受限租户上下文，但不公开 JWT、密码、Authorization Header 或内部认证状态。

### Capability、Policy 与 Eval

Capability 是 Agent 看见的业务级工具，可以组合多个 Operation。Read Workflow 支持：

```text
call  pick  map  filter  assert  redact
branch  parallel  foreach  emit
```

Workflow 不是任意代码执行环境：不支持 Python、JavaScript、shell、`eval`、动态导入或动态 URL。所有引用必须在编译期解析；循环和并发必须有固定上限，输出顺序必须稳定。

Policy 描述 required scopes、tenant mode、readable/denied fields 和 redaction rules。Eval 描述输入、Fake System 预置、期望调用、输出 Schema、期望错误以及禁止泄露的字段。每个 Capability 至少需要一个正常 Eval；涉及权限的 Capability 必须包含负例 Eval。

CapabilityQuality 另外记录业务 intent、selector acquisition、producer Capability、组合理由、失败模式和输出预算。单 Operation Capability 不是天然缺陷；search/list、detail、单 job monitor 都可能是正确边界。需要诊断的是不可构造 selector、无发现入口、无业务锚点的独立 fan-in、list 与强制 detail 耦合，以及无法证明或超预算的输出。Capability 输出只有经过可证明的 `pick/map/filter/redact` 或数据流投影才能窄于 Operation 输出。

### Action 状态机与当前边界

Action 使用显式 `prepare → approve → commit → status` 状态机。Action Operation 必须声明 effect、risk、reversibility、retry、idempotency 和 concurrency；编译器证明 preview 只读、commit 的变更拓扑受限，并按风险推导审批要求。部署策略默认 `allowed_effects={read}`，Pack 声明不能自行扩大部署权限。

当前仓库已经有严格的当前模型、证据绑定的 Action semantics、编译与 Runtime 双重证明、Pack/Loader 版本门禁、部署策略、Action Coordinator、secret-safe 审计合同和开发/测试内存 Store。普通 Generic Runtime 的 `tools()`/`call()` 仍会拒绝 Action 并要求专用生命周期，因此 MCP stdio 与 Streamable HTTP 尚未对 Agent 暴露 Action 工具。内存 Store 明确不是 durable 实现；生产 Action 仍缺少可信审批签发、durable Store、生产审计后端和完整 MCP/CLI 接线。不能通过允许任意 `POST` 绕过这些边界。

### Scope callability 与 Coverage

部署 Scope ceiling 只会收紧 Pack 的 Scope 要求。`acc run` 在监听前报告每个 Capability 的 `callable`、`conditional`、`denied` 或 `unknown`；空 ceiling 默认拒绝，`--strict-scope` 可拒绝确定不可调用的部署，`--scope-ceiling-from-pack` 也不代表 Pack 自动获得源权限。登录前未知的用户源权限保持 `unknown`，登录后仍由源系统执行最终授权。

Coverage 直接消费平台中立的 Scope Inventory，并分别报告 `route_disposition`、`operation_trace`、`scenario_coverage`、`constructability`、`discoverability_graph`、`composition`、`schema_fidelity`、`output_budget` 和 `live_observations`。它不生成总分，也不把“路由已分类”解释为“Capability 可用”。

### Capability Pack

`acc pack` 生成类似 `example-crm-0.1.0.accpkg` 的确定性归档：

```text
manifest.json
project.yaml
operations/
capabilities/
policies/
evals/
evidence/
pack.lock
```

Pack 携带经过校验的 SourceContract、CapabilityQuality 和编译证明摘要；Loader 按当前格式白名单拒绝未知成员。Pack 不携带生产 Secret、原始审批材料或可执行客户代码。

同样输入应生成完全一致的摘要。Loader 拒绝符号链接、路径穿越、未知额外文件和摘要不匹配；文件顺序和时间戳必须稳定或归一化。

## 安全模型

安全边界不是提示词约定，而是编译器和 Runtime 的强制约束：

- **只读源工作区**：Engineer Skill 在 Preflight 检查写入风险，只能修改独立 ACC 项目。
- **效果边界**：Read Operation 仅允许 `GET`/`HEAD` 且 effect 为 `read`；Action 必须经过显式模型、编译证明和部署授权。
- **固定目标**：禁止绝对 URL、动态 Host、任意外部域名、路径穿越和工具参数覆盖 Header。
- **凭据隔离**：工具输入不能携带 Token；Pack 的 Provider auth 只保存环境引用或 Gateway source 类型；Runtime 注入凭据且不得记录 Secret。
- **严格 Schema**：公开模型禁止未知字段，Operation 输入输出和 Capability 输出均通过 JSON Schema Draft 2020-12 校验。
- **证据门禁**：无 Evidence 的正式 Operation 无法通过校验；推测必须保持为未确认事项。
- **权限与租户**：Runtime 从 `PrincipalContext.effective_scopes` 检查 Scope、tenant mode、字段许可和脱敏规则；Agent 不能绕过原系统权限或 `context_bindings`。
- **资源限制**：文件读取、循环、并发、请求超时和响应大小均有上限。
- **确定执行**：Runtime 不调用 LLM、不改 Pack、不生成代码，也不获得原系统源码写权限。
- **安全日志**：不记录完整上游响应或凭据，错误使用稳定结构映射。

访问真实生产数据仍需遵守原系统授权、租户边界和 ACC Policy。Engineer Skill 不得获取生产 Secret、访问生产环境或自动部署；当前也没有可据此宣称生产写入安全的 durable Action 实现。

### 请求身份与传输边界

`stdio` 是单进程、固定身份入口：启动时构造一个 `PrincipalContext`，默认 principal 为 `stdio-local`，部署方可用 `ACC_PRINCIPAL_ID` 覆盖；它绝不从工具参数推断用户。源权限不可获得时，`source_scopes` 保持 unavailable，`effective_scopes` 只取部署 ceiling；若登录响应提供源权限，则有效 Scope 为映射后的源权限与 ceiling 的交集。

`streamable_http` 面向多用户会话。Gateway 会对每个已认证请求重新校验 Gateway Session；每次工具执行再按会话恢复并绑定可信 `PrincipalContext`，认证状态按 principal、目标系统和 Gateway session 隔离。MCP Session ID 也会由 SDK 绑定到创建它的 Gateway 身份；A 的 token 不能恢复 B 的 MCP Session。Core 仅接受 `password_bearer + gateway_session` 这一安全组合。

有效权限不是 Gateway 自行生成的“公开查询 key”。登录响应提供的源 Scope 经显式 mapping 后，再与部署方的 `--scope` ceiling 取交集；后续每次源 API 请求仍携带该用户的源 JWT，由原系统继续执行账号、角色、租户和数据权限。部署 ceiling 只能收紧，不能扩大原系统权限。账号、密码、JWT、Cookie、Authorization 和 principal/tenant 覆盖值都不是 MCP tool 参数。

验证结果使用三个明确等级：直接 Fake Runtime 为 `offline_candidate`；真实 Gateway 与官方 MCP 客户端对 Fake Source 的协议路径通过后为 `gateway_offline_verified`；只有获得明确授权并成功连接本地或隔离测试源系统，才能标为 `source_connected_verified`。三者都不证明生产行为，也不能外推到未实际连接的系统。跳过、未配置或仅完成静态合同检查不能冒充更高等级。

## FastAPI CRM 示例

`examples/fastapi-crm/` 是端到端验收场景，并使用 `provider.auth.kind: bearer_secret`；六个 Operation 都不保存 `credential_ref`：

```text
examples/fastapi-crm/
├── system/       # 模拟已有 CRM；ACC 接入期间保持只读
└── acc-project/  # 独立生成的 Evidence、Operation、Capability、Policy 和 Eval
```

Fake CRM 覆盖客户、联系人、跟进记录、待办、Bearer 认证、Scope 和 `tenant_id`。目标 Capability 为：

| Capability | 业务含义 |
| --- | --- |
| `search_customers` | 按允许的条件检索当前租户客户 |
| `get_customer_context` | 组合客户、联系人、跟进与待办等多个底层 Operation |
| `find_overdue_followups` | 查找当前租户内逾期且允许读取的跟进事项 |

完整本地验收覆盖正常、空数据、404、403、跨租户拒绝、字段脱敏、超时、响应过大、错误映射，以及 MCP `tools/list` 和 `tools/call`。验证证据与限制见 `examples/fastapi-crm/acc-project/HANDOFF.md`；这只对应仓库内 synthetic CRM，不代表生产部署或其他系统已验证。

## 开发

安装全部 workspace 包和开发依赖：

```bash
uv sync --all-packages --group dev
```

常用质量门禁：

```bash
uv run ruff format --check packages tests skills
uv run ruff check packages tests skills
uv run mypy packages tests skills/acc-engineer/scripts
uv run pytest
```

如需自动格式化：

```bash
uv run ruff format packages tests skills
```

每个 Milestone 完成后都应运行完整测试、lint 和类型检查，并检查 `git diff`。提交应保持单一目的；不要把多个里程碑压入一个提交。

## 贡献

欢迎围绕当前 Milestone 提交小而聚焦的改动：

1. 从 issue 或设计讨论确认变更范围，避免提前扩展当前发布范围之外的抽象。
2. 新建分支并添加实现、文档和必要测试。
3. 运行上述格式、lint、类型和测试命令。
4. 确认没有修改示例中的只读源系统，也没有提交 Secret、生成 Pack 或临时文件。
5. 在 PR 中说明行为变化、验证命令、未覆盖范围和安全影响。

涉及公开 Schema、Pack 格式、Runtime 权限边界或 CLI 退出码的变更，应先提交 ADR。Engineer Skill 的平台中立工作流只维护在 `skills/acc-engineer/HARNESS.md`；Codex 和 Claude Code 集成只提供薄包装，不复制核心流程。

## 开发状态

状态仅表示当前仓库的实现进度，不代表发布承诺。只有经过测试、lint、类型检查和验收后，里程碑才会标记为完成。

| Milestone | 范围 | 当前状态 |
| --- | --- | --- |
| M0 | uv workspace、包骨架、README、LICENSE、ADR、CI、Ruff、mypy、pytest | 已完成 |
| M1 | Core Models、Schema、`init`、`doctor`、`schema`、`validate` | 已完成 |
| M2 | Workflow Compiler、Pack、Coverage、Freeze、可重复构建、`compile`、`pack`、`diff` | 已完成 |
| M3 | Generic Runtime、REST Provider、MCP stdio、SecretRef、`run` | 已完成 |
| M4 | Eval、Testkit、Fake System、Coverage、E2E | 已完成 |
| M5 | 完整 ACC Engineer Skill | 已完成 |
| M6 | FastAPI CRM 端到端验收 | 已完成 |
| M7 | Provider 级认证、PrincipalContext 与结构化范围治理 | 已完成 |
| M8 | 可选多用户 Streamable HTTP Gateway | 已完成 |
| M9 | SourceContract、CapabilityQuality、Scope callability、九轴 Coverage | 已完成 |
| M10 | Action 编译/Runtime 状态机与 Live 验证 | 开发中：基础实现存在，MCP Action、durable Store 和生产审批/审计尚未完成 |

更细的检出版本进度记录在 `docs/progress.md`。生产可用性必须以发布说明、对应 Pack/Runtime 测试证据和安全评审为准。

## 路线图原则

后续版本继续完成 Action MCP/CLI 接线、durable Store、可信审批与审计实现。在这些边界有明确实现和验证前，以下规则保持不变：运行期无 LLM、原系统源码零代码修改、正式 Operation 必须证据绑定、Runtime 通用且确定、部署默认只允许 read、不能宣称生产写入已可用。

## License

许可证文本见 [`LICENSE`](LICENSE)。
