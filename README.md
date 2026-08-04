# Agent Capability Compiler (ACC)

ACC 是一个**零代码侵入式 Agent 能力接入工具链**。它帮助 Coding Agent 从已有系统的源码、接口文档、权限规则和测试中提取有证据支持的业务能力，将其编译为可重复构建的 Capability Pack，再由固定的通用 Runtime 通过 MCP 暴露给 Agent。

ACC 不修改已有业务系统，不要求业务系统嵌入 Agent SDK 或接入 MCP。运行时只访问已有 REST API，或访问独立部署的旁路 Adapter。

> [!IMPORTANT]
> 本项目正在从零实现首个 MVP。下文同时描述已确定的产品契约和目标使用方式；它不表示所有命令已经可用。请先查看[开发状态](#开发状态)，不要将未完成的里程碑用于生产环境。

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
       System Map / Evidence / Operation / Capability / Eval
                         │
                         ▼
          ACC Core：校验、编译、测试、确定性打包
                         │
                         ▼
                  Capability Pack (.accpkg)
                         │
                         ▼
              ACC Generic Runtime（无 LLM）
                         │ MCP stdio
                         ▼
                       Agent
                         │
                         ▼
             原系统 REST API / 独立 Adapter
```

## 产品边界

ACC 负责：

- 稳定的 `acc` CLI、Schema 和结构化诊断；
- Evidence 绑定、引用检查、Policy 校验和 Workflow 编译；
- Eval、Coverage 和可重复构建的 Capability Pack；
- 固定通用 Runtime、MCP stdio、REST Provider 和 SecretRef；
- Adapter SDK 基础契约、测试工具和 Fake Adapter；
- 面向 Coding Agent 的 ACC Engineer Skill。

ACC **不**负责：

- 集成 OpenAI、Anthropic 或其他模型 SDK；
- 模型选择、Token 管理、上下文压缩、Agent Loop、模型重试或计费；
- 修改原系统代码、数据库、认证逻辑或部署；
- 在 Runtime 中动态生成代码、HTTP 请求或工作流；
- 第一版中的生产写入、Web 管理后台、SaaS 控制面、插件市场、Kubernetes、Helm、OCI、SOAP、gRPC、数据库 Adapter、消息队列、RPA 或浏览器录制。

MVP 仅支持 **REST API、GET/HEAD 只读操作、MCP stdio、Capability Pack 和通用 Runtime**。

## 架构

仓库由四个可独立测试的 Python 包和一套平台中立的 Engineer Skill 组成：

| 组件 | 职责 |
| --- | --- |
| `acc-core` | 数据模型、JSON Schema、CLI、Evidence、校验器、编译器、Coverage、Eval、Pack |
| `acc-runtime` | Pack Loader、MCP stdio、Workflow 执行、REST Provider、SecretRef、Policy、结构化错误 |
| `acc-adapter-sdk` | Adapter Contract、Server 基础骨架、测试工具和 Fake Adapter 示例 |
| `acc-testkit` | Fake REST System、MCP 测试客户端、E2E 断言、故障模拟和示例数据 |
| `skills/acc-engineer` | `preflight → analyze → model → plan → implement → validate → test → refine → handoff` |

核心原则：

1. **Skill-first**：AI 能力由 Coding Agent 宿主提供，ACC 本身不集成模型。
2. **AI 负责创造，ACC 负责约束**：分析和候选定义可以由 Agent 完成，最终有效性由确定性工具验证。
3. **通用 Runtime**：每个系统只生成数据化的 Pack，不复制一套 Runtime 源码。
4. **证据绑定**：正式 Operation 的路径、方法、字段、权限、租户边界、效果和错误必须能回溯到证据。
5. **原系统只读**：所有生成物写入独立 ACC 项目；Engineer Skill 最终停在人工 Git Review 之前。

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

在首个可用版本中，一个典型的只读接入流程将是：

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

以上 ACC 命令的可用性取决于对应里程碑；当前检出版本请以 `uv run acc --help` 和[开发状态](#开发状态)为准。开发仓库中也可以统一写成 `uv run acc ...`。

## CLI 契约

MVP 命令面如下：

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

Project 绑定只读源工作区和 HTTP Provider，但只保存凭据引用：

```yaml
schema_version: "1"
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
```

### Operation 与 Evidence

Operation 是已有系统的原子 HTTP 操作。MVP 只接受 `GET` 和 `HEAD`；正式 Operation 必须绑定 Evidence：

```yaml
schema_version: "1"
id: crm.get_customer
title: 获取客户资料
kind: http
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
  credential_ref: CRM_USER_TOKEN
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

### Capability、Policy 与 Eval

Capability 是 Agent 看见的业务级工具，可以组合多个 Operation。Workflow MVP 仅支持：

```text
call  pick  map  filter  assert  redact
branch  parallel  foreach  emit
```

Workflow 不是任意代码执行环境：不支持 Python、JavaScript、shell、`eval`、动态导入或动态 URL。所有引用必须在编译期解析；循环和并发必须有固定上限，输出顺序必须稳定。

Policy 描述 required scopes、tenant mode、readable/denied fields 和 redaction rules。Eval 描述输入、Fake System 预置、期望调用、输出 Schema、期望错误以及禁止泄露的字段。每个 Capability 至少需要一个正常 Eval；涉及权限的 Capability 必须包含负例 Eval。

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

同样输入应生成完全一致的摘要。Loader 拒绝符号链接、路径穿越、未知额外文件和摘要不匹配；文件顺序和时间戳必须稳定或归一化。

## 安全模型

安全边界不是提示词约定，而是编译器和 Runtime 的强制约束：

- **只读源工作区**：Engineer Skill 在 Preflight 检查写入风险，只能修改独立 ACC 项目。
- **只读网络操作**：MVP Operation 仅允许 `GET`/`HEAD`，且 `safety.effect` 必须为 `read`。
- **固定目标**：禁止绝对 URL、动态 Host、任意外部域名、路径穿越和工具参数覆盖 Header。
- **凭据隔离**：工具输入不能携带 Token；Pack 只引用 SecretRef；Runtime 注入凭据且不得记录 Secret。
- **严格 Schema**：公开模型禁止未知字段，Operation 输入输出和 Capability 输出均通过 JSON Schema Draft 2020-12 校验。
- **证据门禁**：无 Evidence 的正式 Operation 无法通过校验；推测必须保持为未确认事项。
- **权限与租户**：Runtime 检查 Scope、tenant mode、字段许可和脱敏规则；Agent 不能绕过原系统权限。
- **资源限制**：文件读取、循环、并发、请求超时和响应大小均有上限。
- **确定执行**：Runtime 不调用 LLM、不改 Pack、不生成代码，也不获得原系统源码写权限。
- **安全日志**：不记录完整上游响应或凭据，错误使用稳定结构映射。

访问真实生产数据仍需遵守原系统授权、租户边界和 ACC Policy。MVP 不允许访问生产写接口，也不允许 Engineer Skill 获取生产 Secret、访问生产环境或自动部署。

## FastAPI CRM 示例

`examples/fastapi-crm/` 是 MVP 的端到端验收场景：

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

完整验收需要同时覆盖正常、空数据、404、403、跨租户拒绝、字段脱敏、超时、响应过大、错误映射，以及 MCP `tools/list` 和 `tools/call`。在 Milestone 6 完成前，此目录和上述能力属于验收目标，不应被视为已经跑通的生产示例。

## 开发

安装全部 workspace 包和开发依赖：

```bash
uv sync --all-packages --group dev
```

常用质量门禁：

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy packages tests
uv run pytest
```

如需自动格式化：

```bash
uv run ruff format .
```

每个 Milestone 完成后都应运行完整测试、lint 和类型检查，并检查 `git diff`。提交应保持单一目的；不要把多个里程碑压入一个提交。

## 贡献

欢迎围绕当前 Milestone 提交小而聚焦的改动：

1. 从 issue 或设计讨论确认变更范围，避免提前扩展 MVP 之外的抽象。
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
| M3 | Generic Runtime、REST Provider、MCP stdio、SecretRef、`run` | 未完成 |
| M4 | Eval、Testkit、Fake System、Coverage、E2E | 未完成 |
| M5 | 完整 ACC Engineer Skill | 未完成 |
| M6 | FastAPI CRM 端到端验收 | 未完成 |

更细的检出版本进度记录在 `docs/progress.md`。生产可用性必须以发布说明、对应 Pack/Runtime 测试证据和安全评审为准。

## 路线图原则

首个 MVP 完成后再评估写操作、更多 Provider 或分发能力。在此之前，以下规则保持不变：运行期无 LLM、原系统零代码修改、正式 Operation 必须证据绑定、Runtime 通用且确定、生产写入为零。

## License

许可证文本见 [`LICENSE`](LICENSE)。
