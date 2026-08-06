# ACC Engineer 范围完整性门禁设计

## 背景

当前 ACC Engineer Skill 能严格约束只读、安全、Evidence、权限和租户边界，但缺少“系统范围是否完整”的可验证分母。Agent 可以先选择少量高价值接口，再让 `acc coverage` 对这批已选 Operation 得出完整覆盖结论；该结果只能证明候选内部自洽，不能证明已有系统的只读接口已被完整分析。

本设计为 Skill 增加明确的范围模式、全量只读路由处置清单和确定性审计门禁。它不改变 ACC 核心 Operation/Capability/Policy/Eval 公共模型，也不执行原系统代码。

## 目标

1. 当用户只说“分析已有系统并做 MCP”时，默认按全系统只读完整模式执行。
2. 只有用户明确说“样板、试点、MVP”时才允许使用试点模式。
3. 为合格的 `GET`/`HEAD` 路由建立可审查分母，每条路由都有明确处置。
4. 通过确定性脚本阻止遗漏路由、无理由排除、统计不一致和范围静默降级。
5. 区分候选内部覆盖、源系统范围覆盖和真实系统连接验证。
6. 保持源系统不可变、平台中立、不执行源代码和不访问生产环境的现有边界。

## 非目标

- 不自动解析或导入任意应用框架。
- 不执行 FastAPI、Django、Spring 等原系统代码以获取路由。
- 不把所有路由机械转换为 MCP 工具。
- 不在本次修改中增加写 Operation。
- 不在本次修改中完成 `baogao-jin` 的全系统只读能力扩展；Skill 完成后另行重新审计。

## 范围模式

每个 ACC 项目必须在 `scope-inventory.yaml` 中声明一个范围模式。

### `system_readonly_complete`

默认模式。适用于用户未明确缩小范围的“分析已有系统”“为系统做 MCP”等请求。

- 发现范围覆盖整个源系统。
- 全部已发现且符合 ACC 只读边界的 `GET`/`HEAD` 路由必须进入清单。
- 每条合格路由必须处于终态处置；存在未审查或证据阻塞时不得标记完整。

### `domain_complete`

仅当用户明确指定一个或多个业务域时使用。

- 必须声明所选业务域和域边界 Evidence。
- 所选域内的合格只读路由必须全部处置。
- 域外路由不计入覆盖分母，但必须在发现摘要中记录为域外。

### `pilot`

仅当用户明确使用“样板、试点、MVP”等语义时使用。

- 必须记录用户确认摘要。
- 可以只选择部分高价值路由。
- 交付状态必须包含 `pilot`，不得写成系统完整或领域完整。

Agent 不得因为仓库较大、时间不足或证据获取困难自行把默认模式降级为 `pilot`。这些情况应产生阻塞或显式限制，而不是改变范围语义。

## `scope-inventory.yaml`

新增规划期工件，位于 ACC 项目根目录，不进入正式 Operation 集合。

顶层结构：

```yaml
schema_version: "1"
scope:
  mode: system_readonly_complete
  user_confirmation: null
  selected_domains: []
discovery:
  source_commit: "git:0123456789abcdef"
  methods: [GET, HEAD]
  include_paths: [backend/app/api]
  evidence_sources: [api-router]
domains:
  - {id: customer, status: selected}
routes:
  - id: customer.search
    domain: customer
    method: GET
    path: /api/customers/search
    evidence_sources: [customer-routes]
    eligibility: eligible
    disposition: planned
    operation_id: customer.search
    capability_ids: [search_customers]
summary:
  discovered_routes: 1
  eligible_read_routes: 1
  planned: 1
  composed: 0
  excluded: 0
  blocked_on_evidence: 0
  out_of_scope: 0
  unresolved: 0
```

### 路由记录

每条路由记录至少包含：

- `id`：范围清单内稳定标识。
- `domain`：所属业务域。
- `method` 与 `path`。
- `evidence_sources`：证明路由存在及其边界的 Evidence ID。
- `eligibility`：`eligible` 或 `ineligible`。
- `disposition`：`planned`、`composed`、`excluded`、`blocked_on_evidence`、`out_of_scope`。
- `operation_id`：`planned`/`composed` 时必填。
- `capability_ids`：已组合进的业务能力，可为空直到 Plan 完成。
- `reason`：`excluded`、`blocked_on_evidence`、`out_of_scope` 时必填。

`ineligible` 用于写方法、动态/不安全请求或不符合 ACC 里程碑边界的接口，不进入合格只读路由分母，但仍保留发现记录。`excluded` 仅用于合格只读路由在业务价值、重复性或披露风险上明确不进入候选的情况。

### 统计摘要

`summary` 必须由明细可重算，至少包括：

- 发现路由总数。
- 合格只读路由数。
- 各 disposition 数量。
- 所选域内与域外数量。
- 未进入终态的数量。

清单不保存凭据、生产地址、完整响应或生产数据。

## 发现策略

采用两阶段发现，兼顾大型仓库安全和范围完整性。

### 第一阶段：浅层全局发现

使用只读文本搜索、静态路由文件、OpenAPI 文件、前端 API 客户端和路由注册表定位业务域与候选路由。允许使用 `rg` 等不会执行源代码的工具。该阶段覆盖整个声明范围，但只读取用于发现的轻量文件。

### 第二阶段：有界深度取证

对第一阶段发现的合格路由，使用 Preflight `--include` 清单读取路由、Schema、权限、租户和测试文件并捕获 Evidence。大型生成物、依赖目录、Secret 路径和二进制资产继续 fail closed。

`--include` 是深度取证边界，不得被当成系统路由发现分母。这样避免“先选文件，再宣称这些文件代表全系统”的循环偏差。

## 确定性范围审计

新增 `skills/acc-engineer/scripts/scope_audit.py`，输入：

- `--inventory scope-inventory.yaml`
- `--system-map system-map.yaml`
- `--plan capability-plan.yaml`
- `--coverage-baseline coverage-baseline.json`

输出沿用 Skill JSON envelope：`command`、`ok`、`result`、`diagnostics`。

审计规则：

1. 校验文件存在、YAML/JSON 结构和 schema version。
2. 校验范围模式、用户确认和 selected domains 的组合。
3. 校验 route ID 唯一，方法和路径合法，Evidence 引用非空。
4. 校验 disposition 必填字段和互斥字段。
5. 从 routes 重算 summary，拒绝统计不一致。
6. 校验 `planned`/`composed` 的 operation ID 存在于 System Map 和 Plan 依赖中。
7. 校验合格路由没有缺失处置。
8. `system_readonly_complete` 拒绝 `out_of_scope` 和未解决的 `blocked_on_evidence`。
9. `domain_complete` 拒绝所选域内的 `out_of_scope` 和未解决阻塞，并要求域外项明确标记。
10. `pilot` 要求非空用户确认，并在结果中返回不可宣称完整的限制。
11. 校验 coverage baseline 的源系统范围统计与 inventory 一致。

诊断必须包含稳定 code、path 和 pointer，不复制敏感源内容。

## Coverage 语义

Coverage 分为三层：

1. `source_scope`：源系统发现的合格只读路由及其处置覆盖。
2. `operation_coverage`：已规划 Operation 是否被 Capability 使用。
3. `eval_coverage`：Capability 是否具备正常、空/缺失和权限负例。

现有 `acc coverage` 继续负责后两层。`scope_audit.py` 负责第一层，并校验 `coverage-baseline.json` 增加的以下字段：

```json
{
  "scope_mode": "system_readonly_complete",
  "source_scope": {
    "eligible_read_routes": 0,
    "planned_or_composed": 0,
    "excluded": 0,
    "blocked_on_evidence": 0,
    "unresolved": 0
  }
}
```

不得用 `acc coverage` 的无孤儿结论替代 source scope 完整性结论。

## 验证等级

交付状态拆分为：

### `offline_candidate`

满足以下条件：

- 范围审计与 ACC Validate/Compile/Coverage 通过。
- Contract、Fake Runtime 和 MCP E2E 通过。
- 双重 Pack 一致。
- 未连接真实源系统。

### `source_connected_verified`

在 `offline_candidate` 基础上，经用户明确授权后连接本地或隔离测试环境，验证真实认证、响应 Schema、权限和数据可见性。不得连接生产环境或调用写接口。

未完成真实连接测试时，HANDOFF 必须明确写为 `offline_candidate`，不得使用“真实系统已验收”等措辞。

## Handoff 工件

Phase 8 增加 `scope-audit-report.json`。

- Git 管理的 ACC 项目继续生成 `candidate.diff`。
- 非 Git ACC 项目生成 `artifact-manifest.json`，记录相对路径、大小和 SHA-256；不得伪造空 diff。
- `HANDOFF.md` 必须声明范围模式、发现分母、各 disposition 数量、验证等级和未运行项。

## Skill 和指南调整

- `SKILL.md`：加入默认范围语义、范围审计必需门禁和验证等级。
- `HARNESS.md`：把范围选择与浅层发现放在 Preflight/Analyze 交界处。
- `02-analyze.md`：要求生成完整 `scope-inventory.yaml`。
- `03-model.md`：要求候选 Operation 与范围路由一一回溯。
- `04-plan.md`：要求所有合格路由获得 disposition，且计划与清单一致。
- `05-implement.md`：只实现已审计的 planned/composed Operation。
- `06-validate.md`：在 ACC 校验前运行 scope audit。
- `07-test.md`：明确 Fake E2E 与 source-connected 测试的区别。
- `08-refine.md`：同时检查三层覆盖，不以工具数量为优化目标。
- `09-handoff.md`：增加范围报告、验证等级和非 Git manifest 规则。

## 测试设计

### 单元测试

先写失败测试，再实现脚本。至少覆盖：

- 未指定模式时拒绝，而模板默认显式写入 `system_readonly_complete`。
- `pilot` 没有用户确认时拒绝。
- route ID 重复。
- 合格路由缺少 Evidence 或 disposition。
- `excluded`、`blocked_on_evidence`、`out_of_scope` 缺少 reason。
- summary 与明细不一致。
- planned/composed Operation 不存在于 System Map 或 Plan。
- system complete 存在 out-of-scope 或阻塞项。
- domain complete 的 selected domain 不完整。
- coverage baseline 与 inventory 分母不一致。
- 合法 pilot、domain complete 和 system complete 示例通过。
- JSON diagnostics 不包含源内容或 Secret。

### Skill 结构测试

- 新模板可被 YAML/JSON 解析且无占位符提交风险。
- SKILL、HARNESS 和 Phase 1/3/5/8 明确引用 scope audit。
- SKILL 保持少于 500 行，平台 wrapper 继续委托单一 Harness。

### 完整验证

- `uv run pytest -q`
- `uv run ruff check .`
- `uv run mypy packages tests skills/acc-engineer/scripts`
- Skill Creator 的 `quick_validate.py skills/acc-engineer`

## 迁移与兼容性

这是 Skill 工作流门禁升级，不修改 ACC 核心项目 Schema，因此旧 ACC Pack 仍可由 ACC CLI 加载。旧 ACC 工程在再次使用新版 Skill 审计或交付时，必须新增 `scope-inventory.yaml` 并更新 coverage baseline；未迁移前只能保持历史交付状态，不能用新版 Skill 宣称范围完整。

`baogao-jin-acc` 当前候选在迁移后应标记为 `pilot` 与 `offline_candidate`。随后使用新版默认 `system_readonly_complete` 重新执行全系统只读发现和扩展。
