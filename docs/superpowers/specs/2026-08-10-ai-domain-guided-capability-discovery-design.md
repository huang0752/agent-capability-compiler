# AI 领域向导式能力发现与用户决策设计

## 状态

已由用户确认总体方向，等待规格文档复核后进入实施计划。

## 背景

ACC 已能扫描完整接口分母、编译 Read/Action Capability，并通过确定性 Core 校验 Evidence、Schema、身份传递边界和 Action 安全合同。但现有流程仍可能出现两类失真：

1. AI 或项目生成器先挑少量容易实现的能力，再把其他候选批量标记为 `ineligible`；
2. 用户面对完整接口清单逐项确认，认知成本过高，无法按业务目标做选择。

以任意大型前后端分离系统为例，路由、前端交互、后台任务和状态流转可能跨越多个代码模块。ACC 需要平台中立的人机协作流程：AI 全量发现并按业务域推进，用户确认业务目标和异常决策，Core 负责确定性证明。该流程不能依赖某个项目的路径、权限名或业务实体。

## 目标

- 全量扫描接口、前端交互、权限、状态流转和关联数据，不因用户尚未选择而缩小分母。
- 以大范围业务域为用户交互单位，而不是一次展示全部接口。
- 每个领域采用“开始确认策略、AI 自动处理明确项、只询问异常项、结束确认结果”的向导流程。
- Read、Action、客户端交互和未知候选均保留证据状态与差距。
- 用户选择业务目标，不负责选择技术接口或编写 ACC 合同。
- Core 从 typed evidence 和合同派生可发布状态，不信任 AI 自报的 `eligible`。
- 支持代码变更后的增量重扫、影响分析和版本化领域决策。
- 保持原系统为用户、租户、角色、资源和动态权限的唯一授权终裁者；ACC 不复制源 RBAC。

## 非目标

- 不让 Runtime 或 Core 调用 LLM。
- 不让 AI 直接获得生产凭据、调用生产写接口或绕过审批。
- 不用单一 Coverage 总分代表业务可用性。
- 不要求一次完成整个大型系统的深度分析。
- 不把前端隐藏、按钮禁用或 HTTP 方法当成权限和业务效果证明。
- 不为特定系统硬编码领域、路由、权限或 Action 白名单。
- 不根据源权限列表向用户授予能力，也不把 ACC Scope 映射当成源系统授权替代品。

## 核心原则

1. **全量发现，渐进处理**：所有候选始终留在全局分母；领域可按顺序逐个完成。
2. **业务目标优先**：用户确认“Agent 应该完成什么”，AI 映射接口、交互和依赖。
3. **证据状态独立于用户选择**：未选择、缺证据和不适合 Agent 是不同事实。
4. **AI 提案，Core 裁决**：AI 生成分类和合同候选，Core 计算诊断与发布状态。
5. **明确项自动推进，异常项才询问**：降低用户负担，但不替用户猜业务政策。
6. **领域结果版本化**：完成后不能静默改写；跨域发现通过变更请求处理。
7. **验证等级诚实分层**：静态建模、离线执行、沙箱验证、源连接和生产发布互不冒充。
8. **源系统授权终裁**：ACC 只验证身份不可伪造、调用使用当前源会话、部署边界只能收窄；每次资源访问仍由源 JWT 和源接口决定。

## 总体架构

```text
Source Workspace
  -> Global Discovery Scanner
  -> Domain Map + Global Dependency Graph
  -> Domain Orchestrator
  -> Domain Deep Scanner
  -> Capability Candidate Ledger
  -> User Domain Policy / Exception Decisions
  -> Contract Planner
  -> ACC Core Validation / Compilation / Coverage
  -> Versioned Domain Decision
  -> Next Domain or Change Request
```

### 1. Global Discovery Scanner

执行有界、只读的浅扫描，发现：

- GET、HEAD、POST、PUT、PATCH、DELETE 等注册路由；
- 前端页面、导航、事件、API 调用、默认值、条件、选项和结果消费；
- 登录交换、JWT 使用方式、租户/主体上下文和权限终裁边界；
- 实体名称、状态字段、服务调用和测试入口；
- 下载、流式响应、异步任务、外部集成等特殊边界。

扫描器只输出候选事实和 Evidence，不在浅层阶段推断最终 effect、risk 或 eligibility。

### 2. Domain Classifier

AI 根据业务意图聚类，而不是按文件夹聚类。分类信号包括：

- 页面与导航结构；
- 实体关系和 API 调用图；
- 权限名称与状态流转；
- 前端文案、表单和操作入口；
- Service、Schema 和测试中的业务术语。

一个业务域可以跨越多个代码模块。分类结果包含置信度、证据和未归类候选；Core 只校验引用闭包和分母完整性，不判断自然语言领域名称是否正确。

### 3. Domain Orchestrator

维护领域状态和推荐顺序。默认顺序参考：

1. 身份、权限和可信上下文；
2. 主数据和查询入口；
3. 核心业务流程；
4. 财务、审批等高风险操作；
5. 配置与平台治理。

AI 可以按依赖、业务价值和风险推荐顺序，用户可调整。一次只激活一个领域；未开始领域保持 `not_started`，不视为排除。

### 4. Domain Deep Scanner

进入领域后才深读相关路由、Service、Schema、数据库约束、前端交互和测试。它补齐每个候选的：

- 业务意图、资源和状态流；
- 请求/响应 Schema；
- 身份传递、租户/主体防覆盖和源系统授权终裁方式；
- Read/Action effect 候选；
- Action risk、reversibility、approval、retry、idempotency、conflict control 和 outcome resolution；
- 默认值、选项、关联数据、条件和客户端状态；
- 所需测试路径与现有证据差距。

### 5. User Decision Interface

用户不审接口，而审业务能力卡片。领域开始时确认 `DomainPolicy`：

```yaml
domain_id: order_fulfillment
goals:
  - search_orders
  - inspect_order_context
  - cancel_order
allowed_effects: [read, transition]
maximum_risk: high
approval_required_for: [cancel, void]
excluded_intents: [hard_delete]
```

AI 自动处理符合该策略且证据充分的候选。只有以下情况询问用户：

- 源码、前端或测试互相冲突；
- 业务效果、风险或身份/授权终裁边界无法确定；
- 多种 Capability 组合都合理；
- Action 的审批、冲突控制或结果恢复需要业务选择；
- 需要用户补充测试环境、人工流程或领域术语。

每个问题必须说明原因、Evidence、选项影响和默认建议。用户可用自然语言补充，AI 将其转换为结构化 `UserDecision`，原文和结构化结果都保留。

## 数据模型

### DomainMap

```yaml
schema_version: "2"
domains:
  - id: order_fulfillment
    title: 订单履约
    status: not_started
    route_ids: []
    interaction_ids: []
    dependency_domain_ids: []
    evidence_refs: []
unclassified_candidate_ids: []
```

状态为：

- `not_started`
- `in_progress`
- `awaiting_user`
- `validation_failed`
- `ready_for_review`
- `completed`
- `stale`

### CapabilityCandidateLedger

每个候选记录事实、声明、差距和用户状态，不直接存最终 eligibility：

```yaml
id: order.cancel
domain_id: order_fulfillment
business_intent: cancel_order
route_ids: []
interaction_ids: []
kind_claim: action
effect_claim: transition
claims:
  authorization_boundary:
    status: upstream_authoritative
    evidence_refs: []
  schema: {status: proven, evidence_refs: []}
  risk: {status: candidate, evidence_refs: []}
  conflict_control: {status: missing, evidence_refs: []}
  idempotency: {status: unknown, evidence_refs: []}
  outcome_resolution: {status: candidate, evidence_refs: []}
user_disposition: undecided
verification_level: action_discovered
gaps: []
```

`authorization_boundary` 证明的是“哪个源身份发起调用、可信上下文不能被 Agent 覆盖、源接口仍会终裁”，而不是证明 ACC 复刻了原系统权限。允许的状态包括：

- `upstream_authoritative`
- `identity_binding_proven`
- `context_isolation_proven`
- `unknown`

若登录响应提供源 permissions，ACC 可以把它们映射为调用性提示或提前拒绝，但该映射只能收窄，不能授予权限。any-of、动态权限、资源级权限和数据空间判断可以保持 `upstream_authoritative`，由源接口每次调用终裁。

候选状态包括：

- `action_discovered`
- `semantics_evidenced`
- `contract_ready`
- `offline_verified`
- `sandbox_verified`
- `source_connected_verified`
- `deployment_ready`
- `blocked_on_evidence`
- `deferred_by_user`
- `rejected_by_user`

### DomainDecision

领域结束确认形成版本化记录：

```yaml
domain_id: order_fulfillment
revision: 1
policy: {}
accepted_capability_ids: []
deferred_capability_ids: []
rejected_capability_ids: []
blocked_candidate_ids: []
unresolved_questions: []
dependency_snapshot_digest: sha256:...
evidence_digest: sha256:...
user_confirmation: {}
```

### DomainChangeRequest

后续发现不能直接修改已完成领域，而是生成：

- 触发变更的代码/Evidence；
- 受影响的领域、Capability 和决策；
- 原决策与建议新决策；
- 是否影响安全或部署；
- 用户确认结果。

## Action 安全策略扩展

Action 继续 fail closed，但不能把乐观版本号和 source idempotency key 当作所有系统的唯一模式。

### ConflictControlStrategy

平台中立候选包括：

- `optimistic_token`
- `conditional_mutation`
- `server_serialized_state_predicate`
- `unique_constraint`
- `append_only`
- `compensating_transaction`
- `unsupported`

每种策略都需要 typed Evidence Claims。Compiler 按 effect、risk、retry 和策略组合判断是否可接受；不能仅凭“使用了行锁”自动放行。

### IdempotencyStrategy

- `source_key`
- `natural_key`
- `state_idempotent`
- `conditional_unique_create`
- `runtime_dedupe_with_outcome_query`
- `unsupported`

### OutcomeResolutionStrategy

- `synchronous_result`
- `status_query`
- `reconciliation_query`
- `source_event`
- `outcome_unknown`

这些策略属于通用 ActionSemantics，不写入任何项目专属名称。

## 身份、权限与部署边界

ACC 明确区分三种不同事实：

1. **源系统授权**：账号密码换取的源 JWT 是否能访问某个租户、资源或操作，由原系统最终判断；ACC 不复制 RBAC、角色继承、动态 any-of 权限或数据空间算法。
2. **ACC 部署收窄**：Capability allowlist、effect ceiling、maximum risk 和可选 Scope precheck 决定当前 Agent 部署最多可以尝试什么。它们不能把源系统拒绝的调用变成允许。
3. **单次 Action 意图确认**：用户拥有源权限不代表用户授权 Agent 执行本次高风险操作。`prepare → approve → commit → status` 的 approval 绑定本次输入、预览、Principal、会话和 Pack。

运行时必须满足：

- 用户账号密码只用于源登录交换，Agent 不接收密码或源 JWT；
- Gateway token 只能恢复其绑定的 Principal 和源认证状态；
- Capability 输入不能覆盖 Principal、tenant、source scopes、Authorization 或认证句柄；
- 每次 REST 调用继续携带当前用户的源认证并由源接口终裁；
- 源 401/403/404 被映射为稳定错误，不触发权限推断、权限提升或跨用户重试；
- 可选 Scope mapping 只提供 callability 和提前拒绝，未知或动态权限不伪装成已证明；
- 部署策略和 Action approval 只增加限制，不替代源授权。

## 领域处理流程

### 阶段 A：全局准备

1. 只读扫描完整分母。
2. AI 生成 DomainMap 和全局依赖图。
3. Core 校验所有候选都有归属或进入 unclassified 集合。
4. AI 推荐领域顺序，用户可调整。

### 阶段 B：领域开始

1. 展示领域摘要、建议业务目标和风险边界。
2. 用户确认 DomainPolicy，可自然语言补充。
3. 保存用户原文及结构化决策。

### 阶段 C：自动深度分析

1. 深读领域相关证据。
2. 生成或更新 Candidate Ledger。
3. 自动建模证据充分且符合策略的明确项。
4. 将缺证据项标为 `blocked_on_evidence`，不得改成 `ineligible` 消失。

### 阶段 D：异常决策

一次只向用户提出一个问题。问题解决后继续自动分析，直到：

- 所有候选已接受、延后、拒绝或有具体证据缺口；
- 所有跨域依赖已闭合或明确延后；
- Core 不再有领域级错误。

### 阶段 E：领域结束

展示独立结果：

- 业务目标覆盖；
- route/interaction/candidate disposition；
- Read 与 Action 合同；
- selector constructability；
- 身份绑定、上下文隔离、源授权终裁和部署收窄边界；
- Action lifecycle、安全策略和验证等级；
- blocked、deferred、rejected 和 unknown；
- 跨域依赖和测试结果。

用户确认后生成 DomainDecision，领域进入 `completed`。

## Coverage 与门禁

新增独立 Action/领域轴，不生成总分：

- `domain_disposition`
- `business_goal_coverage`
- `candidate_classification`
- `semantics_provenance`
- `identity_and_upstream_authorization`
- `lifecycle_constructability`
- `conflict_control_fidelity`
- `idempotency_fidelity`
- `outcome_resolution`
- `verification_level`
- `cross_domain_dependencies`
- `user_decision_trace`

`system_complete` 下：

- 候选不能因缺证据直接标为 `ineligible`；
- 未归类候选是 error；
- `blocked_on_evidence` 可以保存和交接，但阻止领域标记 `completed`，除非用户明确把能力设为 `deferred_by_user`；
- `deferred_by_user` 不生成 MCP，不算永久排除；
- `rejected_by_user` 必须保存用户原文和精确业务能力 ID；
- 高 Action 候选排除率必须独立显示，不能被 Read 覆盖率掩盖。

## 增量重扫

1. 对 Git diff、路由、Schema、权限和客户端交互进行变化定位。
2. 通过依赖图计算受影响领域。
3. 将相关 DomainDecision 标为 `stale`，不自动删除已发布能力。
4. 生成 DomainChangeRequest。
5. 只重跑受影响的 Evidence、合同、测试和用户问题。
6. 用户确认后产生新 revision。

安全相关变化在重新确认前应使对应能力部署状态变为不可用；纯描述性变化可以保持运行但产生审计提示。

## 错误与恢复

- AI 扫描中断：保留扫描游标和已冻结 Evidence，不把部分结果标为完成。
- 候选分类冲突：保持 unknown，生成单个用户问题。
- Evidence 漂移：使对应 Claim 失效并触发变更请求。
- 源 permissions 缺失或动态：保持 `upstream_authoritative`，不阻止建模，但禁止宣称 ACC 已完成等价权限预检。
- 用户暂不回答：领域进入 `awaiting_user`，其他无依赖领域可以继续。
- Core 校验失败：领域进入 `validation_failed`，保留诊断和修复建议。
- 跨域循环：生成依赖组，由用户确认统一处理顺序或拆分边界。
- LLM 输出异常：严格 Schema 解析失败后重试；持续失败则保留原始安全摘要并停止当前步骤。

## 测试策略

### 单元测试

- DomainMap、Candidate Ledger、Decision 和 ChangeRequest 严格模型；
- 用户自然语言决策到结构化策略的边界校验；
- candidate gap 与 verification 状态转换；
- Action conflict/idempotency/outcome 策略组合；
- 不允许 `ineligible` 吞掉缺证据候选；
- 领域 revision 和 stale 传播。

### 集成测试

- AI fixture 输出经过 Core 校验，错误分类不能通过；
- 领域开始、异常提问、结束确认的完整状态机；
- 跨域依赖和 ChangeRequest；
- Read、Action、UI Interaction 与 Scope/Coverage 同源闭包；
- 当前用户源 JWT 终裁、A/B 会话隔离、身份参数防覆盖，以及 Scope 仅收窄不授权；
- 中断后恢复和 Evidence 漂移。

### 跨行业 E2E Fixtures

- CRM：客户发现、详情和关联数据；
- ERP：订单履约及状态流转；
- 财务：高风险作废、审批和冲突控制；
- 内容系统：发布、撤回和长文本展示；
- 任务系统：异步执行、取消和结果恢复；
- 权限系统：动态授权、租户和角色治理；
- 移动端/纯客户端：无直接 route 的交互能力。

每个 fixture 必须证明相同流程适用于不同技术栈，不能出现项目专属分支。

## 分阶段交付

1. Candidate Ledger、DomainMap、DomainDecision 和 Action Coverage 模型。
2. Scope eligibility 派生与 `blocked_on_evidence` 门禁。
3. Skill 的领域向导流程、Action 模板和跨行业示例。
4. 通用 conflict/idempotency/outcome 策略扩展。
5. AI Scanner/Classifier/Orchestrator 与可恢复状态机。
6. CLI 领域向导和结构化用户决策。
7. 增量重扫、ChangeRequest 和跨域影响分析。
8. 跨行业回归及既有项目迁移审计。

## 验收标准

- 全系统候选无静默丢失或批量 generic exclusion。
- 用户一次只处理一个业务领域，且主要选择业务目标而非接口。
- 证据明确项自动完成，用户只处理异常和策略选择。
- 每个领域有版本化决策、独立 Coverage 和可复查用户原文。
- Read 和 Action 数量不是成功标准；每个未发布候选都有具体状态、Evidence 或可执行缺口。
- Core 能拒绝 AI 伪造的 effect、eligibility、并发或幂等结论。
- 没有沙箱只降低验证等级，不阻止静态候选和证据账本建立。
- 任意源代码变化可定位到受影响领域并产生显式 ChangeRequest。
- 跨行业 fixtures 不包含任何 baogao-jin 专属路径、权限或实体规则。
