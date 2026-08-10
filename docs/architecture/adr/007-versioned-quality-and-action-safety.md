# ADR 007: Current quality contracts and default-deny Actions

## Status

Accepted; production Action integration remains deployment work.

## Context

ACC 提供证据绑定的 Read/Action 模型、Capability Pack、Generic Runtime、MCP stdio 和可选多用户 Gateway。继续扩展能力时不能把样本观测写成 Schema 上界、把 route 处置率写成 Agent 可用性、把用户审批写成源权限，或仅因接口使用 `POST` 就允许真实变更。

质量分析、源系统授权与 Action 执行是三个不同边界。SourceContract、CapabilityQuality、Domain/Candidate Coverage、Scope callability、Action 编译证明、审批协议、状态存储和 MCP 暴露可以分别演进；文档与 Runtime 必须说明哪些路径已实现和验证，不能把严格模型或 Fake Source 测试等同于生产能力。

## Decision

ACC 使用单一当前格式 `2`。Project、DomainMap、Candidate Ledger、DomainDecision、Operation、Capability、IR 和 Pack 不接受旧格式，也不做隐式迁移。

质量与可调用性保持正交：

- 每个 Operation 必须有 SourceContract，每个 Capability 必须有 CapabilityQuality。Evidence provenance 支持请求/响应 Schema、selector acquisition、组合理由和输出预算；无法证明的关系保持 `unknown`。
- Capability 输出只有经过确定性工作流可证明投影后才能收紧。单 Operation Capability 不是质量缺陷，工具数量也不是优化目标。
- Scope callability 比较 Capability 的路径要求、部署 Scope ceiling 和当前已知 Principal Scope。ACC Scope 只能收窄，不能授予源系统权限；空 ceiling 默认拒绝，登录前无法知道的源权限保持 `unknown`。
- 源 JWT 与源 API 是最终授权者。Runtime 在每次 REST 请求上保留源身份和上下文绑定，由源系统重新做最终鉴权；ACC 不复制用户、角色、租户或数据 RBAC。
- Coverage 不生成总分或 deployable/usable 总结。除九个基础质量轴和十个交互轴外，`domain_disposition`、`business_goals`、`candidate_classification`、`semantics_provenance`、`identity_authorization`、`action_lifecycle`、`conflict_control`、`idempotency`、`outcome_resolution`、`verification`、`cross_domain_dependency`、`user_decision_trace` 构成十二个相互独立的领域与 Action Coverage 轴。

Action 使用默认拒绝的显式状态机：

```text
prepare -> approve -> commit -> status
```

- Action Operation 明确声明 effect、risk、reversibility、retry、idempotency、concurrency 和 outcome resolution；HTTP 方法本身不能证明业务效果。
- 编译器证明 preview 只读、commit 变更拓扑受限，并按风险推导审批要求。Approval 只确认一项已证明变更，不是源系统授权。
- 乐观并发策略必须使用 Runtime 获得的 token 和证据绑定的源 precondition，Agent 不能注入伪版本。
- 服务端状态谓词策略必须引用声明的 Read Operation，先读取允许状态，并与相同 state pointer 的状态幂等、`retry: never` 和 `status_query` 结果解析同时成立。已处于终态时不重复 mutation；mutation 后结果无法闭合时持久保持 `outcome_unknown`，重放不能再次写入。
- 部署方独立配置 allowed effects、最大风险、Capability allowlist、durable Store、ApprovalAuthority 和审计策略；默认只允许 `read`，Pack 不能扩大部署授权。
- approval handle、Principal、凭据、并发令牌和已密封的执行事实都属于可信 Runtime/宿主边界，不是 Agent 可构造参数。

Compiler 和 Runtime 只执行类型化、摘要绑定的确定性逻辑。ACC Core 与 Runtime 都不调用 LLM；AI 分析和候选生成只发生在 ACC Engineer Skill 所在的 Coding Agent 编译期。

验证等级必须反映实际路径：

- `offline_candidate`：直接 Fake Runtime；
- `gateway_offline_verified`：真实 Gateway 和官方 MCP 客户端连接 Fake Source；
- `source_connected_verified`：经明确授权连接本地或隔离测试源并通过声明场景。

任何等级都不等于生产认证，源连接也不能替代客户端适配或源权限验收。运行 observation 不会反写为 SourceContract 上界。

## Current implementation boundary

当前实现包含单一格式模型、Schema、项目 sidecar 校验、Domain/Candidate/Decision 合同、十二个领域与 Action Coverage 轴、Scope callability、Action 编译证明、部署策略、Runtime Action Coordinator、乐观并发与服务端状态谓词执行、开发/测试内存 Store 和 Live Gateway 测试基础。

普通 Generic Runtime 的 `tools()`/`call()` 仍拒绝 Action。多用户 Gateway 只从当前已验证 Pack、同一 Provider 和显式 Action 部署依赖构造 Coordinator；允许的 Action 以业务专属 prepare 工具加通用 approve/commit/status 工具暴露，并绑定 Principal、Gateway session、Pack、审批、并发令牌和审计。官方 MCP SDK 已完成 Fake Source 下的既有多用户离线生命周期验证；服务端状态策略目前由独立 Runtime/Fake Provider 测试验证。

仓库仍未提供生产 durable Action Store、生产 ApprovalAuthority 或集中审计后端，也没有对生产源 Action 做 source-connected 验证。因此当前证据最多支持 `gateway_offline_verified`，不能宣称生产源 Action 已连接验证或生产写入已发布。

## Consequences

- 旧格式项目和 Pack 在解析边界被拒绝，避免通过兼容默认值获得新语义。
- 质量报告保留 unknown、deferred 和各轴事实，不能通过合并工具、删 route、隐藏 Candidate 或编造上界刷分。
- 源权限变化不要求 ACC 维护第二套 RBAC；但失效身份、上下文或 Evidence 会使相关路径拒绝或进入影响分析。
- 生产 Action 需要部署者提供 ACC 仓库之外的持久状态、审批和审计集成，并通过独立安全验收。

## Rejected alternatives

- **保留旧格式并加入可选写字段**：会让旧合同通过默认值获得新语义。
- **按 HTTP 方法自动允许 Action**：`POST` 可能是查询，`GET` 也可能触发副作用，方法不能替代 Evidence。
- **由 ACC 复制源系统 RBAC**：会形成漂移的第二权限源，并可能越过源 JWT 的最终裁决。
- **用单一 Coverage 分数作为发布门禁**：会掩盖不可构造、Schema 失真、候选消失和 Action 语义缺口。
- **把内存 Action Store 用于生产**：重启、并发和多实例语义不足，无法满足 durable 状态要求。
- **让 Agent 直接提交审批、凭据或并发材料**：破坏可信边界并允许模型构造授权或重放写入。
