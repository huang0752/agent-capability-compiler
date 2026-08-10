# ADR 007: Current quality contracts and default-deny Actions

## Status

Accepted; implementation is incremental.

## Context

ACC 提供证据绑定的 Read Operation、Capability Pack、Generic Runtime、MCP stdio 和可选多用户 Gateway。继续扩展能力时有三类风险：把样本观测误写成 Schema 上界、把路由处置率误写成 Agent 可用性，以及通过允许 `POST` 让默认部署意外获得写权限。

质量分析与 Action 执行也不是同一个发布边界。SourceContract、CapabilityQuality、Coverage、Scope callability、Action 编译证明、审批协议、状态存储和 MCP 暴露可以分别演进；文档与 Runtime 必须说明哪些层已经实现，不能把模型或测试基础设施等同于生产能力。

## Decision

ACC 使用单一当前格式合同：

- Project、Operation、Capability、IR 和 Pack 只接受格式 `2`；旧格式稳定拒绝，不做隐式迁移。
- 每个 Operation 必须有 SourceContract，每个 Capability 必须有 CapabilityQuality。Evidence provenance 支持请求/响应 Schema、selector acquisition、组合理由和输出预算；无法证明的关系保持 unknown。
- Capability 输出只有经过确定性工作流可证明投影后才能收紧。单 Operation Capability 不是质量缺陷，工具数量也不是优化目标。

部署可调用性与设计覆盖分别处理：

- Scope callability 比较 Capability 的路径要求、部署 Scope ceiling 和已知 Principal Scope。空 ceiling 默认拒绝；登录前无法知道的源权限保持 unknown。
- Coverage 独立报告九个基础质量轴，以及 surface disposition、interaction trace、input/default/option/condition fidelity、related-data graph、state scenarios、presentation projection、client-adapter evidence 十个交互轴；不生成总分，也不把 route closure 当作 usable。

交互验证采用彼此独立的 `contract_declared`、`static_verified`、`headless_verified`、`runtime_offline_verified`、`source_connected_verified` 与 `client_adapter_verified` 事实。真实源连通不能替代客户端适配验证；required scenario 的失败或跳过都不能形成 verified 报告。Runtime 只消费 compiler 输出的安全公共投影，不承担客户端渲染与交互执行。

Action 采用默认拒绝的显式状态机：

```text
prepare -> approve -> commit -> status
```

- Action Operation 明确声明 effect、risk、reversibility、retry、idempotency 和 concurrency；HTTP 方法本身不能证明业务效果。
- 编译器证明 preview 只读、commit 变更拓扑受限，并按风险推导审批要求。
- 部署方独立配置 allowed effects、最大风险、Capability allowlist、durable Store 和审计策略；默认只允许 `read`，Pack 不能扩大部署授权。
- approval handle、Principal、凭据和并发令牌都属于可信 Runtime/宿主边界，不是 Agent 可构造参数。

验证等级必须反映实际路径：

- `offline_candidate`：直接 Fake Runtime；
- `gateway_offline_verified`：真实 Gateway 和官方 MCP 客户端连接 Fake Source；
- `source_connected_verified`：经明确授权连接本地或隔离测试源并通过声明场景。

任何等级都不等于生产认证，观测值也不会反写为 SourceContract 上界。

## Current implementation boundary

当前实现已包含单一格式模型、Schema、项目 sidecar 校验、Schema fidelity、Capability quality、基础质量轴与十个交互轴 Coverage、Scope callability、Action 编译证明、部署策略、Runtime Action Coordinator、开发/测试内存 Store 和 Live Gateway 测试基础。

跨行业 fixture 以完整的当前格式 Project、Operation、Capability、Policy、Eval、SourceContract、CapabilityQuality、Scope 和 UI 合同运行 fidelity analyzer、compiler 与 Coverage，证明同一平台中立合同可表达 CRM list→detail、ERP 共享标识与真实 Action Capability 生命周期声明、独立 selector、单 job 监控、长文本展示、增长列表和纯客户端交互。它们使用受控 client artifact Evidence，不代表这些行业的生产客户端、权限源或线上数据已经验证。

普通 Generic Runtime 的 `tools()`/`call()` 仍拒绝 Action。多用户 Gateway 只从当前已验证 Pack、同一 Provider 和显式 Action 部署依赖构造 Coordinator；允许的 Action 以业务专属 prepare 工具加通用 approve/commit/status 工具暴露，且绑定 Principal、Gateway session、Pack、审批、并发令牌和审计。官方 MCP SDK 已完成 Fake Source 下的多用户离线生命周期验证。仓库仍未提供生产 durable Action Store、可信审批签发服务或集中审计后端，因此这证明 `gateway_offline_verified`，不等于生产 Action 已发布或真实业务写入已验证。

## Consequences

- 旧格式项目和 Pack 在版本边界被拒绝，避免通过隐式回退获得错误语义。
- 质量报告保留 unknown 和各轴事实，不能通过合并工具、删路由或编造上界刷分。
- 生产 Action 需要部署者提供 ACC 仓库之外的持久状态、审批和审计集成，并通过独立安全验收。
- Core、Runtime、Testkit、Skill 和公开文档必须使用一致的版本与验证术语。

## Rejected alternatives

- **保留旧格式并加入可选写字段**：会让旧合同通过默认值获得新语义。
- **按 HTTP 方法自动允许 Action**：`POST` 可能是查询，`GET` 也可能触发副作用，方法不能替代 Evidence。
- **用单一 Coverage 分数作为发布门禁**：会掩盖不可构造、Schema 失真和路由闭包断裂。
- **把内存 Action Store 用于生产**：重启、并发和多实例语义不足，无法满足 durable 状态要求。
- **让 Agent 直接提交审批或凭据材料**：破坏可信边界并允许模型构造授权。
