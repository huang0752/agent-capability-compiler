# ADR 007: Versioned quality contracts and default-deny Actions

## Status

Accepted; implementation is incremental.

## Context

ACC v1 已提供证据绑定的只读 Operation、Capability Pack、Generic Runtime、MCP stdio 和可选多用户 Gateway。继续扩展能力时有三类风险：把样本观测误写成 Schema 上界、把路由处置率误写成 Agent 可用性，以及通过允许 `POST` 让旧 Pack 或默认部署意外获得写权限。

质量分析与 Action 执行也不是同一个发布边界。SourceContract、CapabilityQuality、Coverage、Scope callability、Action 编译证明、审批协议、状态存储和 MCP 暴露可以分别演进；文档与 Runtime 必须说明哪些层已经实现，不能把模型或测试基础设施等同于生产能力。

## Decision

ACC 使用显式版本合同保持兼容：

- v1 Project、Operation、Capability、IR 和 Pack 保持只读语义；升级 Core 或 Runtime 不会赋予旧 Pack 写能力。
- v2 为每个 Operation 增加 SourceContract，为每个 Capability 增加 CapabilityQuality。Evidence provenance 支持请求/响应 Schema、selector acquisition、组合理由和输出预算；无法证明的关系保持 unknown。
- Capability 输出只有经过确定性工作流可证明投影后才能收紧。单 Operation Capability 不是质量缺陷，工具数量也不是优化目标。

部署可调用性与设计覆盖分别处理：

- Scope callability 比较 Capability 的路径要求、部署 Scope ceiling 和已知 Principal Scope。空 ceiling 默认拒绝；登录前无法知道的源权限保持 unknown。
- Coverage v2 独立报告 route disposition、Operation trace、scenario coverage、constructability、discoverability、composition、schema fidelity、output budget 和 live observations，不生成总分，也不把 route closure 当作 usable。

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

当前工作树已包含 v2 模型、Schema、项目 sidecar 校验、Schema fidelity、Capability quality、Coverage v2、Scope callability、Action 编译证明、部署策略、直接 Runtime Action Coordinator、开发/测试内存 Store 和 Live Gateway 测试基础。

普通 Generic Runtime/MCP 工具面仍拒绝 Action 并要求专用生命周期；尚无生产 durable Action Store、可信审批签发服务或集中审计后端。Action 的 MCP/CLI 接线、v2 端到端发布门禁和生产部署门禁仍是后续工作。因此当前已完成发布门禁并稳定对 Agent 暴露的执行面仍是 v1 read Capability，不能宣称 v2 Action 或完整 v2 运行链路已完成。

## Consequences

- 旧项目和旧 Pack 可继续按只读合同运行，不会因升级获得新效果。
- 质量报告保留 unknown 和各轴事实，不能通过合并工具、删路由或编造上界刷分。
- 生产 Action 需要部署者提供 ACC 仓库之外的持久状态、审批和审计集成，并通过独立安全验收。
- Core、Runtime、Testkit、Skill 和公开文档必须使用一致的版本与验证术语。

## Rejected alternatives

- **在 v1 中加入可选写字段**：会让旧合同通过默认值获得新语义。
- **按 HTTP 方法自动允许 Action**：`POST` 可能是查询，`GET` 也可能触发副作用，方法不能替代 Evidence。
- **用单一 Coverage 分数作为发布门禁**：会掩盖不可构造、Schema 失真和路由闭包断裂。
- **把内存 Action Store 用于生产**：重启、并发和多实例语义不足，无法满足 durable 状态要求。
- **让 Agent 直接提交审批或凭据材料**：破坏可信边界并允许模型构造授权。
