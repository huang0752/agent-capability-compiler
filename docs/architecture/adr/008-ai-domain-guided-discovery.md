# ADR 008: AI domain-guided capability discovery

## Status

Accepted.

## Context

按接口清单生成 MCP 会产生两个相反问题：一方面大量 Read 工具没有业务组织，用户无法判断它们是否完成一个真实目标；另一方面 Action、前端默认值、条件展示、关联数据和纯客户端交互可能根本不在后端接口清单中。把全部 route 或全部候选一次性交给用户逐条选择，也会把接口分析责任转嫁给不了解实现细节的业务用户。

ACC 又必须保持平台中立和运行期确定性。它不能为某个项目内置领域分类，也不能在 Runtime 中调用模型、临时猜接口或动态改变 Pack。用户确认应表达业务意图和风险策略，而不是替 Evidence、源系统权限或 compiler 安全证明背书。

## Decision

ACC 采用“全局浅扫、领域分组、单领域闭环、再进入下一领域”的能力发现流程。

1. 全局 AI 扫描由 ACC Engineer Skill 所在的 Coding Agent 执行。它只读检查源码、OpenAPI、测试、权限边界、前端交互、默认值、选项、条件、关联数据和状态分支，生成平台中立的 `DomainMap`、`CapabilityCandidateLedger` 与 Evidence 引用。
2. `DomainMap` 按业务领域组织 Candidate，记录显式依赖、稳定优先顺序和一个可校验的 active decision 引用。Core 根据完整性、候选安全声明和已确认依赖确定 readiness；它不通过模型选择领域。
3. 向导一次只激活一个依赖已就绪的领域。用户确认业务目标与策略，不逐条选择 route。可确认内容限定为 goals、allowed effects、maximum risk、approval-required business intents 和 excluded intents；源权限不属于 DomainPolicy。
4. Coding Agent 深扫当前领域，自动处理证据清晰的候选。只有 Evidence 不能闭合的例外才询问用户，而且一次只问一个决策问题；不能要求用户逐条批准完整接口清单。
5. Read、Action 与 `unknown` 是显式 Candidate 分类。unknown 候选不能被伪装为 ineligible 或消失；客观不可用必须有独立 `ineligibility_claim` Evidence。缺失 Action 生命周期、冲突控制、幂等或结果解析证据只会形成阻塞缺口。
6. 一个领域用版本化的 `DomainDecision` 闭合。Decision 精确绑定完整 Candidate Ledger 摘要、当前领域候选快照、Evidence 快照、已完成依赖、每个候选 disposition 和一次单一目的的用户确认；任何事实变化都通过新 revision 或 `DomainChangeRequest` 重开，而不是覆盖历史。
7. 当前领域完成后，确定性 CLI 才推荐下一个依赖已就绪领域。Coverage 分别报告业务目标、Candidate 分类、安全 provenance、身份授权、Action 生命周期、冲突控制、幂等、结果解析、验证等级、跨领域依赖和用户决策轨迹，不生成总分。

授权边界独立于领域确认：源 JWT 与源 API 是最终授权者。ACC Scope 只能收窄，不授予源权限；部署 allowlist、Action approval 和 DomainDecision 都不能绕过源系统对每次 REST 请求的鉴权。若登录前无法知道实际源权限，状态保持 `unknown`，不能因用户选择升级为 allowed。

AI 与确定性边界同样固定：ACC Core 与 Runtime 都不调用 LLM。Core 负责类型、引用、摘要、闭包、readiness、Coverage、影响分析、编译和确定性打包；Runtime 只消费 compiler IR，执行固定 Workflow、Policy、认证绑定和 Action 状态机。模型输出在成为这些组件的输入前必须先满足当前格式合同。

## Current implementation boundary

当前仓库已实现平台中立的 DomainMap、Candidate Ledger、版本化 DomainDecision、DomainChangeRequest、readiness、十二个独立领域与 Action Coverage 轴、`acc domains status/show/review/impact` 的确定性命令、ACC Engineer Skill 单领域向导和跨行业 current-format fixtures。Runtime 没有 AI 扫描路径。

这些实现与受控 fixtures 证明合同、确定性选择和失败关闭行为，不证明生产 AI 扫描已经验证。AI 扫描质量取决于实际 Coding Agent、可读取证据与人工确认；未连接的生产系统、真实客户端和生产源 Action 均不能据此声明 `source_connected_verified` 或 `client_adapter_verified`。

## Consequences

- 用户按业务领域做少量高价值决策，不承担 route 分类和接口安全审查工作。
- ACC 可以覆盖 CRM、ERP、财务、监控、内容、权限和移动端等不同形态，而不把任何行业命名或专属权限写进 Core/Runtime。
- 前端交互、默认值和关联数据成为独立 Evidence 输入，不再把 OpenAPI 完整度误当作业务能力完整度。
- Candidate、Decision 与 Evidence 摘要形成可重复构建和变更影响链；源或客户端变化可以精确重开受影响领域。
- 全局浅扫仍可能遗漏事实，因此 `unknown`、未分类 Candidate、Evidence gap 和 Coverage 轴必须保留，不能用总分掩盖。

## Rejected alternatives

- **一次列出全部 route 让用户选择**：认知负担过高，也把实现分析责任转嫁给业务用户。
- **每个接口直接生成一个工具**：缺少业务目标、组合关系、Action 生命周期和客户端事实。
- **只扫描后端或 OpenAPI**：会遗漏默认值、条件、关联数据、纯客户端交互和真实使用路径。
- **让用户确认等同于 Evidence 或权限**：业务选择不能证明接口事实，也不能授予源系统权限。
- **在 Core/Runtime 内嵌 LLM 分类**：破坏确定性、可重复构建、离线执行和平台中立边界。
- **覆盖旧 DomainDecision**：丢失用户决策、Evidence 快照与变更影响审计链。
