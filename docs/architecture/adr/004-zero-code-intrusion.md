# ADR 004: Zero-code intrusion into source systems

## Status

Accepted.

## Context

ACC 面向已有业务系统。为了接入 Agent 而修改原系统代码、认证、数据库或部署结构，会增加升级与回滚成本，也可能把 ACC 的风险传播到核心业务系统。工程接入阶段还会运行具有文件修改能力的 Coding Agent，因此必须明确写入边界。

## Decision

原系统源码目录在整个 ACC 工程阶段一律视为只读。ACC Engineer Skill、工具和流程不得修改或提交原系统文件，不得添加 Controller、MCP 或 Agent SDK，也不得修改数据库和认证逻辑。

所有生成的 System Map、Evidence、Operation、Capability、Policy、Eval、Adapter 和报告都写入独立 ACC 项目目录。Runtime 仅通过原系统已有 REST API，或独立部署的旁路 Adapter，按原系统权限和 ACC Policy 访问数据。第一版只允许只读能力，不执行生产写入。

## Consequences

- 接入和移除 ACC 不要求改动原系统，原系统升级路径保持独立。
- Preflight 与最终 Handoff 必须验证原系统修改数量为零，并在存在写入风险时停止。
- 可用能力受已有 API 约束；缺少安全可用接口时只能记录缺口或建设独立 Adapter。
- Adapter 自身必须独立部署、接受审查并遵守原系统认证和租户边界，不能成为绕过权限的后门。

## Rejected alternatives

- **向原系统嵌入 Agent SDK 或 MCP Server**：侵入业务代码并耦合发布周期。
- **自动给原系统生成新接口**：改变受保护的系统边界，且难以证明业务与权限正确性。
- **直接读取原系统数据库**：绕过业务校验、认证和审计语义。
- **允许接入流程自动提交原系统修改**：使只读边界无法可靠审查。
