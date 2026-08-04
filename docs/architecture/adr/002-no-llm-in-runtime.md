# ADR 002: No LLM in production runtime

## Status

Accepted.

## Context

Coding Agent 可以在接入阶段阅读源码、创建 ACC 定义、运行测试并修复候选，但生产执行直接接触真实业务数据、权限和凭据。若运行时依赖 LLM 动态决定请求、生成代码或修改能力定义，执行结果将难以验证和复现，也可能绕过已经审核的权限边界。

## Decision

生产 ACC Runtime 不调用任何 LLM。它只加载经过校验的 Capability Pack，并按已编译工作流执行已声明的 Operation。

运行时禁止动态生成代码、HTTP 请求、URL 或工作流，禁止修改 Capability Pack，也不得把系统凭据暴露给 Agent。输入、输出、Scope、租户边界、脱敏、超时和响应大小限制都由声明式契约和固定运行时代码执行。

## Consequences

- 相同 Pack、输入和上游响应产生可解释、可测试的执行路径。
- 生产环境无需配置模型凭据、Token 预算、模型重试或计费机制。
- Agent 只能选择已发布工具并提供其公开输入，不能临时扩展访问范围。
- 新业务行为必须回到工程阶段修改定义、重新校验、测试和打包后才能发布。

## Rejected alternatives

- **运行时让 LLM 自由生成 HTTP 请求**：无法在编译期证明目标、参数和权限边界。
- **运行时动态生成或执行代码**：引入不可控代码执行和不可复现行为。
- **允许模型直接持有系统凭据**：破坏 SecretRef 隔离并增加泄露风险。
- **运行时自动修补 Pack**：绕过审核、完整性校验和可重复构建。
