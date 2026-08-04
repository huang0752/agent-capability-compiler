# ADR 001: Skill-first integration

## Status

Accepted.

## Context

ACC 的接入阶段需要理解已有系统、规划业务能力、编写定义并根据测试结果持续修复。这些开放式工作适合由 Codex、Claude Code、Hermes、OpenCode 等现成 Coding Agent 完成。若 ACC 自己集成模型 API 或实现 Agent Loop，就会重复宿主已经提供的能力，并引入模型选择、Token、上下文、重试、计费等与能力编译无关的复杂度。

## Decision

ACC 采用 Skill-first 集成方式：提供平台中立的 ACC Engineer Skill、稳定 CLI、Schema 和机器可修复的 JSON diagnostics，由宿主 Coding Agent 完成分析与创作。

ACC 本身不集成模型 SDK，不选择或调用模型，也不实现 Agent Loop。Codex 和 Claude Code 等平台集成只保留薄包装，共享同一份核心工作流。

## Consequences

- ACC 可以独立于模型厂商、模型版本和宿主 Agent 演进。
- 智能推理发生在工程接入阶段；ACC Core 只承担确定性的校验、编译、测试和打包。
- CLI、Schema、诊断码及 Skill 指南成为主要集成契约，必须保持稳定且适合自动修复。
- 使用者需要自行提供受支持的 Coding Agent；ACC 不单独提供自主接入体验。

## Rejected alternatives

- **在 ACC 内嵌 OpenAI 或 Anthropic SDK**：会绑定厂商并扩大凭据、计费和运行维护范围。
- **由 ACC 实现自己的 Coding Agent**：重复宿主能力，偏离能力编译器的职责。
- **为每个 Coding Agent 维护独立工作流**：会造成行为漂移和重复维护。
