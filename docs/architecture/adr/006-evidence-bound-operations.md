# ADR 006: Evidence-bound operations

## Status

Accepted.

## Context

Coding Agent 擅长从源码、OpenAPI、测试和文档中提炼接口，但也可能把推测写成事实。正式 Operation 一旦进入 Capability Pack，Runtime 会用它访问真实系统；错误的路径、字段、权限或租户假设会导致越权、数据泄露或不可用工具。

## Decision

每个正式 Operation 必须绑定可验证的 Evidence。至少要能追溯其 API 路径、HTTP 方法、输入字段、输出字段、权限、Scope、租户边界、读取或写入效果以及错误状态。

第一版 Evidence 支持文件路径与行号范围、JSON Pointer、OpenAPI Operation 和内容摘要。Operation 引用 Evidence 的定位信息与摘要；ACC Core 校验引用存在、格式有效且覆盖正式声明。缺失、失效或不足以支持声明的 Evidence 使校验失败。未确认内容必须保留为待确认事项，不能编译为正式 Operation。

Operation 还必须使用封闭的输入输出 Schema，并在第一版明确声明 `safety.effect: read`；仅允许有证据支持的 `GET`/`HEAD`，不得用常识补造接口、字段或权限。

## Consequences

- 每个运行时操作都可以回溯到原系统事实，审查者能定位并复核依据。
- 源系统变化导致摘要或定位失效时，接入项目需要重新分析、冻结 Evidence 并测试。
- Evidence 捕获和覆盖校验增加接入成本，但把不确定性阻挡在编译期。
- 证据只能证明来源中表达的事实；多个来源冲突时必须停止并人工澄清。

## Rejected alternatives

- **允许无 Evidence 的正式 Operation**：无法区分系统事实与模型推测。
- **只记录自由文本说明**：缺少机器可校验的定位与完整性信息。
- **仅依赖 OpenAPI**：OpenAPI 可能缺少权限、租户、错误或业务效果，需要源码、测试等补充证据。
- **运行时再验证接口猜测**：把设计错误和潜在越权推迟到生产环境。
