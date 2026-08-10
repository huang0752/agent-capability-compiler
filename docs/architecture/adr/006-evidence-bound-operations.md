# ADR 006: Typed Evidence for operations and capability candidates

## Status

Accepted.

## Context

Coding Agent 能从源码、OpenAPI、测试、文档和客户端实现中发现能力，也可能把推测写成事实。只查看接口还会漏掉前端默认值、选项来源、显示条件、状态分支、关联数据和纯客户端交互。正式 Operation 一旦进入 Capability Pack，Runtime 会用它访问真实系统；错误的路径、字段、效果、权限或租户假设会导致越权、数据泄露或不可用工具。

能力发现还有一个更早的风险：如果扫描结果只保留“看起来可做”的接口，不确定的业务候选就会静默消失。后续 Coverage 无法区分“没有能力”和“能力尚未证明”，用户也无法确认完整的业务领域。

## Decision

ACC 只维护当前格式 `2`，不提供旧格式兼容或隐式迁移。Evidence 是独立、带摘要的事实注册表；Domain、Candidate、Decision、Operation、SourceContract 和交互合同只保存受限引用与可审查的结构化结论，不把原始秘密、完整源码或用户确认原文打入 Pack。

全局浅扫必须把发现结果写入类型化的 `CapabilityCandidateLedger`。Candidate 记录业务意图、领域、route、interaction、`unknown`/`read`/`action` 分类，以及 schema、effect、risk、reversibility、approval、retry、conflict control、idempotency、outcome resolution、lifecycle、authorization boundary、identity binding 和 context isolation 等独立声明。每个权威声明都必须引用匹配的 Evidence；缺证据的声明保持 `unknown`、`missing` 或 `candidate`。

`unknown` 候选不能被伪装为 `ineligible` 或消失。客观不可用结论必须由单独的 `ineligibility_claim` 与 Evidence 支持；缺少 Action 安全 Evidence 只能形成阻塞缺口，不能自动把候选降格为 Read 或排除。Candidate 也不会因为用户选择而直接成为可执行能力；只有完成证据闭包、经版本化 DomainDecision 接受并物化为通过校验的 Operation/Capability 后，才可能进入 Pack。

每个正式 Operation 必须绑定可验证的 Evidence，至少能追溯 API 路径、HTTP 方法、输入字段、输出字段、身份与上下文绑定、Scope、租户边界、业务效果和错误状态。Evidence 可以定位文件与行号、JSON Pointer、OpenAPI Operation 或受限外部事实，并携带内容摘要。SourceContract 把这些事实归一化为封闭请求/响应 Schema、完整性与 JSON Pointer 级 provenance：Operation 输入必须是源接受范围的安全子集，输出必须覆盖源可能响应；运行 observation 不能证明业务上界。

Action 的 method、effect、risk、reversibility、retry、idempotency、concurrency 与结果解析同样需要逐字段 provenance。前端 Evidence 可以证明交互、默认值、关联关系和客户端状态，但不能单独证明服务端授权或写入语义；OpenAPI 也不能替代缺失的权限、租户和业务效果证据。多个来源冲突时保持 contradicted 或停止，不能选择更方便的结论。

## Consequences

- 每个候选与运行时 Operation 都可回溯到原系统事实，审查者能区分已证明、未决、矛盾和失效状态。
- 全局扫描不会通过隐藏未知项制造虚假的高覆盖率；补证据和明确排除都会留下可审查轨迹。
- 源系统或客户端变化导致摘要失效时，相关 Candidate、DomainDecision 和物化能力必须进入影响分析与重新确认。
- Evidence 捕获与闭包校验增加接入成本，但把接口猜测、权限猜测和 Action 安全猜测阻挡在编译期。

## Rejected alternatives

- **允许无 Evidence 的正式 Operation 或 Candidate 权威声明**：无法区分系统事实与模型推测。
- **只记录自由文本说明**：缺少机器可校验的定位、摘要、声明类型和依赖闭包。
- **仅依赖 OpenAPI 或后端 route**：会漏掉权限、租户、业务效果和客户端独有交互。
- **把 unknown 自动标记为 ineligible**：掩盖待发现的业务能力，并允许通过删除未决项刷 Coverage。
- **运行时再验证接口猜测**：把设计错误和潜在越权推迟到真实系统。
