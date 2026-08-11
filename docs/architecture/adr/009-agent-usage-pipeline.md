# ADR 009: Independent Agent Usage pipeline

## Status

Accepted.

## Context

Capability Project 与 Capability Pack 证明工具定义、输入输出、组合关系、Policy 和 Action 生命周期能够被确定性编译及执行，但它们不自动证明 Agent 会按真实业务使用路径调用这些工具。只看后端接口还会遗漏客户端默认值、选项来源、展示条件、关联数据、结果消费方式、错误分支和纯客户端交互。

把 Usage 生成耦合进 Capability 编译也不安全。第一次生成的 MCP 往往需要用户自行测试并经过多轮反馈；若 Tool Schema、Action 行为或业务范围尚未稳定，提前生成宿主指南只会固化错误假设。Usage 输出还可能面向不同 Agent Host，不能把 Codex、Claude Code 或某个项目的 Skill 格式写进 Core。

## Decision

ACC 在 Capability 编译与运行管道之后增加一条独立的 Agent Usage 管道。

1. 管道 B 是可选但推荐的后续流程。它只能从用户已接受的精确 MCP Release 开始；Acceptance 绑定 Pack、IR、Tool Schema、测试报告和领域集合摘要。`compile`、`pack` 与 `run` 不会隐式启动 Usage。
2. Usage Engineer 所在的 Coding Agent 对当前领域及其直接依赖进行新一轮只读源码确认，同时检查 client、service、test、MCP 合同和允许的 runtime observation。Core 与 Runtime 不扫描源码、不调用 LLM。
3. 向导一次处理一个完整业务领域。证据清晰的事实自动建模；用户确认业务目标、纳入 route、已知限制与高风险边界，而不是逐接口审批。确认绑定精确 Decision 摘要，原始确认文本不进入包。
4. `DomainUsageContract` 使用类型化引用表达默认值、条件、选项来源、关联数据、结果消费、错误处理和 Action 生命周期。Evidence Claim 必须绑定目标字段、权威层和独立 Evidence 身份；无法闭合时失败关闭。
5. 验证保留六个独立轴：source usage traced、Usage contract、headless agent、host adapter、real MCP 和 user acceptance。没有总分，也不能由静态合同、Fake Source 或用户确认推导生产验证。
6. `.accusage` 是与 `.accpkg` 不同的确定性格式。它只投影 active `released` 领域中 Decision/Release 选择的闭包，并携带必要的 Scenario 与 Evidence 身份元数据；源文件、Capability Pack、凭据、JWT、请求 payload、原始用户文本和未发布领域均不进入包。
7. 核心消费面是平台中立的 verified projection。Generic Markdown、MCP Resources/Prompts 和宿主特定 Skill 都是可选 Adapter；Adapter 只能忠实降维，不能增加工具、权限、业务目标或绕过 Action 生命周期。
8. 源 JWT 和源 API 对每次真实调用保持最终授权。Usage Decision、Release、Package、Prompt、Resource 或 Host Adapter 都不创建角色、不授予权限；ACC 只能在源权限之上继续收窄。

## Release semantics

`limited` 表示 Usage 合同可以保留并明确交接，但仍有验证限制；它不能进入 active published release 集合。`released` 要求 source usage、contract、headless、real MCP 和 user acceptance 等核心发布轴成立。`host_adapter_verified` 只对具体命名 Adapter 有效，不会自动推广到其他宿主。

`real_mcp_verified` 只能由专用 real MCP runner 产生的受信结果建立。普通 Evidence Claim、手写 runtime observation、文件名或自我声明的连接标签都不是验证权威。即使 runner 使用受控测试源，其结论也不能冒充生产源连接；只有实际授权并成功连接对应源系统的结果才能声明该源的 source-connected 边界。

## Current implementation boundary

当前仓库实现独立 Usage 模型、项目加载与闭包校验、MCP Release Acceptance、影响分析、六轴验证、确定性 `.accusage`、平台中立渲染输入、Generic Markdown 参考 Adapter、MCP Usage Overlay，以及 CRM、ERP、财务 Action、监控、CMS、权限和移动端七类 current-format profile。

Task 15 的七类 profile 用于验证业务结构和失败关闭，没有运行专用 real MCP runner，也没有验证具体 Host Adapter。因此它们全部保持 `limited`、`real_mcp_verified=false`，不进入 published release；构建出的 `.accusage` 不包含这些未发布领域。

## Consequences

- Capability 修复和 Agent 使用指导可以分别迭代，Usage 不会污染 `.accpkg` 或 Generic Runtime。
- 前端默认值、条件、共享标识、陈旧状态、长文本消费和 conditional-approval Action 可以成为可验证业务事实。
- 每个领域可独立确认、发布和失效；一个领域变化不要求重新确认全部领域。
- Host 可以选择是否生成 Skill、Prompt 或 Resource，但平台中立合同保持唯一事实来源。
- 多一次源码复扫和独立测试会增加成本，因此 Usage 只在 MCP 稳定且用户接受后推荐启动。

## Rejected alternatives

- **第一次编译 MCP 时同时生成 Usage**：基线尚未稳定，反馈无法区分 Capability 缺陷与使用指导缺陷。
- **只从 tools/list 或 OpenAPI 生成指南**：遗漏客户端默认值、条件、关联数据和结果消费。
- **把 Usage 写入 Capability Pack**：混淆执行合同和宿主指导，扩大 Runtime 信任面。
- **把输出固定为 Codex Skill**：破坏平台中立，其他 Agent Host 无法复用。
- **让用户一次确认全部 route**：认知负担过高，并把源码分析责任转嫁给业务用户。
- **让 Usage 确认授予权限**：违反源 JWT 与源 API 的最终授权边界。
