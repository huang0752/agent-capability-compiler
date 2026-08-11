# README architecture diagrams design

## Goal

让第一次阅读 ACC README 的产品、业务与工程读者在不查看源码的情况下理解：ACC 为什么分为编译期和运行期、业务能力如何从 Evidence 进入 Pack、Read 与 Action 如何执行，以及源 JWT/API 为什么始终拥有最终授权权威。

本次只改进公开文档，不改变代码、Schema、Pack 或 Runtime 行为。

## Documentation structure

README 使用“两层结构、三张 Mermaid 图”：</n+
1. 在“为什么需要 ACC”中用一张全局总览图替换现有 ASCII 图。
2. 在“架构”中增加编译期细图。
3. 在“架构”中增加运行期细图。

总览图只表达端到端主干；两张细图再展开关键组件和安全边界，避免一张巨图同时承担产品介绍、实现细节和安全说明。

## Diagram 1: end-to-end overview

总览图从左到右分为四个稳定区：

- Source system facts：后端源码、OpenAPI、前端交互、默认值、关联数据、权限规则与测试。
- AI-assisted compile time：Coding Agent、ACC Engineer Skill、领域向导和用户业务决策。
- Deterministic ACC：Core validation、Compiler、Coverage/Eval 与 Capability Pack。
- No-LLM runtime：MCP client、Generic Runtime 或 Gateway、REST Provider 和源 API。

图中必须明确标注：AI 只存在于编译期；Pack 是编译期和运行期的唯一数据化交界；运行期不调用 LLM；源系统仍执行最终鉴权。

## Diagram 2: compile-time detail

编译期图采用阶段流水线：

1. Coding Agent 只读发现 backend、OpenAPI、frontend、defaults、options、conditions、related data、auth 和 tests。
2. Evidence 与 ScopeInventory 固化可追溯事实。
3. DomainMap 与 CapabilityCandidateLedger 保存完整候选分母，包括 `read`、`action`、`unknown` 和纯客户端候选。
4. 领域向导一次只激活一个依赖已就绪领域；用户确认业务目标与 DomainPolicy，不逐条确认 route。
5. SourceContract、Operation、CapabilityQuality、Capability、Policy、Eval 与 InteractionContract 形成当前格式项目。
6. ACC Core 执行 closure、schema fidelity、constructability、Action safety、Coverage 和 contract tests。
7. Compiler 生成 Capability IR，Packager 生成确定性 `.accpkg`。

任何 Evidence gap、冲突或缺失的 Action 安全声明都必须停留为 blocked/unknown，不能绕过校验进入 Pack。

## Diagram 3: runtime detail

运行期图从 MCP client 开始，先分为本地 stdio 与多用户 streamable HTTP Gateway，再汇入已验证 Pack 和 Generic Runtime。

Read 路径显示：tool call → PrincipalContext/Scope/Policy → WorkflowExecutor → REST Provider → source API → output validation/filtering → MCP result。

Action 路径显示：业务专属 prepare → DeploymentPolicy → read-only preview → external approval → commit → status；ActionCoordinator、durable Store、ApprovalAuthority 和 AuditSink 属于可信部署边界。Mutation 只能使用 compiler-proven workflow、密封输入和 Runtime 管理的并发/幂等事实。

两条路径最终都携带对应用户的源身份访问源 API。ACC Scope、DeploymentPolicy 和 approval 只能收窄；源 JWT/API 对账号、角色、租户和数据权限做最终裁决。

## Component guide

保留现有组件表，但补齐并统一以下职责：

- `acc-core`：当前格式模型、Evidence/Domain contracts、validation、compiler、Coverage/Eval、Pack。
- `acc-runtime`：Pack loader、MCP adapters、Gateway composition、Workflow、Policy、Provider、Read/Action execution。
- `acc-adapter-sdk`：旁路 Adapter 的合同与骨架。
- `acc-testkit`：Fake source、MCP/Gateway clients、interaction evaluator、faults 和 E2E assertions。
- `skills/acc-engineer`：宿主 Coding Agent 的全局浅扫和单领域闭环工作法。

表格后增加简短“读图不变量”，避免读者误解：

1. Core/Runtime 不调用 LLM。
2. Pack 不包含用户账密或 JWT。
3. 用户确认不等于 Evidence，也不授予源权限。
4. 普通 Read 工具不能绕过 Action 生命周期执行 mutation。
5. Fake/offline 验证不能冒充生产 source-connected 验证。

## Mermaid and rendering constraints

- 使用 GitHub README 可直接渲染的 `flowchart LR` 或 `flowchart TB`，不依赖外部图片、CSS、JavaScript 或本地 URL。
- 节点文字保持短句；复杂解释放在图后正文，不把整份合同塞进节点。
- 节点 ID 仅使用 ASCII；中文只放在方括号标签中。
- 使用 subgraph 表达边界，不依赖颜色传达唯一语义，保证浅色、深色和纯文本环境都可理解。
- 不展示真实 endpoint、项目名、token、账号或行业专属权限。

## Verification

- README 中必须恰好保留清晰的总览、编译期和运行期三张架构图。
- 文档测试断言关键节点和安全边界存在。
- Mermaid 代码块做静态结构检查：每块有合法图类型、唯一节点 ID、闭合 subgraph 和预期关键标签。
- 运行 `ruff format --check .`、`ruff check .`、README 文档测试与 `git diff --check`。
- 本次仅为文档变更，不声称改变 Runtime 行为或生产验证等级。
