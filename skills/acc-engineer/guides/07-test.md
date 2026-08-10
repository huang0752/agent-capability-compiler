# Phase 6：Test

在隔离的 Fake System 和通用 Runtime 上验证契约、执行和 MCP 行为。

## 输入

- Validate 通过的编译候选、Evals、fixtures 和安全测试入口。
- Capability Plan 规定的正常与负例场景。

## 动作

1. 运行 `acc test contract --json` 和直接 Fake Runtime 套件并标记 `offline_candidate`；只有真实 Gateway/官方 MCP 客户端对 Fake Source 的协议路径通过后才标记 `gateway_offline_verified`。
2. 覆盖正常、空数据、404、403、跨租户、字段脱敏、超时、响应过大和稳定错误映射。
3. 验证 expected calls 的操作、参数和顺序，以及输入/输出 JSON Schema。
4. 验证 MCP `tools/list` 与 `tools/call`，并检查协议输出、日志和报告不包含 Secret 或完整上游响应。
5. 检查实际结果和 diagnostics；不得隐藏失败、跳过项或仅报告通过数量。
6. 仅当用户明确授权连接本地/测试原系统，且源连接套件真实通过时，才标记 `source_connected_verified`。
7. 覆盖 `none`、`bearer_secret` 或所选 `password_bearer` 合同，确认 `PrincipalContext` 与 `context_bindings` 不进入 Agent 输入；`stdio` 只使用固定身份，`streamable_http` 只有实际 Gateway 请求级身份测试通过后才能声明可用。
8. 对显式 Action 只在隔离沙箱验证 `prepare → approve → commit → status`，并覆盖过期/跨会话 approval、重复提交、并发冲突、上游拒绝和结果未知。严禁把生产写操作当成自动测试。

## 门禁

- Contract、Runtime、E2E 的 JSON 结果均与 Eval 预期一致。
- `forbidden_fields` 不出现在结果中，Token 不出现在工具参数、日志或报告中。
- 测试只使用 Fake/隔离环境和非生产 fixtures，不调用生产环境或写接口。
- 原系统只读基线无变化；所有失败和未覆盖项均如实记录。
- `offline_candidate`、`gateway_offline_verified` 与 `source_connected_verified` 严格分开，三者都不得表述为生产验证。
- environment Secret、Gateway session、JWT、Authorization、Cookie 和认证状态不得进入 Pack、MCP tools、错误、日志或测试报告。

## 输出

- 含 validation level（`offline_candidate`、`gateway_offline_verified` 或 `source_connected_verified`）的测试证据、失败诊断和覆盖明细。

## 停止条件

- 全部必需场景通过后进入 Refine。
- 若出现失败、Secret 泄漏、生产依赖、写调用或原系统变更，立即停止并修复；不得跳过或隐藏后继续。
