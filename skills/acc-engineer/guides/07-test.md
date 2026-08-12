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
9. 用平台中立 headless evaluator 覆盖 missing/null/explicit defaults、options 成功/空/错误/分页、cascade stale response、conditions、related data、states、presentation projection，以及 Action lifecycle events。
10. 只有全部 required interaction scenarios 未跳过且通过时才记录 `headless_verified`。实际连接本地/测试源只支持 `source_connected_verified`；只有真实客户端 adapter 重放同一合同通过时才记录 `client_adapter_verified`，三者互不推导。
11. 当前领域的证据清晰候选自动运行适用测试；只把失败、冲突、高风险策略或必须由用户控制的测试边界逐个提交用户决定。
12. Action 同时覆盖 optimistic token 与 server-serialized state predicate：前者验证 CAS 冲突，后者验证源端串行状态谓词、禁止业务重试和显式 outcome/status 查询。
13. 当 Eval 使用 CLI 内置 `runtime_context` 之外的项目 fixture namespace，而部署方没有显式注入受信 fixture adapter 时，`runtime/e2e` 必须返回 `status: not_provisioned`、精确 case IDs 和 `calls: 0`；不得动态导入项目代码，也不得把它混成测试失败或通过。fixture 格式错误或已 provision runner 的执行错误仍是 `failed`。

## 门禁

- Contract、Runtime、E2E 的 JSON 结果均与 Eval 预期一致。
- `not_provisioned` 不是通过，也不是执行失败；它阻止完整发布验收，但允许诚实交付 limited/offline 结果。
- `forbidden_fields` 不出现在结果中，Token 不出现在工具参数、日志或报告中。
- 测试只使用 Fake/隔离环境和非生产 fixtures，不调用生产环境或写接口。
- 原系统只读基线无变化；所有失败和未覆盖项均如实记录。
- `offline_candidate`、`gateway_offline_verified` 与 `source_connected_verified` 严格分开，三者都不得表述为生产验证。
- environment Secret、Gateway session、JWT、Authorization、Cookie 和认证状态不得进入 Pack、MCP tools、错误、日志或测试报告。
- UI `hidden/disabled` 不是授权测试；必须保留服务端 permission/cross-tenant 负例。
- `source_connected_verified` 不是 `client_adapter_verified`，headless 通过也不能声称真实客户端已验证。
- 源 JWT 仍是权限最终裁决；测试中的 Scope 和 approval 只能增加拒绝路径，不能授予源权限。

## 输出

- 分别列出 `offline_candidate`、`gateway_offline_verified`、`headless_verified`、`source_connected_verified`、`client_adapter_verified` 的实际证据、失败诊断和覆盖明细；未运行者明确为未验证。

## 停止条件

- 全部必需场景通过后进入 Refine。
- 若出现失败、Secret 泄漏、生产依赖、写调用或原系统变更，立即停止并修复；不得跳过或隐藏后继续。
