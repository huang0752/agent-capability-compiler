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
8. 对每个已获明确授权且 Evidence 闭合的 Action，只在隔离沙箱验证 `prepare → approve → commit → status`，并覆盖过期/跨会话 approval、重复提交、并发冲突、上游拒绝和结果未知。未授权或未闭合 Action 保持 `blocked_on_evidence`，严禁把生产写操作当成自动测试或把未测 Action 排除后宣称完整。
9. 用平台中立 headless evaluator 覆盖 missing/null/explicit defaults、options 成功/空/错误/分页、cascade stale response、conditions、related data、states、presentation projection，以及 Action lifecycle events。
10. 只有全部 required interaction scenarios 未跳过且通过时才记录 `headless_verified`。实际连接本地/测试源只支持 `source_connected_verified`；只有真实客户端 adapter 重放同一合同通过时才记录 `client_adapter_verified`，三者互不推导。
11. 当前领域的证据清晰候选自动运行适用测试；只把失败、冲突、高风险策略或必须由用户控制的测试边界逐个提交用户决定。
12. Action 同时覆盖 optimistic token 与 server-serialized state predicate：前者验证 CAS 冲突，后者验证源端串行状态谓词、禁止业务重试和显式 outcome/status 查询。
13. 若使用 `local_development_state_guard`，必须以 `--development-actions --local-development-action-guards` 双重 opt-in 在单进程隔离源测试；覆盖同资源双 handle、prepare 后状态漂移、terminal 幂等、fresh Read 失败和一次 mutation。报告明确它只串行化 ACC 协作者，外部写仍可在 Read 与 mutation 之间竞态，不能升级为 source concurrency 或生产验证。
14. 若用本地操作者审批 `approval: required`，仅在 `streamable_http` loopback Gateway 以 `--development-action-operator-approval --action-operator-secret-ref <ENV>` 启用。验证 endpoint 不在 MCP tools/list、错误 secret 为统一 401、未知/过期/错绑定 handle 为统一 404、超 1 KiB/chunked body 为 413、会话撤销后不能审批、响应与日志不含 action/approval/operator secret。该入口只 approve，绝不自动 commit；stdio 当前不支持。
15. 若开发部署选择 `--development-action-store sqlite`，要求 path/store-secret-ref/store-salt-ref 三项齐全且引用名和值彼此独立，也不复用 operator secret；inspection 不披露 path/ref。验证 shutdown/reopen 保留认证行，同时明确 Gateway session 与 operator registry 不持久：重启前 prepared handle 必须重新 prepare，旧 handle 在新 session 下的 status/commit 仍因绑定不匹配而拒绝。SQLite durable 不得被描述为跨重启用户会话恢复。

## 门禁

- Contract、Runtime、E2E 的 JSON 结果均与 Eval 预期一致。
- `forbidden_fields` 不出现在结果中，Token 不出现在工具参数、日志或报告中。
- 测试只使用 Fake/隔离环境和非生产 fixtures，不调用生产环境或写接口。
- 原系统只读基线无变化；所有失败和未覆盖项均如实记录。
- `offline_candidate`、`gateway_offline_verified` 与 `source_connected_verified` 严格分开，三者都不得表述为生产验证。
- environment Secret、Gateway session、JWT、Authorization、Cookie 和认证状态不得进入 Pack、MCP tools、错误、日志或测试报告。
- UI `hidden/disabled` 不是授权测试；必须保留服务端 permission/cross-tenant 负例。
- `source_connected_verified` 不是 `client_adapter_verified`，headless 通过也不能声称真实客户端已验证。
- 源 JWT 仍是权限最终裁决；测试中的 Scope 和 approval 只能增加拒绝路径，不能授予源权限。
- system-complete 测试报告必须逐项列出全部 Action/composite intent；任何 blocked、excluded、deferred 或 skipped Action 都阻止 complete，不能由 Read 测试通过数抵消。

## 输出

- 分别列出 `offline_candidate`、`gateway_offline_verified`、`headless_verified`、`source_connected_verified`、`client_adapter_verified` 的实际证据、失败诊断和覆盖明细；未运行者明确为未验证。

## 停止条件

- 全部必需场景通过后进入 Refine。
- 若出现失败、Secret 泄漏、生产依赖、写调用或原系统变更，立即停止并修复；不得跳过或隐藏后继续。
