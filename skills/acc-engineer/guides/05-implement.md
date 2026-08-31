# Phase 4：Implement

仅在独立 ACC 项目中实现已批准的定义和测试夹具。

## 输入

- `capability-plan.yaml`、`coverage-baseline.json`、System Map 与 Evidence。
- ACC 的 Operation、Capability、Policy 和 Eval Schema/模板。

## 动作

1. 仅为 disposition 是 `planned` 或 `composed` 的路由创建 Evidence、SourceContracts、Operations、Capabilities、CapabilityQuality、Policies、Evals 和 Fake fixtures；仅为已 adopt 且有 Evidence 的交互创建 `interaction-contracts/<capability-id>.yaml`。
2. 从证据选择唯一的 Provider `auth`：`none`、环境引用的 `bearer_secret`，或 `password_bearer`。`password_bearer` 在 `stdio` 使用 `environment_secret`，在 `streamable_http` 使用 `gateway_session`。新 Operation 不得包含 `credential_ref`。
3. 从 SourceContract 和 provenance 投影 Operation Schema：Operation 输入不得超出源接受范围，Operation 输出不得窄于源可能响应。需要受信 principal/tenant 值时才声明 `context_bindings`；目标必须映射到已证实的请求位置，且不得出现在 Capability input 或 Workflow arguments。
4. 使用受限工作流步骤 `call/pick/map/filter/assert/redact/branch/parallel/foreach/emit`；引用、循环和并发保持静态有界。
5. 将敏感字段限制落实到 Policy、redact 和 Eval 的 `forbidden_fields`。
6. 每次修改后检查写入路径和原系统只读基线。
7. 为 CapabilityQuality 落实 selector acquisition、producer graph、failure isolation、output budget 与长文本披露。Capability 输出收紧必须由工作流的 pick/map/filter/redact/dataflow 可证明，不能靠手写 Schema 假设。
8. Read Operation 必须显式声明 `read` effect，不能从 HTTP 方法推断；对已获沙箱授权且 Evidence 闭合的 Action 实现 `prepare → approve → commit → status`。commit 使用不透明 approval handle，并落实 idempotency、concurrency、retry 和 outcome 合同。未闭合 Action 留在 ledger 的 `blocked_on_evidence`，不得实现、静默排除或简单放开 POST。
9. 将 adopted bindings/defaults/options/conditions/related data/states 转为受限 InteractionContract；`hidden/disabled` 不是授权。只有 Compiler 可证明的 public default 才进入确定性规范化，前端默认值和前端条件不能修改 SourceContract。
10. 只实现版本化 `DomainDecision` 中 accepted 且证据闭合的当前领域候选；deferred、blocked、rejected 和未激活领域都不生成 MCP。
11. optimistic conflict 使用 Runtime 持有的 token/precondition；server-serialized transition 使用已证明的状态谓词、`retry: never` 和显式 status/outcome query。两者都保留 `prepare → approve → commit → status`。
12. 只有显式授权的本地/开发沙箱可对低风险、`runtime_deduplicate`、`retry: never` 且源端 `concurrency: not_supported` 的 update/delete/transition 声明 `action.local_development_state_guard`。资源键必须来自 required scalar Capability input，状态 Read 必须在 preview 中且状态字段公开未改写。不得把该 guard 写成源端并发 Evidence。

## 门禁

- 正式 Operation 均有 Evidence，且不存在绝对 URL、动态 Host、Token 参数、Header 覆盖或路径穿越。
- Read Operation 不包含写方法、动态代码、Shell、`eval`、任意导入或运行时生成请求。Action 只能使用模型允许且有 Evidence 的显式方法和 effect。
- 定义中只有 SecretRef 名称，没有生产 Secret；fixtures 不复制生产数据。
- Provider auth 与 transport 组合合法；Operation 不得保存 `credential_ref`。
- `PrincipalContext`、JWT、密码和 Header 不属于公共 Schema；`context_bindings` 目标不能由 Agent 或 Workflow 覆盖。
- 原系统文件、数据库、认证和部署修改数量为零。
- 每个实现的 Operation 都可经 `scope_route_ids` 回溯到 `planned`/`composed` 路由。
- Schema fidelity 无 evidence conflict；unknown 保持诊断，不通过伪造上界消除。
- Action 的 approval、幂等、并发、重试和状态查询合同完整，且没有把 Secret/Principal/approval grant 暴露为 Agent 输入。
- 当前实现没有把 Read-only 子集标成 `system_complete`；任何未实现 Action/composite intent 都仍以阻断状态出现在计划、Coverage 和风险报告中。
- InteractionContract 没有任意客户端表达式，trusted binding 不进入公共输入，unknown 没有被伪装为通过。
- 源 JWT/接口最终裁决权限；Scope 只能收窄，approval 不是授权且不能使源端拒绝变为允许。

## 输出

- 完整的 `operations/`、`capabilities/`、`policies/`、`evals/`、`evidence/` 和测试 fixtures 候选。

## 停止条件

- 计划内定义和 Eval 齐备后进入 Validate。
- 一旦发现需要修改原系统、访问生产、直接执行源写调用或伪造 Evidence，立即停止；Action 定义与隔离 Fake/沙箱验证不等于源系统写入。
