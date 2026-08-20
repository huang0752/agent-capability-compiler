# Phase 8：Handoff

把可审查的候选、证据、测试与风险完整交给人工 Git Review。

## 输入

- 最终 System Map、Evidence、定义、Coverage、Validate/Test 结果和风险清单。
- Preflight 建立的原系统只读基线及 ACC 项目差异。

## 动作

1. 交付证据化定稿的 `intent-plan.yaml`，并生成 `HANDOFF.md`、`scope-audit-report.json`、适用时的 `interaction-audit-report.json`、`coverage-report.json`、`test-report.json` 和 `risk-report.json`；把全部 warning（包括 scope 与 interaction audit）同时写入风险与交付文档。
2. 分别说明 route scope、interaction scope，以及 `offline_candidate`、`gateway_offline_verified`、`headless_verified`、`source_connected_verified`、`client_adapter_verified` 的 Evidence、实际命令、失败/未运行项和已知限制。
3. 使用 Preflight 时相同的深层 `--include` 列表复核源快照，并复核浅层全局发现分母。Git ACC 项目生成 `candidate.diff`；非 Git 项目运行 `artifact_manifest.py --project <acc_project> --output artifact-manifest.json`。
4. 扫描交付物中的 Secret、生产地址、Token、完整上游响应和生产数据；发现即停止并清理。
5. 给出人工复核顺序，但不自动提交、push、部署或访问生产环境。
6. 明确记录 Provider auth 类型、`stdio` 或 `streamable_http` 验证边界、`PrincipalContext` 来源及 `context_bindings` 是否实际使用；没有绑定的示例不得表述为绑定验收。
7. Coverage 报告逐轴交付 `route_disposition`、`operation_trace`、`scenario_coverage`、`constructability`、`discoverability_graph`、`composition`、`tool_portfolio`、`schema_fidelity`、`output_budget`、`live_observations`；明确“不生成总分”，记录 portfolio budget/overlap/orphan/under-coverage findings，并区分静态上界与 live observation。
8. 同时逐轴交付 `surface_disposition`、`interaction_trace`、`input_binding_fidelity`、`default_provenance`、`option_resolution`、`condition_coverage`、`related_data_graph`、`state_scenarios`、`presentation_projection`、`client_adapter_evidence`；不生成总分。`source_connected_verified` 不代表 `client_adapter_verified`。
9. 按领域交付 `DomainMap`、Candidate Ledger、每个版本化 `DomainDecision`、active dependency refs 和十二个 Domain/Action 独立轴；明确 accepted、deferred、blocked、rejected，并逐项对账 Read/Create/Update/Delete/transition/execute/composite 业务表面，绝不附一份全部 route 让用户重新选择。
10. 记录领域处理顺序、当前完成领域和下一依赖已就绪领域；源 JWT 最终裁决、Scope 只能收窄、approval 不是授权三条边界必须原样保留。
11. 解释每个 intent 的 merge/split/compose Evidence、blocked boundary、route coverage 和 `IntentRelationship`；报告最终 Capability/MCP 数量为派生 observation，并明确没有固定工具配额、route-per-tool 默认或由用户指定数量。

## 门禁

- 所有结论可由 Evidence、结构化 diagnostics 或真实测试结果复核。
- 不隐藏失败，不把未运行测试写成通过，不把推测写成事实。
- 原系统代码、数据库、认证和部署变更均为零；交付物不含 Secret 或绕过安全生命周期的 Action。
- 风险与限制已明确，候选仍符合已声明范围和平台中立边界。
- Git diff 或非 Git artifact manifest 已按项目类型生成，不混用两种交付证据。
- HANDOFF、Test Report 与 candidate diff 使用同一次候选的 IR/Pack 摘要和带日期门禁计数，不保留旧版本成功声明。
- 验证等级必须诚实：Fake Runtime、Gateway、headless、source-connected 与 real client adapter 证据分别记录，任何一级都不自动证明下一级。warning 不降低 `ok`，但必须进入两份风险交付物。
- 每个 completed 领域都有精确 active `DomainDecision` 与用户确认；历史完成记录不能冒充当前激活决策。
- 用户确认只覆盖 `DomainPolicy`、用户控制的测试边界与显式异常/高风险决定；不得伪造用户确认 AI 规划的工具数量或普通 route 分组。
- `system_complete` 交付的 `blocked_on_evidence` 必须为零，且无 eligible Action intent 被 excluded/deferred。缺写沙箱授权、幂等/并发/审批/outcome Evidence 或 Action 测试时只能交付“未完成/阻断”报告，不能使用 complete 措辞。

## 输出

- `HANDOFF.md`
- `intent-plan.yaml`
- `scope-audit-report.json`
- `interaction-audit-report.json`（发现适用客户端面时）
- `coverage-report.json`
- `test-report.json`
- `risk-report.json`
- Git 项目：`candidate.diff`
- 非 Git 项目：`artifact-manifest.json`

## 停止条件

- 交付物通过门禁后停止，等待人工 Git Review。
- 不自动 commit、push、发布、部署或调用生产接口；任何后续动作都需要明确人工授权。
