# Phase 7：Refine

对照系统事实、实现和测试收敛能力质量，而不是盲目提高数量。

## 输入

- System Map、Operations、Capabilities、Policies、Evals。
- Coverage baseline、Validate/Test 结果与所有已知风险。

## 动作

1. 独立对比既有九轴：`route_disposition`、`operation_trace`、`scenario_coverage`、`constructability`、`discoverability_graph`、`composition`、`schema_fidelity`、`output_budget`、`live_observations`；不生成总分，不把 route closure 当 usable。
2. 独立对比十个交互轴：`surface_disposition`、`interaction_trace`、`input_binding_fidelity`、`default_provenance`、`option_resolution`、`condition_coverage`、`related_data_graph`、`state_scenarios`、`presentation_projection`、`client_adapter_evidence`；不得合成总分或用 source-connected observation 填充 adapter 证据。
3. 查找孤立 Operation/interaction、重复 Capability、不可构造 selector、未证明 default、断裂 option/related-data graph、条件循环、缺失 state scenario、权限 Evidence 不足和 Schema fidelity 风险。一接口一工具不是天然缺陷，工具数量不是优化目标。
4. 检查重复 decision rationale、整域零能力、前端使用路由被排除，以及高排除率信号。eligible `>= 10` 且 excluded `>= 70%` 只是 warning。
5. 查找 Agent 不应获得的参数、未脱敏字段和可以进一步收紧的权限/租户边界；`hidden/disabled` 不是授权。
6. 仅依据现有 Evidence 改进 ACC 项目；需要新事实时返回 Analyze，而不是推测。
7. 每轮改进后重跑 scope audit、interaction audit、Validate 和 Test，并分别比较全部独立 Coverage 轴、warning 与风险变化。

## 门禁

- 改进未引入写接口、生产依赖、Secret、业务特例或原系统修改。
- 既有九轴和十个交互轴事实都不倒退，所有门禁仍通过；不得靠合并工具、删分母、伪造默认或 Schema 上界刷指标。
- 高风险、Evidence 缺口和未确认事项已修复或明确保留为风险。
- 候选保持业务级组合，避免为了指标增加低价值工具。
- 重复 decision 和整域零能力 error 已消除；高排除率 warning 已解释并保留，不能靠删 Evidence 或改分母消除。

## 输出

- 收敛后的 ACC 候选、更新的 Coverage/测试证据和明确的剩余风险。

## 停止条件

- 不再存在未处理的高严重度缺口，且全量验证通过后进入 Handoff。
- 若新需求超出已声明范围、需要生产访问、Action 缺少安全生命周期或缺少 Evidence，停止并交由人工决定，不得自行扩展范围。
