# Phase 7：Refine

对照系统事实、实现和测试收敛能力质量，而不是盲目提高数量。

## 输入

- System Map、Operations、Capabilities、Policies、Evals。
- Coverage baseline、Validate/Test 结果与所有已知风险。

## 动作

1. 独立对比三层覆盖：`source_scope` 路由 disposition、Operation 对 `scope_route_ids` 的追溯、Capability/Eval 场景。
2. 查找一接口一工具、孤立 Operation、重复 Capability、无正常/负例、权限 Evidence 不足和过宽 Schema。
3. 查找 Agent 不应获得的参数、未脱敏字段和可以进一步收紧的权限/租户边界。
4. 仅依据现有 Evidence 改进 ACC 项目；需要新事实时返回 Analyze，而不是推测。
5. 每轮改进后重跑 scope audit、Validate 和 Test，并分别比较三层 Coverage 与风险变化。

## 门禁

- 改进未引入写接口、生产依赖、Secret、业务特例或原系统修改。
- 源路由、Operation 追溯和 Eval 三层 Coverage 都不倒退，所有 Validate/Test 门禁仍通过。
- 高风险、Evidence 缺口和未确认事项已修复或明确保留为风险。
- 候选保持业务级组合，避免为了指标增加低价值工具。

## 输出

- 收敛后的 ACC 候选、更新的 Coverage/测试证据和明确的剩余风险。

## 停止条件

- 不再存在未处理的高严重度缺口，且全量验证通过后进入 Handoff。
- 若新需求超出只读 MVP、需要生产访问或缺少 Evidence，停止并交由人工决定，不得自行扩展范围。
