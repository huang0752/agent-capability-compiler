# Phase 3：Plan

围绕用户目标设计业务级 Capability，而不是机械地把每个接口变成一个工具。

## 输入

- 完成建模的 `system-map.yaml`、Evidence 和候选 Operation 清单。
- 用户目标、风险偏好和已声明的范围边界。

## 动作

1. 为每条 eligible 路由分配 `planned`、`composed`、`excluded` 或 `blocked_on_evidence`；只有声明范围允许时才使用 `out_of_scope`。
2. 根据 `scope-inventory.yaml` 重算并对账 `coverage-baseline.json` 的 `source_scope`，再选择高价值场景与组合能力。
3. 区分 Agent 推理与 Runtime 确定性工作流，规划窄 Schema、Policy、权限和租户约束。
4. 为每个 Capability 设计正常、缺失/空数据和错误场景；权限相关能力必须包含权限或跨租户负例。
5. 移除或合并低价值、重复、高风险或“一接口一工具”候选。

## 门禁

- 所有计划能力均由 Evidence 支持，只组合 `GET`/`HEAD` Operation。
- 每个 Capability 至少有一个正常 Eval；权限相关能力有明确权限负例。
- Schema 尽量窄，Secret、认证 Header、动态 URL 和不应由 Agent 控制的参数均不暴露。
- 计划不依赖生产环境、生产数据写入或原系统代码修改。
- `source_scope` 与路由 disposition 统计一致，无未分类 eligible 路由。

## 输出

- `capability-plan.yaml`
- `coverage-baseline.json`
- 使用 `templates/coverage-baseline.json`，并明确它是规划基线而非 `acc coverage` 的运行结果。

## 停止条件

- 计划通过价值、安全和覆盖门禁后进入 Implement。
- 若用户目标不清、能力需要写操作/生产访问，或关键 Evidence 不足，可输出 `status: blocked_on_evidence` 的可审查计划，但必须停止并请求确认或回到 Analyze，不得进入 Implement。
