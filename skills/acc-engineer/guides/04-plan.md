# Phase 3：Plan

围绕用户目标设计业务级 Capability，而不是机械地把每个接口变成一个工具。

## 输入

- 完成建模的 `system-map.yaml`、Evidence 和候选 Operation 清单。
- 用户目标、风险偏好和已确认的 MVP 边界。

## 动作

1. 选择高价值只读场景，并判断哪些接口需要组合成一个业务能力。
2. 区分应由 Agent 推理的信息与 Runtime 必须确定性执行的工作流。
3. 规划输入/输出 Schema、隐藏参数、字段脱敏、Policy、权限和租户约束。
4. 为每个 Capability 设计正常、缺失/空数据和错误场景；单资源读取若以 404 表达缺失，可将 `empty` 明确记为 `not_applicable` 并由 not-found Eval 覆盖。权限相关能力必须包含 401/403 或跨租户负例，未受保护能力应移除/置空该计划项。
5. 识别低价值、重复、高风险或近似“一接口一工具”的候选并移除或合并。

## 门禁

- 所有计划能力均由 Evidence 支持，只组合 `GET`/`HEAD` Operation。
- 每个 Capability 至少有一个正常 Eval；权限相关能力有明确权限负例。
- Schema 尽量窄，Secret、认证 Header、动态 URL 和不应由 Agent 控制的参数均不暴露。
- 计划不依赖生产环境、生产数据写入或原系统代码修改。

## 输出

- `capability-plan.yaml`
- `coverage-baseline.json`
- 使用 `templates/coverage-baseline.json`，并明确它是规划基线而非 `acc coverage` 的运行结果。

## 停止条件

- 计划通过价值、安全和覆盖门禁后进入 Implement。
- 若用户目标不清、能力需要写操作/生产访问，或关键 Evidence 不足，可输出 `status: blocked_on_evidence` 的可审查计划，但必须停止并请求确认或回到 Analyze，不得进入 Implement。
