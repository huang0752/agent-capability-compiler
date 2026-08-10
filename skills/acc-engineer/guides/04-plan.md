# Phase 3：Plan

围绕用户目标设计业务级 Capability，而不是机械地把每个接口变成一个工具。

## 输入

- 完成建模的 `system-map.yaml`、Evidence 和候选 Operation 清单。
- 用户目标、风险偏好和已声明的范围边界。

## 动作

1. 先复核当前领域的独立轴：业务目标、candidate disposition、语义 provenance、身份与源授权、Action lifecycle/conflict/idempotency/outcome、验证等级、跨领域依赖和用户决策轨迹；不生成总分。
2. 将证据清晰项自动形成 accepted 建议；用户 deferred 与 `blocked_on_evidence` 分开。只逐个询问异常、高风险和测试边界，不把全部 route 交给用户选择。
3. 用户确认后生成版本化 `DomainDecision`。只有当前领域完成后才选择下一个依赖已就绪领域；未完成领域不得批量进入实现。
4. 为每条 eligible 路由分配 `planned`、`composed`、`excluded` 或 `blocked_on_evidence`；只有声明范围允许时才使用 `out_of_scope`。
5. 在 `system_complete` 中，每个 eligible excluded 路由必须引用一条顶层 `exclusion_rules` 规则，并有逐 route 的 `exclusion_decision`（独立 rationale、Evidence、capability IDs 与 replacement route IDs）。结构合法时它们是唯一权威，不再要求 `reason`；若结构不合法，仍以缺 reason 报错。Capability Plan 只保存 decision 引用，禁止维护第二份自由文本权威排除事实。
6. `operational_polling` 和 `low_business_value` 必须在 `scope.exclusion_approval` 记录用户批准原文与精确 route IDs；前端使用路由的排除同样需要精确批准。
7. ineligible、`blocked_on_evidence`、`out_of_scope`，以及 pilot/domain 模式的 excluded 路由仍要求 route-level `reason` 与 Evidence；ineligible 不进入 eligible 分母。`blocked_on_evidence` 在系统完整模式下是发布阻断，不得计为完成。
8. 根据 `scope-inventory.yaml` 重算并对账 `coverage-baseline.json` 的 `source_scope`；Capability Plan 的 `coverage.scope_mode` 必须精确等于 Inventory mode，`coverage.scope_inventory` 必须精确为 `scope-inventory.yaml`，`route_dispositions` 必须与 Inventory 按 disposition 精确一致，`exclusion_decision_refs` 必须用 `/routes/{index}/exclusion_decision` 精确覆盖系统完整模式的 eligible excluded decisions，再选择高价值场景与组合能力。
9. 区分 Agent 推理与 Runtime 确定性工作流。为每个必填 selector 记录 `selector acquisition`（caller、trusted context、default、upstream step 或 producer Capability）；无法从低摩擦入口或生产者构造的 selector 必须阻断。
10. 为 list/search 明确 `empty success path`，不能强制随后执行 detail；记录 `failure isolation`，当前只支持可验证的 `fail_fast` 时不得声称 partial success。声明 `output budget` 与长文本披露，不得为了预算编造 SourceContract 上界。
11. 为每个 Capability 设计正常、缺失/空数据和错误场景；权限相关能力必须包含权限或跨租户负例。Capability 输出只有经过可证明的 pick/map/redact/dataflow 投影才可比 Operation 输出更窄。
12. 一接口一工具不是天然缺陷。保留有明确 business intent 的单 Operation search、detail、monitor；只拆分独立 selector、无数据流关系或失败语义不一致的组合。`duplicate_or_subsumed` 必须形成 excluded route → replacement planned/composed route → Operation → Capability dependency 的闭包。
13. 显式 Action 计划必须采用 `prepare → approve → commit → status`，记录 effect、risk、approval、idempotency、concurrency、retry 与目标资源版本；不得简单放开 POST，也不得让 Agent 提供 JWT、密码或任意 approval 内容。
14. 为每个高价值 interaction 选择 adopt 或 evidence-backed omission；adopt 时建立 `InteractionContract` 计划，显式记录 bindings、defaults、options、conditions、related data、states 和 required headless scenarios。未经证据的客户端细节保持 unknown。

## 门禁

- 所有计划能力均由 Evidence 支持；Read 只组合显式 `read` effect Operation，Action 只组合完成安全合同与审批生命周期的 Action Operation，不从 HTTP 方法猜业务 effect。
- 每个 Capability 至少有一个正常 Eval；权限相关能力有明确权限负例。
- Schema 尽量窄，Secret、认证 Header、动态 URL 和不应由 Agent 控制的参数均不暴露。
- 计划不依赖生产环境、生产数据写入或原系统代码修改。
- `source_scope` 与路由 disposition 统计一致，无未分类 eligible 路由。
- 系统完整模式下，每个 eligible excluded route 均有合法 rule、独立 decision、Evidence；主观或前端使用排除均有逐 route 精确批准。
- ineligible 的 reason/Evidence 完整，且不存在被当作已完成的 `blocked_on_evidence`。
- Capability Plan 无悬空、遗漏、重复或空白 route ID，无旧 `deliberately_excluded` 自由文本权威字段，decision 引用均指向真实对象。
- 每个 Capability 的 selector acquisition、empty success path、failure isolation 和 output budget 均完整；producer graph 可达，独立业务根没有被强行聚合。
- Action 有可审查的 preview/approval/commit/status 合同与隔离沙箱计划；缺一项即阻断 Implement。
- 每个 adopted interaction 都可回溯到 UI inventory；前端 `hidden/disabled` 不是授权，前端默认值和前端条件不会冒充 `SourceContract`。

## 输出

- `capability-plan.yaml`
- `coverage-baseline.json`
- 使用 `templates/coverage-baseline.json`，并明确它是规划基线而非 `acc coverage` 的运行结果。

## 停止条件

- 计划通过价值、安全和覆盖门禁后进入 Implement。
- 若用户目标不清、需要生产访问、Action 缺少完整安全合同，或关键 Evidence 不足，可输出 `status: blocked_on_evidence` 的可审查计划，但必须停止并请求确认或回到 Analyze，不得进入 Implement。
