# 结构化范围治理实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 ACC Engineer 的路由范围审计从自由文本排除升级为可验证的结构化规则，防止完整只读分析因批量套用理由而静默漏能力。

**Architecture:** 治理规则留在 Skill 层，不进入 Core/Runtime。Scope Inventory 是路由处置事实源；System Map 的 `scope_route_ids` 与 Capability Plan 依赖建立可验证闭包。Error 阻断流程，warning 保留结果并进入风险交付物。

**Tech Stack:** Python 3.12、PyYAML、pytest、现有 JSON envelope、ruff、mypy。

---

## 固定契约

```yaml
scope:
  mode: system_readonly_complete
  selected_domains: []
  user_confirmation: null
  exclusion_approval:
    approved_route_ids: [GET /api/health]
    approval_text: "同意排除仅用于运维轮询的健康检查接口"
exclusion_rules:
  - id: operational-health
    category: operational_polling
    route_ids: [GET /api/health]
    rationale: "仅返回运行状态，不形成用户可调用的业务能力"
    evidence_sources: [evidence/routes.md#health]
routes:
  - id: GET /api/health
    domain_id: platform
    eligibility: eligible
    disposition: excluded
    usage_evidence_sources: [evidence/frontend.md#health-poll]
    exclusion_rule_id: operational-health
    exclusion_decision:
      rationale: "前端只用于页面存活探测，不向 Agent 暴露"
      evidence_sources: [evidence/frontend.md#health-poll]
      capability_ids: []
      replacement_route_ids: []
```

类别固定为 `binary_or_download`、`sensitive_configuration`、`alternate_identity_boundary`、`unsafe_dynamic_authorization`、`unavailable_or_disabled`、`operational_polling`、`duplicate_or_subsumed`、`low_business_value`。其中 `operational_polling` 和 `low_business_value` 是主观类别，必须逐 route 批准。理由复用采用去首尾空白、合并连续空白并转小写后的完全相等。eligible 路由至少 10 条且排除率达到 70% 才产生高排除率 warning；它只是风险信号，不改变 `ok`，也不是正确性阈值。

### Task 1: 支持非阻断 warning

**Files:**

- Modify: `skills/acc-engineer/scripts/verify_read_only_workspace.py`
- Modify: `skills/acc-engineer/scripts/scope_audit.py`
- Test: `tests/unit/skill/test_verify_read_only_workspace.py`
- Test: `tests/unit/skill/test_scope_audit.py`

- [ ] 写失败测试：`diagnostic(..., severity="warning")` 被保留，默认仍为 error；warning-only 退出 0、`ok=true`、result 非空；有任一 error 退出 3 且保留全部 diagnostics。
- [ ] 运行红灯：`uv run pytest tests/unit/skill/test_verify_read_only_workspace.py tests/unit/skill/test_scope_audit.py -k 'warning or severity' -v`。
- [ ] 给 `diagnostic()` 和 `add_issue()` 增加 severity；新增 `has_error()`，`main()` 只按 error 决定失败。
- [ ] 运行绿灯并提交：

```bash
uv run pytest tests/unit/skill/test_verify_read_only_workspace.py tests/unit/skill/test_scope_audit.py -v
git commit --only -m 'feat(skill): 支持范围审计警告' -- skills/acc-engineer/scripts/verify_read_only_workspace.py skills/acc-engineer/scripts/scope_audit.py tests/unit/skill/test_verify_read_only_workspace.py tests/unit/skill/test_scope_audit.py
```

### Task 2: 校验 rule 与逐路由 decision

**Files:**

- Modify: `skills/acc-engineer/scripts/scope_audit.py`
- Modify: `tests/unit/skill/test_scope_audit.py`

- [ ] 扩充 fixture，支持 `exclusion_rules`、approval、usage evidence、rule id 和 decision。
- [ ] 写正反例：未知/空 rule、悬空 route、rule 指向非 excluded、同 route 多 rule、rule/decision 缺 Evidence、空 rationale、复用 rationale。
- [ ] 保留并显式回归两个发布门禁：每个 `ineligible` route 仍必须有非空 `reason` 与 Evidence；`system_readonly_complete` 中存在任何 `blocked_on_evidence` 时必须失败，不能计为完成。
- [ ] 断言错误码 `ACC_SCOPE_EXCLUSION_RULE_REQUIRED`、`ACC_SCOPE_EXCLUSION_RULE_UNKNOWN`、`ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH`、`ACC_SCOPE_EXCLUSION_EVIDENCE_REQUIRED`、`ACC_SCOPE_ROUTE_EXCLUSION_DECISION_REQUIRED`、`ACC_SCOPE_EXCLUSION_DECISION_REUSED`。
- [ ] 运行红灯：`uv run pytest tests/unit/skill/test_scope_audit.py -k 'exclusion_rule or exclusion_decision' -v`。
- [ ] 实现 `normalize_rationale()`、`index_routes()`、`audit_exclusion_rules()`、`audit_route_exclusion_decision()`。只对 `system_readonly_complete + eligible + excluded` 强制新合同；旧模式与 ineligible 保持兼容。
- [ ] 运行绿灯并提交：

```bash
uv run pytest tests/unit/skill/test_scope_audit.py -v
git commit --only -m 'feat(skill): 结构化只读路由排除决策' -- skills/acc-engineer/scripts/scope_audit.py tests/unit/skill/test_scope_audit.py
```

### Task 3: 建立 Operation trace 与 subsumed 替代闭包

**Files:**

- Modify: `skills/acc-engineer/scripts/scope_audit.py`
- Modify: `tests/unit/skill/test_scope_audit.py`

- [ ] 将 System Map fixture 升级为包含非空 `scope_route_ids` 的 Operation，将 Capability Plan fixture 升级为 capability 到 dependencies 的映射。
- [ ] 写失败测试：trace 缺失、route 不存在、trace 指向 excluded/ineligible/blocked、operation id 不一致、Capability dependency 不存在。
- [ ] 写 `duplicate_or_subsumed` 正反例，闭包必须为 excluded route → replacement planned/composed route → System Map Operation → 指定 Capability dependency；excluded route 本身不得作为普通 trace。
- [ ] 运行红灯：`uv run pytest tests/unit/skill/test_scope_audit.py -k 'route_trace or subsumed or replacement' -v`。
- [ ] 实现 `system_operations()`、`plan_capabilities()`、`audit_operation_route_traces()`、`audit_subsumed_replacement_closure()`，返回稳定的 `ACC_SCOPE_OPERATION_ROUTE_TRACE_* `和 `ACC_SCOPE_SUBSUMED_* `错误。
- [ ] 运行绿灯并提交：

```bash
uv run pytest tests/unit/skill/test_scope_audit.py -v
git commit --only -m 'feat(skill): 校验能力与路由追踪闭包' -- skills/acc-engineer/scripts/scope_audit.py tests/unit/skill/test_scope_audit.py
```

### Task 4: 批准、前端使用、整域零能力与启发式

**Files:**

- Modify: `skills/acc-engineer/scripts/scope_audit.py`
- Modify: `tests/unit/skill/test_scope_audit.py`

- [ ] 写失败测试：主观排除无精确批准、approval 文本为空、前端使用 route 被排除、存在 eligible route 的域没有 planned/composed、跨域套用同 rationale、高排除率。
- [ ] 固定语义：system complete 下，前端使用的 eligible route 未精确批准时 `ACC_SCOPE_FRONTEND_USED_ROUTE_EXCLUDED` 为 error；pilot/domain 为 warning；有效 subsumed 闭包可满足整域直接能力例外。
- [ ] 运行红灯：`uv run pytest tests/unit/skill/test_scope_audit.py -k 'approval or frontend or zero_capability or exclusion_ratio or template_reused' -v`。
- [ ] 实现 `approved_exclusion_route_ids()`、`audit_subjective_exclusion_approval()`、`audit_frontend_used_exclusions()`、`audit_domain_capability_coverage()`、`audit_exclusion_heuristics()`。
- [ ] 运行绿灯并提交：

```bash
uv run pytest tests/unit/skill/test_scope_audit.py -v
git commit --only -m 'feat(skill): 阻断无依据的能力范围缩减' -- skills/acc-engineer/scripts/scope_audit.py tests/unit/skill/test_scope_audit.py
```

### Task 5: 更新模板与阶段指南

**Files:**

- Modify: `skills/acc-engineer/templates/scope-inventory.yaml`
- Modify: `skills/acc-engineer/templates/capability-plan.yaml`
- Verify: `skills/acc-engineer/templates/system-map.yaml`
- Modify: `skills/acc-engineer/HARNESS.md`
- Modify: `skills/acc-engineer/guides/02-analyze.md`
- Modify: `skills/acc-engineer/guides/03-model.md`
- Modify: `skills/acc-engineer/guides/04-plan.md`
- Modify: `skills/acc-engineer/guides/06-validate.md`
- Modify: `skills/acc-engineer/guides/08-refine.md`
- Modify: `skills/acc-engineer/guides/09-handoff.md`
- Modify if needed: `skills/acc-engineer/SKILL.md`
- Test: `tests/unit/skill/test_skill_structure.py`

- [ ] 先写模板字段集合测试；Capability Plan 只引用 Inventory decision，不维护第二份自由文本排除事实。
- [ ] 运行红灯：`uv run pytest tests/unit/skill/test_skill_structure.py -k 'scope or template' -v`。
- [ ] 更新模板和指南：Analyze 归一化前端使用 Evidence；Model 只 trace planned/composed；Plan 生成 rule/decision；Validate 保留 warning；Refine 检查异常排除；Handoff 将 warnings 写入 `risk-report.json` 与 `HANDOFF.md`。保持 `SKILL.md` 少于 500 行。
- [ ] 运行绿灯；根据实际变更路径执行精确提交：

```bash
uv run pytest tests/unit/skill/test_skill_structure.py tests/unit/skill/test_scope_audit.py -v
git commit --only -m 'docs(skill): 固化结构化范围治理流程' -- skills/acc-engineer/templates/scope-inventory.yaml skills/acc-engineer/templates/capability-plan.yaml skills/acc-engineer/HARNESS.md skills/acc-engineer/guides/02-analyze.md skills/acc-engineer/guides/03-model.md skills/acc-engineer/guides/04-plan.md skills/acc-engineer/guides/06-validate.md skills/acc-engineer/guides/08-refine.md skills/acc-engineer/guides/09-handoff.md tests/unit/skill/test_skill_structure.py
```

### Task 6: 完整验证

- [ ] 运行：

```bash
uv run pytest tests/unit/skill -v
uv run ruff check .
uv run mypy packages tests
uv run pytest
```

- [ ] 确认 warning-only 成功但进入风险交付，任一 error 失败；ineligible 理由/Evidence 和 system complete 的 blocked route 门禁均有回归；审计器不解析业务前端源码，只消费 Analyze 归一化的 Evidence。
- [ ] 不改 Core、Runtime、`baogao-jin` 或 `.understand-anything/`。
