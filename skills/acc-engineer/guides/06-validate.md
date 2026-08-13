# Phase 5：Validate

用 ACC 的确定性诊断验证定义和编译结果，并只在 ACC 项目内修复。

## 输入

- Implement 阶段生成的完整 ACC 项目候选。
- 当前 ACC CLI 与结构化诊断契约。

## 动作

1. 先运行 `scope_audit.py --project <acc_project>`；发现客户端面时紧接运行 `interaction_audit.py --project <acc_project> --output interaction-audit-report.json`。任一审计失败前不得运行 ACC 校验命令。
2. 再依次运行 `acc validate --json`、`acc compile --check --json` 和 `acc coverage --json`；route 与 interaction denominator 必须分别闭合。
3. 同时检查退出码、`ok`、`result` 和全部 `diagnostics`；不得只凭命令退出判断成功。Scope audit 的 warning 不阻断（warning-only 仍为 `ok: true`），但必须原样保留到风险交付物，不能当作“无诊断”。
4. 修复 ACC 定义或事实来源后，每次都从 scope audit 重新验证；不得放宽 Schema 掩盖错误。
5. 复核原系统只读基线及 Secret 扫描结果。
6. 检查 `provider.auth`/transport 组合、Operation 禁止凭据、`context_binding_allowlist` 与全部 `context_bindings` 编译诊断；不要把 Schema 可验证误写为 `streamable_http` Gateway 已运行。
7. 分别检查 `route_disposition`、`operation_trace`、`scenario_coverage`、`constructability`、`discoverability_graph`、`composition`、`tool_portfolio`、`schema_fidelity`、`output_budget`、`live_observations`。Coverage 不生成总分，route closure 也不代表 usable。`tool_portfolio` 的 budget/overlap/orphan warning 必须解释或整改，under-covered materialized route 是错误；blocked denominator 仍保留为未完成事实。
8. 另外逐项检查十个交互轴：`surface_disposition`、`interaction_trace`、`input_binding_fidelity`、`default_provenance`、`option_resolution`、`condition_coverage`、`related_data_graph`、`state_scenarios`、`presentation_projection`、`client_adapter_evidence`。不生成总分，源连接不能填充 client adapter 证据。
9. 对每个已处理领域逐项检查十二个 Domain/Action 独立轴；Read route closure 不得掩盖 blocked/excluded/deferred Action，`source_connected_verified` 不得升级安全或源授权证明。
10. 校验当前版本 `DomainDecision`、candidate ledger digest、active dependency refs 与用户确认绑定；未激活领域的历史 completed decision 不能填充依赖或确认轴。

## 门禁

- 三个命令均真实执行并返回 `ok: true`，不存在被忽略的 error diagnostics。
- Scope/interaction audits 先于三个 ACC 命令通过，且 JSON 已保留。
- 编译仅接受静态引用、有界工作流、证据绑定的 Read，以及具备完整安全生命周期的 Action。
- 修复未触及原系统，未连接生产环境，也未引入 Secret 或未经安全合同的 Action。
- 任何失败、警告或未运行项都被如实保留。
- 任一 error 都阻断后续命令；只有 warning 时可以继续，但不得丢弃 warning。
- 当前领域必须可由独立轴复核；没有总分或“整体可用”字段可替代逐轴失败。
- `system_complete` 必须对账 Read/Create/Update/Delete/transition/execute/composite 业务表面，且 `blocked_on_evidence=0`、无 eligible Action exclusion 或 deferred Action；否则即使 validate/compile 返回 `ok: true` 也不得进入完成态。
- 当 system-complete 项目发现 frontend denominator 时，UI scope 必须是 `complete`；每个 surface 有全局唯一 usage context 与 entry Evidence，每个 interaction 七维 disposition 完整，其 Evidence 必须同时闭合到 interaction claims 和所属 surface sources，且全部 interaction 被 adopted 或以 immutable Evidence 明确 omitted。`ACC_UI_DIMENSION_DISPOSITION_REQUIRED`、`ACC_UI_DIMENSION_EVIDENCE_UNRESOLVED`、`ACC_UI_SURFACE_ENTRY_EVIDENCE_REQUIRED` 和 `ACC_UI_SYSTEM_SCOPE_INCOMPLETE` 是旧 wrapper 清单的迁移诊断，不能忽略。

## 输出

- `scope-audit-report.json`、适用时的 `interaction-audit-report.json`、通过校验的编译候选、Coverage 结果和可复查诊断。

## 停止条件

- 全部门禁通过后进入 Test。
- 若诊断无法在不猜测事实、不放宽安全边界的情况下修复，停止并回到 Analyze/Plan；不得隐藏失败继续。
