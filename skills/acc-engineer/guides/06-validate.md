# Phase 5：Validate

用 ACC 的确定性诊断验证定义和编译结果，并只在 ACC 项目内修复。

## 输入

- Implement 阶段生成的完整 ACC 项目候选。
- 当前 ACC CLI 与结构化诊断契约。

## 动作

1. 先运行 `scope_audit.py --project <acc_project>` 并将 JSON 保留为 `scope-audit-report.json`；审计通过前不得运行 ACC 校验命令。
2. 再依次运行 `acc validate --json`、`acc compile --check --json` 和 Coverage v2；若当前 CLI 已提供版本选择，使用 `acc coverage --version 2 --json`，否则调用当前 Core v2 API 并明确记录 CLI 尚未接线，不能拿 v1 报告冒充。
3. 同时检查退出码、`ok`、`result` 和全部 `diagnostics`；不得只凭命令退出判断成功。Scope audit 的 warning 不阻断（warning-only 仍为 `ok: true`），但必须原样保留到风险交付物，不能当作“无诊断”。
4. 修复 ACC 定义或事实来源后，每次都从 scope audit 重新验证；不得放宽 Schema 掩盖错误。
5. 复核原系统只读基线及 Secret 扫描结果。
6. 检查 `provider.auth`/transport 组合、Operation 级 legacy credential 警告、`context_binding_allowlist` 与全部 `context_bindings` 编译诊断；不要把 Schema 可验证误写为 `streamable_http` Gateway 已运行。
7. 分别检查 `route_disposition`、`operation_trace`、`scenario_coverage`、`constructability`、`discoverability_graph`、`composition`、`schema_fidelity`、`output_budget`、`live_observations`。Coverage v2 不生成总分，route closure 也不代表 usable。

## 门禁

- 三个命令均真实执行并返回 `ok: true`，不存在被忽略的 error diagnostics。
- Scope audit 先于三个 ACC 命令通过，且 JSON 已保留。
- 编译仅接受静态引用、有界工作流和证据绑定的只读 Operation。
- 修复未触及原系统，未连接生产环境，也未引入 Secret 或写接口。
- 任何失败、警告或未运行项都被如实保留。
- 任一 error 都阻断后续命令；只有 warning 时可以继续，但不得丢弃 warning。

## 输出

- `scope-audit-report.json`、通过校验的编译候选、Coverage 结果和可复查诊断。

## 停止条件

- 全部门禁通过后进入 Test。
- 若诊断无法在不猜测事实、不放宽安全边界的情况下修复，停止并回到 Analyze/Plan；不得隐藏失败继续。
