# Phase 8：Handoff

把可审查的候选、证据、测试与风险完整交给人工 Git Review。

## 输入

- 最终 System Map、Evidence、定义、Coverage、Validate/Test 结果和风险清单。
- Preflight 建立的原系统只读基线及 ACC 项目差异。

## 动作

1. 生成 `HANDOFF.md`、`scope-audit-report.json`、`coverage-report.json`、`test-report.json` 和 `risk-report.json`。
2. 说明 scope mode、validation level（`offline_candidate` 或经授权的 `source_connected_verified`）、Evidence 来源、实际命令、失败/未运行项和已知限制。
3. 使用 Preflight 时相同的深层 `--include` 列表复核源快照，并复核浅层全局发现分母。Git ACC 项目生成 `candidate.diff`；非 Git 项目运行 `artifact_manifest.py --project <acc_project> --output artifact-manifest.json`。
4. 扫描交付物中的 Secret、生产地址、Token、完整上游响应和生产数据；发现即停止并清理。
5. 给出人工复核顺序，但不自动提交、push、部署或访问生产环境。

## 门禁

- 所有结论可由 Evidence、结构化 diagnostics 或真实测试结果复核。
- 不隐藏失败，不把未运行测试写成通过，不把推测写成事实。
- 原系统代码、数据库、认证和部署变更均为零；交付物不含 Secret 或写接口。
- 风险与限制已明确，候选仍符合已声明只读范围和平台中立边界。
- Git diff 或非 Git artifact manifest 已按项目类型生成，不混用两种交付证据。

## 输出

- `HANDOFF.md`
- `scope-audit-report.json`
- `coverage-report.json`
- `test-report.json`
- `risk-report.json`
- Git 项目：`candidate.diff`
- 非 Git 项目：`artifact-manifest.json`

## 停止条件

- 交付物通过门禁后停止，等待人工 Git Review。
- 不自动 commit、push、发布、部署或调用生产接口；任何后续动作都需要明确人工授权。
