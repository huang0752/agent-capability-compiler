# Phase 8：Handoff

把可审查的候选、证据、测试与风险完整交给人工 Git Review。

## 输入

- 最终 System Map、Evidence、定义、Coverage、Validate/Test 结果和风险清单。
- Preflight 建立的原系统只读基线及 ACC 项目差异。

## 动作

1. 生成 `HANDOFF.md`、`coverage-report.json`、`test-report.json`、`risk-report.json` 和 `candidate.diff`。
2. 说明能力范围、Evidence 来源、安全边界、实际执行的命令、通过/失败/未运行项和已知限制。
3. 验证 `candidate.diff` 仅包含 ACC 项目内容，原系统修改数量为零。
4. 扫描交付物中的 Secret、生产地址、Token、完整上游响应和生产数据；发现即停止并清理。
5. 给出人工复核顺序，但不自动提交、push、部署或访问生产环境。

## 门禁

- 所有结论可由 Evidence、结构化 diagnostics 或真实测试结果复核。
- 不隐藏失败，不把未运行测试写成通过，不把推测写成事实。
- 原系统代码、数据库、认证和部署变更均为零；交付物不含 Secret 或写接口。
- 风险与限制已明确，候选仍符合只读 MVP 和平台中立边界。

## 输出

- `HANDOFF.md`
- `coverage-report.json`
- `test-report.json`
- `risk-report.json`
- `candidate.diff`

## 停止条件

- 交付物通过门禁后停止，等待人工 Git Review。
- 不自动 commit、push、发布、部署或调用生产接口；任何后续动作都需要明确人工授权。
