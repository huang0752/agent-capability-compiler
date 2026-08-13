# Phase 0：Preflight

先建立工程边界；任何分析或生成工作都不得先于本阶段通过。

## 输入

- 原系统源码目录、独立 ACC 项目目录和用户目标。
- 当前 ACC 安装、原系统文档、OpenAPI、测试入口及运行约束。
- 用户明确的范围语言；未说明时按 `system_complete` 处理。

## 动作

1. 用 `pwd -P` 或 `realpath` 解析两个目录的真实路径，确认它们互不包含；安全脚本会有意拒绝含符号链接的路径组成，包括 macOS `/var` 别名。
2. 对全新目标先运行 `acc init <acc_project>` 并进入该目录，再运行 `acc doctor --json`；不得对尚无 `project.yaml` 的空目录直接执行 Doctor。
3. 记录范围模式、选定域与用户确认原文；`pilot` 只有用户明确提出 MVP/试点时才可使用。
4. 记录 `system_complete` 的业务表面合同：Read、Create、Update、Delete、transition、execute 与 composite intent 全部进入发现分母；不能把 system complete 解释为 Read-only。
5. 只读盘点路由注册、OpenAPI 和客户端入口；`--include` 仅用于后续深层 Evidence 采集，不得当作全局发现分母。方法只用于发现，kind/effect 必须由 Evidence 判定。
6. 建立原系统只读基线，并检查命令是否可能修改源码、数据库、认证或依赖文件。
7. 识别疑似生产凭据、Token、私钥和生产地址；只报告风险位置，不读取、复制或输出 Secret 值。
8. 单独记录写沙箱、审批签发、幂等、并发和结果查询 Evidence 是否可获得。缺失时预设对应 Action 为 `undetermined/blocked_on_evidence`，继续完成安全的全局发现，但禁止进入该 Action 的 Implement/Test。
9. 为领域向导建立可恢复状态；本阶段只允许准备全局浅扫，不激活领域、不深扫，也不要求用户选择 route。

## 门禁

- 原系统与 ACC 项目边界明确，原系统可按只读方式工作。
- 不需要生产 Secret 或生产环境。全局分母覆盖全部已发现业务 effect；Read 候选仅使用已有 REST `GET`/`HEAD`，Action 只在明确授权的隔离测试源中实现和验证。
- 未获写沙箱授权或缺少 effect/risk/retry/idempotency/concurrency/approval/outcome Evidence 的 Action 已明确标为 `blocked_on_evidence`；它仍留在 system-complete 分母并阻止 complete，不能改标 excluded/ineligible 来通过门禁。
- 可用安全方式运行必要测试，且命令不会写入原系统。
- `acc doctor --json` 的实际结果已检查，不能只看退出码。
- 范围模式已记录，且 `pilot` 有可审计的用户明确确认。
- 后续流程明确一次只激活一个依赖已就绪领域，局部 include 不会变成全局分母。

## 输出

- 可审计的 Preflight 结论、目录边界、只读基线、可用资料和安全测试入口。
- 明确列出的风险、限制与待确认事项，供 Phase 1 使用。
- 按 `templates/preflight-report.json` 形成的结构化 Preflight 报告。
- 已声明的 scope mode、选定域和用户确认记录。

## 停止条件

- 通过全部门禁后进入 Analyze。
- 若目录重叠、只读边界无法保证或需要生产凭据/生产访问，立即停止并请求人工处理。若 Action 没有独立隔离沙箱和明确授权，只停止该 Action 的深扫后执行与测试，把它保留为 `blocked_on_evidence`；继续安全发现其他业务表面，但最终不得宣称 `system_complete` 已完成。
