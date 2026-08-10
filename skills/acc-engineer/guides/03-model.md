# Phase 2：Model

把已证实的系统事实整理为业务模型和候选操作目录。

## 输入

- `system-map.yaml`、`analysis-report.md` 与 `evidence/`。
- 用户目标及 Analyze 阶段的冲突、限制和未确认事项。

## 动作

1. 建立业务领域、实体、关系，以及 Read/Action 数据与状态流。
2. 建立候选 Operation 目录，每项添加非空 `scope_route_ids`，且只指向 eligible 且 disposition 为 `planned` 或 `composed` 的路由；同时标明对应 API、权限、Scope、租户边界、错误和 Evidence。
3. 记录 API 调用关系、原系统已有测试及可复用的安全测试数据。
4. 把环境变量名称建模为引用；不得记录凭据值、动态 Host 或调用方可覆盖的认证 Header。
5. 保留未确认事项，不用通用经验填补原系统事实。
6. 对每个候选 Operation 比较 SourceContract：Operation 输入必须是源 `request_schema` 可接受范围的安全子集，Operation 输出必须覆盖源 `response_schema` 的可能结果；未知关系保持 unknown。
7. 从 UI inventory 建立 interaction dependency graph：输入 binding、default provenance、option producer、condition target、related data、result consumption 与 state transition 均保留 Evidence；不把呈现状态解释成授权。

## 门禁

- 每个候选 Operation 均可回溯到 Analyze Evidence；Read 与 Action 的 kind/effect 精确一致且不从 HTTP 方法猜测。
- 权限、租户和错误模型来自原系统证据，不由 ACC 推断或放宽。
- 模型不包含生产 Secret、生产地址或原系统改造方案；Action 仅建模有完整安全合同的既有业务操作。
- 原系统只读基线无变化。
- 每个候选 Operation 的 `scope_route_ids` 都存在于 `scope-inventory.yaml`，且不指向 excluded、ineligible 或 blocked 路由。
- 不存在用样本 observation 收紧数组、长文本、枚举或对象字段的人工 Schema；限制必须有 provenance。
- UI `hidden/disabled` 不是授权，前端默认值与前端条件不能提升 `SourceContract` authority。

## 输出

- 补充业务领域、实体、操作目录、interaction dependency graph、权限/租户模型、关系、测试和未知项后的 `system-map.yaml`。
- 可供 Capability 规划使用的、按证据分级的候选 Operation 清单。

## 停止条件

- 核心业务关系和安全边界足够清晰后进入 Plan。
- 若候选 Operation 的证据、权限或租户语义仍不完整，停止该候选并返回 Analyze。
