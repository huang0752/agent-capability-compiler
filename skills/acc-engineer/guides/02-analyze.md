# Phase 1：Analyze

从原系统的只读事实建立可追溯的系统地图，不把推测写成接口事实。

## 输入

- 已通过的 Preflight 结论与只读基线。
- README、路由/Controller、Service、数据模型、权限中间件、客户端入口与交互、OpenAPI、测试、SOP 和示例数据。

## 动作

1. 先做全局浅扫：对路由注册、OpenAPI 和客户端调用面建立完整 `scope-inventory.yaml`；route usage 不替代后端接口分母。
2. 交叉核对源码、OpenAPI、调用方和测试；冲突必须记录，不能自行选择一个版本当作事实。
3. 只对可能形成 Evidence 的路径使用有界 `--include` 深入检查，为 API 路径、字段、权限、租户、效果和错误捕获 Evidence。
4. Evidence 使用文件与行号、JSON Pointer、OpenAPI Operation 或内容摘要，并记录稳定摘要值。 bundled capture 脚本的行号是 locator，digest 始终覆盖整个有界文件，与 `acc freeze` 一致。
5. 将调用证据归一化为路由 `usage_evidence_sources`，再独立建立 `ui-interaction-inventory.yaml`。以平台中立语义记录 surfaces、events、bindings、defaults、options、conditions、related data、states 与 unknowns；审计器不解析或执行任何客户端框架源码。
6. 为每项交互记录完整 Evidence claim、所用 route IDs、输入来源和结果消费方式。`hidden/disabled` 不是授权证据；权限必须回到服务端策略与接口 Evidence。
7. 将无法确认的客户端表达式或数据来源保留为 unknown，不补造交互、字段、默认值或权限。
8. 把源接口 Evidence 另行归一化为 `SourceContract`。前端默认值和前端条件只能证明客户端行为，不能冒充 `SourceContract` 的 request/response Schema、业务上界、权限或 effect。
9. 从完整分母生成 Candidate Ledger、`DomainMap` 和依赖顺序；绝不把全部 route 交给用户选择，也不因某领域容易分析而先缩小分母。
10. 只推荐一个依赖已就绪的大领域供下一阶段激活；其余领域保持未激活并保留完整候选。

## 门禁

- 每个正式候选 Operation 的关键结论都有可定位 Evidence。
- 静态发现覆盖 GET、HEAD、POST、PUT、PATCH、DELETE 及证据声明的 Read/Action effect；不探测生产环境，不实际调用源写接口，不接触生产 Secret。
- 原系统只读基线无变化，所有分析产物均位于 ACC 项目目录。
- 事实、冲突和推测已明确分开。
- 全局发现分母独立于 Evidence `--include` 列表，每条路由都有稳定 ID。
- 未观察到客户端使用的路由保持 `usage_evidence_sources: []`，不得伪造使用证据；已观察到的调用和 interaction IDs 双向可追溯。
- `complete` 交互范围没有 unresolved；`discovered` 必须明确保留缺口；`none` 必须有 Evidence 与 rationale。
- 每个候选 Operation 都有 SourceContract；Schema 约束能回溯到 provenance，证据冲突或未知没有被伪装成通过。
- Candidate Ledger 与 `DomainMap` 覆盖全局分母，未归类候选显式保留，且没有混入领域深扫推测。

## 输出

- `system-map.yaml`
- `scope-inventory.yaml`
- `ui-interaction-inventory.yaml`（发现适用客户端面时）
- `analysis-report.md`
- `evidence/`
- `source-contracts/` 候选及 provenance ledger

## 停止条件

- 证据覆盖足以支持建模后进入 Model。
- 若高价值接口、交互、权限或租户边界缺少证据，停止该候选并列入待确认事项；不得带着猜测继续实现。
