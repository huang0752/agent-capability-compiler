# Phase 1：Analyze

从原系统的只读事实建立可追溯的系统地图，不把推测写成接口事实。

## 输入

- 已通过的 Preflight 结论与只读基线。
- README、路由/Controller、Service、数据模型、权限中间件、前端 API 调用、OpenAPI、测试、SOP 和示例数据。

## 动作

1. 先对路由注册、OpenAPI 和客户端调用面做浅层全局发现，建立所有发现路由的 `scope-inventory.yaml`。前端客户端只提供“正在被使用”的证据，不替代后端路由/OpenAPI 建立的正式分母。
2. 交叉核对源码、OpenAPI、调用方和测试；冲突必须记录，不能自行选择一个版本当作事实。
3. 只对可能形成 Evidence 的路径使用有界 `--include` 深入检查，为 API 路径、字段、权限、租户、效果和错误捕获 Evidence。
4. Evidence 使用文件与行号、JSON Pointer、OpenAPI Operation 或内容摘要，并记录稳定摘要值。 bundled capture 脚本的行号是 locator，digest 始终覆盖整个有界文件，与 `acc freeze` 一致。
5. 将前端调用证据归一化为路由的 `usage_evidence_sources`（稳定文件 locator、OpenAPI 引用或 Evidence ID）；审计器只消费该字段，不解析 Vue、React 或其他前端框架源码。
6. 将无法确认的内容标为未知，不补造接口、字段或权限。

## 门禁

- 每个正式候选 Operation 的关键结论都有可定位 Evidence。
- 只分析已有 `GET`/`HEAD`；不探测生产环境，不调用写接口，不接触生产 Secret。
- 原系统只读基线无变化，所有分析产物均位于 ACC 项目目录。
- 事实、冲突和推测已明确分开。
- 全局发现分母独立于 Evidence `--include` 列表，每条路由都有稳定 ID。
- 前端已使用的路由均有非空、去重的 `usage_evidence_sources`，没有用前端扫描结果替代路由分母。

## 输出

- `system-map.yaml`
- `scope-inventory.yaml`
- `analysis-report.md`
- `evidence/`

## 停止条件

- 证据覆盖足以支持建模后进入 Model。
- 若高价值接口、权限或租户边界缺少证据，停止该候选并列入待确认事项；不得带着猜测继续实现。
