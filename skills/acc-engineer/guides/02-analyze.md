# Phase 1：Analyze

从原系统的只读事实建立可追溯的系统地图，不把推测写成接口事实。

## 输入

- 已通过的 Preflight 结论与只读基线。
- README、路由/Controller、Service、数据模型、权限中间件、前端 API 调用、OpenAPI、测试、SOP 和示例数据。

## 动作

1. 只读梳理业务模块、REST 路由、字段、权限、Scope、租户边界、错误状态和现有测试。
2. 交叉核对源码、OpenAPI、调用方和测试；冲突必须记录，不能自行选择一个版本当作事实。
3. 为 API 路径、方法、输入/输出字段、权限、租户、效果和错误结论捕获 Evidence。
4. Evidence 使用文件与行号、JSON Pointer、OpenAPI Operation 或内容摘要，并记录稳定摘要值。 bundled capture 脚本的行号是 locator，digest 始终覆盖整个有界文件，与 `acc freeze` 一致。
5. 将无法确认的内容标为未知，不补造接口、字段或权限。

## 门禁

- 每个正式候选 Operation 的关键结论都有可定位 Evidence。
- 只分析已有 `GET`/`HEAD`；不探测生产环境，不调用写接口，不接触生产 Secret。
- 原系统只读基线无变化，所有分析产物均位于 ACC 项目目录。
- 事实、冲突和推测已明确分开。

## 输出

- `system-map.yaml`
- `analysis-report.md`
- `evidence/`

## 停止条件

- 证据覆盖足以支持建模后进入 Model。
- 若高价值接口、权限或租户边界缺少证据，停止该候选并列入待确认事项；不得带着猜测继续实现。
