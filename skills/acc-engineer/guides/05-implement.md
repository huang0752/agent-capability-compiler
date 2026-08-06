# Phase 4：Implement

仅在独立 ACC 项目中实现已批准的定义和测试夹具。

## 输入

- `capability-plan.yaml`、`coverage-baseline.json`、System Map 与 Evidence。
- ACC 的 Operation、Capability、Policy 和 Eval Schema/模板。

## 动作

1. 仅为 disposition 是 `planned` 或 `composed` 的路由创建 Evidence 引用、Operations、Capabilities、Policies、Evals 和 Fake fixtures。
2. 从证据选择唯一的 Provider `auth`：`none`、环境引用的 `bearer_secret`，或 `password_bearer`。`password_bearer` 在 `stdio` 使用 `environment_secret`，在 `streamable_http` 使用 `gateway_session`。新 Operation 不得包含 `credential_ref`。
3. 为 Operation 定义严格输入/输出 Schema、`GET`/`HEAD` 请求、Scope、超时和响应大小限制。需要受信 principal/tenant 值时才声明 `context_bindings`；目标必须映射到 path/query，且不得出现在 Capability input 或 Workflow arguments。
4. 使用受限工作流步骤 `call/pick/map/filter/assert/redact/branch/parallel/foreach/emit`；引用、循环和并发保持静态有界。
5. 将敏感字段限制落实到 Policy、redact 和 Eval 的 `forbidden_fields`。
6. 每次修改后检查写入路径和原系统只读基线。

## 门禁

- 正式 Operation 均有 Evidence，且不存在绝对 URL、动态 Host、Token 参数、Header 覆盖或路径穿越。
- 不包含写方法、动态代码、Shell、`eval`、任意导入或运行时生成请求。
- 定义中只有 SecretRef 名称，没有生产 Secret；fixtures 不复制生产数据。
- Provider auth 与 transport 组合合法；Operation 级 `credential_ref` 只用于 legacy `stdio`，新项目不得依赖。
- `PrincipalContext`、JWT、密码和 Header 不属于公共 Schema；`context_bindings` 目标不能由 Agent 或 Workflow 覆盖。
- 原系统文件、数据库、认证和部署修改数量为零。
- 每个实现的 Operation 都可经 `scope_route_ids` 回溯到 `planned`/`composed` 路由。

## 输出

- 完整的 `operations/`、`capabilities/`、`policies/`、`evals/`、`evidence/` 和测试 fixtures 候选。

## 停止条件

- 计划内定义和 Eval 齐备后进入 Validate。
- 一旦发现需要修改原系统、访问生产、使用写接口或伪造 Evidence，立即停止；不得用临时代码绕过门禁。
