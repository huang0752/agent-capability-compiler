# Phase 4：Implement

仅在独立 ACC 项目中实现已批准的定义和测试夹具。

## 输入

- `capability-plan.yaml`、`coverage-baseline.json`、System Map 与 Evidence。
- ACC 的 Operation、Capability、Policy 和 Eval Schema/模板。

## 动作

1. 创建 Evidence 引用、Operations、Capabilities、Policies、Evals 和 Fake fixtures。
2. 为 Operation 定义严格输入/输出 Schema、`GET`/`HEAD` 请求、SecretRef、Scope、超时和响应大小限制。
3. 使用受限工作流步骤 `call/pick/map/filter/assert/redact/branch/parallel/foreach/emit`；引用、循环和并发保持静态有界。
4. 将敏感字段限制落实到 Policy、redact 和 Eval 的 `forbidden_fields`。
5. 每次修改后检查写入路径和原系统只读基线。

## 门禁

- 正式 Operation 均有 Evidence，且不存在绝对 URL、动态 Host、Token 参数、Header 覆盖或路径穿越。
- 不包含写方法、动态代码、Shell、`eval`、任意导入或运行时生成请求。
- 定义中只有 SecretRef 名称，没有生产 Secret；fixtures 不复制生产数据。
- 原系统文件、数据库、认证和部署修改数量为零。

## 输出

- 完整的 `operations/`、`capabilities/`、`policies/`、`evals/`、`evidence/` 和测试 fixtures 候选。

## 停止条件

- 计划内定义和 Eval 齐备后进入 Validate。
- 一旦发现需要修改原系统、访问生产、使用写接口或伪造 Evidence，立即停止；不得用临时代码绕过门禁。
