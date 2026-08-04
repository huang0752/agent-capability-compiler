# ADR 005: Capability Pack as the deployment artifact

## Status

Accepted.

## Context

Generic Runtime 需要一个可移交、可校验且不包含客户 Runtime 源码的部署输入。直接加载工程目录中的松散 YAML 会让文件集合、版本和摘要含糊，也难以防止运行时读取未审核内容或在不同机器上构建出不同结果。

## Decision

ACC 将编译结果发布为扩展名为 `.accpkg` 的 Capability Pack。Pack 是 ZIP 或等价的确定性归档，并且只包含：

```text
manifest.json
project.yaml
operations/
capabilities/
policies/
evals/
evidence/
pack.lock
```

构建必须使用稳定文件排序和归一化时间戳，并为内容生成稳定摘要，使相同输入产生完全相同的 Pack。构建器和 Runtime 都拒绝符号链接、路径穿越、绝对路径、重复或未知文件以及与 `pack.lock` 不一致的内容。Runtime 将 Pack 视为不可变输入。

## Consequences

- Pack 成为编译期与运行时之间唯一、可复现的部署契约。
- 发布、缓存、比较和回滚可以基于版本及内容摘要完成。
- 每次定义或 Evidence 变化都需要重新编译、测试并打包。
- Pack 格式及兼容性规则需要版本化；确定性归档会限制可携带的元数据。

## Rejected alternatives

- **Runtime 直接加载工程目录**：无法严格界定已审核文件集合，结果也容易受环境影响。
- **为每个项目发布生成的 Runtime 源码**：违反通用 Runtime 决策并复制安全逻辑。
- **允许 Pack 携带任意额外文件或符号链接**：增加路径逃逸和隐式运行依赖风险。
- **由 Runtime 在加载时补全或修改 Pack**：破坏摘要、审计和可重复性。
