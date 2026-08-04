# ADR 003: One generic runtime

## Status

Accepted.

## Context

ACC 需要为不同系统提供能力，但为每个客户生成一套完整 Runtime 源码会复制安全敏感逻辑。超时、凭据、Schema 校验、权限和错误处理的缺陷将散落在大量生成项目中，难以及时统一修复。

## Decision

ACC 提供一套固定的 Generic Runtime。客户差异仅通过编译后的 `.accpkg` Capability Pack 表达：

```text
Capability definitions -> ACC compile -> .accpkg -> Generic Runtime
```

Runtime 负责 Pack 加载与完整性检查、MCP stdio、工具枚举与调用、REST Provider、SecretRef、输入输出 Schema 校验、Scope、脱敏、超时、响应大小限制和结构化错误。第一版只执行只读 HTTP `GET`/`HEAD` Operation；特殊系统通过独立部署且遵守固定契约的 Adapter 接入，而不是复制 Runtime。

## Consequences

- Runtime 安全修复和协议改进只需实现、验证和发布一次。
- Capability Pack 必须是完整、版本化且可校验的运行输入，不能依赖客户生成代码。
- Runtime 与 Pack 的兼容性需要清晰的 Schema 和版本契约。
- 第一版牺牲客户级任意扩展，以换取一致的执行语义和更小的攻击面。

## Rejected alternatives

- **每个接入项目生成独立 Runtime**：复制安全逻辑并造成版本漂移。
- **在 Runtime 内加载任意客户插件或代码**：扩大执行面，削弱确定性校验。
- **为每种业务系统实现专用 Runtime**：把系统差异错误地固化进执行引擎。
