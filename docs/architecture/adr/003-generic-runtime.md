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

Runtime 负责 Pack 加载与完整性检查、MCP 传输、工具枚举与调用、REST Provider、Provider 级认证、输入输出 Schema 校验、Scope、脱敏、超时、响应大小限制和结构化错误。第一版只执行只读 HTTP `GET`/`HEAD` Operation；特殊系统通过独立部署且遵守固定契约的 Adapter 接入，而不是复制 Runtime。

认证合同固定为互斥联合类型：

- `none` 没有 credential source；
- `bearer_secret` 通过部署环境中的 `token_ref` 注入已有 Bearer Secret；
- `password_bearer` 通过受限登录请求获取 JWT。`stdio` 使用 environment secret 引用，`streamable_http` 只接受 `gateway_session` 的一次性用户材料。

认证属于 Provider，而不是 Operation。Operation 级 `credential_ref` 只保留为旧 `stdio` Pack 的迁移兼容入口；新项目不能使用它。Operation 和 MCP tool 都不能读取密码、JWT、Cookie 或 Authorization Header。

每次执行都必须绑定不可变 `PrincipalContext`。它包含 principal、目标系统、源权限、部署 Scope ceiling、有效 Scope 和受限租户上下文；认证状态只以不透明 handle 关联。Policy 只读取 `effective_scopes`。Operation 的 `context_bindings` 只能从受信 principal/tenant 路径注入已声明的 path/query 输入，且 Agent 参数和 Workflow 都不能覆盖。

传输边界不同：

- `stdio` 在进程启动时创建固定 principal；源权限 unavailable 时，有效 Scope 只取部署 ceiling。
- `streamable_http` 需要 Gateway 为每个已认证请求创建 `PrincipalContext`，并按 principal、目标系统和 session 隔离认证状态。Core 已约束配置组合，但在 Gateway 交付前 `acc run` 不提供该 HTTP 服务。

验证等级也是合同的一部分：Fake Runtime/Fake E2E 只能记录为 `offline_candidate`；只有明确授权且成功连接本地或测试源的运行才能记录为 `source_connected_verified`。任何本地结果都不能被表述为生产验证或未连接系统的验证。

## Consequences

- Runtime 安全修复和协议改进只需实现、验证和发布一次。
- Capability Pack 必须是完整、版本化且可校验的运行输入，不能依赖客户生成代码。
- Runtime 与 Pack 的兼容性需要清晰的 Schema 和版本契约。
- 多用户不是把账号放进工具参数，而是由 Gateway 把已认证会话映射为请求级 `PrincipalContext`。
- 部署 Scope ceiling 不能扩大源系统返回的权限；源权限可得时只取两者交集。
- 第一版牺牲客户级任意扩展，以换取一致的执行语义和更小的攻击面。

## Rejected alternatives

- **每个接入项目生成独立 Runtime**：复制安全逻辑并造成版本漂移。
- **在 Runtime 内加载任意客户插件或代码**：扩大执行面，削弱确定性校验。
- **为每种业务系统实现专用 Runtime**：把系统差异错误地固化进执行引擎。
