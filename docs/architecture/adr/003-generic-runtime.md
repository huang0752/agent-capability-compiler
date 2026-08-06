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

HTTP Gateway 是这套 Generic Runtime 的可选传输与身份适配层，不改变 ACC 作为 compiler/runtime 工具链的边界。它不持有用户目录、角色模型或持久化控制面数据；原系统仍是账号、租户和数据可见性的权威来源。

认证合同固定为互斥联合类型：

- `none` 没有 credential source；
- `bearer_secret` 通过部署环境中的 `token_ref` 注入已有 Bearer Secret；
- `password_bearer` 通过受限登录请求获取 JWT。`stdio` 使用 environment secret 引用，`streamable_http` 只接受 `gateway_session` 的一次性用户材料。

认证属于 Provider，而不是 Operation。Operation 级 `credential_ref` 只保留为旧 `stdio` Pack 的迁移兼容入口；新项目不能使用它。Operation 和 MCP tool 都不能读取密码、JWT、Cookie 或 Authorization Header。

Gateway 的用户会话流程为：

1. 用户 A/B/C 分别向受限会话端点一次性提交自己的账号和密码。
2. `password_bearer` 调用原系统登录接口，将源 JWT 与对应用户的认证状态保留在当前进程内，密码随后丢弃。
3. Gateway 向客户端返回另一枚短期 opaque token；会话 Store 只按该 token 的 SHA-256 摘要索引，不保存原值。
4. 客户端用 Gateway token 访问 `/mcp` 并创建自己的 MCP Session，SDK 会进一步绑定该 MCP Session 的 owner。
5. Runtime 每次执行仍使用当前用户的源 JWT 调用原系统。Gateway 不会把账号、密码、JWT 或用户标识改成 MCP tool 参数。

每次执行都必须绑定不可变 `PrincipalContext`。它包含 principal、目标系统、源权限、部署 Scope ceiling、有效 Scope 和受限租户上下文；认证状态只以不透明 handle 关联。Policy 只读取 `effective_scopes`。Operation 的 `context_bindings` 只能从受信 principal/tenant 路径注入已声明的 path/query 输入，且 Agent 参数和 Workflow 都不能覆盖。

传输边界不同：

- `stdio` 在进程启动时创建固定 principal；源权限 unavailable 时，有效 Scope 只取部署 ceiling。
- `streamable_http` 由 Gateway 对每个已认证请求重新解析会话并创建 `PrincipalContext`，按 principal、目标系统、Gateway Session 和 MCP Session 隔离状态。A 的 token 不能恢复 B 的 MCP Session。

权限计算采用双重上限。登录响应中可验证的源 Scope 先按 Pack 声明的 mapping 转换，再与部署 Scope ceiling 取交集；原系统还会在真正的 API 请求上重新判定账号、角色、租户和数据空间。因此 ceiling 只能收紧源权限，不是可以公开或扩权的查询 key。源系统返回 401 时，对应 Gateway Session 进入 `reauth_required`，其他用户会话继续有效。

Gateway v1 是单进程、`workers=1` 的进程内会话实现。所有请求先经过精确 Host/Origin allowlist 和请求体大小限制；明文监听只允许 loopback，非 loopback 需 TLS。部署必须配置 Gateway Session TTL、最大会话数和不高于 TTL 的 MCP idle timeout。

`DELETE /runtime/sessions/current` 会立即撤销 Gateway token，之后的 MCP 请求不再认证。但 MCP SDK 1.29 没有按单个 Gateway Session 立即 terminate 底层 Streamable HTTP 传输的公开 manager API；已建立 SSE/传输实例由有限 idle timeout 在上限内回收。这个限制不延长 token 的授权寿命。

验证等级也是合同的一部分：Fake Runtime/Fake E2E 只能记录为 `offline_candidate`；只有明确授权且成功连接本地或测试源的运行才能记录为 `source_connected_verified`。任何本地结果都不能被表述为生产验证或未连接系统的验证。

## Consequences

- Runtime 安全修复和协议改进只需实现、验证和发布一次。
- Capability Pack 必须是完整、版本化且可校验的运行输入，不能依赖客户生成代码。
- Runtime 与 Pack 的兼容性需要清晰的 Schema 和版本契约。
- 多用户不是把账号放进工具参数，而是由 Gateway 把已认证会话映射为请求级 `PrincipalContext`。
- 部署 Scope ceiling 不能扩大源系统返回的权限；源权限可得时只取两者交集。
- Gateway 重启后所有进程内 Gateway/MCP Session 失效；需要水平扩展或持久会话时，必须另行设计共享状态与安全边界。
- 第一版牺牲客户级任意扩展，以换取一致的执行语义和更小的攻击面。

## Rejected alternatives

- **每个接入项目生成独立 Runtime**：复制安全逻辑并造成版本漂移。
- **在 Runtime 内加载任意客户插件或代码**：扩大执行面，削弱确定性校验。
- **为每种业务系统实现专用 Runtime**：把系统差异错误地固化进执行引擎。
- **把 Gateway 扩展为用户/租户控制面**：重复原系统的身份与权限职责，也会把 ACC 从通用 compiler/runtime 扩成另一个业务平台。
