# 08 Release — B9

## 单领域发布

发布前要求 accepted MCP 完整匹配、无未处理 drift、必需 scenario/输入/Capability/Action lifecycle 闭合、Secret 扫描通过、Usage Contract 与 Headless 通过，并取得绑定 exact decision digest 的用户接受。

宿主或 real MCP 未测时可以发布 `limited`，但必须如实保留 `host_adapter_verified=false` 或 `real_mcp_verified=false` 及 known limitations。六轴保持独立，不得用用户接受升级技术事实。

source JWT 与 source API 继续对每次请求最终授权；前端 hidden/disabled、Action approval 或 Usage Release 都不能授予权限。401/403 不扩大 Scope、不换高权账号、不隐藏错误。

本领域接受、延后或排除后，才回到 B1 推荐下一个依赖就绪领域。
