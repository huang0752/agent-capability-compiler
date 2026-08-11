---
name: acc-usage-engineer
description: 从已接受的 MCP Release 按领域重建、验证并发布平台中立的 Agent Usage Package。
---

# ACC Usage Engineer

本 Skill 是独立于 Capability/MCP 编译的第二条管道。只有用户已测试、反馈并接受固定 MCP Release 后才建议启动；不要求每个项目都生成 Usage Package。

## 不变量

- 显式提供 `source_workspace`、`acc_project`、`usage_project`，三者必须互不重叠；前两者只读，唯一写入根是 Usage 工程。
- 先校验 `mcp-release-acceptance.yaml` 的 accepted MCP digest，再执行任何扫描源码动作。
- 一次只处理一个选定领域和清单内直接依赖；完成、接受或明确延后后，才进入下个领域。
- 二次确认 client、service、test，并用 accepted MCP 与必要的 runtime observation 对照；未知事实保持 unknown。
- 证据层固定为 `usage-evidence/client`、`usage-evidence/service`、`usage-evidence/test`、`usage-evidence/mcp`、`usage-evidence/runtime_observation`。
- client surface 固定为 `web`、`mobile`、`desktop`、`cli`、`automation`、`other`。
- 产物是平台中立结构化合同；Markdown、Resource、Prompt 或宿主适配器都是可选投影，不是事实源。
- 不保存 secret、业务 payload、JWT、Cookie 或 Authorization；源工程零写入。
- Usage 合同不能授予权限；source JWT 和 source API 始终执行最终授权。

## B0–B9

1. **B0**：按 [01-preflight.md](guides/01-preflight.md) 固定 accepted MCP，检查三根目录与漂移。
2. **B1–B3**：按 [02-scan-domain.md](guides/02-scan-domain.md) 推荐、选择并只读扫描单领域。
3. **B4**：按 [03-model.md](guides/03-model.md) 自动建模证据清晰的业务使用事实。
4. **B5**：按 [04-review.md](guides/04-review.md) 只集中询问 scope/conflict/high-risk/real-test 边界。
5. **B6**：按 [05-build.md](guides/05-build.md) 构建平台中立 Usage Package。
6. **B7–B8**：按 [06-test.md](guides/06-test.md) 先 Headless，再按授权测试宿主或 real MCP。
7. 漂移时按 [07-impact.md](guides/07-impact.md) 局部失效并生成 Change Request。
8. **B9**：按 [08-release.md](guides/08-release.md) 取得领域用户接受并发布。
9. 按 [09-handoff.md](guides/09-handoff.md) 交付核心产物和可选适配器，在 Git 审阅前停止。

完整命令合同、停止规则和验证轴见 [HARNESS.md](HARNESS.md)。
