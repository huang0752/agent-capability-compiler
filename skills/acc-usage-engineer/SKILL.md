---
name: acc-usage-engineer
description: 从已接受的 MCP Release 为一个业务领域安全采集平台中立的 Agent Usage Evidence。
---

# ACC Usage Engineer

本 Skill 建立独立的 Agent Usage 管道。核心产物是平台中立的结构化合同，不是任何宿主专用格式。

## 不变量

- 必须显式提供 `source_workspace`、`acc_project`、`usage_project`，三者必须互不重叠。
- 先读取 `usage_project/mcp-release-acceptance.yaml` 完成 accepted MCP digest 校验，再扫描源码。
- 一次只处理一个选定领域，以及清单明确列出的直接依赖；不重扫整个系统。
- 证据只可写入 `usage-evidence/frontend`、`usage-evidence/backend`、`usage-evidence/tests`。
- `source_workspace` 和 `acc_project` 始终只读，要求源工程零写入。
- 捕获物只保存定位、摘要和行号元数据，不复制源码、凭据或业务数据。

## 工作流

1. 执行 [01-preflight.md](guides/01-preflight.md) 的三根目录与 Release 门禁。
2. 执行 [02-scan-domain.md](guides/02-scan-domain.md) 的领域边界扫描与分类捕获。
3. 任一摘要、领域、路径、安全或只读检查不闭合时立即停止，不降级放行。

完整输入、命令合同与停止规则见 [HARNESS.md](HARNESS.md)。
