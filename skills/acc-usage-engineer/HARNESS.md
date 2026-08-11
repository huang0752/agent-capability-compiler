# ACC Usage Engineer Harness

## 输入根目录

调用方必须分别提供：

- `source_workspace`：被取证源码，只读；
- `acc_project`：已发布 Capability/MCP 工程，只读；
- `usage_project`：独立 Agent Usage 工程，是唯一写入根。

三者必须互不重叠，任一路径段不得是符号链接。开始任何扫描源码动作前，必须先验证
`usage_project/mcp-release-acceptance.yaml` 的 accepted MCP digest 与本次固定摘要相同，且
`domain_id` 已在 `accepted_domain_ids` 中。

## 领域边界

只加载一个选定领域及 `usage-scan-manifest.yaml` 中显式列出的直接依赖。直接依赖不能递归扩展；
未知领域、间接依赖和全工程兜底扫描均停止处理。

## 分类与输出

每个来源先分类，再捕获：

- 前端：`usage-evidence/frontend`；
- 后端：`usage-evidence/backend`；
- 测试：`usage-evidence/tests`。

捕获脚本只写摘要定位元数据并使用同目录临时文件原子替换。输出路径逃逸、符号链接、敏感文件名、
超限文件、读取期间变化或源工程零写入检查失败，均返回机器可读诊断且不产生捕获物。

## 平台边界

Usage Evidence 和后续结构化合同保持平台中立。宿主适配器只能消费核心产物，不能反向成为事实源。
