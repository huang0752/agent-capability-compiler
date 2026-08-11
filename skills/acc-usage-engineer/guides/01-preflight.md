# 01 Preflight — B0

## 输入与动作

读取 `source_workspace`、`acc_project`、`usage_project`、`accepted_mcp_digest` 和目标 `domain_id`。验证三个真实目录无符号链接且三者必须互不重叠。源工程与 ACC 工程只读。

在任何扫描源码动作前，安全读取固定的 `mcp-release-acceptance.yaml`，逐一核对 Pack、compiled IR、Tool Schema、测试报告和 accepted MCP digest；确认领域属于 accepted domains，并记录 source revision。

## 门禁与输出

B0 只输出固定 Release 身份、三根目录审计和领域候选。摘要漂移、接受记录无效、领域未接受或无法证明只读时立即停止；用户口头确认不能替代摘要证据。

B1 在依赖就绪领域中推荐下一个大类别，但不自动进入；B2 由用户选择处理、延后或不需要。
