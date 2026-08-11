# 01 Preflight

## 输入

- `source_workspace`
- `acc_project`
- `usage_project`
- `accepted_mcp_digest`
- `domain_id`

## 动作

1. 验证三个真实目录无符号链接，且三者必须互不重叠。
2. 读取固定路径 `mcp-release-acceptance.yaml`，拒绝超限、敏感字段或非普通文件。
3. 在任何扫描源码动作之前比较 accepted MCP digest，并确认领域已被接受。

## 门禁

摘要必须精确相等；一次只能激活一个选定领域，且只能附带直接依赖。

## 输出

通过的根目录、固定 Release 摘要和领域边界。

## 停止条件

根目录重叠、路径不安全、接受记录无效、摘要漂移或领域未接受。
