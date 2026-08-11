# 09 Handoff

交付每个已接受领域的 `.accusage`、结构化合同、Scenario、独立六轴报告、known limitations、影响基线和使用说明。顶层索引只包含已发布领域；测试中、阻断或延后领域不得进入可用路由。

可选交付平台中立 Markdown、MCP Resources/Prompts，以及用户选择的宿主适配器；明确标注其 adapter id 与单独验证状态。核心合同在没有任何适配器时仍可消费。

再次确认：source/ACC 零写入，无 secret/payload，current MCP digest 匹配，真实 mutation 未越权，source JWT 最终授权。输出后在 Git stage、commit、push、PR 和外部发布前停止，等待用户审阅。
