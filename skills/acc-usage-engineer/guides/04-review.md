# 04 Review — B5

## 集中问题

先自动处理证据清晰项，只把仍会实质改变领域结果的问题合并成一次领域审阅：

1. `scope`：是否处理、延后或排除，以及要覆盖的 business_goal；
2. `conflict`：前后端证据冲突或多条同样合理的产品路径；
3. `high-risk`：高风险 Action 是否纳入；
4. `real-test`：哪些场景需要真实账号、数据、环境或 mutation 授权。

不得让用户判断 HTTP route、Schema、JWT、digest、幂等、并发或 Capability constructability。技术缺口保持 blocked，并附 Evidence gaps 或退回管道 A。

## 决策绑定

记录领域整体 disposition、目标、route、限制和 contract digest；用户确认只保存原文摘要并绑定 canonical decision digest，不把原始对话或敏感信息写入工程。用户接受不能授予权限，也不能把任何技术验证轴改为 true。
