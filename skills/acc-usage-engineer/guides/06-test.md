# 06 Test — B7/B8

## B7 Headless

先执行确定性合同校验和 Headless Agent Eval，覆盖正常、空结果、缺输入、关联缺失、401/403/404、超时、stale、候选工具选择、禁止行为，以及 Action prepare/approve/commit/status、并发冲突和 outcome_unknown。Trace 只记录公开指针、结果类别和摘要，不记录 secret 或 payload。

## B8 宿主与 real MCP

Headless 通过后，才测试可选目标宿主适配器；适配器 A 通过不能升级适配器 B。real MCP 测试必须连接固定 digest，且只有显式 real-test 环境授权才执行。真实 mutation 默认禁止；授权必须限定环境、账号范围、具体操作和回滚/状态核验。

按独立轴记录 `source_usage_traced`、`usage_contract_verified`、`headless_agent_verified`、`host_adapter_verified`、`real_mcp_verified`、`user_accepted`。不生成总分，不推导 `usable=true`，任一轴都不蕴含另一轴。
