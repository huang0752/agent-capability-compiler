# 07 Impact — Drift

Pack、IR、Tool Schema、SourceSnapshot 或单份 Evidence digest 改变时先停止当前领域发布，运行只读 `acc usage impact`。沿 Domain→Scenario→Capability→Tool Schema→Evidence 精确分类：`unaffected`、`revalidate`、`regenerate`、`blocked`。

只让受影响领域 stale，不能因顶层 Pack 变化把所有领域失效。绑定或描述变化需要 regenerate；Capability/Evidence/安全合同删除需要 blocked。

若根因是 MCP 缺工具、Schema、Runtime 或受信 Action lifecycle，生成管道 A MCP Change Request；若根因是工具选择、组合、结果消费或适配器投影，留在管道 B。Change Request 只引用领域、场景、Capability、Evidence 和旧新 digest，不携带敏感 payload。
