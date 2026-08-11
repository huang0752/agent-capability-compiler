# 03 Model — B4

## 自动建模

AI 先按业务目标而非工具数量聚类。证据清晰且 client/service/test/mcp 一致的事实自动写入结构化合同，不逐 route 要求用户确认：

- `business_goal` 与完成定义；
- `tool_route` 的先后步骤、停止条件及 Capability 绑定；
- `input_binding` 的 public input、route input 与 prior-step output JSON Pointer；
- `default` 的来源、优先级和提交规则；
- `option_source` 的搜索、分页、空值和错误行为；
- `condition` 的 visible/enabled/required/reset/execute 语义；
- `related_data` 的生产者、消费者、基数和 stale 检查；
- `result_consumption` 的 return/display/navigate/download/store_reference；
- `error_branch` 的空结果、401/403/404、超时、重试与 outcome_unknown；
- `action_lifecycle` 的 prepare、按需 approve、commit、独立 status。

Read 路径至少建模 search→detail：search 返回公开对象标识，detail 只从此前公开结果绑定。Action 不得把 trusted context 转成 public input，不得绕过编译证明的生命周期。

## 证据权威

每项事实绑定 target、authority、source_layer 和 evidence refs。client 可证明交互组合但不能证明授权或后端 effect；service/contract/test/observation 各自只证明其边界。冲突不按“多数证据”静默解决。
