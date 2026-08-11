# 02 Scan Domain — B3

## 范围

只读扫描一个选定领域和清单中非递归的直接依赖。必须从源码二次确认，不可只看接口：

- `client`：web/mobile/desktop/cli/automation/other 的页面、路由、状态、API client、默认值、显示/启用/重置条件、选项加载、关联导航与结果消费；
- `service`：后端路由、Schema、Service、默认语义、错误、授权与 Action 生命周期；
- `test`：组件、契约、Service 与端到端测试；
- `mcp`：accepted MCP Capability、Tool Schema、Eval 和报告；
- `runtime_observation`：必要且已脱敏的运行观测定位。

每份捕获写入同名 `usage-evidence/<source_layer>`，client 必须声明 `client_surface`。脚本输出只包含 Evidence core 与 `source_layer/domain_id/size_bytes/client_surface` audit allowlist；旧 frontend/backend/tests `classification` 输入必须拒绝。

## 安全与停止

拒绝遍历、绝对输出、符号链接、Secret-like 路径、超限文件、payload、文件变化和分类目录逃逸。扫描前后比较源工作树，维持源工程零写入。证据冲突不猜测，标记 conflict；证据缺失标记 unknown。
