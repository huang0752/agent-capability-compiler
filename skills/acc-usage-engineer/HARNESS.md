# ACC Usage Engineer Harness

## 调用合同

调用方提供只读 `source_workspace`、只读 `acc_project` 和独立可写 `usage_project`。三者必须互不重叠且无符号链接。任何扫描源码动作前，B0 必须验证 `usage_project/mcp-release-acceptance.yaml`、`.accpkg`、compiled IR、Tool Schema 和测试报告摘要均匹配 accepted MCP digest。

只加载一个选定领域和 `usage-scan-manifest.yaml` 明列的直接依赖；不能递归扩展、兜底扫描全工程或把技术路由分类工作推给用户。

## 证据合同

`usage_evidence_capture.py` 只生成 `Evidence` core 字段和 loader audit allowlist：`source_layer`、`domain_id`、`size_bytes`、可选 `client_surface`。固定目录如下：

- `usage-evidence/client`：web、mobile、desktop、cli、automation 或 other 客户端交互；
- `usage-evidence/service`：路由、Schema、Service 和授权/生命周期实现；
- `usage-evidence/test`：组件、契约、服务和端到端测试；
- `usage-evidence/mcp`：accepted MCP Capability、Tool Schema 和报告；
- `usage-evidence/runtime_observation`：经脱敏的真实观测定位，不含请求或响应 payload。

捕获只保存摘要、定位、摘要哈希、大小和可选行号。拒绝旧 `classification`、路径逃逸、符号链接、敏感文件名、超限文件和读取期间变化，且持续核验源工程零写入。

## 建模与提问

AI 自动处理证据清晰且一致的 `business_goal`、`tool_route`、`input_binding`、`default`、`option_source`、`condition`、`related_data`、`result_consumption`、`error_branch` 和 `action_lifecycle`。仅将以下问题按领域集中成一组交给用户：

- `scope`：处理、延后、排除，以及业务目标范围；
- `conflict`：前后端冲突或两条同样合理的产品流程；
- `high-risk`：高风险 Action 是否进入指南；
- `real-test`：真实账号、数据、环境和 mutation 的明确授权边界。

技术证据不闭合不得用用户确认替代，应 blocked 或退回管道 A。

## 验证与权限

验证保持六个独立轴，**不生成总分**、不生成 `usable=true`，也不互相升级：

- `source_usage_traced`
- `usage_contract_verified`
- `headless_agent_verified`
- `host_adapter_verified`
- `real_mcp_verified`
- `user_accepted`

用户接受不能授予权限。source JWT 与 source API 对每次真实请求进行最终鉴权；401/403 保留源系统裁决，不扩大 Scope、不换高权账号。真实 mutation 默认禁止。

## 受信验证 Artifact 桥

`acc usage release` 和 `acc usage build` 不能信任 Usage 工程里手写或反序列化的 verification 布尔值。Headless caller 与 real MCP client 必须由显式受信 runner/profile 注入；该 runner 用独立 HMAC 密钥生成 canonical JSON verification artifact。artifact 只包含 `key_id`，并绑定当前 Usage project、accepted MCP、Pack、IR、Tool Schema、测试报告、Domain、合同、决策、Scenario 分母和 release bundle。

密钥只允许存在于 runner 与验证端的同一管理信任域。trust-store 必须通过独立路径提供，且不得位于 source workspace、ACC project 或 Usage project 内，不得经过 symlink/junction；包签名密钥只允许通过 SecretRef 环境变量名称传入，不能作为 CLI 明文或工程文件。artifact 必须含 nonce、`observed_at`、`expires_at`，有效期大于 0 且不超过 24 小时。非 canonical、篡改、过期、stale、digest mismatch、错误 Pack 或链接路径一律 fail-closed。

正式命令需要显式给出 `--verification-artifact`、`--verification-trust-store`、`--accepted-pack`、`--accepted-tools` 和 `--accepted-test-report`。`usage build` 另加 `--package-signing-secret-env <ENV_NAME>`；未提供受信证据时保持 `ACC_USAGE_*_EVIDENCE_NOT_PROVISIONED`，不得降级为读取 release 自我声明。

## 停止与反馈分流

- MCP 缺工具、Schema/Runtime/Action lifecycle 错误：生成管道 A MCP Change Request；
- 工具选择、组合、结果消费或宿主投影错误：修正管道 B 合同或适配器；
- digest 或源码 Evidence 漂移：停止发布，做领域影响分析；
- accepted MCP、必需 Evidence、Headless 测试或用户接受不闭合：不得发布；
- 完成交付清单后，在任何 Git stage、commit、push 或 PR 前停止，交由用户审阅。
