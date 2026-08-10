# ACC 通用质量合同与 Action Capability 设计

## 目标

把 ACC 从“可证据化的只读 MCP 编译器”演进为“可证据化、可部署约束、可验证的业务能力编译器”，同时保留只读默认、安全失败、确定性编译和零侵入源系统边界。

本设计不以 `baogao-jin` 为产品边界。CRM、ERP、Warehouse、IAM、CMS、LLM、监控和 `baogao-jin` 都只是跨系统验收夹具或真实采用案例；ACC Core、Runtime、CLI、Testkit 与 Skill 中不得出现任何单一系统的路由、权限名、工具数量或业务阈值。

## 产品边界

ACC 继续由以下部分组成：

1. Agent Skill/plugin：以只读方式分析已有系统并建立 Evidence。
2. `acc` CLI 与 Python SDK：校验、编译、测试和交付 Capability Pack。
3. Capability IR：Operation、Capability、Policy、Eval、Source Contract 与质量元数据的唯一事实源。
4. Generic Runtime：执行经过编译的确定性工作流，提供 stdio 与可选 Streamable HTTP Gateway。
5. Testkit：提供离线、Gateway 协议和授权测试源连接验证。

ACC 不是用户、租户、审批、密钥或集中审计控制平台。人工批准 UI、企业 Vault 和集中审计存储属于宿主或外部 Provider；ACC 只定义、校验并消费稳定合同。

## 核心原则

1. **读取默认开启，写入默认关闭。** 旧 Pack 和未显式授权的部署继续只能执行 `read`。
2. **证据先于约束。** Operation Schema 的每个收紧约束必须有可定位的 Source Contract claim；观测样本不能证明业务上界。
3. **业务效果先于 HTTP 方法。** `POST` 可以是查询，`GET` 可以是动作前检查；风险由 Evidence 证明的 effect 决定。
4. **权限不能由 Pack 自动授予。** 有效授权是源权限、Scope mapping、部署 ceiling、允许 effect、Capability allowlist 与当前批准的交集。
5. **组合服从数据流。** 多 Operation Capability 只有共享业务锚点、显式数据依赖或一致事务语义时才成立。
6. **未知是合法结果。** Schema 包含关系或输出上界无法证明时必须报告 `unknown`，不得编造 `maxItems` 或 `maxLength`。
7. **验证标签表达实际路径。** Fake Runtime、真实 Gateway 协议和真实测试源连接必须使用不同验证等级。

## 总体架构

```text
Source adapters / static discovery
        |
        v
SourceContract + EvidenceClaim
        |
        v
Operation IR ---- schema fidelity ----> diagnostics
        |
        v
Capability Planner / CapabilityQuality
        |
        v
Capability IR + Policy + Eval
        |
        v
Compiler -> Pack -> Runtime / Gateway -> MCP
        |                         |
        v                         v
Coverage v2               Runtime observations
        \_________________________/
                 |
                 v
          Test report / HANDOFF
```

## 1. MCP Schema 投影

Runtime 必须通过单一 `SchemaProjection` 把 Capability output schema 投影为 MCP `structuredContent.result` schema。原 schema 作为完整 JSON Schema resource 嵌入；缺少 `$id` 时注入由 Capability id 与 schema digest 派生的绝对、确定性 `$id`。已有合法 `$id` 保留。

投影必须保持 `$defs`、根相对 JSON Pointer、递归 `$ref`、`$dynamicRef`、组合关键字和嵌套资源语义。无法由 Pack 自包含解析的外部相对引用在编译期拒绝。stdio 与 Streamable HTTP 使用相同投影函数，并由官方 MCP SDK 验证 tools/list 和 tools/call。

## 2. 传输感知测试

验证等级定义为：

- `contract_verified`：静态模型、编译和合同测试通过。
- `offline_candidate`：Fake Provider 与直接 Generic Runtime 通过。
- `gateway_offline_verified`：真实 Gateway、官方 MCP SDK 与 Fake Source 通过。
- `source_connected_verified`：真实 Gateway 与经用户授权的本地或隔离测试源通过。

`acc test e2e` 必须报告实际 transport，不得把直接调用 Generic Runtime 描述为 Gateway E2E。新增 `acc test live`，使用无秘密的声明式 profile；凭据只从安全提示或 SecretRef 取得。真实源未配置的错误场景标记 `skipped/not_provisioned`，不能算通过。

## 3. Scope 可调用性

Core 为每个 Capability 派生路径感知的 Scope requirements。顺序和并行路径取并集；branch 保留最小备选集合；条件和 foreach 保守表达。Runtime/CLI 将其与 deployment ceiling 比较，输出 pre-login 调用性矩阵。用户源权限在登录前保持 `unknown`。

空 ceiling 继续 default-deny，但 CLI 必须在启动监听前输出高可见度 warning。`--strict-scope` 可使确定不可调用的部署拒绝启动。显式 `--scope-ceiling-from-pack` 只设置部署 ceiling，不代表 Pack 自动获得授权；长期由命名 deployment profile 代替手写 scope 列表。

## 4. Source Contract 与 Schema fidelity

Source Contract 归一化不同框架的请求、响应、资源、权限、分页和 Evidence claim。Provenance 通过独立 claim ledger 关联 JSON Schema Pointer，不能把私有元数据写进标准 JSON Schema。

权威级别为 `contract | implementation | test | observation`。Operation 输入必须是源系统接受输入的安全子集；Operation 输出必须覆盖源系统可能返回的结果。Capability 输出只有经过可证明的 pick/map/redact/dataflow 后才能收紧。

第一阶段包含分析支持 type、required、enum、const、数值边界、字符串/数组边界、additionalProperties、items、`$defs/$ref` 和常见组合。无法证明时发出 unknown warning；证据明确冲突时 error。

## 5. Capability Quality 与 Coverage v2

Capability 增加 intent、输入 selector 获取方式、组合理由、失败模式和输出预算。Planner 先构建资源发现与数据流图，再完成路由处置；不能以最少工具数为首要目标。

有效组合包括：无 ID 的 list/search、单 ID detail、单 anchor related aggregate、单 job monitor、显式 compare。独立根调用、多必填且不可发现的 selector、list 与强制 detail 耦合、未使用的 Operation 结果和无低摩擦入口必须诊断。

Coverage v2 独立报告 route closure、operation trace、scenario coverage、constructability、discoverability、schema fidelity、composition quality、output budget 和 live observations，不生成可刷分的单一总分。

## 6. 输出预算

Capability 可声明 `output_budget.max_bytes` 与长文本披露策略。静态分析只输出 `proven_bounded | unknown | exceeds_budget`。缺少真实上界时保持 unknown，不得为了预算分析修改源数据 Schema。

Runtime 在 Policy 过滤和 Capability Schema 校验后按紧凑 UTF-8 JSON 计数；超过限制返回 `ACC_RUNTIME_CAPABILITY_OUTPUT_TOO_LARGE`，不静默截断，审计只记录字节数。Live 报告记录 observed p50/p95/max，但观测不回写为 Schema 上界。

## 7. Action Capability

### Effect 与风险

v1 `Operation` 与 `Capability` 保持原样，只允许 `GET/HEAD/read`。v2 使用显式分型的 `ReadOperationV2 | ActionOperationV2` 与 `ReadCapabilityV2 | ActionCapabilityV2`，避免让旧文档通过一组可选字段意外获得新语义。Action Operation 的安全合同为：

```yaml
safety:
  effect: read | create | update | delete | transition | execute
  risk: low | medium | high | irreversible
  approval: none | runtime | human
  idempotency: none | optional | required
  retry: never | idempotent_only
```

v2 写 Operation 必须显式填写完整安全合同，不允许依靠默认值降级风险。v1 Pack 在新 Runtime 中仍按原只读合同执行；旧 Runtime 在 manifest 阶段明确拒绝 v2 Pack。

### 部署授权

Pack 声明其使用的 effects，但默认只启用 `read`。Runtime 还需要不可由 Agent 修改的 `allowed_effects` 和 Capability allowlist。最终授权为：

```text
mapped source scopes
∩ deployment scope ceiling
∩ allowed effects
∩ capability allowlist
∩ approval grant
```

### Preview 与 Commit

Action Capability 采用 `prepare → approve → commit → status` 合同。`preview_workflow` 只能引用 read Operation；`commit_workflow` 才允许 Action Operation。初版每个 Action Capability 最多执行一个变更 Operation，并禁止在 parallel/foreach 中隐含批量写；未来多写步骤只通过有明确事务或补偿合同的 `source_transaction/saga` 扩展。高风险、不可逆或需要人工批准的动作在 prepare 阶段读取最新资源、规范化参数并生成变更摘要；commit 绑定一次性 approval grant、preview digest、目标资源版本和幂等键。批准绑定 principal、Gateway session、Capability、effect、目标、参数摘要和期限，不能跨会话、跨参数或重复使用。

MCP 工具不能接受 JWT、密码、Principal、Scope 或任意批准内容，只接受不透明 approval handle。批准签发由可信 Runtime/宿主入口完成，不由模型自行制造。

### 幂等、并发和重试

- create/execute 没有源系统幂等机制时禁止自动重试。
- update/delete/transition 优先要求 ETag、版本号或等价乐观锁。
- `idempotency=required` 时 Provider 必须按 Evidence 映射固定 Header 或请求字段。
- 只有明确标记且携带稳定幂等键的 Action 才能在传输失败后重试。
- 源系统 401 的重新认证与业务 Action 重放分开处理；无法证明请求未到达源系统时不得自动重放。

### 审计与错误

Action 审计只记录 Pack/Capability/Operation digest、匿名 principal/session reference、effect、目标摘要、approval digest、idempotency digest、状态和时间，不记录 Secret 或完整业务 payload。错误必须区分未授权 effect、缺少/失效批准、并发冲突、幂等冲突、结果未知和上游拒绝。

### 验证

Action 验证等级为 `action_contract_verified | action_offline_verified | action_sandbox_verified | action_source_connected_verified`。真实 Action 测试只允许隔离沙箱，并验证操作前状态、调用、操作后状态、审计、重复提交、并发冲突、越权、跨租户和回滚/补偿说明。生产写操作不进入自动测试默认范围。

## 8. 兼容迁移

1. MCP Schema 修复作为 Runtime patch，不改变 Capability 的公开输出结构。
2. 新 IR 元数据先 optional；旧 Pack 由 Runtime 派生兼容值。
3. Coverage v1 保留一个兼容周期；Coverage v2 同时输出，不复用旧单分数。
4. 新诊断在 `legacy_audit` profile 下先 warning；新生成项目采用更严格 profile。
5. Action 支持必须由新 Pack schema version 或显式 feature declaration 开启；旧 Pack 永远不会因升级 Runtime 获得写权限。
6. 任何部署升级后 `allowed_effects` 缺省仍为 `{read}`。

## 9. 跨系统验收

- CRM：list/search 到 detail 的 selector 可发现性。
- ERP：围绕同一 order id 的合法聚合与乐观锁更新。
- Warehouse：分页、大集合和幂等库存调整。
- Monitor：单 job id 查询与显式 cancel transition。
- Finance：独立资源列表必须拆分，付款类动作默认不可重试。
- CMS/LLM：长文本预算和发布 preview/commit。
- IAM：超过 100 项权限集合和高风险角色变更。
- Schema stress：递归 `$defs`、组合、嵌套 `$id` 和外部引用拒绝。
- Gateway：A/B/C 会话、跨会话批准拒绝和 logout。
- Source drift：契约、实现、测试和观测之间的冲突。

## 10. 发布门禁

发布必须证明：

1. Core/Runtime 中无业务系统专名与专用分支。
2. 官方 MCP SDK 在两个 transport 上验证复杂 Schema。
3. Gateway E2E 真实经过登录、session、MCP initialize/list/call/logout。
4. Scope 矩阵不静默扩大权限。
5. 无证据 Schema 上界被诊断。
6. 不可构造 mega Capability 被诊断，合法 aggregate 不误报。
7. Action 默认关闭；无批准、错误 effect、重复和并发调用 fail closed。
8. Secret 不进入工具 Schema、Pack、日志、异常和报告。
9. 旧 Pack 兼容矩阵与可重复构建门禁通过。
