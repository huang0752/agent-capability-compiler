# `baogao-jin` 的 ACC 验证方案

## 目标

将 `/Users/chou/code/baogao-jin` 作为一个已有且不可修改的源系统，验证 ACC Engineer 面向真实多用户 FastAPI 应用的完整接入流程。最终形成一个独立的 ACC 工程：把一条有证据支撑的业务能力链编译为可重复构建的 Capability Pack，并通过通用 MCP stdio Runtime 对外提供能力。

本次工作验证的是 Agent Capability Compiler，不修改也不部署 `baogao-jin`。

验收分为两个等级：

- **离线完整验收**：基于 `baogao-jin` 的真实源码证据完成建模、编译、Fake REST、MCP Runtime、Eval 和确定性打包；三项计划 Capability 全部通过才算完成。
- **真实服务联调验收**：在离线完整验收基础上，使用已经可用的本地或隔离测试服务及多类测试身份完成真实请求验证。缺少测试服务或测试身份时，只能表述为“离线完整验收完成，真实服务联调未执行”，不能表述为真实系统联调通过。

## 工作区边界

- 源系统目录：`/Users/chou/code/baogao-jin`。
- ACC 工程目录：`/Users/chou/code/baogao-jin-acc`。
- 两个目录解析后的真实路径必须不同，且不能互相包含。
- `baogao-jin` 仅作为只读证据来源。不得在其中修改、格式化或生成文件，不得安装依赖、启动或重启服务、执行迁移或种子、运行测试、提交代码或部署。
- 分析前记录 `baogao-jin` 的 Git 提交和脏工作区状态；交付前再次检查，确认基线未被本流程改变。
- 如果执行期间源系统的提交、跟踪文件或未跟踪文件清单发生变化，停止交付并重新确认变化来源，再重新捕获受影响的 Evidence。
- Evidence、Operation、Capability、Policy、Eval、测试夹具、构建产物和交付文件只能写入独立 ACC 工程。
- 如果 ACC 工程目录已经存在且非空，不覆盖、不清理，先停止并请求人工确认。新工程在 `acc init` 后记录自身基线，`candidate.diff` 以该基线为比较起点。
- 本轮先把 ACC 当作被测产品使用，不在接入过程中顺手修改 `/Users/chou/code/agent-capability-compiler` 的编译器或 Runtime。发现产品缺陷时记录复现步骤和诊断，另行获得修复授权后再处理。
- 不访问生产服务、生产数据或生产凭据。

## 代表性业务链

第一轮验证后台登录用户的客户业务上下文，不采用外部公开查询接口。

候选原子操作仅限已有 `GET` 接口，而且必须同时具备源码、Schema、鉴权、租户边界和现有测试等证据：

1. 获取当前登录用户、租户成员身份、权限和菜单信息。
2. 搜索该用户有权查看的客户。
3. 获取一个可见客户的业务概览。
4. 在用户权限允许时，查询该客户的报告和证书记录。

如果某个候选接口的路径、返回结构、权限要求、租户或数据空间规则、错误行为缺少充分证据，Analyze 阶段必须缩减或阻断该候选能力，不能编造替代接口。

计划形成三项业务能力：

- `inspect_current_access`：说明当前测试身份对应的用户、租户和只读权限，不暴露 JWT 或内部 Secret。
- `search_visible_customers`：只返回当前用户有权查看的客户。
- `get_customer_document_context`：组合客户概览，以及当前用户有权查看的报告和证书摘要。

三项 Capability 是离线完整验收的最低交付范围。Analyze 阶段可以因为证据不足阻断其中任何一项，但阻断后本轮状态必须标记为“未完成”，只能交付分析结果和风险报告，不能用其余能力替代完整验收。

## 鉴权和多用户模型

用户身份认证、租户成员关系、自定义角色权限和数据空间访问控制仍由 `baogao-jin` 负责。

- MCP Runtime 不把用户名、密码、JWT、租户 ID、权限集合或 Base URL 暴露为工具参数。
- `baogao-jin` 的登录接口使用写方法，而 ACC MVP 的正式 Operation 仅支持 `GET` 和 `HEAD`，因此登录不进入 Capability Pack。
- 启动 Runtime 前，由用户或测试环境管理员通过现有登录流程为每个测试身份取得 JWT，再通过基于环境变量的 SecretRef 注入。账号和密码不交给 ACC，不写入 ACC 工程或交付报告。
- 第一版中，每个测试身份运行一个独立的 MCP stdio Runtime 进程，不在一个共享凭据进程中混用多个用户。
- Runtime 配置的 Scope 和租户上下文必须与被测身份一致。它们属于纵深防护，不能代替 `baogao-jin` 自身的权限判断。
- 不使用管理员 JWT 或一个拥有全部权限的共享 JWT 模拟普通用户。

测试身份至少覆盖：

1. 具有客户和文档所需读取权限的用户。
2. 至少缺少一项文档读取权限的用户。
3. 属于另一个租户的用户，用于验证租户隔离。
4. 如果当前测试环境启用了可验证的数据空间边界，再提供同租户不同数据空间的用户，单独验证数据空间隔离。

只能使用本地或隔离测试环境的凭据。如果无法安全提供合适的测试身份，则将真实服务 E2E 标记为阻断；仍可运行基于 Fake REST 的确定性测试，但不能把它表述为真实系统联调通过。

每次真实联调前检查 JWT 是否有效；测试期间过期时停止该身份的用例，由测试环境管理员重新提供环境变量，不在 MCP 内刷新或重新登录。JWT、Authorization 请求头及环境变量值不得出现在正常输出、错误输出、日志、Pack 或交付文件中。

## 证据与建模

严格按 ACC Engineer 状态机依次执行：

`PREFLIGHT -> ANALYZE -> MODEL -> PLAN -> IMPLEMENT -> VALIDATE -> TEST -> REFINE -> HANDOFF`

分析阶段需要交叉核对路由定义、响应 Schema、共享鉴权依赖、权限目录、租户和数据空间辅助逻辑、前端 API 调用方及现有静态测试。每个正式 Operation 的请求方法、路径、参数、输出字段、权限、租户边界、调用效果和预期错误，都必须绑定带稳定摘要的 Evidence。

事实、冲突和未知项必须分开记录。`baogao-jin` 当前工作区中已有的用户改动归用户所有；如果缺少路由、Schema、鉴权逻辑和测试源码等相互印证，不能把这些改动直接视为稳定发布行为。现有测试只作为静态证据阅读，本流程不运行源系统测试。

## Runtime 数据流

1. 宿主为一个测试身份启动通用 ACC MCP stdio Runtime。
2. Runtime 从环境变量引用中解析 `baogao-jin` 测试服务 Base URL 和该身份的 JWT。
3. Agent 调用业务 Capability，既不接触也不传入凭据。
4. Runtime 校验 Capability 输入，注入只存在于运行期的 Policy 上下文，只向固定测试服务 Origin 发出编译完成的 `GET` 请求。
5. `baogao-jin` 校验 JWT、租户成员关系、业务权限和数据空间访问权。
6. ACC 校验上游响应 Schema，映射错误，执行输出字段白名单和脱敏，最后返回大小受限的 MCP 结构化结果。

Runtime 不得动态构造新路由、切换 Origin、执行登录、使用其他身份重试，也不能在权限失败后扩大权限范围。

## 错误与披露规则

Capability Pack 及其测试至少要覆盖：

- JWT 缺失或无效；
- 权限不足；
- 跨租户或跨数据空间资源按源系统既有安全语义返回 404，不向 MCP 调用方泄露资源是否真实存在；
- 资源不存在；
- 客户或文档查询结果为空；
- 上游请求超时；
- 响应体超过大小限制；
- 返回内容不是有效 JSON，或不符合输出 Schema。

Capability 输出必须排除凭据、Authorization 请求头、密码哈希、内部 Secret 字段，以及业务结果不需要的租户或数据空间标识。`inspect_current_access` 只返回判断当前能力是否可用所需的用户显示名、当前租户显示信息和有效只读权限代码，不返回内部成员关系主键或 Secret。`get_customer_document_context` 的任一必需子操作被拒绝时，整体返回结构化权限错误，不静默返回不完整结果。

## 测试策略

在独立 ACC 工程目录中执行并检查以下确定性门禁：

```bash
acc doctor --json
acc validate --json
acc compile --check --json
acc coverage --json
acc test contract --json
acc test runtime --json
acc test e2e --json
```

上述命令属于离线确定性门禁。每条命令都必须满足：进程退出码为 `0`、JSON 顶层 `ok` 为 `true`、没有 `error` 级诊断；测试结果必须为零失败、零非预期跳过。Coverage 必须覆盖三项 Capability、它们引用的全部正式 Operation，以及每项 Capability 至少一个正向 Eval；受保护的 Capability 还必须至少有一个权限拒绝 Eval。Warning 可以保留，但必须逐项写入风险报告并说明为何不阻断本轮验收。

Contract 和 Runtime 测试使用 ACC 工程自己的夹具和 Fake REST 边界，在不运行 `baogao-jin` 的前提下覆盖正常结果、空结果、401、403、404、跨租户或数据空间、超时、响应过大、Schema 错误、MCP 工具枚举及 MCP 工具调用。

真实服务 E2E 是第二级验收，只能连接已经可用且由用户确认的本地或隔离 `baogao-jin` 测试服务，并通过允许的 Origin 清单限制目标。不得由本流程启动 `baogao-jin`、调用写接口或使用生产配置。正式纳入的 `GET` 接口必须有无业务写入的源码证据；测试服务自身的基础设施访问日志不视为业务数据修改。跳过或被阻断的真实服务 E2E 必须如实记录，不能标记为通过。

使用锁定的当前 ACC CLI 和依赖版本执行两次独立打包：

```bash
acc pack --output build/baogao-jin-first.accpkg --json
acc pack --output build/baogao-jin-second.accpkg --json
```

两次命令均须退出码为 `0`、JSON 顶层 `ok` 为 `true`，两个 `.accpkg` 的 SHA-256 摘要必须完全相同。Pack 内不得包含绝对路径、环境变量值、JWT 或非确定时间戳。

## 交付物与完成条件

独立 ACC 工程必须包含：

- `preflight-report.json` 和 `source-baseline.json`；
- `system-map.yaml`、`analysis-report.md` 和捕获的 `evidence/`；
- `capability-plan.yaml` 和 `coverage-baseline.json`；
- 有 Evidence 绑定的 Operation、Capability、Policy、Eval 和测试夹具；
- `HANDOFF.md`、`coverage-report.json`、`test-report.json`、`risk-report.json` 和 `candidate.diff`；
- 当编译和打包门禁全部通过时，提供确定性构建的 Capability Pack。

离线完整验收只有在三项 Capability、全部确定性门禁和双重打包都通过后才完成。真实服务联调验收还要求全部可用测试身份的预定用例通过，至少包含正常查询、权限不足、跨租户 404，以及启用时的同租户跨数据空间 404。任何必需 Capability、门禁或打包失败，都只能交付“未完成”状态及风险报告。

完成表示相应等级的 ACC 工作流及其验证边界已经得到证明，不表示 `baogao-jin` 已被修改、部署、生产测试或获得安全认证。流程最终停在人工 Git 审查之前，不推送代码。
