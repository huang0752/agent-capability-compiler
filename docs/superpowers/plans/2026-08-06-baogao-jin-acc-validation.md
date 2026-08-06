# `baogao-jin` ACC 离线完整验收实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不修改或运行 `baogao-jin` 的前提下，完成独立 ACC 工程的分析、建模、编译、Fake REST 测试、MCP stdio 测试和确定性打包。

**Architecture:** `/Users/chou/code/baogao-jin` 只提供有界源码证据，所有生成物写入 `/Users/chou/code/baogao-jin-acc`。三项业务 Capability 由证据绑定的 `GET` Operation、声明式 Workflow、Policy、Eval 和 Fake fixtures 组成，再由当前通用 ACC Runtime 编译和执行；本轮不连接真实服务。

**Tech Stack:** Python 3.12、`uv`、ACC CLI、YAML/JSON Capability IR、JSON Schema、Fake REST、MCP stdio。

---

## 文件结构

独立 ACC 工程最终包含：

```text
/Users/chou/code/baogao-jin-acc/
├── project.yaml
├── preflight-report.json
├── source-baseline.json
├── system-map.yaml
├── analysis-report.md
├── capability-plan.yaml
├── coverage-baseline.json
├── evidence/
├── operations/
├── capabilities/
├── policies/
├── evals/
├── fixtures/
├── build/
├── HANDOFF.md
├── coverage-report.json
├── test-report.json
├── risk-report.json
└── candidate.diff
```

`agent-capability-compiler` 只新增本计划文档；执行阶段不修改编译器或 Runtime。`baogao-jin` 不产生任何文件变化。

### Task 1：Phase 0 Preflight 与只读基线

**Files:**
- Create: `/Users/chou/code/baogao-jin-acc/project.yaml`
- Create: `/Users/chou/code/baogao-jin-acc/preflight-report.json`
- Create: `/Users/chou/code/baogao-jin-acc/source-baseline.json`

- [ ] **Step 1：确认目标目录不存在且两个真实路径互不包含**

Run:

```bash
realpath /Users/chou/code/agent-capability-compiler
realpath /Users/chou/code/baogao-jin
test ! -e /Users/chou/code/baogao-jin-acc
```

Expected: 前两条返回不同的真实路径，第三条退出码为 `0`。

- [ ] **Step 2：初始化独立 ACC 工程**

Run from `/Users/chou/code/agent-capability-compiler`:

```bash
uv run acc init /Users/chou/code/baogao-jin-acc --json
```

Expected: JSON 顶层 `ok` 为 `true`，所有创建路径位于 `/Users/chou/code/baogao-jin-acc`。

- [ ] **Step 3：运行 ACC Engineer Preflight**

Run:

```bash
uv run python skills/acc-engineer/scripts/preflight.py \
  --source-workspace /Users/chou/code/baogao-jin \
  --project-dir /Users/chou/code/baogao-jin-acc \
  --acc-command "uv run acc"
```

Expected: 路径分离、工具可用和项目初始化检查通过；检查 JSON 结果而非只看退出码。

- [ ] **Step 4：捕获源系统基线并写入 Preflight 报告**

Run:

```bash
uv run python skills/acc-engineer/scripts/verify_read_only_workspace.py \
  --workspace /Users/chou/code/baogao-jin
```

Expected: 将结构化输出保存为 `source-baseline.json`，并按 `skills/acc-engineer/templates/preflight-report.json` 写入真实结果；记录当前 commit、分支、脏文件清单和资料入口，不读取 `.env` 或 Secret 值。

### Task 2：Phase 1 Analyze 与 Evidence 捕获

**Files:**
- Create: `/Users/chou/code/baogao-jin-acc/system-map.yaml`
- Create: `/Users/chou/code/baogao-jin-acc/analysis-report.md`
- Create: `/Users/chou/code/baogao-jin-acc/evidence/*.json`

- [ ] **Step 1：有界盘点源码资料**

Run:

```bash
uv run python skills/acc-engineer/scripts/inventory.py \
  --workspace /Users/chou/code/baogao-jin
```

Expected: 只读取普通文件，不跟随符号链接；聚焦 README、`backend/app/api/router.py`、用户会话、客户、报告、证书、权限、数据空间、前端 API 调用和相关测试。

- [ ] **Step 2：核实三项 Capability 的候选 GET Operation**

Inspect only:

```text
backend/app/domains/iam/routes/profile.py
backend/app/domains/customer/routes/customers.py
backend/app/domains/report/routes.py
backend/app/domains/formal_report/routes.py
backend/app/domains/green_certificate/routes.py
backend/app/domains/aaa_certificate/routes.py
backend/app/domains/qualification_certificate/routes.py
backend/app/shared/deps.py
backend/app/domains/iam/services/data_space_access.py
backend/app/core/permission_catalog.py
backend/tests/test_*data_space*.py
backend/tests/test_*permission*.py
frontend/admin/src/api/**
```

Expected: 为方法、完整 `/api` 路径、参数、响应 Schema、权限、租户/数据空间边界、404/403 语义和只读效果找到至少两个相互印证的证据来源；证据不足的候选标记为阻断。

- [ ] **Step 3：使用 Evidence helper 捕获有界证据**

Run once per selected source file:

```bash
uv run python skills/acc-engineer/scripts/evidence_capture.py \
  --source-workspace /Users/chou/code/baogao-jin \
  --project-dir /Users/chou/code/baogao-jin-acc \
  --source backend/app/domains/iam/routes/profile.py \
  --source-id baogao-profile-route \
  --output evidence/baogao-profile-route.json
```

Expected: 每份 Evidence 包含源相对路径、定位信息和整个有界文件的稳定摘要；其他已选路由、Schema、鉴权、权限和测试证据使用不同 `source-id` 重复执行。

- [ ] **Step 4：生成系统地图和分析报告**

Expected: `system-map.yaml` 基于模板填写真实领域、实体、Operation 候选、权限、租户、数据空间、错误、调用关系、测试和未知项；`analysis-report.md` 明确区分事实、源码冲突、脏工作区风险和未确认项。

### Task 3：Phase 2–3 Model 与 Capability Plan

**Files:**
- Modify: `/Users/chou/code/baogao-jin-acc/system-map.yaml`
- Create: `/Users/chou/code/baogao-jin-acc/capability-plan.yaml`
- Create: `/Users/chou/code/baogao-jin-acc/coverage-baseline.json`

- [ ] **Step 1：完成业务与安全模型**

Expected: 映射当前用户、租户、数据空间、客户、报告和证书关系；每个候选 Operation 均绑定 Evidence、权限、错误和只读效果，环境配置仅出现 `BAOGAO_JIN_BASE_URL` 与 `BAOGAO_JIN_USER_TOKEN` 引用名。

- [ ] **Step 2：规划三项业务 Capability**

Expected:

```text
inspect_current_access
search_visible_customers
get_customer_document_context
```

每项 Capability 都有窄输入/输出 Schema、明确的 Operation 组合、Policy、字段白名单、脱敏规则、一个正向 Eval 和权限负例；JWT、Base URL、租户和权限集合不作为 Agent 输入。

- [ ] **Step 3：写入规划覆盖基线**

Expected: `coverage-baseline.json` 使用模板结构，列出三项计划 Capability、被采用/排除/阻断的 Operation 及原因，并明确这是规划基线而不是 `acc coverage` 运行结果。

### Task 4：Phase 4 Implement 声明式工程

**Files:**
- Create: `/Users/chou/code/baogao-jin-acc/operations/*.yaml`
- Create: `/Users/chou/code/baogao-jin-acc/capabilities/*.yaml`
- Create: `/Users/chou/code/baogao-jin-acc/policies/*.yaml`
- Create: `/Users/chou/code/baogao-jin-acc/evals/*.yaml`
- Create: `/Users/chou/code/baogao-jin-acc/fixtures/*`

- [ ] **Step 1：导出当前公开 Schema 并以其为准**

Run from ACC project:

```bash
uv run --project /Users/chou/code/agent-capability-compiler acc schema --output build/schemas --json
```

Expected: JSON 顶层 `ok` 为 `true`，后续 YAML 字段与当前 Schema 一致。

- [ ] **Step 2：创建 Evidence 绑定的 GET Operations**

Expected: 每个 Operation 具有严格输入/输出 Schema、相对路径、参数映射、`credential_ref: BAOGAO_JIN_USER_TOKEN`、超时和响应大小限制；不存在 POST、动态 Host、Token 参数或 Header 覆盖。

- [ ] **Step 3：创建三项 Capabilities 和 Policies**

Expected: 使用受限 `call/pick/map/filter/assert/redact/branch/parallel/foreach/emit` 工作流；当前身份和客户搜索保持单一职责，客户文档上下文只组合已验证 Operation；输出禁止 Secret、内部主键及无关租户字段。

- [ ] **Step 4：创建 Evals 与 Fake fixtures**

Expected: 覆盖正常、空结果、401、403、404、跨租户、可验证时的跨数据空间、超时、响应过大、无效 JSON、Schema 不匹配、敏感字段禁止和 MCP 调用；fixtures 使用虚构 UUID、企业名和 JWT，不复制真实业务数据。

### Task 5：Phase 5 Validate

**Files:**
- Create: `/Users/chou/code/baogao-jin-acc/build/*`
- Create: `/Users/chou/code/baogao-jin-acc/coverage-report.json`

- [ ] **Step 1：依次运行三项确定性校验**

Run from ACC project with the repository CLI:

```bash
uv run --project /Users/chou/code/agent-capability-compiler acc validate --json
uv run --project /Users/chou/code/agent-capability-compiler acc compile --check --json
uv run --project /Users/chou/code/agent-capability-compiler acc coverage --json
```

Expected: 每条命令退出码 `0`、`ok: true`、零 error diagnostics；Coverage 结果保存为 `coverage-report.json`。

- [ ] **Step 2：按诊断修复 ACC 工程并从头重跑**

Expected: 只修改 `/Users/chou/code/baogao-jin-acc`；不放宽 Schema 或删除负例掩盖失败。任何无法由证据修复的问题返回 Analyze/Plan 并标记未完成。

### Task 6：Phase 6 Test

**Files:**
- Create: `/Users/chou/code/baogao-jin-acc/test-report.json`

- [ ] **Step 1：运行 Contract、Runtime 和 E2E Eval**

Run:

```bash
uv run --project /Users/chou/code/agent-capability-compiler acc test contract --json
uv run --project /Users/chou/code/agent-capability-compiler acc test runtime --json
uv run --project /Users/chou/code/agent-capability-compiler acc test e2e --json
```

Expected: 每项退出码 `0`、`ok: true`、零失败、零非预期跳过；保存完整的套件名称、用例数、通过/失败/跳过和 diagnostics 到 `test-report.json`。

- [ ] **Step 2：检查 MCP 与 Secret 边界**

Expected: `tools/list` 只出现三项 Capability；`tools/call` 参数不含 JWT、Base URL、租户或权限配置；正常输出、错误输出、日志、报告和 fixtures 不含真实 Secret 或完整上游响应。

### Task 7：Phase 7 Refine

**Files:**
- Modify: `/Users/chou/code/baogao-jin-acc/{operations,capabilities,policies,evals,fixtures}/**`
- Modify: `/Users/chou/code/baogao-jin-acc/coverage-report.json`
- Modify: `/Users/chou/code/baogao-jin-acc/test-report.json`

- [ ] **Step 1：审计孤立、重复和过宽定义**

Expected: 删除孤立 Operation、合并一接口一工具式重复、收紧输入/输出 Schema 和字段披露；不为了 Coverage 增加低价值能力。

- [ ] **Step 2：完整重跑 Validate 与 Test**

Expected: Task 5 和 Task 6 的全部命令再次满足通过条件，Coverage 不倒退，风险变化有记录。

### Task 8：Phase 8 Handoff 与确定性打包

**Files:**
- Create: `/Users/chou/code/baogao-jin-acc/HANDOFF.md`
- Create: `/Users/chou/code/baogao-jin-acc/risk-report.json`
- Create: `/Users/chou/code/baogao-jin-acc/candidate.diff`
- Create: `/Users/chou/code/baogao-jin-acc/build/baogao-jin-first.accpkg`
- Create: `/Users/chou/code/baogao-jin-acc/build/baogao-jin-second.accpkg`

- [ ] **Step 1：重新验证源系统只读基线**

Run:

```bash
uv run python skills/acc-engineer/scripts/verify_read_only_workspace.py \
  --workspace /Users/chou/code/baogao-jin \
  --baseline /Users/chou/code/baogao-jin-acc/source-baseline.json
```

Expected: 基线完全一致；如有并发变化则停止交付、记录并重新确认，不宣称完成。

- [ ] **Step 2：生成五项交付物并扫描敏感信息**

Expected: `HANDOFF.md`、`coverage-report.json`、`test-report.json`、`risk-report.json`、`candidate.diff` 均说明真实命令、结果、限制和未运行的真实服务联调；`candidate.diff` 只包含 ACC 工程；敏感信息扫描无 JWT、Authorization 值、密码、生产地址或真实业务数据。

- [ ] **Step 3：独立打包两次并比较摘要**

Run:

```bash
uv run --project /Users/chou/code/agent-capability-compiler acc pack --output build/baogao-jin-first.accpkg --json
uv run --project /Users/chou/code/agent-capability-compiler acc pack --output build/baogao-jin-second.accpkg --json
shasum -a 256 build/baogao-jin-first.accpkg build/baogao-jin-second.accpkg
```

Expected: 两次打包均 `ok: true`，两个 SHA-256 完全相同，Pack 不含绝对路径、Secret 或非确定内容。

- [ ] **Step 4：停止在人工审查门禁**

Expected: 不提交、不推送、不部署 ACC 工程；报告离线完整验收结论，并明确真实服务联调未执行。
