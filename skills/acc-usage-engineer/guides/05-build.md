# 05 Build — B6

## 构建

在 accepted MCP 与 SourceSnapshot 未漂移时运行独立 `acc usage build --domain <id>`。核心输入是 DomainUsageContract、UsageScenario、Evidence 和领域决策；核心输出是确定性的、平台中立的 `.accusage`。

宿主 Markdown、MCP Resources/Prompts、Skill 或插件配置均属于可选适配器。适配器只能忠实投影或收窄核心合同，不能添加 route、权限、默认值或行为，也不能反向成为事实源。

## 门禁

构建前校验所有 Capability/Tool/step/binding/default/option_source/condition/related_data/result_consumption/error_branch/action_lifecycle 闭包。模板中的 `<replace-with-sha256>` 是故意不可发布的占位符，必须替换成实际摘要。

构建只写 `usage_project`，不得触发 `acc compile`、修改 `.accpkg` 或连接源系统。

正式构建示例：

```powershell
acc usage release --domain <id> --project <usage_project> --check `
  --verification-artifact <runner-artifact.json> `
  --verification-trust-store <independent-trust-store.json> `
  --accepted-pack <release.accpkg> --accepted-tools <tools.json> `
  --accepted-test-report <test-report.json>

acc usage build --domain <id> --project <usage_project> --output dist/<id>.accusage `
  --verification-artifact <runner-artifact.json> `
  --verification-trust-store <independent-trust-store.json> `
  --accepted-pack <release.accpkg> --accepted-tools <tools.json> `
  --accepted-test-report <test-report.json> `
  --package-signing-secret-env ACC_USAGE_PACKAGE_SIGNING_SECRET
```

trust-store 由独立管理域配置，不能放在 source、ACC 或 Usage 三根目录内。verification artifact 最长有效 24 小时；任何过期、篡改、错误摘要或非 canonical 输入都必须重新运行受信验证，而不是手工修改 artifact。
