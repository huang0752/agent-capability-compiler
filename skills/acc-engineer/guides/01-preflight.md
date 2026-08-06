# Phase 0：Preflight

先建立工程边界；任何分析或生成工作都不得先于本阶段通过。

## 输入

- 原系统源码目录、独立 ACC 项目目录和用户目标。
- 当前 ACC 安装、原系统文档、OpenAPI、测试入口及运行约束。

## 动作

1. 用 `pwd -P` 或 `realpath` 解析两个目录的真实路径，确认它们互不包含；安全脚本会有意拒绝含符号链接的路径组成，包括 macOS `/var` 别名。
2. 对全新目标先运行 `acc init <acc_project>` 并进入该目录，再运行 `acc doctor --json`；不得对尚无 `project.yaml` 的空目录直接执行 Doctor。
3. 只读盘点 README、OpenAPI、测试和权限文档；不要启动或连接生产环境。大型仓库应给 `preflight.py`、`inventory.py` 和两次 `verify_read_only_workspace.py` 传入完全相同、可重复的相对路径 `--include` 白名单，只覆盖可能形成 Evidence 的源码与测试文件；默认不传时仍执行全工作区 fail-closed 扫描。
4. 建立原系统只读基线，并检查计划中的命令是否可能修改源码、数据库、认证或依赖文件。
5. 识别疑似生产凭据、Token、私钥和生产地址；只报告风险位置，不读取、复制或输出 Secret 值。

## 门禁

- 原系统与 ACC 项目边界明确，原系统可按只读方式工作。
- 不需要生产 Secret、生产环境或写接口；MVP 候选仅使用已有 REST `GET`/`HEAD`。
- 可用安全方式运行必要测试，且命令不会写入原系统。
- `acc doctor --json` 的实际结果已检查，不能只看退出码。

## 输出

- 可审计的 Preflight 结论、目录边界、只读基线、可用资料和安全测试入口。
- 明确列出的风险、限制与待确认事项，供 Phase 1 使用。
- 按 `templates/preflight-report.json` 形成的结构化 Preflight 报告。

## 停止条件

- 通过全部门禁后进入 Analyze。
- 若目录重叠、只读边界无法保证、需要生产凭据/生产访问/写操作，或测试可能污染原系统，立即停止并请求人工处理。
