# Phase 5：Validate

用 ACC 的确定性诊断验证定义和编译结果，并只在 ACC 项目内修复。

## 输入

- Implement 阶段生成的完整 ACC 项目候选。
- 当前 ACC CLI 与结构化诊断契约。

## 动作

1. 依次运行 `acc validate --json`、`acc compile --check --json` 和 `acc coverage --json`。
2. 同时检查退出码、`ok`、`result` 和全部 `diagnostics`；不得只凭命令退出判断成功。
3. 按诊断的 code、path 和 pointer 修复 ACC 定义，然后从第一条命令重新验证。
4. 对 Evidence 缺失、引用非法、Policy/Eval 不完整等问题修复事实来源，不能放宽 Schema 掩盖错误。
5. 复核原系统只读基线及 Secret 扫描结果。

## 门禁

- 三个命令均真实执行并返回 `ok: true`，不存在被忽略的 error diagnostics。
- 编译仅接受静态引用、有界工作流和证据绑定的只读 Operation。
- 修复未触及原系统，未连接生产环境，也未引入 Secret 或写接口。
- 任何失败、警告或未运行项都被如实保留。

## 输出

- 通过校验的编译候选、Coverage 结果和可复查的结构化诊断记录。

## 停止条件

- 全部门禁通过后进入 Test。
- 若诊断无法在不猜测事实、不放宽安全边界的情况下修复，停止并回到 Analyze/Plan；不得隐藏失败继续。
