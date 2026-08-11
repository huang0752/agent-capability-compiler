# 02 Scan Domain

## 输入

- 已通过 Preflight 的三根目录；
- 排序后的 `usage-scan-manifest.yaml`；
- 一个领域源文件与 `frontend`、`backend`、`tests` 分类。

## 动作

1. 只扫描一个选定领域与清单中的直接依赖。
2. 调用 `scripts/usage_evidence_capture.py` 捕获摘要、路径、大小和可选行范围。
3. 将分类映射到 `usage-evidence/frontend`、`usage-evidence/backend` 或
   `usage-evidence/tests`，原子写入定位元数据。
4. 比较读取前后的源文件身份与元数据，保持源工程零写入。

## 门禁

拒绝遍历、绝对输出、符号链接、Secret-like 路径、超限文件、源文件变化和分类目录逃逸。

## 输出

平台中立、无源码正文的 Usage Evidence JSON。

## 停止条件

任何安全诊断、分类不明、范围超出选定领域及直接依赖，或接受 Release 发生漂移。
