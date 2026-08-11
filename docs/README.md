# APKScanner 文档索引

本文档目录只保留当前实现规范、可复现评测和明确标注的能力边界。若文档与代码行为冲突，
以根目录 `README.md`、`backend/apkscanner/config.py` 和自动化测试为准。

## 从这里开始

| 文档 | 适合读者 | 状态 |
| --- | --- | --- |
| [快速开始指南](getting-started.zh-CN.md) | 第一次安装、启动和连接设备 | 当前实现 |
| [关键设计决策](design-decisions.zh-CN.md) | 希望快速理解工程取舍的读者 | 当前实现 |
| [架构与判定模型](architecture.zh-CN.md) | 需要理解完整控制流、数据模型和证据口径的开发者 | 当前实现 |
| [Worker 镜像准备](worker-image.zh-CN.md) | 构建 Codex Docker 环境 | 当前实现 |

## Android 检测与验证

| 文档 | 内容 | 状态 |
| --- | --- | --- |
| [Android 攻击链分析](android-attack-chain-analysis.zh-CN.md) | PendingIntent、文件导入、动态 Receiver、Socket、WebView/JSBridge 等 | 当前实现与扩展方法 |
| [Samsung 漏洞案例集覆盖分析](samsung-vulnerability-coverage-review.zh-CN.md) | 140 份详细案例的模式映射、本轮补齐与后续边界 | 研究报告与实现映射 |
| [AdaptiveCases 真机评测](adaptivecases-real-device-evaluation.zh-CN.md) | 合成 APK 的测试口径、已知限制与动态证明要求 | 评测记录 |
| [私有已知漏洞集盲测计划](private-benchmark-plan.zh-CN.md) | Ground truth 隔离、验收分层和公开披露规则 | 验收计划 |
| [运行时控制与版本演进](runtime-control-and-evolution.zh-CN.md) | 设备池、重新分析、验证 Profile、事件性能 | 当前实现 |

## Codex 与隔离执行

| 文档 | 内容 | 状态 |
| --- | --- | --- |
| [Codex Docker 执行架构](codex-docker-architecture.zh-CN.md) | SDK、Thread、UID 工作区、Proof Gateway、Capability、Supervisor | 当前实现规范 |

## 版本安全与知识复用

| 文档 | 内容 | 状态 |
| --- | --- | --- |
| [版本安全演进](version-security-evolution.md) | 静态 CAS、Security Snapshot、Diff、PoC 重放和 Finding 生命周期 | 当前实现规范 |

## 文档维护约定

- “已实现”必须能够在代码、测试或公开 API 中找到对应入口；
- benchmark 数字必须注明 APK 集合、设备 Profile、模型、时间和 ground truth 版本；
- 不把 `supported_static`、模型候选或人工演示仿真统计为动态复现；
- 文档、示例和日志中不得出现真实 API Key、私有 APK、账号、SSH 私钥或生产端点；
- 重大行为变化应同步更新根 README、相关设计文档和 `.env.example`。
