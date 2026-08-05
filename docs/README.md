# APKScanner 文档索引

本文档目录同时包含当前实现规范、后续设计和迁移历史。阅读时应以文档顶部的状态说明为准；
若文档与代码行为冲突，以根目录 `README.md`、`backend/apkscanner/config.py` 和自动化测试为准。

## 从这里开始

| 文档 | 适合读者 | 状态 |
| --- | --- | --- |
| [快速开始指南](getting-started.zh-CN.md) | 第一次安装、启动和连接设备 | 当前实现 |
| [关键设计决策](design-decisions.zh-CN.md) | 希望快速理解工程取舍的开发者/面试官 | 当前实现 |
| [架构与判定模型](architecture.zh-CN.md) | 需要理解完整控制流、数据模型和证据口径的开发者 | 当前实现 |
| [Worker 镜像准备](worker-image.zh-CN.md) | 构建 Codex Docker 环境 | 当前实现 |

## Android 检测与验证

| 文档 | 内容 | 状态 |
| --- | --- | --- |
| [Android 攻击链分析](android-attack-chain-analysis.zh-CN.md) | PendingIntent、文件导入、动态 Receiver、Socket、WebView/JSBridge 等 | 当前实现与扩展方法 |
| [AdaptiveCases 真机评测](adaptivecases-real-device-evaluation.zh-CN.md) | 合成 APK 的测试口径、已知限制与动态证明要求 | 评测记录 |
| [私有已知漏洞集盲测计划](private-benchmark-plan.zh-CN.md) | Ground truth 隔离、验收分层和公开披露规则 | 验收计划 |
| [运行时控制与版本演进](runtime-control-and-evolution.zh-CN.md) | 设备池、重新分析、验证 Profile、事件性能 | 当前实现 |

## Codex 与隔离执行

| 文档 | 内容 | 状态 |
| --- | --- | --- |
| [Codex Docker 执行架构](codex-docker-architecture.zh-CN.md) | SDK、Thread、UID 工作区、Proof Gateway、Capability、Supervisor | 实现规范；状态表区分 DONE/PARTIAL |
| [Codex SDK 兼容性](../gpt-5.6-codex-sdk-compatibility.md) | 固定 SDK 基线与协议兼容性记录 | 技术调研 |

## 版本安全与知识复用

| 文档 | 内容 | 状态 |
| --- | --- | --- |
| [版本安全演进](version-security-evolution.md) | 静态 CAS、Security Snapshot、Diff、PoC 重放和 Finding 生命周期 | 当前实现规范 |
| [版本回归设计](release-regression.zh-CN.md) | 人工漏洞库和跨版本复验的早期完整方案 | 设计历史；部分能力已落地 |

## 历史资料

以下文档用于解释架构为什么演进到当前形态，不代表当前运行路径：

- [OpenCode + DeepSeek 退役设计](opencode-deepseek.zh-CN.md)：记录已删除的 OpenCode
  Server/Worker/轮询方案及其稳定性问题；
- [迁移前项目汇报快照](project-brief.zh-CN.md)：记录 Codex 重构之前的阶段性口径，其中
  OpenCode、测试数量和代码路径已经过时。

## 文档维护约定

- “已实现”必须能够在代码、测试或公开 API 中找到对应入口；
- benchmark 数字必须注明 APK 集合、设备 Profile、模型、时间和 ground truth 版本；
- 不把 `supported_static`、模型候选或人工演示仿真统计为动态复现；
- 文档、示例和日志中不得出现真实 API Key、私有 APK、账号、SSH 私钥或生产端点；
- 重大行为变化应同步更新根 README、相关设计文档和 `.env.example`。
