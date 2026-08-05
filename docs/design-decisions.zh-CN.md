# APKScanner 关键设计决策

本文面向希望快速理解项目工程取舍的读者。它解释“为什么这样设计”，具体字段和接口以
[架构与判定模型](architecture.zh-CN.md)为准。

## 1. Evidence-first，而不是 LLM-first

模型适合提出攻击假设、追踪跨类调用、生成脚本和修正 PoC，但不适合担任自身输出的事实裁判。
因此 APKScanner 将职责分开：

- 平台确定性枚举入口并保存 Coverage；
- Agent 根据当前证据选择信息增益最高的实验；
- ADB/Proof Gateway 执行有身份边界的操作；
- Oracle 观察 UI、日志、Binder、Provider、文件状态或网络语义；
- Finding Policy 校验 Evidence ID、调用身份和危害等级。

这使得模型升级可以改善探索能力，却不会改变“什么才算漏洞”的底层口径。

## 2. 为什么使用 Codex SDK 与 Responses API

当前路径固定使用 Codex SDK 和 Responses API，统一提供：

- 原生 Bash、文件、补丁和 Web Search；
- 持久 Thread、Turn interrupt 和 `thread_resume`；
- `output_schema` 结构化结果；
- 单一事件协议和持久运行时台账。

结构化输出仍可能出现类型漂移或 JSON 后附加自然语言，因此 Worker 先提取完整 JSON 候选，再用
Pydantic Schema 校验并规范化已知兼容字段。解析放宽不等于降低结论门槛：Evidence 和 Verdict
仍由平台二次校验。

## 3. 为什么一个扫描一个容器，而不是一个任务一个容器

Worker 镜像包含 Android SDK、JADX、Apktool、Java、Node、Python 和 Codex，按入口反复创建容器
会增加启动延迟、镜像层读取和容器数量。APKScanner 因此采用：

- 一个 Scan 创建一个无 Key keeper 容器；
- 每个 `task + attempt + role` 分配不复用的 Unix UID；
- 每个 UID 拥有独立 HOME、`CODEX_HOME`、TMPDIR、cache 和 workspace；
- 扫描级 JADX/Apktool/archive 通过只读目录共享；
- Provider Key 只进入当前 UID worker 的 exec 环境，不进入 keeper 全局环境。

这样既复用重型工具链，又保持角色之间的可写数据隔离。它适合单用户授权实验室，不声称达到
敌对多租户容器平台的隔离等级。

## 4. 为什么并发由设备数量决定

Android 动态验证的稀缺资源通常不是 CPU worker，而是拥有正确账号态和系统版本的设备。固定
“最多三个探索任务”会在新增设备时浪费容量，在设备不足时制造大量假运行任务。

设备池将一个完整任务绑定到一个 serial：健康检查、安装/复用、Agent 调查、PoC 回放、Oracle
和清理期间不会换机。运行中接入新设备会扩大容量，排空只阻止新 lease，不打断当前任务。
无设备时仍允许静态 lane 前进。

## 5. 为什么开发旧机和 Android 16 正式结论分开

只允许 API 36 会让本地旧设备无法完成 Finding 落库和验证链调试；完全接受旧设备又会把历史
平台行为错误外推到 Android 16。项目因此显式保存 `verdict_scope`：

- `development_legacy`：旧设备上的开发动态事实；
- `development_android16`：开发环境 API 36 事实；
- `android16_release`：正式 Profile 下 API 36+ 的发布级事实。

UI、Benchmark 和版本回归读取字段判断资格，不依赖容易被忽略的提示文案。

## 6. 为什么默认不清除目标应用数据

真实应用的登录态、隐私协议、初始化数据和 App Link 状态往往是漏洞前置条件。每个任务执行
`pm clear` 不仅增加人工成本，还可能让原本可测试的链路消失。因此默认 reset policy 为 `never`；
只有公开合成 fixture 或明确可丢弃的测试账号才允许按轮次清理。

## 7. 为什么复用静态资源但不复用 Finding

相同 APK 和工具版本的 JADX、Apktool、归档与代码索引是确定性计算，可以通过
`artifact_sha256 + analysis_profile` 缓存。Finding 则依赖模型版本、设备、账号态、系统版本和
动态实验，不能跨 Scan 直接继承。

版本升级时，历史 PoC 只作为“攻击配方”：必须在新 APK 上重新构建、重新执行并形成新的
ProofAttempt，才能判定漏洞持续、修复或回归。

## 8. 为什么增加扫描终局 Adaptive Verifier

固定 Oracle 无法预先描述所有业务影响，例如 JSBridge 返回的 Token、文件导入造成的状态覆盖或
需要远端页面配合的语义链。为每个候选创建 Agent 又会重复读取大量上下文。

平台因此在普通入口任务结束后，把少量静态证据较强但未闭环的候选交给一个扫描级高权限 Agent：

- 候选按字符预算拆批，避免单个请求超过 Provider 上下文上限；
- 每批结果和 checkpoint 持久化，失败可以从未完成批次恢复；
- Agent 可以组合 Bash、ADB、PoC、Web、SSH、MCP 或固定 Python Capability；
- 大模型负责判断实验语义，平台仍记录实际调用和结果，不能凭空制造动态 Evidence。

该机制承认验证类型具有开放性，同时保留最基本的可审计边界。

## 9. 为什么限制 Critic 次数，但不限制单轮探索深度

工具调用次数、PoC 修正次数和探索轮数的固定上限容易在复杂 APK 上提前截断真正有价值的链路。
项目不设置这些单轮扫描配额，而使用任务生命周期、取消、设备租约、进程隔离和无事件超时保障运行。

Critic、Rescue 和 Final 每个阶段仍最多启动一次。这个限制控制的是角色扇出和来回辩论，不限制
已经启动的 Turn 阅读代码、执行工具或修正实验。

## 10. 为什么事件与页面状态分层

Agent 工具事件数量可能远高于业务状态变化。如果总览持续加载完整事件、每条 SSE 都刷新 Scan
详情，页面会出现滚动、选中文本和复制卡顿。

当前前端将事件分为摘要和完整审计流：总览不加载扫描活动时间线，任务页按 cursor 增量读取最近
窗口，高频事件批量合并，版本 Diff 和大型 Artifact 按 Tab/展开状态懒加载。完整事件仍保存在
数据库中，性能优化不会删除审计信息。
