# AdaptiveCases 真机评测（2026-08-04）

## 结论

本轮使用真实 DeepSeek API、Codex Docker 后端和一台 Pixel 4 真机完成了端到端扫描。
目标 APK 的五个正例均被 Codex 静态语义分析覆盖，也都由普通应用 PoC 在真机上触发出预期行为；
但平台最终严格分数仍为 0/5，因为设备是 Android 13 / API 33，只能作为兼容性烟测，且终局
Adaptive Verifier 两次执行都在提交结构化结果前超时。因此这轮证明了调查能力已经具备，但也
证明“发现并实际做出来”与“平台及时落成正式 Finding”之间仍有明显缺口。

## 固件与环境

- 当前可复现 fixture：`testapk/adaptivecases.apk`
- 当前 SHA-256：`64538a7792ff3d0b28ac00c779bcf8b566e16d3cc7627933b9df730a94acd755`
- package：`io.apkscanner.adaptivecases`
- minSdk 26，compileSdk/targetSdk 36，APK Signature Scheme v2/v3
- 模型：`deepseek-v4-flash`，reasoning `high`
- 后端：Codex SDK、Docker、scan-scoped container、真实 API key
- 真机：Pixel 4，Android 13 / API 33，serial `9B081FFAZ00BX6`
- scan ID：`c539fba1-b9a9-4705-90d1-38597e4a5528`
- 数据目录：`.data/adaptivecases-real-20260804-1`

真机扫描时 APK 的容器 SHA-256 为
`b84cd34bd6658447e18870a6fb242bbf612a010238b89653fd25f7fd586cf888`。测试后发现旧构建会把
当前时间写入 ZIP/签名元数据，因此修复为可复现构建；当前 APK 与被扫描 APK 的
`AndroidManifest.xml` 和 `classes.dex` 内容哈希完全一致，变化仅为打包元数据。正式基准仍应
在 Android 16 设备上以当前可复现 APK 重新跑一轮。

## 用例与真机观察

| ID | 用例 | 静态发现 | API 33 普通应用烟测 | 正式 Android 16 判定 |
|---|---|---:|---:|---:|
| AC-002 | ACTION_SEND ZIP Slip | 是 | 恶意 ZIP 的 `../shared_prefs/session.xml` 被成功处理并写出；同批文件被目标 WebView 读取并回调 | 未判定 |
| AC-003 | exported dynamic Receiver + attacker PendingIntent | 是 | 攻击者 Receiver 收到目标账号和 session token | 未判定 |
| AC-004 | unauthenticated localhost TCP | 是 | 普通应用连接 `127.0.0.1:48765`，收到账号、token、expiry | 未判定 |
| AC-005 | external URL -> WebView -> AccountBridge | 是 | 页面调用 JSB 后，回调端收到账号、token、expiry | 未判定 |
| AC-006 | exported Binder transaction 7 | 是 | 普通应用收到 `code=200`、账号、token、expiry | 未判定 |

另有两个对抗性控制：

- Mutable implicit PendingIntent 可以被重定向，攻击者 Receiver 也能看到 content URI 与
  ClipData，但打开非导出 `VaultProvider` 时得到 `SecurityException`。它不是有效的 URI 泄露
  正例，已从 ground truth 正例集中删除，保留用于检查模型是否把“可重定向”误判成“已泄露”。
- `SafeCapabilityActivity` 使用 signature permission 和 immutable PendingIntent，作为明确负例。

Android 官方说明 Intent 的 grant flag 会把 data/ClipData URI 权限授予接收方，同时也明确提醒
PendingIntent creator 与实际 sender 不等价。本轮以普通应用 UID 做的反例结果优先于静态推断。

## 指标

### 平台严格指标

- Ground truth：5
- `reproduced_blackbox`：0
- TP/FP/FN：0 / 0 / 5
- Precision/Recall/F0.5：0 / 0 / 0
- `supported_static` Agent 风险：8，均被严格评测列为 unproven AI noise

严格分数不能解释为“模型一个都没找到”。它表示没有 API 36+ 的平台证据与成功落库的终局
Adaptive 结果，符合当前正式证据策略。

### 静态发现诊断指标（非正式分数）

把相同 ground truth 临时降为 static proof 只用于诊断：

- TP/FP/FN：5 / 3 / 0
- Precision：0.625
- Recall：1.0
- F0.5：0.675676（67.57）

三个额外 Finding 来自 ZIP 链重复生成两次，以及 PendingIntent 近似漏洞反例。说明静态语义
覆盖已经达到 5/5，但 Finding 去重和“风险可能性/实际危害”收口仍需加强。

### 耗时与可靠性

- 扫描总耗时：7078.6 秒（约 118 分钟，包含三次 Adaptive 尝试）
- preliminary：2.3 秒
- 4 个 static-review：64.1、84.9、134.3、146.7 秒
- 5 个 component：378.8～902.7 秒；4 completed、1 inconclusive
- 常规九任务到 Adaptive 开始：约 69 分钟；8 completed、1 inconclusive
- 常规 Codex 流程没有出现 OpenCode server/fetch/session-idle 生命周期故障
- 出现一次 DeepSeek stream reconnect，自动恢复
- Adaptive attempt 1：worker 环境变量 allowlist 缺少 `APKSCANNER_ADB_POLICY`，立即失败；已修复
- Adaptive attempt 2：约 28.5 分钟，152 次 tool、172 条 ADB Evidence、6 次 web search，超时
- Adaptive attempt 3：成功复用前轮 180 条 Evidence，但仍执行 114 次 tool、96 条 ADB Evidence、
  4 次 web search，约 14.3 分钟后超时

当时提示词中的“最多 80 次工具调用”既限制自主探索，也没有形成可靠的运行控制，现已删除。
平台不再用工具、PoC 重建、重放、轮次、单轮测试或候选数量阈值终止探索；真正的终止条件是
Agent 判断没有进一步实质动作、全部假设已有 Proof、用户取消或任务生命周期到期。checkpoint
仍值得实现，但它只用于逐项持久化成功 assessment 和超时/进程故障后的续跑，不能变成新的
隐式探索次数上限。

### 事件与前端负载

- scan events：3083 条，序列化体积约 1.31 MB
- agent runtime events：2126 条，约 0.26 MB
- Evidence：497 条，artifact 文件合计约 22.3 MB
- Evidence artifact 中 31 个大于 100 KB，10 个大于 1 MB
- 仅 `model.tool.started/completed`、reasoning start/completed 和 ADB completed 就贡献了大部分事件

这验证了前端不应一次性拉取/渲染完整事件线。事件列表必须分页/虚拟化；tool start+completed 应
折叠为一个逻辑节点；Evidence 正文只能按需打开，base64 上传命令必须摘要化。

## 本轮触发的修复

- Codex worker 接受并严格校验 `APKSCANNER_ADB_POLICY={scoped,adaptive}`。
- Adaptive retry 会读取同一 task 的历史 Evidence，避免从零开始。
- Adaptive 提示词要求 PoC compile/target API 36+，只允许降低 minSdk 兼容旧机；dx fallback 仍可用，
  但不得把 targetSdk 降到手机版本。本轮修复前生成的 PoC targetSdk 为 33，暴露了该契约缺口。
- Adaptive 结果落库增加 Android 16 硬门槛：API < 36 上即使模型返回 `reproduced_blackbox`，
  平台也只保留 `supported_static` 和 compatibility-smoke 元数据。
- fixture 构建改为固定 ZIP 时间并禁用 v1 签名，连续构建 SHA-256 一致。
- Ground truth 调整为五个真实正例，PendingIntent URI grant 近似用例改为对抗性控制。

## 后续优先级

1. 为 Adaptive Verifier 增加按候选 checkpoint 和部分结果持久化，使生命周期到期或进程故障后
   能从同一证据状态继续，而不是限制 Agent 的工具调用次数。
2. 在进入 Adaptive 前按攻击链语义合并重复 Finding；一个实验可以更新多个关联 Finding。
3. 将 Adaptive 的普通应用 PoC、回调日志等动态 Evidence 转成平台可直接接受的证据引用，而不是
   只有 Agent 最终 JSON 返回后才生效。
4. 在 Android 16 / API 36+ 真机上用当前可复现 APK 重跑，取得正式 5-case 指标。
5. 前端默认只展示结论事件，工具/Reasoning/ADB 事件按 task 分页、折叠和虚拟化。
