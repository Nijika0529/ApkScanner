# AdaptiveCases 真机兼容性评测

评测日期：2026-08-04

评测性质：Android 13 / API 33 开发烟测，不是 Android 16 正式回归。

## 1. 目的

`testapk/adaptivecases.apk` 是公开的合成漏洞集，用于验证静态语义、Codex 调查、普通 App UID
PoC、ADB Gateway 和 Oracle 能否形成完整链路。该 APK 的 minSdk 为 26，compileSdk/targetSdk 为
36，并使用可复现构建。

本次使用固定 Codex Docker Worker、DeepSeek V4 Flash 和一台 Pixel 4/API 33 设备。设备序列号、
扫描 UUID、API Key 和本地数据目录不属于评测口径，不记录在公开文档中。

## 2. 用例

| ID | 攻击链 | 静态识别 | API 33 普通应用观察 | Android 16 正式结论 |
| --- | --- | ---: | --- | --- |
| AC-002 | ACTION_SEND Zip Slip | 是 | 恶意 ZIP 越界写入 canary 状态，目标 WebView 随后读取 | 未判定 |
| AC-003 | exported dynamic Receiver | 是 | 攻击者 Receiver 收到目标账号和会话字段 | 未判定 |
| AC-004 | unauthenticated localhost TCP | 是 | 普通应用连接本地端口并收到账号和会话字段 | 未判定 |
| AC-005 | external URL → WebView → JSBridge | 是 | 授权测试页面调用桥，回调端收到账号和会话字段 | 未判定 |
| AC-006 | exported Binder transaction | 是 | 普通应用读取多值 Binder reply | 未判定 |

测试集还包含两个安全对照组：

- Mutable implicit PendingIntent 可以被重定向，但接收方没有打开私有 Provider 的 URI 权限；
- signature permission 与 immutable PendingIntent 保护的 Activity 应保持不可利用。

对照组用于阻止模型把“可重定向”直接解释为“已泄露”。

## 3. 结果口径

### 3.1 正式严格指标

- Ground truth：5；
- `reproduced_blackbox`：0；
- TP / FP / FN：0 / 0 / 5；
- Precision / Recall / F0.5：0 / 0 / 0。

严格指标为 0 的原因是设备低于 API 36，所有动态观察只能进入 development scope。该结果不能解释为
“模型没有找到漏洞”，也不能用 API 33 行为替代 Android 16 发布结论。

### 3.2 静态诊断指标

将同一 ground truth 临时降为 static proof，仅用于诊断静态覆盖：

- TP / FP / FN：5 / 3 / 0；
- Precision：0.625；
- Recall：1.0；
- F0.5：0.675676。

三个额外结果来自 ZIP 链重复 Finding 和 PendingIntent 近似漏洞对照组。这一指标促成了跨任务
`semantic_fingerprint` 归并和对照组反证约束，但不作为项目正式检出率。

## 4. 运行数据

- preliminary 静态阶段约 2.3 秒；
- 常规入口任务在约 69 分钟内结束；
- 全扫描约 118 分钟，主要耗时来自终局开放式验证；
- 扫描事件约 3,083 条，Evidence 约 497 条，artifact 约 22.3 MB；
- Provider 发生一次 stream reconnect，SDK 自动恢复；
- 常规入口任务没有发生本地 Server、fetch 或 session-idle 生命周期故障。

事件规模验证了前端的摘要化设计：总览不加载完整事件线，任务页按 cursor 增量读取，高频工具事件
批量合并，Evidence 正文和大型 artifact 按需加载。

## 5. 评测暴露的问题及当前处理

| 问题 | 当前处理 |
| --- | --- |
| Zip Slip 只证明入口可达，没有证明文件变化 | 增加 `target_file_sha256`，比较执行前后文件存在性和摘要 |
| 同一 WebView/JSBridge 根因跨任务生成多条 Finding | 按 `finding_identity.semantic_fingerprint` 归并，Adaptive Verifier 可指定 canonical Finding |
| 终局候选过多导致上下文超限 | 按字符预算拆批并持久化 assessment/checkpoint |
| Verifier 失败后从零开始 | 同一 task 读取已完成批次和历史 Evidence，只恢复未完成部分 |
| 旧设备结果可能被误写为正式漏洞 | Verdict 保存 `development_legacy` / `android16_release` scope，API 36 是发布硬门槛 |
| 工具调用次数限制导致复杂链提前结束 | 移除固定工具/PoC/轮次上限，保留生命周期、取消和无事件超时 |
| 目标应用数据在任务间被清空 | 默认 `APKSCANNER_DEVICE_RESET_POLICY=never` |

## 6. 可复现性

APK、源码和 ground truth 位于：

```text
testapk/adaptivecases.apk
testapk/adaptivecases-src/
testapk/adaptivecases-ground-truth.json
```

构建脚本固定 ZIP 时间并禁用 v1 签名，使相同源码能够产生稳定 APK SHA-256。正式 Benchmark 必须
记录 commit、模型、ground truth 版本、Validation Profile 和设备 API；API 33 烟测与 API 36 发布回归
必须分别展示。
