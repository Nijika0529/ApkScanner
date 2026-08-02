# 运行时控制、独立复核与版本演进实现规范

状态：已实现第一阶段

基线日期：2026-08-02
动态验证环境：Android 16 / API 36 及以上

本文记录已落地的运行契约。Codex Docker、UID 工作区、事件协议、ADB/Proof Gateway 的底层设计仍以
[`codex-docker-architecture.zh-CN.md`](codex-docker-architecture.zh-CN.md) 为准。

## 1. 静态工具与 PoC 基线

- 平台能力只展示并使用 `aapt2`、`apksigner`、`apktool`、`jadx`、`adb`；不再注册 MobSF 或
  APKAnalyzer。历史数据库中的 `ENGINE-MOBSF` coverage 行不再返回给控制台。
- PoC 必须使用精确的 Android Platform 36+ `android.jar`、`d8`、`aapt2`、`zipalign` 和
  `apksigner`。不回退旧 Platform，不使用 `dx`，`targetSdkVersion` 不得低于 36。
- Agent 提交预构建 APK 时，平台通过 `aapt2 dump badging` 检查包名、入口、minSdk 和 targetSdk；
  targetSdk 缺失或低于 36即拒绝。
- 真机执行前再次读取 `ro.build.version.sdk`。PoC target 低于 36 或无法确认运行时兼容性时，产生
  `poc_incompatible`。默认拒绝 API 35 及以下；本地可显式开启 legacy smoke，但其全部 Evidence
  都带 `android16_verdict_eligible=false`，只能验证安装、启动、ADB 和证据链，不能证明或反驳
  Android 16 漏洞。

## 2. 重新分析的两个语义

`POST /api/v1/tasks/{task_id}/reanalyses` 接受：

```json
{"context_mode":"continue"}
```

或：

```json
{"context_mode":"independent"}
```

`continue` 沿用原任务身份；超时任务装载该任务已有 Evidence，其他终态任务重新排队。`independent`
创建新的 Task ID、Hypothesis、Codex role session、attempt 和工作区，原任务保持不变。

独立复核只复用内容寻址的 APK、Manifest、JADX/Smali、代码索引等确定性静态产物；明确不复用原任务
Evidence、模型结论、Thread/Turn、版本 PoC 回放和历史 Finding。该策略同时写入任务 result、Codex
`platform_context.context_policy` 和 `exploration.independent.requested` 事件。

扫描级“全新重扫”继续使用 `/scans/{scan_id}/fresh-run`，它比任务级独立复核更强：创建新的 Scan ID
和空白扫描对象，只复用经过 SHA-256 校验的原始 APK。

## 3. 动态 ADB 设备池

探索 worker 不再有固定的 3 任务上限。可提交并发动态跟随当前未排空的 ADB 设备数量；没有设备时只
保留一个静态分析 lane。运行中的 dispatcher 每 500ms 重新读取容量，因此中途接入第二台设备后会
直接领取第二个任务。每个任务从 prepare、Probe、Agent 多轮、PoC、Oracle 到 cleanup 全程独占同一
serial；跨扫描的最终 ADB 并发仍由全局 device lease 队列约束。

设备成员持久化在 `adb_devices` 表，环境变量中的 serial 只作为首次启动 seed。运行时接口为：

| 操作 | API | 语义 |
| --- | --- | --- |
| 列表/探测 | `GET /devices?probe=true` | 读取设备、API、占用任务和错误 |
| 接入 | `POST /devices` | 可执行 `adb connect`；默认仅 API 36+，显式 legacy smoke 设备不可产出裁决 |
| 排空 | `POST /devices/{serial}/drain` | 停止新 lease；不打断当前任务 |
| 重连 | `POST /devices/{serial}/reconnect` | 活跃设备拒绝重连；探测成功后恢复调度 |
| 移除 | `DELETE /devices/{serial}` | 活跃设备拒绝移除；删除持久成员关系 |

新增设备会唤醒设备条件队列，因此扫描过程中等待的第二、第三个 worker 可以立即扩容。设备操作投影为
`device.pool.*` 扫描事件；任务自身继续记录 queued/acquired/released 完整事件线。

本地兼容性冒烟必须同时设置：

```bash
export APKSCANNER_DEVICE_MIN_API=33
export APKSCANNER_ALLOW_LEGACY_DEVICE_SMOKE=true
```

`APKSCANNER_ANDROID_API`、PoC compileSdk 和 targetSdk 仍保持 36+。发布门禁、漏洞复现、平台缓解、
版本“已修复/回归”结论仍只接受 API 36+ Proof。

## 3.1 控制台事件性能契约

- 历史事件默认只返回最近 300 条，`after + limit` 用于增量分页；SSE 从客户端当前 cursor 开始，
  单批最多读取 200 条，不再从 0 重放整条时间线。
- 浏览器直接把 SSE 事件合并到最多 500 条的本地窗口；数据刷新以 650ms debounce 合并，单条
  `exploration.*` 不再触发 13 个详情接口。
- Entry、快照、版本 Diff 和模式匹配使用有界 GET 缓存；`static.completed/scan.final` 会主动失效。
- AI 审计列表默认只返回 Evidence 元数据；用户进入“AI 审计”页时才读取正文并做 SHA-256 校验。

## 4. 静态资产和版本演进

静态缓存键是 `artifact_sha256 + analysis_profile`。只有完整、可缓存的反编译结果才原子发布到
`static-cache/`；不同 Scan 可复用缓存，但每次调查的 Evidence、结论和动态证明始终独立。

新 APK 上传可携带 `baseline_scan_id`。显式基线必须已经 final；静态完成后还必须满足包名、签名和制品
身份检查。差分 summary 保存 `baseline_selection`、`identity_result` 和两侧 `analysis_profile`。显式基线
不兼容时记录 `version.baseline.rejected`，不静默改选其他版本，也不执行自动 PoC 回放。

版本线使用以下稳定对象：

- `applications`：包名维度的应用身份；
- `application_releases`：Scan、签名快照、版本、APK SHA-256、快照 hash 和分析 profile；
- `vulnerability_cases`：人工明确创建的跨版本漏洞身份；
- `vulnerability_occurrences`：该案例在某个 APK 上的机器观测与证明级别。

`POST /findings/{finding_id}/regression-case` 需要 `case_key`、实际危害和最低证明等级。创建动作不会修改
原 Finding，也不会把人工文字升级为动态 Evidence。后继版本仅在稳定入口 identity 可映射时生成
`pending_revalidation` occurrence；无法唯一映射则是 `unmappable`。旧证据只用于生成回放配方，新版本必须
产生自己的 Proof/Evidence 后才能判断“仍存在”；回放失败只能是 `inconclusive`，不能单独证明“已修复”。

## 5. 特殊调查入口与未来监督 Agent

Python/MCP 能力仍通过 hash-pinned Capability Manifest 注册。任意非标准测试先创建
`InvestigationBrief`，必须包含目标、scope、attacker model、前置条件、可执行 Campaign Plan 和
Evaluation Contract。Evaluation Contract 至少声明所有成功条件和 inconclusive 条件，可进一步要求
Evidence kind。

接口为：

1. `POST /investigation-briefs`：保存入口和评判契约；
2. `POST /investigation-briefs/{id}/validate`：检查 DAG、扫描引用和 Capability 可用性；
3. `POST /investigation-briefs/{id}/launch`：生成隔离 scan/capability 入口并执行；
4. `POST /investigation-briefs/{id}/evaluate`：逐项绑定 Evidence 并形成 passed/failed/inconclusive。

`passed` 必须满足全部 success criteria，且 Evidence kind 覆盖契约要求；模型摘要不能替代平台 Evidence。
因此 AST 解析、登录流程、应用内部业务能力或未来 MCP 测试不需要硬编码成新的导出组件类型，同时仍有
可复核的完成标准。

监督 Agent 使用 `/supervisor/snapshot`、Capability catalog、Campaign validate/launch 和
Investigation Brief API 即可生成一组入口、检查依赖、启动测试并观察事件。它不能绕过 Capability
allowlist、设备 lease、PoC/Oracle 策略或 Evaluation Contract。
