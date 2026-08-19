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
- `compileSdk/targetSdk` 与运行设备 API 不要求相等。平台始终以 36+ 编译和声明目标版本，但 D8
  `--min-api` 必须与 Manifest `minSdkVersion` 使用同一个有效值；开发 Profile 可将该值降到本地
  设备 API，正式结论仍只由 Android 16 Profile 签发。
- Agent 提交预构建 APK 时，平台通过 `aapt2 dump badging` 检查包名、入口、minSdk 和 targetSdk；
  targetSdk 缺失或低于 36即拒绝。
- 真机执行前再次读取 `ro.build.version.sdk`。PoC target 低于 36 或无法确认运行时兼容性时，产生
  `poc_incompatible`。默认拒绝 API 35 及以下；本地可显式开启 legacy smoke，但其全部 Evidence
  都带 `android16_verdict_eligible=false`，只能验证安装、启动、ADB 和证据链，不能证明或反驳
  Android 16 漏洞。
- 安装和启动阶段分别记录 `install_failure_kind` 与 `launch_failure_kind`。若 `am start` 表面成功但
  没有产生关联结果，平台额外采集 PoC 进程的 AndroidRuntime 日志，区分 DEX 校验、缺类、Activity
  实例化和普通运行时崩溃，不再把这些情况统一归为“未复现”。
- Adaptive Verifier 通过任务级 ADB 安装 `io.apkscanner.poc.*` 时，如果手机遗留同包名、不同签名的
  临时 PoC，平台只卸载该临时包并重试一次；目标应用始终受 `DEVICE_RESET_POLICY` 保护。`am start`
  返回码为 0 但输出 `Error type 3`、组件不存在或权限拒绝时，网关将其规范化为失败回执，阻止 Agent
  在安装失败后继续误判运行结果。

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

探索 worker 不再有固定的 3 任务上限。静态分析和 Agent 推理受各自资源池控制；可并行的真机批次数量
跟随当前未排空的 ADB 设备数量。运行中的 dispatcher 每 500ms 重新读取容量，因此中途接入第二台设备
后可以直接扩大动态验证并发。任务只在健康检查、安装、执行、观察和清理组成的短动态批次内独占
serial；代码阅读、Critic/Rescue、下一轮规划和 PoC 构建不占设备。后续批次优先回到原 serial，设备不可用
时可以迁移并重新准备目标；跨扫描的最终 ADB 并发仍由全局 device lease 队列约束。

宿主和容器的 ADB 命令空间必须分离：宿主通过 `APKSCANNER_HOST_ADB` 固定真实
platform-tools 绝对路径，`ToolRunner` 在执行时解析该覆盖值但 Evidence 仍记录规范化的 `adb`
argv；Python 包只安装 `apkscanner-adb-gateway`，仅 Worker 镜像把它链接成 `/usr/local/bin/adb`。
因此安装或启动平台不会覆盖操作者终端里的真实 `adb`。`start.sh` 会用 `adb version` 拒绝误指向
任务 Gateway 的候选；未找到真实客户端时进入 static-only，而不是依赖 PATH 顺序碰运气。

设备成员持久化在 `adb_devices` 表，环境变量中的 serial 只作为首次启动 seed。运行时接口为：

| 操作 | API | 语义 |
| --- | --- | --- |
| 列表/探测 | `GET /devices?probe=true` | 读取设备、API、占用任务和错误 |
| 接入 | `POST /devices` | 可执行 `adb connect`；development 接受 API 26+ 范围化动态裁决，android16_release 仅接受 API 36+ |
| 排空 | `POST /devices/{serial}/drain` | 停止新 lease；不打断当前任务 |
| 重连 | `POST /devices/{serial}/reconnect` | 活跃设备拒绝重连；探测成功后恢复调度 |
| 移除 | `DELETE /devices/{serial}` | 活跃设备拒绝移除；删除持久成员关系 |

新增设备会唤醒设备条件队列，因此扫描过程中等待的第二、第三个 worker 可以立即扩容。设备操作投影为
`device.pool.*` 扫描事件；任务自身继续记录 queued/acquired/released 完整事件线。

本地开发默认配置为：

```bash
export APKSCANNER_VALIDATION_PROFILE=development
export APKSCANNER_DEVICE_MIN_API=26
export APKSCANNER_ALLOW_LEGACY_DEVICE_SMOKE=true
```

旧设备可以形成 `dynamic_verdict_eligible=true`、`verdict_scope=development_legacy` 的 Finding，
避免本地验证永远无法落库；同时固定 `release_gate_eligible=false`。正式环境设置
`APKSCANNER_VALIDATION_PROFILE=android16_release`，并要求 API 36+。`APKSCANNER_ANDROID_API`、
PoC compileSdk 和 targetSdk 在两种 Profile 下都保持 36+。发布门禁、平台缓解、版本“已修复/回归”
结论仍只接受 `release_gate_eligible=true` 的 Proof。

## 3.1 控制台事件性能契约

- 历史事件默认只返回最近 300 条，`after + limit` 用于增量分页；交互控制台使用
  `detail=summary`，过滤 tool/step/session/evidence 等高频运行遥测，完整事件仍保留在数据库和审计
  Evidence 中。SSE 从客户端当前 cursor 开始，不再从 0 重放整条时间线。
- 总览不再挂载扫描活动时间线；顶层 SSE 只分发轻量事件且不把每条事件写回详情 state。探索任务页
  打开时才读取 300 条关键事件窗口，750ms 批量合并；单个折叠时间线展开后最多生成最近 100 条 DOM。
- 只有会改变任务、Finding、Hypothesis 或扫描状态的摘要事件触发 650ms debounce 数据刷新；相同的
  health、device、scan 和 mutable detail 响应保留原 React 引用，不产生空重渲染。
- Entry、快照、版本 Diff 和模式匹配使用有界 GET 缓存；`static.completed/scan.final` 会主动失效。
- 版本快照、Diff 和模式匹配只在进入“版本演进”时加载。AI 审计列表只返回 Evidence 元数据，正文按
  单条 `audit_id` 加载并校验 SHA-256；JSON/Markdown 仅在具体 artifact 展开后格式化。
- 常驻扫描侧栏最多首屏 100 项；攻击面、覆盖、任务、验证链和审计均分批挂载，并对离屏卡片使用
  `content-visibility`。固定侧栏、顶栏和普通 Card 不使用大面积 backdrop blur，减少选择文本和滚动时重绘。

## 3.2 状态化 Dynamic Experiment Capsule

单次 `am start` 无法表达登录态、授权代理、动态插件、PendingIntent 或回调链。平台提供扫描级
Dynamic Experiment Capsule，把前置状态、多条 ADB 动作、中间观察、最终断言和清理步骤保存在同一对象：

- `POST /scans/{scan_id}/dynamic-experiments` 创建实验；步骤可声明 exit code、stdout 子串/正则、
  状态变量和 Runtime Observation 类型；
- `POST /dynamic-experiments/{id}/run` 获取全局设备独占 lease 并执行，每步 ADB 输出单独进入 Evidence；
- 步骤未满足断言时状态变为 `paused`，再次调用 `run` 只继续失败或未执行步骤；
- cleanup 有独立回执。控制面重启时，正在执行的步骤记为失败，Capsule 回到 `paused`，不会丢失之前
  已完成的步骤；
- `POST /dynamic-experiments/{id}/cancel` 可取消排队或运行中的实验。目标应用数据仍遵守 preserve-state
  约定，Capsule 不隐式执行 `pm clear`。

Agent 可在 `requested_tests[].experiment` 中提交同一结构。平台先校验步骤 ID、action/assert 组成、
assertion 与 observation kind 的绑定，再创建 Capsule，并将其关联到当前 Hypothesis 的
`ProofAttempt(platform_dynamic_experiment)`。assert 步骤只有在全部声明断言通过、语义
ImpactContract 完整且设备满足当前 validation profile 时，才会形成 `harm_demonstrated=true`；普通
action 成功只证明执行发生。暂停的 Capsule 保留正在执行的 Proof，人工或平台再次 `run` 后只执行失败或
未执行步骤，进入 completed/canceled 终态时再统一闭合 Proof。

## 3.3 扫描质量漏斗

`GET /scans/{scan_id}/quality-summary` 从结构化台账实时聚合入口、任务、Hypothesis、静态支持、
Proof 规划、设备执行、危害证明和动态 Finding 八个阶段，并按 schema/provider/构建/安装/运行时/设备/
Oracle/超时/取消分类失败。总览同时展示 Agent 调用与 token、缓存输入比例、各 phase 耗时、设备等待与
持有时间、PoC 构建数和 Dynamic Experiment 数。接口不读取大型 artifact 正文，且在没有新事件时返回
稳定的 `generated_at`，避免事件轮询制造无意义重渲染。

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

每个新建 `ProofAttempt` 都保存平台生成的 `ProofRecipe`。配方去掉 scan-local 的 hypothesis/entry ID，
保留操作、输入、Oracle、生成器版本和源码依赖模式。平台 Harness 在后继版本直接重新生成；Agent 源码型
PoC 恢复内容寻址的源码归档；Dynamic Experiment 则重新绑定新版本入口后回放步骤与语义断言。三种路径都会绑定新版本的入口和 Hypothesis，并产生
全新的 build、ADB、Oracle 与 Proof Evidence，不复制旧版本动态结论。

## 4.1 运行时插件采集与增量调查

静态包内不存在、启动后才下载或解出的插件可通过
`POST /scans/{scan_id}/runtime-artifacts/captures` 导入。当前支持两种来源：

- `device_path`：从目标设备的普通可读路径执行 `adb pull`；
- `run_as`：对可调试测试包从应用私有相对路径进行二进制采集，适合本地 fixture。正式包无法
  `run-as` 时，可由具备相应权限的测试设备把文件放到可读路径后使用前一种方式。

采集期间只占用一个设备 lease；文件立即按 SHA-256 写入 CAS。随后复用同一 `ApkInspector` 与静态缓存，
生成 Manifest、JADX/Apktool、Native/JNI、插件入口和子 ArtifactGraph。平台在宿主图谱中追加
`loader → loads_runtime_apk → plugin entry` 链，并只为新插件入口创建 InvestigationTask。

同一 scan 再次采集相同 SHA-256 时，不重复反编译或创建任务；仅复用既有入口/任务，并在发现新的
Loader 来源时补充加载边。运行时采集对象、状态和复用来源可通过
`GET /scans/{scan_id}/runtime-artifacts` 查询。

## 5. 扩展调查入口与监督 Campaign

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
因此 AST 解析、登录流程、应用内部业务能力或 MCP 测试不需要硬编码成新的导出组件类型，同时仍有
可复核的完成标准。

监督 Agent 使用 `/supervisor/snapshot`、Capability catalog、Campaign validate/launch 和
Investigation Brief API 即可生成一组入口、检查依赖、启动测试并观察事件。它不能绕过 Capability
allowlist、设备 lease、PoC/Oracle 策略或 Evaluation Contract。
