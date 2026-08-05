# APK Scanner

以证据为导向的 Android APK 安全扫描控制面，提供确定性攻击面覆盖、远程 ADB 验证和可选的 Codex SDK + DeepSeek V4 Flash 调查。

v1 产品是一个单用户、仅限本机（localhost）的 Web 应用。它接收一个可安装的 APK，构建带版本号的 Security IR（安全中间表示），枚举所有 Android 组件入口和 Deep Link，记录覆盖缺口，并分派有边界的调查任务。Agent 输出在缺乏平台证据 ID 的情况下永远不会成为"已复现"的发现。

## 已实现功能

- APK 大小/ZIP 安全检查、SHA-256 内容寻址、签名与包元数据。
- Manifest 生效状态下的 Activity、Service、Receiver、Provider、权限和 Deep Link 分析。
- 正确处理 Intent Filter 中分离的 `<data>` 属性的笛卡尔积展开。
- 内置面向 MASVS 的 Manifest、代码模式、归档文件、原生库和加固规则。
- Apktool/Smali 基线分析，JADX 仅作为便利视图；JADX 局部失败不会阻断结论。
- 持久化的 SQLite Scan/Task/Finding/Evidence/Coverage/Event 模型。
- 持久化 Hypothesis、Hunter/Critic 论证、Proof Attempt、危害 Oracle 和平台 Verdict；模型文字不能自证漏洞成立。
- 私有 APK ground-truth 评测：只对平台确认的最终 Finding 计分，默认要求动态证明，并用 F0.5 重罚不匹配真值的高危结论。
- 所有扫描全局只运行一个入口调查任务；该任务从设备准备、多轮 Agent/PoC 回放到清理始终独占 ADB。
- 远程 ADB 适配器、可选普通 App UID Probe 快速路径、Agent 专用 PoC、客观 Oracle；默认保留待测应用数据，仅对一次性测试 fixture 显式启用 `pm clear`。
- 官方 `openai-codex==0.144.4` + DeepSeek Responses 集成：严格 JSON Schema、完整事件线、无子 Agent fan-out、全权限 Codex sandbox 和证据支撑的结果降级。
- 每个扫描一个无密钥 keeper 容器；每个 `task + attempt + role` 使用独立 Unix UID、HOME、`CODEX_HOME`、TMPDIR 和可写工作区，同时只读挂载 JADX/Apktool/archive 输入。
- OpenCode 可执行运行时、critic、fallback 和 Node Worker 已删除；仅保留历史报告读取兼容与退役设计文档。
- 响应式明亮主题 React 审核控制台、人工 Finding 判定、实时事件、任务停止/删除、JSON/HTML/SARIF 导出。
- 最终 Finding 与静态线索分层：只有平台 Oracle 证明具体危害且 Evidence 引用完整的动态复现才计为 Finding。

详细的控制流程、信任边界、Security IR 和判定规则参见 [`docs/architecture.zh-CN.md`](docs/architecture.zh-CN.md)。
用于内部汇报的一页式说明与数据口径参见
[`docs/project-brief.zh-CN.md`](docs/project-brief.zh-CN.md)。
后续版本差分、人工漏洞库和安全复验方案参见
[`docs/release-regression.zh-CN.md`](docs/release-regression.zh-CN.md)。

## 本地搭建

推荐 Python 3.12+ 和 Node 22.13+。最小的有用静态工具集为 `aapt2`、`apksigner` 和 `apktool`；`jadx` 可选但能改善代码检索。

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'

cd frontend
npm install
npm run build
cd ..

export APKSCANNER_FRONTEND_DIST="$PWD/frontend/dist"
scanctl serve
```

打开 `http://127.0.0.1:8000`。如需独立前端开发，在 `frontend/` 中运行 `npm run dev`，Vite 会将 `/api` 代理到 8000 端口。

旧分支曾把任务级 Gateway 注册成宿主全局 `adb`。升级已有 editable install 后执行一次
`python -m pip install --force-reinstall --no-deps -e .` 和 `hash -r`；新版只注册
`apkscanner-adb-gateway`，不会覆盖 platform-tools 的 `adb`。

无需 Web UI 执行前台扫描：

```bash
scanctl scan /absolute/path/to/application.apk --investigator configured
scanctl capabilities
```

对已有已知漏洞结论的私有 APK，可复制
[`config/benchmark-ground-truth.example.json`](config/benchmark-ground-truth.example.json)
填写真值，然后直接比较不同模型：

```bash
scanctl benchmark /absolute/path/to/application.apk \
  --truth /absolute/path/to/ground-truth.json \
  --investigator codex

scanctl evaluate --scan-id SCAN_ID \
  --truth /absolute/path/to/ground-truth.json
```

如果只需要提前演练汇报页面，可以在一个已完成扫描上创建明确标注的召回率仿真。该命令
只新增 `BenchmarkEvaluation`，不会伪造 Finding、Evidence、模型归因或真机验证：

```bash
scanctl simulate-evaluation --scan-id SCAN_ID \
  --truth /absolute/path/to/ground-truth.json \
  --target-recall 0.75 \
  --seed report-rehearsal-v1

# 或显式指定应当漏掉的已知漏洞，便于模拟当前能力边界
scanctl simulate-evaluation --scan-id SCAN_ID \
  --truth /absolute/path/to/ground-truth.json \
  --omit-id GT-004 --omit-id GT-009
```

仿真卡片始终显示“仿真数据”水印，并记录 `synthetic_demo` provenance、选择规则与完整漏报
列表。它只能用于界面和汇报流程演练，不能作为目标 APK 的扫描结论或 phone-verified 证据。

`candidate`、`inconclusive`、人工 accepted 和没有平台证明的模型描述都不算“发现”。普通
Probe 成功只记录 `execution_demonstrated`；动态真值还要求领域 Prover 给出平台可校验的
`security_impact_observed`。真值默认使用 `minimum_proof: dynamic`；仅仅发现导出声明、
危险 API 或成功打开组件不能得分。平台已确认但无法匹配任何真值的 Finding 会计为 false
positive，未证明的 AI 输出则单独列为噪声。

Web 上传对话框和 CLI 均可将每次扫描锁定为 `codex` 或 `none`；`configured` 在扫描创建时解析服务默认值，并随该扫描持久化。

## 动态设备配置

配置已在本地 ADB 服务器中记录的远程 Android 16 ADB 序列号或端点：

```bash
export APKSCANNER_HOST_ADB=/真实的/platform-tools/adb
"$APKSCANNER_HOST_ADB" connect cloud-device.example:5555
export APKSCANNER_ADB_SERIAL=cloud-device.example:5555
```

如需快速以普通 App UID 调用 Activity、Service、Receiver、Provider、Deep Link 或简单 Binder
事务，可选地构建 [`probe/`](probe/) 中的故意导出辅助程序；它只能安装在专用测试设备上。
构建使用固定 Worker 镜像，不要求宿主安装 Gradle/Android SDK：

```bash
./probe/build-probe.sh
export APKSCANNER_PROBE_APK="$PWD/probe/app/build/outputs/apk/debug/app-debug.apk"
```

Probe receiver 要求 `android.permission.DUMP`，只有 ADB shell/platform caller 能下发请求；真正的
入口调用仍由 Probe 自己的普通应用 UID 执行。`binder_transact` 由平台读取 typed reply 并通过
`binder_reply` Oracle 判定，不信任 Agent PoC 自报的返回值。

没有 ADB 时，扫描仍会依据静态证据完成。没有可选 Probe APK 时，Agent 仍可使用原始
ADB 探索或构建专用 PoC；仅当某个实际申请的普通 App 测试两种执行路径都不可用时，
平台才记录具体缺口。`adb shell` 成功会保留为独立身份，永远不会被视为普通第三方应用。

当 `APKSCANNER_ANDROID_SDK_ROOT` 指向包含 API 36 platform 和 build-tools 的 Android SDK
时，Codex Agent 可以在隔离工作区的 `poc/` 下生成 Manifest/Java 源码型 PoC，也可以
自行构建签名 APK。控制面会校验路径、大小、签名、包名和启动组件，登记源码/APK SHA-256，
再进入同一 ADB 队列，以普通应用 UID 安装和启动，通过随机 nonce 关联结果，最后卸载。
host `personal_lab` 模式可用原始 ADB 做探索，但普通 App 可利用性仍须由平台关联的
Probe/PoC 执行证据确认。PoC 自报影响仍只是声明；还需要 UI、目标进程日志、崩溃等
独立平台观察才能满足实际危害证明条件。

单 ADB 模式下，控制面在领取任务前执行全局串行化。一个任务从健康检查、安装和初始探索，
到 Agent 多轮分析、实时 PoC 回放、Review 和最终清理始终占有设备；其他任务保持 `queued`，
不会提前显示成“运行中”或“等待设备”。设备层仍保留一个轻量互斥作为误并发保护，但不再
承担 3 个 worker 之间的优先级排队。

## Codex 配置

Codex 是唯一的 AI 调查后端，默认关闭；不启用时确定性静态/动态流水线仍可运行。当前只允许
DeepSeek V4 Flash、Responses API 和固定的 `openai-codex==0.144.4`。先构建固定 Worker
镜像，再通过控制面进程环境提供 DeepSeek Key：

```bash
docker build \
  --build-arg DEBIAN_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian \
  -f Dockerfile.worker \
  -t apk-scanner-codex-worker:0.2.0 \
  .

export DEEPSEEK_API_KEY=...
export APKSCANNER_INVESTIGATOR_BACKEND=codex
export APKSCANNER_CODEX_ISOLATION=docker
export APKSCANNER_CODEX_ENABLED=true
scanctl capabilities --deep
# 或由已验证过 Key 环境的启动脚本启动控制台：
./start.sh
```

`start.sh` 不读取 `.env`，也不包含默认 Key；调用者未设置 `DEEPSEEK_API_KEY` 时会立即拒绝启动。

受限网络下的构建提示：Dockerfile 已默认固定阿里云 PyPI 索引（`PIP_INDEX_URL`），且每个 `curl`
下载都带 `--retry`。JADX 与 Apktool 层从 `docker/vendor/`（本地检出、已被 git 忽略）复制而非
从 GitHub 下载，因此缓慢的 GitHub 路由不会卡住构建。如需刷新这些 vendored 工具，将替换后的
目录放到 `docker/vendor/jadx/` 与 `docker/vendor/apktool/` 下重新构建即可。

一次完整扫描只创建一个无密钥 keeper 容器，不会为每个小探索反复创建容器。每个
`task + attempt + role` 分配不复用的 Unix UID 与私有 HOME、`CODEX_HOME`、TMPDIR、cache
和可写 workspace；不同 role 依赖 Unix 权限互相隔离。扫描级 `jadx/`、`apktool/` 和
`archive/` 以 `/scan-input/*` 只读挂载。Codex 在这层容器边界内使用
`Sandbox.full_access`、`ApprovalMode.deny_all`，可直接使用 Bash、补丁、JADX、Apktool、
Android Platform 36 / Build Tools 36.1 和实时 Web Search；SDK 子 Agent fan-out 固定关闭。

keeper 启动时不获得 Provider Key。仅启动某个 UID worker 的 `docker exec` 继承
`DEEPSEEK_API_KEY`，密钥值不出现在 Docker argv、扫描清单、事件或镜像中；Codex 的 shell
环境策略也会从 Agent 执行的 Bash 子进程移除 Provider Key。当前开发版使用 Docker CLI；
后续切换 Engine API 时保持同一执行契约。

`APKSCANNER_CODEX_ISOLATION=host` 只用于个人机器诊断，必须同时设置
`APKSCANNER_ALLOW_HOST_CODEX=true`。它同样使用 full-access sandbox，但没有容器、UID 和
资源边界，不能作为默认部署方式。除非已验证外部 CLI 与固定 SDK 协议兼容性，否则不要
覆盖 `APKSCANNER_CODEX_BIN`。

Worker Protocol v3 已为每个 `task + attempt + role` 保持持久、非 ephemeral Thread；primary
自动轮次复用同一 Thread，替换 Worker 可通过 `thread_resume` 恢复。任务级 ADB/Proof Gateway、
实时 PoC/Binder Probe 回放、版本化 Python/MCP Capability 入口和监督 Campaign API 均已落地；
任意 Capability 自动发现、企业级 RBAC/egress 和完整跨进程 Session/Turn 投影仍是后续能力。详见
[`docs/codex-docker-architecture.zh-CN.md`](docs/codex-docker-architecture.zh-CN.md)。退役的
OpenCode 设计仅供历史追溯：
[`docs/opencode-deepseek.zh-CN.md`](docs/opencode-deepseek.zh-CN.md)。

动态设备池、独立复核、Android 16 PoC、稳定漏洞案例和特殊 Investigation Brief 的已实现接口见
[`docs/runtime-control-and-evolution.zh-CN.md`](docs/runtime-control-and-evolution.zh-CN.md)。

## 执行流水线

```
APK 上传
  → ZIP 安全检查、SHA-256 寻址
  → Apktool 反编译 + JADX 反编译（可选）
  → 生成组件级代码索引；区分 JADX 全局部分失败与目标类源码可用性
  → Manifest 解析：枚举 Activity、Service、Receiver、Provider、Deep Link
  → 内置规则引擎：17+ 条面向 MASVS 的发现
  → 发布 preliminary 报告
  → InvestigationPlanner 创建任务（每个导出组件一个，每个 Deep Link handler 一个）
  → 按风险优先级逐个进入入口探索：
      → 全局一次只领取一个任务，并在整个任务期间独占 ADB
      → 如配置 ADB：安装或复用目标 APK、可选安装 Probe APK、按策略重置测试状态
      → 访客基线：通过 adb shell 探索；Probe 可用时增加普通 App UID 快速调用
      → Agent 可持续分析并通过 apkscanner-proof 实时提交最终 PoC
      → 平台在同一设备会话中构建、回放、返回 Oracle 结果，失败后允许 Agent 修正再测
      → Codex 第二阶段（final_evaluation）：AI 做出最终判定
      → 证据校验：平台检查引用的 Evidence ID 是否存在，降级无效声明
      → 持久化带 Agent 判定的发现
  → 生成最终报告
```

等待中的任务可以直接取消；正在运行的任务可以从 Web 请求停止。控制面会终止对应 UID 的
Codex worker/进程组，保留已产生的关键事件并写入不可变的 `agent.cancellation`
审计证据。被停止的任务不会伪造新的最终判断，可按原有重试预算重新执行。

扫描详情的“探索任务”页提供扫描级 AI 总开关、Codex 后端选择和逐任务 AI
覆盖开关。ADB、Probe 或模型能力后续恢复后，可以“补扫信息不全项”，批量重跑
`blocked_device`、`inconclusive`、`timed_out`、`failed` 以及最终结果为
`inconclusive` 的任务；也可以对任意终态任务单独“重新分析”。补扫直接复用已有 Manifest、
Apktool、JADX/Smali、代码索引和静态 Evidence，不再次反编译。

## 判定与证据规则

| 判定 | 平台最低要求 |
| --- | --- |
| `supported_static` | 静态证据支持风险，至少引用一个 `static.*` Evidence ID |
| `refuted_static` | 静态证据表明攻击路径受保护、不可达或无实际安全影响 |
| `reproduced_blackbox` | 同一 request/test-case ID 的 Probe 调用+日志或专用 PoC 启动+日志成功关联，并由平台 Oracle 独立观察到具体危害 |
| `not_reproduced` | 同一 test-case/request ID 的普通 App UID 尝试 + 结果日志存在，且平台 Prover 明确产生 `oracle_refuted=true`；仅反驳已执行用例，不证明全局安全 |

Agent 声称的、不属于当前 Scan/Task 的 Evidence ID 会被移除。动态危害或负向 Oracle
证据不足时，平台只保留其由静态证据支撑的明确正向或负向判断；可选工具缺失不能成为
“信息不足”结论。真正缺少判定所需 Evidence ID 的结构化输出会被拒绝并重试。

每次扫描还会生成一份带摘要的 Android 威胁模型，固定普通第三方 App/guest 攻击者、
资产、信任边界与最终证据策略。Agent 必须为每个已测试 hypothesis 独立返回
source/control/sink/reachable path/boundary/counterevidence/proof gaps 证据元组；平台不会
再把任务级总判定批量套到所有 hypothesis。Finding 使用跨版本稳定的 `finding_id` 和
单次扫描唯一的 `occurrence_id`。扫描结束时会生成 `scan.seal` Evidence，对 APK、
威胁模型、任务结果、Finding、Evidence 与 Coverage 账本做内容摘要，便于比较和审计。

相同 APK 与相同静态工具链会复用内容寻址的 JADX/apktool/archive/代码索引缓存，但不会
继承旧任务或安全结论。不同版本按 package、签名证书和 versionCode 建立安全语义 Diff，
优先重放历史 PoC，并对 Manifest、DEX、native library、assets、`res/xml` 和 `res/raw`
变化重新生成调查种子。完整规则见
[版本安全演进规范](docs/version-security-evolution.md)，已知目标漏洞的盲测覆盖计划见
[BlueClaw 检测计划](docs/blueclaw-detection-plan.zh-CN.md)。

## 环境变量

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `APKSCANNER_DATA_DIR` | `.data` | SQLite、工作区、APK、证据、报告存储目录 |
| `APKSCANNER_DATABASE_URL` | Data 目录中的 SQLite | SQLAlchemy 数据库 URL |
| `APKSCANNER_FRONTEND_DIST` | 未设置 | FastAPI 提供的前端构建产物目录 |
| `APKSCANNER_HOST_ADB` | 从 PATH 探测 | 宿主真实 platform-tools `adb` 的绝对路径；`start.sh` 会解析并固定 |
| `APKSCANNER_ADB_SERIAL` | 未设置 | 远程云真机 ADB 序列号 |
| `APKSCANNER_PROBE_APK` | 未设置 | 已构建的 Probe APK 路径 |
| `APKSCANNER_ANDROID_SDK_ROOT` | Android SDK 环境变量/未设置 | 平台托管 Agent PoC 构建所用 SDK |
| `APKSCANNER_POC_ENABLED` | `true` | 是否允许经校验的源码型或 Agent 自建预编译 PoC APK |
| `APKSCANNER_POC_BUILD_TIMEOUT` | 180 秒 | PoC 单条构建命令超时（30–600 秒） |
| `APKSCANNER_POC_MAX_SOURCE_BYTES` | 512 KiB | 平台托管 PoC 源码工程上限（64 KiB–16 MiB） |
| `APKSCANNER_POC_MAX_APK_BYTES` | 128 MiB | Agent 自建预编译 PoC APK 上限 |
| `APKSCANNER_INVESTIGATOR_BACKEND` | `codex` | 默认调查后端：`codex` 或 `none` |
| `APKSCANNER_AGENT_PERMISSION_PROFILE` | `personal_lab` | `personal_lab` 开放完整反编译目录和可写工具分析；`strict` 保留仅结构化判断 |
| `APKSCANNER_CODEX_ENABLED` | `false` | 是否分派 Codex 调查 |
| `APKSCANNER_CODEX_ISOLATION` | `docker` | `docker` 或显式 `host` 降级 |
| `APKSCANNER_ALLOW_HOST_CODEX` | `false` | host 诊断模式的第二道显式开关 |
| `APKSCANNER_CODEX_DOCKER_IMAGE` | `apk-scanner-codex-worker:0.2.0` | 固定 Worker 镜像名称 |
| `APKSCANNER_CODEX_PROVIDER` | `deepseek` | 当前唯一允许的 Provider |
| `APKSCANNER_CODEX_MODEL` | `deepseek-v4-flash` | 当前唯一允许的模型 |
| `APKSCANNER_CODEX_REASONING_EFFORT` | `high` | `low`、`high` 或 `max` |
| `APKSCANNER_CODEX_MODEL_CATALOG` | `config/deepseek-models.json` | 固定 DeepSeek 模型目录 |
| `APKSCANNER_CODEX_WEB_SEARCH` | `live` | Codex Web Search 模式；当前契约要求 `live` |
| `APKSCANNER_CODEX_MAX_CONTAINERS` | `2` | 全局并行扫描容器上限 |
| `APKSCANNER_CODEX_MAX_SESSIONS` | `6` | 全局 UID session 上限 |
| `APKSCANNER_CODEX_MAX_SESSIONS_PER_SCAN` | `6` | 单扫描活动 Worker 上限；空闲可恢复 Worker 不占配额 |
| `APKSCANNER_CODEX_UID_MIN` / `APKSCANNER_CODEX_UID_MAX` | `21000` / `21999` | 扫描内不复用的 session UID 池 |
| `APKSCANNER_CODEX_CPU_LIMIT` / `APKSCANNER_CODEX_MEMORY_LIMIT` | `6` / `12g` | 单扫描容器资源上限 |
| `APKSCANNER_CODEX_TURN_TIMEOUT` | 3600 秒 | 单次 Codex 调用硬超时 |
| `APKSCANNER_CODEX_NO_EVENT_TIMEOUT` | 900 秒 | Worker 无事件超时 |
| `APKSCANNER_CODEX_BIN` | 内置 SDK 运行时 | 显式测试过的 Codex 二进制覆盖 |
| `APKSCANNER_ADAPTIVE_VERIFIER_ENABLED` | `true` | 为仍未闭环的静态风险运行一个扫描终局 Codex 验证任务 |
| `APKSCANNER_ADAPTIVE_VERIFIER_MIN_SEVERITY` | `info` | 纳入终局验证的最低严重等级；默认覆盖全部 `supported_static` Finding |
| `APKSCANNER_ADAPTIVE_VERIFIER_TIMEOUT` | 3600 秒 | 所有按提示词预算拆分的验证批次共享的总超时 |
| `APKSCANNER_ADAPTIVE_VERIFIER_PROMPT_MAX_CHARS` | `400000` | 单批传输安全提示词字符上限；有效范围为 `100000..900000` |
| `APKSCANNER_ADAPTIVE_VERIFIER_COPY_HOST_SSH` | `true` | 将宿主 OpenSSH 配置复制到终局验证器的私有 HOME |
| `APKSCANNER_ADAPTIVE_VERIFIER_SSH_SOURCE` | 宿主 `~/.ssh` | 运行时复制的 SSH 目录；设为空值可禁用 |
| `APKSCANNER_DEEPSEEK_BASE_URL` | DeepSeek 默认地址 | 可选的可信 HTTP(S) 网关 |
| `DEEPSEEK_API_KEY` | 未设置 | DeepSeek 凭据；只在 UID worker 的 exec 环境中注入 |
| `APKSCANNER_ANDROID_VERSION` | `16` | 报告的动态基线 Android 版本 |
| `APKSCANNER_ANDROID_API` | `36` | 平台托管 PoC 构建使用的 Android SDK API |
| `APKSCANNER_DEVICE_MIN_API` / `APKSCANNER_DEVICE_MAX_API` | `36` / `99` | 可接受的云真机 API 范围；默认只接受 Android 16 及以上 |
| `APKSCANNER_ALLOW_LEGACY_DEVICE_SMOKE` | `false` | 允许低于 API 36 的本地兼容性冒烟；证据不可产出 Android 16 裁决 |
| `APKSCANNER_DEVICE_INSTALL_POLICY` | `install_or_reuse` | 目标安装策略：`replace`、`install_or_reuse` 或 `reuse_installed` |
| `APKSCANNER_DEVICE_RESET_POLICY` | `never` | `never` 是保留登录态、首次协议和本地数据的硬策略；`per_round`、`per_test` 仅用于可丢弃 fixture |
| `APKSCANNER_MAX_UPLOAD_BYTES` | 512 MiB | 上传大小限制 |
| `APKSCANNER_TASK_TIMEOUT` | 14400 秒 | 每个调查任务的总时间预算 |
| `APKSCANNER_TASK_MAX_ATTEMPTS` | 2 | 重试次数预算 |

调查 Agent 与终局 Adaptive Verifier 不设置工具调用、PoC 重建、fallback 策略、Proof Replay、
探索轮次、单轮测试或候选数量上限。任务/扫描生命周期、取消、设备租约、协议校验和隔离边界仍是
运行保障。Critic、Rescue、Final 每个阶段在单任务中仍最多启动一次；该限制只控制辩论阶段扇出，
不限制获准 Turn 内的审查深度。

## 验证

```bash
pytest
ruff check backend
cd frontend && npm run lint && npm run build

# 可选：要求 root、Docker 和已经构建的固定镜像
APKSCANNER_RUN_DOCKER_TESTS=1 pytest -q backend/tests/test_codex_executor.py
```

测试语料库使用合成 APK 形 ZIP 文件，包含安全/有漏洞的 Manifest 控制项。在将其作为发布门禁之前，请添加签名夹具 APK 和真实的 Android 16 设备测试。

变更 API 调用需要 `X-APKScanner-Request: console` 请求头，Web 控制台会自动添加。服务器绑定 `127.0.0.1` 并拒绝不受信任的 Host 头。

## 安全边界

- 仅限已授权的公司 APK 和专用测试后端。
- APK 代码、资源、字符串、日志和网页内容均为不可信的 prompt 数据。
- Probe APK 是故意危险的工具，必须永远不保留在员工/生产设备上。
- 无源码或服务端权限上下文可用；AUTH 和 PRIVACY 覆盖为部分覆盖。
- v1 覆盖范围：单 APK、专用 Android 测试设备；默认保留目标应用数据，可丢弃 fixture 才显式使用 `pm clear`（而非完整设备快照）。
- Codex Docker Worker 具有只读扫描输入和每 role 独立 UID 的可写工作区；Codex sandbox
  在容器内部为 full access。容器目前不直接挂载设备或 Docker socket。
- Agent 容器对其所选模型 provider 仍保留出站网络连接。团队部署前需将每个 Worker 的出站流量限制到批准的 provider/网关。
- DeepSeek 接收有边界的任务上下文和证据摘要。在用于生产 APK 之前，请确认公司的数据处理、留存、区域和网关策略。

## 项目结构

```
ApkScanner/
  README.md / README.zh-CN.md       # 项目说明
  pyproject.toml                     # Python 项目配置
  Dockerfile.worker                  # Codex Worker Docker 镜像
  docs/
    architecture.zh-CN.md            # 架构与判定模型文档
    codex-docker-architecture.zh-CN.md # Codex Docker 目标架构与实施门禁
    opencode-deepseek.zh-CN.md       # 已退役 OpenCode 历史设计
    release-regression.zh-CN.md      # 版本差分与漏洞回归复验设计
  config/
    benchmark-ground-truth.example.json # 私有真值配置示例
  backend/
    apkscanner/                      # Python 主包
      main.py                        # FastAPI 应用工厂
      cli.py                         # 命令行入口 (scanctl)
      api.py                         # REST API 路由
      config.py                      # 环境变量配置
      db.py / models.py              # SQLAlchemy 数据库与 ORM
      schemas.py / enums.py          # Pydantic Schema 与枚举
      orchestrator.py                # 核心流水线控制器
      static_analysis.py             # APK 静态分析（ZIP/签名/反编译）
      manifest.py                    # AndroidManifest 解析
      rules.py                       # 内置规则引擎（17+ 规则）
      planner.py                     # 调查任务规划器
      tools.py                       # 外部工具调用封装
      device.py                      # ADB 远程设备适配器
      codex_runner.py                # Codex AI 调查集成
      codex_worker.py                # Docker Worker 入口
      codex_executor.py              # 扫描级容器与 UID exec 管理
      agent_workspace.py             # Agent 工作区、权限和 UID 租约
      agent_execution.py             # 冻结执行/Provider/Phase 契约
      evidence.py / artifacts.py     # 证据记录与内容寻址存储
      reports.py                     # 报告生成（JSON/HTML/SARIF）
    tests/                           # pytest 测试套件
  frontend/                          # React + TypeScript + Vite + Tailwind 控制台
    src/
      App.tsx                        # 单页应用
      types.ts / api.ts / lib.ts     # 类型、API 客户端、工具函数
      components/ui.tsx              # UI 组件
  probe/                             # Android Probe APK（Java）
    app/src/main/
      AndroidManifest.xml            # 故意导出的 BroadcastReceiver
      java/.../ProbeReceiver.java    # 跨应用调用执行器
```

## 扩展方式

- **漏洞类型**：在 `InvestigationPlanner` 中增加 Task 类型/假设，在平台请求校验器中增加对应的最小安全动作集。
- **设备供应商**：保持 `prepare → reset/authenticate/probe → cleanup` 和 Evidence 输出契约，替换 ADB 租约实现。
- **新判定级别**：先定义所需的不可伪造 Evidence 条件，再扩展 Agent Schema 和报告层，不能仅改 prompt。

## 上线前仍需完成

- 用公司真实签名 APK 建立回归语料和误报基线。
- 在目标云真机供应商上同时覆盖可选 Probe 快速路径和 Agent 专用 PoC 的 API 36 集成测试。
- 用真实 DeepSeek Key 完成 Responses 计费 smoke，并实现企业网络出口策略。
- 完成持久 Thread/resume、ADB/Proof Gateway、MCP/脚本入口和平台监督 Agent 接口。
- 为需要业务账号态的专项测试另行设计显式 fixture，不让它阻塞普通入口审计。
- 根据发布风险决定人工 gate；当前产品刻意不自动 gate。
