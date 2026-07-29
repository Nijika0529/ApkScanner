# APK Scanner

以证据为导向的 Android APK 安全扫描控制面，提供确定性攻击面覆盖、远程 ADB 验证和可选的 Codex 或 OpenCode + DeepSeek 调查。

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
- 默认 3 个入口探索 worker 并发；所有扫描共享 1 条优先级/FIFO ADB 队列，模型与 Review 阶段不占设备。
- 远程 ADB 适配器、普通 App UID 的 Probe APK 协议、客观 Oracle、`pm clear` 清理和 App Link 状态检查/重置。
- 可选的 MobSF 上传/报告归一化，缺失时显式标注降级覆盖。
- 官方 `openai-codex==0.144.4` 集成：严格 JSON Schema、全新线程、无子 Agent fan-out、一轮平台介导的补充测试、证据支撑的结果降级。
- 固定版本 `@opencode-ai/sdk`/OpenCode `1.18.4` 集成（适配 DeepSeek）：稳定的非思考工具分析器与独立 StructuredOutput 定稿器，带 Ajv/语义/平台 ID 校验、personal-lab 工作区/ADB 能力和完整调用审计。
- 可选的每任务 Docker Worker，带隔离的 task-attempt 挂载和资源/能力限制。
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
  --investigator opencode

scanctl evaluate --scan-id SCAN_ID \
  --truth /absolute/path/to/ground-truth.json
```

`candidate`、`inconclusive`、人工 accepted 和没有平台证明的模型描述都不算“发现”。普通
Probe 成功只记录 `execution_demonstrated`；动态真值还要求领域 Prover 给出平台可校验的
`security_impact_observed`。真值默认使用 `minimum_proof: dynamic`；仅仅发现导出声明、
危险 API 或成功打开组件不能得分。平台已确认但无法匹配任何真值的 Finding 会计为 false
positive，未证明的 AI 输出则单独列为噪声。

Web 上传对话框和 CLI 均可将每次扫描锁定为 `codex`、`opencode` 或 `none`；`configured` 在扫描创建时解析服务默认值，并随该扫描持久化。

## 动态设备配置

配置已在本地 ADB 服务器中记录的远程 Android 16 ADB 序列号或端点：

```bash
adb connect cloud-device.example:5555
export APKSCANNER_ADB_SERIAL=cloud-device.example:5555
```

在 Android SDK 36 工作站上构建 [`probe/`](probe/) 中的故意导出辅助程序，仅安装在专用测试设备上，并配置其路径：

```bash
export APKSCANNER_PROBE_APK="$PWD/probe/app/build/outputs/apk/debug/app-debug.apk"
```

没有 ADB 或 Probe APK 时，扫描仍会完成，并显式标注动态覆盖为 blocked。`adb shell` 成功会保留为独立身份，永远不会被视为等同于普通第三方应用。

当 `APKSCANNER_ANDROID_SDK_ROOT` 指向包含 API 36 platform 和 build-tools 的 Android SDK
时，OpenCode Agent 可以在隔离工作区的 `poc/` 下生成 Manifest/Java 源码型 PoC，也可以
自行构建签名 APK。控制面会校验路径、大小、签名、包名和启动组件，登记源码/APK SHA-256，
再进入同一 ADB 队列，以普通应用 UID 安装和启动，通过随机 nonce 关联结果，最后卸载。
host `personal_lab` 模式可用原始 ADB 做探索，但普通 App 可利用性仍须由平台 Probe/PoC
证据确认。PoC 自报影响仍只是声明，不能单独满足平台实际危害证明条件。

单 ADB 模式默认允许 3 个入口 worker 并发分析，但所有 worker 共用一条全局显式设备队列：
风险优先级高的任务先执行，相同优先级按入队顺序执行。设备租约只覆盖安装、探测和清理；
模型思考阶段释放 ADB，等待设备的时间不消耗单任务 20 分钟预算。
任务在 Web 中依次显示 `等待云真机 → 正在分析 → 已判断/未形成判断`，排队阶段可以立即
取消。每次租约只覆盖健康检查、安装、普通应用 UID 探测、经平台接受的补充测试和最终清理；
完成一段设备操作后先清理并释放，再进入 AI 规划、Critic、Review 或最终判断。AI 后续申请
测试时会重新排队并再次 prepare，避免不同 APK 的应用状态、logcat 和 App Link 状态相互
污染。队列等待时间、设备占用时间和每次获取/释放事件都会写入任务结果。

## Codex 配置

Codex 是可选功能。Docker 是安全的默认隔离模式。构建固定版本的 Worker，提供显式的 Codex 认证文件或 `OPENAI_API_KEY`，然后启用调查：

```bash
docker build -f Dockerfile.worker -t apk-scanner-worker:0.1.0 .
export APKSCANNER_CODEX_AUTH_FILE=/absolute/path/to/codex/auth.json
export APKSCANNER_CODEX_ISOLATION=docker
export APKSCANNER_CODEX_ENABLED=true
scanctl capabilities --deep
```

入口 Worker 默认为 `gpt-5.6-terra` / medium 复杂度。集成为每任务启动全新线程，设置 `agents.max_threads=1`，使用严格的结果 Schema，并拒绝不支持的 SDK 版本。除非你明确测试过外部 CLI 与固定 SDK 的兼容性，否则不要设置 `APKSCANNER_CODEX_BIN`；默认使用内置的匹配运行时。

`APKSCANNER_CODEX_ISOLATION=host` 是供个人受控机器使用的显式降级模式。它不提供 Worker 文件系统边界，不应作为团队部署的默认配置。

## OpenCode + DeepSeek 配置

OpenCode 同样为可选功能，Docker 是默认模式。集成将 SDK 和 CLI 一同固定至 `1.18.4` 版本；使用 DeepSeek 内置 provider，稳定基线与默认模型为 `deepseek-v4-flash`。

```bash
docker build \
  -f Dockerfile.opencode-worker \
  -t apk-scanner-opencode-worker:0.1.0 \
  .

export DEEPSEEK_API_KEY=...
export APKSCANNER_INVESTIGATOR_BACKEND=opencode
export APKSCANNER_OPENCODE_ISOLATION=docker
export APKSCANNER_OPENCODE_ENABLED=true
scanctl capabilities --deep
```

若在个人受控主机上使用 host 降级模式，安装固定版本的 Worker 依赖并选择 host 隔离：

```bash
npm ci --prefix opencode-worker
export DEEPSEEK_API_KEY=...
export APKSCANNER_OPENCODE_ISOLATION=host
export APKSCANNER_OPENCODE_ENABLED=true
export APKSCANNER_INVESTIGATOR_BACKEND=opencode
scanctl capabilities --deep
```

Host Worker 为每次调用创建私有的临时 HOME/XDG 目录树以及认证过的 loopback OpenCode
服务器。默认 `personal_lab` 路径先运行关闭思考的工具分析器，开放 `read`、`glob`、
`grep`、`bash`、完整只读反编译目录和按 `task_id + attempt` 隔离的可写 workspace；
随后由新的无工具 StructuredOutput 会话定稿。host 模式可用原始 ADB 和授权网络做探索，
但要计入证明的 Android 动作仍由 Python 控制面验证并执行。设置
`APKSCANNER_AGENT_PERMISSION_PROFILE=strict` 可回到单次无工具定稿。
Host 模式不提供 PID/同 UID 进程隔离；同机 Agent 可能读取控制面进程可见的信息，因此
它只适合个人受控调试，不能作为凭据隔离边界。生产或处理不受信任 APK 时使用默认 Docker
模式。

`personal_lab` 的分析器和定稿器都关闭思考，避免无界 Thinking 工具循环。只有显式设置
`APKSCANNER_OPENCODE_THINKING_EXPLORER=true` 才进入旧的实验性思考工具循环；定稿器
始终关闭思考并禁用工具。

DeepSeek 思考模式拒绝任何 `tool_choice`，而 OpenCode 1.18.4 会注入
`tool_choice: auto`。一次性 Worker 内的 loopback 兼容代理只在
`thinking.type=enabled` 时删除该字段，同时完整保留 OpenCode 工具循环以及
`reasoning_content` 回放。定稿器始终关闭思考，使用 OpenCode `StructuredOutput`
（`tool_choice: required`），随后再通过 Ajv、平台语义规则以及当前任务
Hypothesis/EntryPoint 白名单校验；每次纠正都使用全新会话，避免
DSML/tool-call 上下文污染。memo-writer 只保留在显式开启的实验性 Explorer 中，不参与
正常扫描。

当前使用默认的 `deepseek-v4-flash` 跑扫描、动态申请和最终裁决全链路。文本输出型
`deepseek-v4-pro` 无法满足强制 StructuredOutput 契约，会在能力检查时提前拒绝；失败时
不会静默换模型。`scanctl capabilities --deep` 会执行一次很小但真实、
会计费的非思考结构化请求。可通过 `APKSCANNER_DEEPSEEK_BASE_URL` 指定企业兼容网关；
远程网关必须使用 HTTPS，纯 HTTP 仅允许 loopback。官方地址应填写
`https://api.deepseek.com`，不要附加 `/v1`。URL 中的凭据、查询参数和片段会被拒绝，
控制面通过一次性 stdin 请求把真实 Key 交给 Worker；Worker 在校验业务 payload 前提取
并删除该内部字段，且启动环境从一开始就不含真实 Key，避免 `/proc/*/environ` 泄漏。
兼容代理只在内存中保留真实 Key，OpenCode 仅获得一次性 loopback 凭据；配置内容和本地
Server 凭据也会从 Bash 子进程环境删除。已退役的
`deepseek-chat` / `deepseek-reasoner` 也会被拒绝。

实现原理、协议、安全控制及升级清单参见 [`docs/opencode-deepseek.zh-CN.md`](docs/opencode-deepseek.zh-CN.md)。

添加 MobSF 广度扫描：

```bash
export APKSCANNER_MOBSF_URL=https://mobsf.internal.example
export APKSCANNER_MOBSF_API_KEY=...
```

## 执行流水线

```
APK 上传
  → ZIP 安全检查、SHA-256 寻址
  → Apktool 反编译 + JADX 反编译（可选）
  → 生成组件级代码索引；区分 JADX 全局部分失败与目标类源码可用性
  → Manifest 解析：枚举 Activity、Service、Receiver、Provider、Deep Link
  → 内置规则引擎：17+ 条面向 MASVS 的发现
  → 可选 MobSF 广度静态扫描
  → 发布 preliminary 报告
  → InvestigationPlanner 创建任务（每个导出组件一个，每个 Deep Link handler 一个）
  → 默认最多 3 个任务并发进入入口探索：
      → 任务 worker 按优先级领取
      → 如配置 ADB：安装或复用 APK、安装 Probe APK、按策略重置测试状态
      → 访客探测：对每个入口通过 adb shell 和 Probe APK 广播分发
      → 清理并释放唯一 ADB，再由 AI 进行 test_planning
      → AI 默认最多请求 8 个限定补充测试（可配置上限 1000）
      → 平台验证申请；如需执行则重新进入单设备队列，prepare 后串行执行并再次释放
      → Codex 第二阶段（final_evaluation）：AI 做出最终判定
      → 证据校验：平台检查引用的 Evidence ID 是否存在，降级无效声明
      → 持久化带 Agent 判定的发现
  → 生成最终报告
```

等待中的任务可以直接取消；正在运行的任务可以从 Web 请求停止。控制面会中断 Codex turn
或终止 OpenCode worker，保留已产生的关键事件并写入不可变的 `agent.cancellation`
审计证据。被停止的任务不会伪造新的最终判断，可按原有重试预算重新执行。

扫描详情的“探索任务”页提供扫描级 AI 总开关、Codex/OpenCode 后端选择和逐任务 AI
覆盖开关。ADB、Probe 或模型能力后续恢复后，可以“补扫信息不全项”，批量重跑
`blocked_device`、`inconclusive`、`timed_out`、`failed` 以及最终结果为
`inconclusive` 的任务；也可以对任意终态任务单独“重新分析”。补扫直接复用已有 Manifest、
Apktool、JADX/Smali、代码索引和静态 Evidence，不再次反编译。

## 判定与证据规则

| 判定 | 平台最低要求 |
| --- | --- |
| `supported_static` | 静态证据支持风险，至少引用一个 `static.*` Evidence ID |
| `refuted_static` | 静态证据表明攻击路径受保护、不可达或无实际安全影响 |
| `reproduced_blackbox` | 同一随机 request ID 的 Probe APK 调用 + Probe 结果日志，且 Probe 返回 success |
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

## 环境变量

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `APKSCANNER_DATA_DIR` | `.data` | SQLite、工作区、APK、证据、报告存储目录 |
| `APKSCANNER_DATABASE_URL` | Data 目录中的 SQLite | SQLAlchemy 数据库 URL |
| `APKSCANNER_FRONTEND_DIST` | 未设置 | FastAPI 提供的前端构建产物目录 |
| `APKSCANNER_ADB_SERIAL` | 未设置 | 远程云真机 ADB 序列号 |
| `APKSCANNER_PROBE_APK` | 未设置 | 已构建的 Probe APK 路径 |
| `APKSCANNER_ANDROID_SDK_ROOT` | Android SDK 环境变量/未设置 | 平台托管 Agent PoC 构建所用 SDK |
| `APKSCANNER_POC_ENABLED` | `true` | 是否允许经校验的源码型或 Agent 自建预编译 PoC APK |
| `APKSCANNER_POC_BUILD_TIMEOUT` | 180 秒 | PoC 单条构建命令超时（30–600 秒） |
| `APKSCANNER_POC_MAX_SOURCE_BYTES` | 512 KiB | 平台托管 PoC 源码工程上限（64 KiB–16 MiB） |
| `APKSCANNER_POC_MAX_APK_BYTES` | 128 MiB | Agent 自建预编译 PoC APK 上限 |
| `APKSCANNER_INVESTIGATOR_BACKEND` | `codex` | 默认调查后端：`codex`、`opencode` 或 `none` |
| `APKSCANNER_AGENT_PERMISSION_PROFILE` | `personal_lab` | `personal_lab` 开放完整反编译目录和可写工具分析；`strict` 保留仅结构化判断 |
| `APKSCANNER_CODEX_ENABLED` | `false` | 是否分派 Codex 调查 |
| `APKSCANNER_CODEX_ISOLATION` | `docker` | `docker` 或显式 `host` 降级 |
| `APKSCANNER_CODEX_DOCKER_IMAGE` | `apk-scanner-worker:0.1.0` | Worker 镜像名称 |
| `APKSCANNER_CODEX_AUTH_FILE` | 未设置 | 仅挂载到 Worker 中的认证文件 |
| `APKSCANNER_CODEX_BIN` | 内置 SDK 运行时 | 显式测试过的 Codex 二进制覆盖 |
| `APKSCANNER_OPENCODE_ENABLED` | `false` | 是否启用 OpenCode + DeepSeek 调查 |
| `APKSCANNER_OPENCODE_MODEL` | `deepseek-v4-flash` | DeepSeek 模型 ID；文本型 V4 Pro 会被拒绝 |
| `APKSCANNER_OPENCODE_THINKING_EXPLORER` | `false` | 实验性的旧 Thinking/工具循环 |
| `APKSCANNER_OPENCODE_REASONING_EFFORT` | `high` | 实验性 Explorer 强度：`high` 或 `max` |
| `APKSCANNER_OPENCODE_AGENT_STEPS` | 1000 | 实验性 Explorer 步数预算（50–1000） |
| `APKSCANNER_OPENCODE_ISOLATION` | `docker` | `docker` 或显式 `host` 降级 |
| `APKSCANNER_OPENCODE_DOCKER_IMAGE` | `apk-scanner-opencode-worker:0.1.0` | Worker 镜像名称 |
| `APKSCANNER_OPENCODE_NODE_BIN` | PATH 中的 `node` | Host 模式下的 Node.js 覆盖 |
| `APKSCANNER_OPENCODE_WORKER_DIR` | 仓库 `opencode-worker/` | Host Worker 目录 |
| `APKSCANNER_DEEPSEEK_BASE_URL` | DeepSeek 默认地址 | 可选的可信 HTTP(S) 网关 |
| `DEEPSEEK_API_KEY` | 未设置 | DeepSeek 凭据，通过一次性 stdin 请求传递给选定的 Worker |
| `APKSCANNER_MOBSF_URL` / `APKSCANNER_MOBSF_API_KEY` | 未设置 | 可选 MobSF API |
| `APKSCANNER_ANDROID_VERSION` | `16` | 报告的动态基线 Android 版本 |
| `APKSCANNER_ANDROID_API` | `36` | 平台托管 PoC 构建使用的 Android SDK API |
| `APKSCANNER_DEVICE_MIN_API` / `APKSCANNER_DEVICE_MAX_API` | `21` / `99` | 可接受的云真机 API 范围 |
| `APKSCANNER_DEVICE_INSTALL_POLICY` | `install_or_reuse` | 目标安装策略：`replace`、`install_or_reuse` 或 `reuse_installed` |
| `APKSCANNER_DEVICE_RESET_POLICY` | `per_round` | `per_test`、`per_round` 或 `never`；单条测试可覆盖 |
| `APKSCANNER_MAX_UPLOAD_BYTES` | 512 MiB | 上传大小限制 |
| `APKSCANNER_TASK_TIMEOUT` | 1200 s | 每个调查任务的时间预算 |
| `APKSCANNER_TASK_MAX_ATTEMPTS` | 2 | 重试次数预算 |
| `APKSCANNER_AGENT_CONCURRENCY` | 3 | 全局入口探索 worker 上限（1–8）；ADB 仍固定单并发 |
| `APKSCANNER_AGENT_MAX_ROUNDS` | 3 | 每任务最大自适应 AI/设备轮数（1–5） |
| `APKSCANNER_AGENT_TESTS_PER_ROUND` | 8 | 每轮最多接受的 AI 测试数（1–1000） |

## 验证

```bash
pytest
ruff check backend
cd frontend && npm run lint && npm run build
cd ../opencode-worker && npm run check && npm test
```

测试语料库使用合成 APK 形 ZIP 文件，包含安全/有漏洞的 Manifest 控制项。在将其作为发布门禁之前，请添加签名夹具 APK 和真实的 Android 16 设备测试。

变更 API 调用需要 `X-APKScanner-Request: console` 请求头，Web 控制台会自动添加。服务器绑定 `127.0.0.1` 并拒绝不受信任的 Host 头。

## 安全边界

- 仅限已授权的公司 APK 和专用测试后端。
- APK 代码、资源、字符串、日志和网页内容均为不可信的 prompt 数据。
- Probe APK 是故意危险的工具，必须永远不保留在员工/生产设备上。
- 无源码或服务端权限上下文可用；AUTH 和 PRIVACY 覆盖为部分覆盖。
- v1 覆盖范围：单 APK、专用 Android 测试设备、`pm clear`（而非完整设备快照）。
- Codex Docker Worker 具有只读扫描挂载。OpenCode personal-lab 为每个任务提供独立可写
  工作区，并暴露完整只读 Apktool/JADX/archive 根目录；允许本地辅助工具和 APK 构建，
  host 模式配置 ADB 后还可直接探索设备。
- Agent 容器对其所选模型 provider 仍保留出站网络连接。团队部署前需将每个 Worker 的出站流量限制到批准的 provider/网关。
- DeepSeek 接收有边界的任务上下文和证据摘要。在用于生产 APK 之前，请确认公司的数据处理、留存、区域和网关策略。

## 项目结构

```
ApkScanner/
  README.md / README.zh-CN.md       # 项目说明
  pyproject.toml                     # Python 项目配置
  Dockerfile.worker                  # Codex Worker Docker 镜像
  Dockerfile.opencode-worker         # OpenCode Worker Docker 镜像
  docs/
    architecture.zh-CN.md            # 架构与判定模型文档
    opencode-deepseek.zh-CN.md       # OpenCode + DeepSeek 实现文档
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
      mobsf.py                       # MobSF 广度扫描集成
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

- **广度引擎**：在 `MobSFAdapter` 或新的静态 Adapter 中归一化为 `FindingDraft`，同时增加引擎覆盖。
- **漏洞类型**：在 `InvestigationPlanner` 中增加 Task 类型/假设，在平台请求校验器中增加对应的最小安全动作集。
- **设备供应商**：保持 `prepare → reset/authenticate/probe → cleanup` 和 Evidence 输出契约，替换 ADB 租约实现。
- **新判定级别**：先定义所需的不可伪造 Evidence 条件，再扩展 Agent Schema 和报告层，不能仅改 prompt。

## 上线前仍需完成

- 用公司真实签名 APK 建立回归语料和误报基线。
- 在目标云真机供应商上编译/安装 Probe APK 并跑 API 36 集成测试。
- 构建并验证 Docker Worker 镜像、企业 Codex 登录方式和网络出口策略。
- 为需要业务账号态的专项测试另行设计显式 fixture，不让它阻塞普通入口审计。
- 根据发布风险决定人工 gate；当前产品刻意不自动 gate。
