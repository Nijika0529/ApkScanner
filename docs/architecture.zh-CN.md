# APK Scanner 架构与判定模型

## 目标与边界

系统面向公司待上线、仅提供 APK 的安全复核。控制面运行在个人电脑本地，动态面只访问已授权的 Android 16 / API 36 云真机和专用测试后端。它提供覆盖面、证据和人工复核辅助，不自动阻断发布。

v1 的固定边界是：单 APK、单用户、单测试账号、`pm clear` 复位、无源码、无服务端权限模型。无法验证的控制项必须显示为 gap，不允许用“扫描成功”替代“已覆盖”。

## 执行流水线

```mermaid
flowchart LR
    A[APK intake] --> B[ZIP/签名/Manifest/JADX·apktool/MobSF]
    B --> C[版本化 Security IR]
    C --> D[入口枚举与平台任务规划]
    D --> E[Guest 黑盒 + Probe APK]
    E --> F[登录流程回放]
    F --> G[Authenticated 黑盒]
    E --> H[Frida 旁路观察]
    G --> I[选定 Agent 提出下一组测试]
    H --> I
    I --> J{需要补充测试?}
    J -- 是 --> K[平台校验并执行本轮最多 4 个用例]
    K --> R{仍有轮次与预算?}
    R -- 是 --> I
    R -- 否 --> L[选定 Agent 最终判断]
    J -- 否 --> L
    L --> M[Evidence ID 与结论级别校验]
    M --> N[Web / JSON / HTML / SARIF + 人工复核]
```

平台而不是 Codex/OpenCode 负责 fan-out。一个导出组件对应一个任务；同一 handler 的 Deep Links 合并成一个任务。Agent 不能创建子 Agent，也不能直接把自己的文字当作复现证据。默认最多进行 3 个自适应测试轮次、每轮接受 4 个受限测试：只能使用当前任务的入口 ID；Deep Link 和 Provider URI 必须保持 Manifest 声明的 scheme、host/authority 和 port；额外参数有数量、键名、类型和长度上限。每轮证据都会回灌下一次判断，最终再执行禁止申请新动作的证据总结。轮次和单轮测试数可在 1–5 / 1–12 的安全范围内配置。每次扫描在创建时固化 `codex`、`opencode` 或 `none`，服务默认值的后续变更不会让同一扫描混用模型后端。

一个任务以 `task_id + attempt` 作为平台逻辑探索运行。为保持一次性 worker 的隔离边界，目前每次物理模型调用使用新的 Codex thread 或 OpenCode session；下一轮会重新装载完整的静态上下文、累计 Evidence 和已执行测试，因此不会依赖供应商侧隐藏状态。Web 将这些物理调用统一聚合到同一个任务时间线。

静态阶段结束即发布 preliminary report，并继续动态任务。外部工具、MobSF 请求和每个任务都有超时；超过 4 小时 preliminary 目标或 24 小时整单预算会写入事件及 coverage gap。

JADX 的非零退出码不直接等同于反编译不可用。平台把结果归一化为完整成功、部分成功、部分超时或工具失败，并生成 `code_index.json`：逐个组件记录目标类是否位于失败列表、可用 Java/Smali 路径、文件 SHA-256 和有界源码片段。Codex 和 OpenCode 都接收相同的目标级代码上下文；OpenCode 不需要文件系统权限。历史扫描在任务重试时可从已有 workspace 与 `static.jadx` Evidence 懒生成索引，不会为了补上下文再次运行 JADX。

## 信任边界

| 区域 | 可访问内容 | 约束 |
| --- | --- | --- |
| 本地控制面 | SQLite、APK、workspace、evidence | FastAPI 仅监听 loopback；变更 API 需要自定义请求头；内容寻址文件拒绝 symlink/摘要冲突 |
| Codex Docker worker | 当前 scan workspace、显式 Codex auth、模型网络 | 每次调用新容器、只读 bind mount/SDK sandbox/rootfs、无 ADB 参数、丢弃 capabilities、PID/CPU/内存限制；默认模式 |
| Codex host worker | 只读 workspace 与模型网络 | 仅作为显式 `host` 降级模式；developer instructions 禁止 ADB/目标网络请求，设备动作仍走平台 |
| OpenCode + DeepSeek Docker worker | 平台生成的 task JSON、DeepSeek API | 不挂载 scan workspace；只读 rootfs、临时 HOME、丢弃 capabilities；禁用文件/Shell/Web/MCP/子 Agent；V4 Pro 无工具并省略 `tool_choice`，Flash 仅允许内部 StructuredOutput |
| OpenCode + DeepSeek host worker | 平台生成的 task JSON、DeepSeek API | 每次调用使用临时 HOME/XDG 与带随机 Basic Auth 的 loopback server；仍仅适合个人受控环境 |
| 云真机 | 目标 APK、Probe APK、测试账号 | 固定 Android 16/API 36；串行 lease；任务前后 `pm clear`；不声称完整快照复位 |
| Probe APK | 以普通 App UID 调用目标入口 | 只接受最初发送者为 shell/root 的调度；仍只允许安装在专用测试设备 |
| MobSF | 上传 APK并返回广度扫描报告 | 可选、显式 URL/API Key；失败不阻断内置基线，但标为 tool gap |

APK、反编译代码、资源、日志、网页和工具输出都属于不可信数据。两个 Agent 后端的 developer instructions 都明确禁止服从这些内容中的指令。Codex Docker worker 只有只读 workspace；OpenCode worker 连 workspace 都不挂载，只接收控制面整理后的 JSON。云真机操作始终由 Python 平台校验后执行，Agent 不持有 ADB 能力。模型网络出口应分别限制到企业 Codex 或获批的 DeepSeek/代理端点。

## Security IR

核心对象全部带 `schema_version`：

- `Scan`：制品摘要、包/版本/SDK、签名、工具版本、状态和时限。
- `EntryPoint`：Activity、Alias、Service、Receiver、Provider、Deep Link；保存有效 exported 原因、权限保护级别、Intent Filter 和 URI 模板。
- `InvestigationTask`：入口集合、假设、前置条件、允许副作用、设备基线、线程/turn 和重试次数。
- `Evidence`：内容摘要、不可变文件、命令 argv、退出码、调用身份、登录态、request/test-case ID。
- `Finding`：规则、MASVS/CWE、严重性、置信度、结论级别、入口和 Evidence 引用、人工结论。
- `CoverageItem`：每个 MASVS 域和每个入口在 static、deterministic、blackbox、authenticated、agent、instrumented 阶段的状态及 gap。

## 结论和证据规则

| 结论 | 平台最低条件 |
| --- | --- |
| `supported_static` | 引用了本 scan 的 `static.*` Evidence ID |
| `reproduced_blackbox` | 同一随机 request ID 的 Probe APK 调用、Probe 结果日志，且 Probe 返回 success；`adb shell` 成功不等价 |
| `observed_instrumented` | Frida 成功加载且至少产生一个非 hook-error 观察事件 |
| `not_reproduced` | 同一 request ID 的普通 App UID 尝试与结果日志存在；它只描述已执行用例，不证明全局安全 |
| `inconclusive` | 证据不足、工具缺失、预算耗尽或前置条件失败 |

Agent 声称但不属于本 scan/task 的 Evidence ID 会被删除。需要证据的结论不满足条件时自动降级为 `inconclusive`。重试产生不同结果时，旧 Agent Finding 不删除，但会标记为已被新 turn 取代且降级为 inconclusive。

## AI 内容审计

每次实际模型调用都会形成独立 `audit_id`，并按调用阶段写入内容寻址的不可变 Evidence：

1. `agent.request`：后端、provider、模型、SDK、隔离方式、developer instructions、精确
   prompt、输出 JSON Schema 和工具边界；
2. `agent.events`：SDK 会话、turn/step、输出校验、工具生命周期、错误等规范化关键事件；
3. `agent.response`：thread/turn、平台收到的结构化原始输出和 token/费用 usage；
4. `agent.test_validation`：Agent 申请的测试、平台接受/拒绝的测试、拒绝原因、实际执行
   用例及其 Evidence ID；
5. `agent.validation`：模型声称的结论和 Evidence ID、平台接受/拒绝的 Evidence ID、是否
   降级以及最终落库结果；
6. `agent.error`：已发起但失败的模型调用错误；
7. `agent.cancellation`：用户停止请求、运行时确认、后端和任务阶段；此前已产生的事件继续
   保留，被停止的调用不生成新的最终结论。

OpenCode 审计还记录实际输出通道。`deepseek-v4-pro` 保持思考模式，但使用无工具的
`format=text`：prompt 携带精确 JSON Schema，worker 用 Ajv 本地校验，失败后最多进行
2 次同 session 纠正；每轮 prompt、原始文本、校验错误和 usage 都写入审计。
`deepseek-v4-flash` 继续使用 OpenCode 的内部 StructuredOutput 工具。这样 Pro 请求不会
携带与思考模式冲突的 `tool_choice`，两个通道最终仍进入相同的平台证据校验。

Codex 的 app-server notification 与 OpenCode 的 `event.subscribe()` SSE 会先归一化为
`exploration.*` 平台事件。Web 只展示假设、阶段、动作、证据和结论等关键事件，不展示或
持久化隐藏思维链；模型必须通过结构化字段提供可审计的简短理由。

这些记录不包含模型 API Key。每份内容在写入时计算 SHA-256，Web 的“AI 审计”页和 JSON
报告展示同一份内容及摘要；Web 会优先展示平台校验后的结论、风险级别、置信度、有效
Evidence 数和降级原因，再提供完整原始 JSON；读取时再次校验文件路径与 SHA-256，损坏或
篡改会显示为完整性异常。没有实际调用 AI 的任务不会伪造审计记录。

## 任务停止

Web 把任务明确区分为等待判断、正在分析、已判断、未形成判断和已停止。排队或等待设备的
任务取消后立即进入 `canceled`；运行中的任务先进入 `cancel_requested`，控制面再调用
Codex `turn/interrupt`，或终止 OpenCode 的一次性进程/容器。设备清理仍在 `finally` 中
执行。运行时确认后任务进入 `canceled`，Coverage 标为 partial，并把取消原因写入事件和
`agent.cancellation` Evidence。停止不会删除已经产生的证据，也不会把半成品模型文本落为
Finding；用户可显式重试或删除已经终止的任务。

## 扫描删除

Web 只允许删除已经 `final` 或 `failed` 的扫描；任务进入重试队列时会先把扫描恢复为
`investigating`，避免删除与后台执行发生竞态。删除操作需要二次确认，会级联删除数据库
中的入口、任务、Finding、Coverage、事件和 Evidence，并删除该扫描独占的 APK、Evidence
文件及 workspace。内容寻址文件如果仍被其他扫描引用则保留，避免删除重复上传 APK 所
共享的数据。

## 扩展方式

- 广度引擎：在 `MobSFAdapter` 或新的静态 adapter 中归一化为 `FindingDraft`，同时增加 engine coverage。
- 漏洞类型：在 `InvestigationPlanner` 增加 task 类型/假设，在平台请求校验器增加对应的最小安全动作集。
- 设备供应商：保持 `prepare → reset/authenticate/probe → cleanup` 和 Evidence 输出契约，替换 ADB lease 实现。
- 新判定级别：先定义所需的不可伪造 Evidence 条件，再扩展 Agent schema 和报告层，不能只改 prompt。

## 上线前仍需完成

- 用公司真实签名 APK 建立回归语料和误报基线。
- 在目标云真机供应商上编译/安装 Probe APK并跑 API 36 集成测试。
- 构建并验证两个 Docker worker 镜像、企业 Codex/DeepSeek 凭据方式和各自网络出口策略。
- 为每个 App 维护稳定的登录流程和 `assert_text` 成功标志。
- 根据发布风险决定人工 gate；当前产品刻意不自动 gate。
