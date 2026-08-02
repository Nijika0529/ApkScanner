# APK Scanner 架构与判定模型

> Codex 迁移后的扫描级 Docker、多 UID 工作区、SDK 选型、Thread、事件线、ADB/Proof、
> DeepSeek Provider、可插拔测试入口、监督 Agent 接口和分阶段实施规范，统一见
> [Codex + DeepSeek Docker 执行架构与迁移规范](codex-docker-architecture.zh-CN.md)。

## 目标与边界

系统面向公司待上线、仅提供 APK 的安全复核。控制面运行在个人电脑本地，动态面只访问已授权的专用 Android 测试设备和测试后端。它提供覆盖面、证据和人工复核辅助，不自动阻断发布。

v1 的固定边界是：单 APK、单用户、按测试策略复位、无源码、无服务端权限模型。

## 执行流水线

```mermaid
flowchart LR
    A[APK intake] --> B[ZIP/签名/Manifest/JADX·Apktool]
    B --> C[版本化 Security IR]
    C --> D[入口枚举与平台任务规划]
    D --> E[普通应用 UID 黑盒：可选 Probe / Agent PoC]
    E --> I[选定 Agent 提出下一组测试]
    I --> J{需要补充测试?}
    J -- 是 --> K[平台校验并执行本轮最多 4 个用例]
    K --> R{仍有轮次与预算?}
    R -- 是 --> I
    R -- 否 --> L[选定 Agent 最终判断]
    J -- 否 --> L
    L --> M[Evidence ID 与结论级别校验]
    M --> N[Web / JSON / HTML / SARIF + 人工复核]
```

平台按风险优先级逐个领取入口任务；多个扫描共享同一个全局任务执行锁。一个导出组件对应
一个任务；同一 handler 的 Deep Links 合并成一个任务。Agent 不能创建子 Agent，也不能
直接把自己的文字当作复现证据。默认最多进行 3 个自适应测试轮次、每轮接受 8 个受限
测试：只能使用当前任务的入口 ID；Deep Link 和 Provider URI 必须保持 Manifest 声明的
scheme、host/authority 和 port；额外参数有数量、键名、类型和长度上限。每轮证据都会回灌
下一次判断，最终再执行禁止申请新动作的证据总结。轮次和单轮测试数可在 1–5 / 1–1000 的
范围内配置。每次扫描在创建时记录初始 `codex` 或 `none`；服务默认值的后续
变更不会静默改变它，只有用户在扫描控制台显式调整才会影响后续任务。

扫描创建后的 Agent 控制分两层：`Scan.stats.agent_control` 是总开关和后端选择；
`InvestigationTask.preconditions.agent_enabled` 是单任务覆盖。总开关关闭时所有任务只运行
规则和确定性动态验证；总开关开启后，任务级开关仍可关闭某个入口的 AI。运行中的任务保留
启动瞬间解析出的配置，避免一次审计调用途中切换模型；新配置只影响未启动或重新分析的任务。

一个任务以 `task_id + attempt` 作为平台逻辑探索运行。当前 Worker Protocol v2 的每次物理
每个 `task + attempt + role` 使用一个持久 Codex Worker 和非 ephemeral Thread；primary 的
下一轮会复用同一 Thread，同时重新装载累计 Evidence 和已执行测试。Critic/Rescue 使用独立
UID、工作区和 Thread。扫描级 Docker 容器继续复用，Web 将物理 Turn 聚合到同一任务时间线。
持久 Thread/resume 按专项架构文档的 Phase 4 实施。

静态阶段结束即发布 preliminary report，并继续动态任务。外部工具和每个任务都有超时；超过 4 小时 preliminary 目标或 24 小时整单预算会写入事件及 coverage gap。

JADX 的非零退出码不直接等同于反编译不可用。平台把结果归一化为完整成功、部分成功、部分超时或工具失败，并生成 `code_index.json`：逐个组件记录目标类是否位于失败列表、可用 Java/Smali 路径、文件 SHA-256 和有界源码片段。Codex 接收目标级物化上下文，并在 personal-lab profile 下通过 `/scan-input/*` 读取完整的只读反编译根。历史扫描在任务重试时可从已有 workspace 与 `static.jadx` Evidence 懒生成索引，不会为了补上下文再次运行 JADX。

## 多云真机调度

`APKSCANNER_ADB_SERIALS` 接受逗号分隔的设备池；未设置时继续兼容单个
`APKSCANNER_ADB_SERIAL`。调查并发数自动等于设备数。控制面按风险优先级领取任务，每个任务
从健康检查、安装/复用、初始探索、Agent 多轮分析、实时 PoC 回放、Review 到最终清理始终
绑定同一个 serial。同一台设备上不会穿插其他 APK 的状态和日志，两台设备则可各运行一个
完整任务。

设备池保留全局优先级队列，每台适配器内部继续保留命令互斥。实时 PoC Proof Context 保存
任务实际获得的 Device Adapter，API 回放不能落到另一台手机。任务结果继续记录
`requested_at`、`acquired_at`、`released_at`、`held_seconds` 和 `serial`，Web 展示当前
任务的设备关键事件。

运行中的 ADB 子进程使用独立进程组；停止任务会终止当前命令，
后续设备命令直接返回 canceled，但 `pm clear` 和 App Link reset 清理仍会忽略取消信号执行。
Web 健康检查使用真正的非阻塞锁；设备繁忙时读取最近一次能力结果，不会插入或等待当前
设备会话。控制面重启时，历史 `awaiting_device` 任务安全恢复为 `queued`；
`cancel_requested` 直接确认为 `canceled`；在模型或平台计算阶段中断的 `running` 任务可
安全重新排队，只有数据库显示“已获取但尚未释放设备租约”的任务才标为 `inconclusive`
并要求人工重试，避免重复外部副作用。

## 信任边界

| 区域 | 可访问内容 | 约束 |
| --- | --- | --- |
| 本地控制面 | SQLite、APK、workspace、evidence | FastAPI 仅监听 loopback；变更 API 需要自定义请求头；内容寻址文件拒绝 symlink/摘要冲突 |
| Codex 扫描级 Docker worker | 扫描只读输入、每 role 独立可写 workspace、DeepSeek/Web 网络 | 一个 scan 一个无密钥 keeper；每个 task/attempt/role 独立 UID/HOME/CODEX_HOME/TMPDIR；Codex `Sandbox.full_access`；rootfs 只读、capabilities 全丢弃、PID/CPU/内存限制；不挂 Docker socket 或设备 |
| Codex host worker | 当前任务 attempt workspace、主机工具和模型网络 | 仅作为双开关启用的个人诊断模式；full-access sandbox，没有容器/UID/资源边界，不能作为默认部署 |
| 云真机 | 目标 APK、可选 Probe APK、Agent PoC、测试账号 | 配置声明目标 Android/API；串行 lease；任务前后 `pm clear`；不声称完整快照复位 |
| Probe APK | 可选的普通 App UID 通用入口快速执行器 | 只接受最初发送者为 shell/root 的调度；复杂 Binder/AIDL/漏洞链改用 Agent 专用 PoC；仍只允许安装在专用测试设备 |

APK、反编译代码、资源、日志、网页和工具输出都属于不可信数据。Codex developer
instructions 明确禁止服从这些内容中的指令。每个 `task_id + attempt + role` 获得独立 UID
和可写 workspace；并发 Agent 不共享可写目录，同时可读取完整只读 Apktool/JADX/archive
根，创建本地脚本、Android 工程和预编译 PoC。平台最终只把带稳定
test-case/request ID 的 Probe/PoC 与客观 Oracle 作为复现证据。模型网络出口应分别限制到
获批的 DeepSeek/代理端点。

## Security IR

核心对象全部带 `schema_version`：

- `Scan`：制品摘要、包/版本/SDK、签名、工具版本、状态和时限。
- `EntryPoint`：Activity、Alias、Service、Receiver、Provider、Deep Link；保存有效 exported 原因、权限保护级别、Intent Filter 和 URI 模板。
- `InvestigationTask`：入口集合、假设、前置条件、允许副作用、设备基线、线程/turn 和重试次数。
- `Evidence`：内容摘要、不可变文件、命令 argv、退出码、调用身份、request/test-case ID。
- `Finding`：规则、MASVS/CWE、严重性、置信度、结论级别、入口和 Evidence 引用、人工结论。
- `CoverageItem`：每个 MASVS 域和每个入口在 static、deterministic、blackbox、agent 阶段的状态及 gap。

## 结论和证据规则

| 结论 | 平台最低条件 |
| --- | --- |
| `supported_static` | 引用了本 scan 的 `static.*` Evidence ID |
| `refuted_static` | 静态证据表明攻击路径受保护、不可达或无实际危害 |
| `reproduced_blackbox` | 同一 request/test-case ID 的 Probe 调用+日志或专用 PoC 启动+日志成功关联，并由平台 Oracle 独立观察到具体危害；`adb shell` 成功不等价 |
| `not_reproduced` | 同一 test-case/request ID 的普通 App UID 尝试与结果日志存在，且平台 Prover 明确产生 `oracle_refuted=true`；它只反驳该已执行用例，不证明全局安全 |

Agent 声称但不属于本 scan/task 的 Evidence ID 会被删除。动态证据不足以支撑复现或负向
Oracle 时，平台保留由已引用静态证据支撑的明确正向/负向结论；完全未引用所需平台证据的
输出会被拒绝，而不是制造“信息不足”Finding。

## 能力恢复后的增量补扫

连接 ADB、补齐可选 Probe/专用 PoC 执行能力或恢复模型后端后，不需要重新上传 APK。单任务“重新分析”
和扫描级“补扫信息不全项”都会把目标任务重新置为 `queued`，将扫描恢复为
`investigating`，随后复用已有 workspace、代码索引和静态 Evidence，重新执行设备租约、
动态验证和按当前开关决定的 Agent 调用。批量补扫仅选择设备阻塞、证据不足、超时、失败及
平台最终结果为 `inconclusive` 的任务，不自动重跑已经确认或当前未复现的结论。

人工重新分析不受自动尝试预算限制，但每次仍增加 `attempts`，产生新的 thread/turn 和完整
AI 审计；旧 Evidence 不删除。批量补扫仅允许在当前扫描已经 `final`/`failed` 时启动，避免
与仍在运行的设备任务竞态。

单任务默认预算为 20 分钟。任务进入 `timed_out` 后，Web 提供“继续深度探索”而不是普通
重跑：控制面重新排队同一 `task_id`，分配一份新的 20 分钟预算，并将该任务历次静态、
ADB、Probe、Agent 请求/响应和平台校验 Evidence 一并装载给新一轮 Agent。续跑轮次
记录在 `manual_continuation.continuation_number`，旧 thread/turn 仅作为关联信息保留，新轮
仍产生独立可审计调用。显式续跑不受原扫描 24 小时截止时间或自动尝试次数限制，但每轮仍
重新获取设备租约、执行准备与最终清理，且只能由已经 `timed_out` 的任务触发。

## 假设、反证与危害证明

入口任务启动时，平台将 Planner 的安全问题固化为 `SecurityHypothesis`。稳定 fingerprint
避免同一扫描重复创建同一主张；攻击者身份、前置条件、预期影响和 proof obligations 不再
只存在于 Prompt。模型输出按角色写入 `HypothesisArgument`：

- Hunter/Advocate 只能提供支持论证和 Evidence 引用；
- Critic 独立寻找权限检查、调用者校验、不可达路径、认证/配置前置和无实际危害的反例；
- Arbiter 是平台 Evidence 校验后的决定，不直接采用任一模型的自评。

host `personal_lab` 模式的主验证路径是实时 Proof Replay：Agent 自由使用 Bash/ADB
探索并构建 PoC，确认最终方案后运行 `apkscanner-proof <回放 JSON>`。控制面使用仅在
当前任务有效的随机令牌接收请求，自动关联当前种子入口和最匹配的 Hypothesis，再执行
PoC 构建、全局串行 ADB、Oracle 和 Evidence 记录，并把结果同步返回给仍在运行的 Agent，
从而允许其基于失败结果修正 PoC 后继续下一轮。相同回放按内容去重。

`requested_tests` 仅作为实时通道不可用时的兼容后备；通过边界校验的请求同样必须关联
当前任务的 Hypothesis，并形成 `ProofAttempt`。`android_entry_probe` Prover 复用现有
ADB/Probe 能力；
Oracle 将“入口执行成功”和“实际危害”分开：普通应用 UID Probe 回执只能设置
`execution_demonstrated=true`；只有领域 Prover 同时给出平台可校验的
`security_impact_observed=true`（例如敏感数据实际返回、未授权状态确实变化或认证边界被
绕过），才设置 `harm_demonstrated=true`。模型文字、导出声明、危险 API 名称、单独
`adb shell` 成功以及单纯打开组件都不能让危害 Proof 通过。Web“验证链”展示候选、正反
论证、Proof Attempt、Evidence 和最终状态。

## 私有 APK 真值评测

`scanctl benchmark APK --truth SPEC --investigator BACKEND` 对 APK 完整扫描并保存
`BenchmarkEvaluation`；`scanctl evaluate --scan-id ID --truth SPEC` 可以对已有结果重复
评分。SPEC 支持按 rule ID、CWE、入口名称和 Finding 文本关键词匹配已知漏洞，并为每项真值
指定 `static` 或 `dynamic` 最低证明等级。

评分和最终 Finding 只统计带有效 Evidence 引用、且平台 Oracle 已确认具体危害的
`reproduced_blackbox`。`supported_static` 与 builtin 规则输出保留为静态线索，不进入
Finding 数量或 SARIF。默认真值要求 `dynamic`，因此只有静态猜测的高危描述既不能命中，
如果已被平台确认为 Finding 但不匹配任何真值，还会计为 false positive。主指标使用 F0.5，
精确率权重是召回率的两倍；`candidate`、`inconclusive`、人工 review 的 accepted 状态和
没有平台证明的模型输出均不算发现，只作为 `unproven_ai_noise` 单独报告。这样可以直接比较
不同模型在同一私有 APK 上“发现了多少真实漏洞”以及“制造了多少看似有用的噪声”。

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

Codex 审计额外记录冻结的执行 profile、ProviderProfile、PhaseRoute 及其 SHA-256、固定
SDK/CLI/源码基线、reasoning effort、容器 generation、session UID/role、thread/turn、
结构化校验和 usage。未知 SDK notification 会归一化为不含原始秘密载荷的安全摘要；事件
带 schema version 与去重键。失败不会静默切换模型或恢复 OpenCode 路由。

Codex app-server notification 会先归一化为 `exploration.*` 平台事件。Web 只展示假设、
阶段、动作、证据和结论等关键事件，不展示或
持久化隐藏思维链；模型必须通过结构化字段提供可审计的简短理由。

这些记录不包含模型 API Key。每份内容在写入时计算 SHA-256，Web 的“AI 审计”页和 JSON
报告展示同一份内容及摘要；Web 会优先展示平台校验后的结论、风险级别、置信度、有效
Evidence 数和降级原因，再提供完整原始 JSON；读取时再次校验文件路径与 SHA-256，损坏或
篡改会显示为完整性异常。没有实际调用 AI 的任务不会伪造审计记录。

## 任务停止

Web 把任务明确区分为等待判断、正在分析、已判断、未形成判断和已停止。排队或等待设备的
任务取消后立即进入 `canceled`；运行中的任务先进入 `cancel_requested`，控制面再调用
Codex `turn/interrupt`，或终止 Docker exec 进程组及对应 session UID 的全部进程。扫描
结束时回收 keeper 容器；设备清理仍在 `finally` 中
执行。运行时确认后任务进入 `canceled`，Coverage 标为 partial，并把取消原因写入事件和
`agent.cancellation` Evidence。停止不会删除已经产生的证据，也不会把半成品模型文本落为
Finding；用户可显式重试或删除已经终止的任务。处于 `cancel_requested` 的任务也允许
立即软删除：后台仍完成中止与设备清理，随后只更新取消确认审计，不会把任务恢复到列表。

## 扫描删除

Web 只允许删除已经 `final` 或 `failed` 的扫描；任务进入重试队列时会先把扫描恢复为
`investigating`，避免删除与后台执行发生竞态。删除操作需要二次确认，会级联删除数据库
中的入口、任务、Finding、Coverage、事件和 Evidence，并删除该扫描独占的 APK、Evidence
文件及 workspace。内容寻址文件如果仍被其他扫描引用则保留，避免删除重复上传 APK 所
共享的数据。

## 扩展方式

- 漏洞类型：在 `InvestigationPlanner` 增加 task 类型/假设，在平台请求校验器增加对应的最小安全动作集。
- 设备供应商：保持 `prepare → reset/authenticate/probe → cleanup` 和 Evidence 输出契约，替换 ADB lease 实现。
- 新判定级别：先定义所需的不可伪造 Evidence 条件，再扩展 Agent schema 和报告层，不能只改 prompt。

## 上线前仍需完成

- 用公司真实签名 APK 建立回归语料和误报基线。
- 在目标云真机供应商上同时覆盖可选 Probe 快速路径和 Agent 专用 PoC 的 API 36 集成测试。
- 构建并验证两个 Docker worker 镜像、企业 Codex/DeepSeek 凭据方式和各自网络出口策略。
- 业务账号态 fixture 作为后续专项能力，不阻塞普通入口审计。
- 根据发布风险决定人工 gate；当前产品刻意不自动 gate。
## 威胁模型、逐假设收口与扫描封印

静态分析完成后，控制面从 APK 元数据和入口点生成确定性的 Android 威胁模型。它固定
普通第三方 App、guest 状态、无 root/system/adb-shell 权限的攻击者，列出资产、信任边界、
攻击面摘要以及“静态只生成线索、最终 Finding 必须由平台危害 Oracle 证明”的证据策略。
威胁模型摘要进入每个 Agent 上下文，防止不同任务自行发明攻击者能力或证据标准。

Agent 的结构化结果包含逐 `hypothesis_id` 的 assessment。平台按 hypothesis 单独记录
source、control、sink、reachable path、boundary、counterevidence、proof gaps、Evidence
引用与 verdict。未评估的 hypothesis 会得到明确的 closure receipt，而不会继承同任务
其他 hypothesis 的总判定。旧 worker 输出仍可走兼容路径，但新提示词要求精确 UUID。

Finding 元数据同时保存稳定 `finding_id`、单次扫描 `occurrence_id` 与 semantic
fingerprint。稳定身份由包名、签名者、规则、类别、入口语义和 claim 生成，不依赖源码
行号或 Scan UUID。扫描结束时 `scan.seal` Evidence 对 APK SHA、威胁模型摘要、任务结果
摘要、Finding 身份、Evidence 内容摘要和 Coverage 状态进行封印；seal Evidence ID 和
SHA-256 写入 `scan.stats.seal`。
