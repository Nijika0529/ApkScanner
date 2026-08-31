# APKScanner 下一步开发 Spec

> 本文是 APKScanner 后续在**漏洞挖掘能力**与**Agent 编排架构**上的唯一权威演进规范。
> 它取代 `samsung-vulnerability-coverage-review.zh-CN.md` 的「下一步建议」与根 `README.md`
> 的旧「后续扩展方向」。目标不是单纯增加 Agent 数量，而是围绕
> **职责、证据边界、可验证覆盖**组织能力。

---

## 实现进度

| 日期 | 方向 | 内容 | 测试 | 状态 |
|------|------|------|------|------|
| 2026-08-26 | 方向三 · 身份混淆 | 新增 3 markers（`service_manager_access`、`self_reported_identity`、`plugin_archive_trust`）+ 新链 `service_manager_identity_bypass` + 扩展现有 `binder_claimed_identity_authorization` + 推断风险分支 | 3 新测试，android_chains 19/19 | ✅ |
| 2026-08-26 | 方向二 · 反向搜索 | `_reverse_chains_for_spec` sink→source BFS + `analyze()` 集成 + 双向汇合提权 + `search_direction` 字段 | 3 新测试，android_chains 19/19 | ✅ |
| 2026-08-26 | 方向四 · 能力一等化 | `CapabilityObject` schema + `capability_objects.py` 提取模块（PendingIntent / URI Grant 生命周期追踪） | 5 新测试，capability_objects 5/5 | ✅ |
| 2026-08-26 | 方向一 · 入口 disposition | `EntryDisposition` 枚举（10 态）+ `disposition.py` 解析器 + `EntryPoint.disposition` 字段 + 覆盖率指标 | 16 新测试，disposition 16/16 | ✅ |

---

## 1. 目标与原则

1. **覆盖不交给模型。** 平台先确定性枚举全部入口，再让 Agent 做策略性探索；Agent 不得自行
   决定"哪些类看起来危险"。
2. **能力对象一等化。** PendingIntent、URI Grant、Binder handle 等跨进程可转移的能力，从
   "正则 marker"升级为 Security IR 中可追溯生命周期的一等实体。
3. **正向 + 反向双向搜索。** 从入口正向追踪到 sink，同时从高危 sink 反向回溯到攻击入口，
   双向汇合处提高优先级，互为正反两面的兜底。
4. **身份与权限绑定。** 漏洞判定必须区分"攻击者声称的身份 / 真实 UID / 权限检查使用的身份 /
   敏感资源所属主体 / 最终操作对象"五个身份。
5. **证据边界不可妥协。** 无论新增多少方向与角色，`reproduced_blackbox` 仍要求同一
   request/test-case ID 的普通 App UID 证明 + 平台 Oracle 独立观测到具体危害；模型文字、
   `adb shell` 成功、危险 API 名、导出声明均不能自证。
6. **可验证覆盖。** 每个入口最终必须有一个明确处置状态；每个方向都配套可复现的合成 fixture、
   ground truth 与回归命令，不写无法复验的"能力"。

---

## 2. 现状基线（2026-08 代码）

### 2.1 攻击面模型

`backend/apkscanner/android_chains.py` 用声明式 `ChainSpec`（`family / chain_kind / sources /
sinks / risks / guards / max_hops / endpoint_discovery`）+ 正则 `MARKERS` / 快速预筛
`MARKER_NEEDLES` 建模。当前共 **11 条链、5 个 family**：

| Family | 已实现链 |
| --- | --- |
| `capability_delegation_boundary` | `pending_intent_delegation`、`nested_intent_redirection`、`uri_permission_redelegation`、`implicit_ipc_sensitive_egress`、`activity_result_content_proxy` |
| `external_file_ingress_boundary` | `external_content_to_private_file`、`external_archive_extraction` |
| `runtime_ipc_boundary` | `dynamic_broadcast_receiver`、`binder_claimed_identity_authorization`、`local_tcp_or_unix_server` |
| `web_content_boundary` | `external_input_to_webview` |

### 2.2 证据与判定模型

`supported_static` → `refuted_static` → `reproduced_blackbox` → `not_reproduced` 四级，配合
`CoverageItem`（每入口 × 每阶段 × gap）、`HypothesisArgument`（Hunter/Advocate/Critic/Arbiter）、
`ImpactContract` / `DynamicExperimentCapsule` / `ProofRecipe` / Oracle。

### 2.3 Agent 角色现状

现有 `Hunter/Advocate`（支持论证）、`Critic`（找权限/UID/origin/签名反例）、`Arbiter`
（平台 Evidence 校验后裁决），外加 `Rescue` / `Final` 有界扇出。平台 Planner 负责确定性覆盖。

### 2.4 关键缺口（与本 Spec 方向一一对应）




- 没有 coroutine/ViewModel/WorkManager/Handler/EventBus 等 **异步与生命周期边**（方向五）；
- Native 只有静态资产级覆盖，没有 **动态原生验证**（Frida/ASan/fuzzer，方向六）；
- 没有显式的 **安全断言 → 反证实验** 产物（方向七）；
- 没有 **Variant Sweeper**（Agent 架构）。

---

## 3. 重点漏洞挖掘方向

### 3.1 方向一：入口清单驱动的全覆盖审计

**目标**：避免 Agent 只审计"看起来危险"的几个类，却遗漏普通组件中的复杂链路。

**内容**：为每个 Android 外部入口建立处置状态。入口包括：

- Exported Activity、Service、Receiver、Provider；
- Activity Alias；
- Deep Link、App Link、自定义 Scheme；
- Binder/AIDL；
- 动态 Receiver；
- PendingIntent 和 IntentSender；
- URI Grant、ClipData、ACTION_SEND；
- localhost TCP、Unix Socket；
- WebView 外部导航和 JSBridge；
- 插件入口、动态加载入口；
- JNI 和 Native 导出入口。

每个入口最终必须具有一种状态：

| 状态 | 含义 |
| --- | --- |
| 未调查 | 尚未分配调查任务 |
| 静态不可达 | 静态分析表明不存在可达路径 |
| 受权限保护 | 存在有效权限检查 |
| 受调用者身份保护 | 调用者身份被校验 |
| 存在候选攻击链 | 已识别潜在攻击链，待验证 |
| 静态支持 | 有静态证据支撑 |
| 动态未复现 | 动态实验未复现危害 |
| 动态已反证 | 动态实验明确反证 |
| 普通 UID 已复现 | 普通 App UID 下已复现危害 |
| 能力缺失或超时 | 因能力不足或超时无法处置 |

**当前状态**：🟢 核心已实现（确定性入口枚举 + `CoverageItem` + `quality_metrics.py` 质量漏斗），
但 `disposition` 现在只用于 **chain 候选**（`android_chains.py`：`review_required` /
`guarded_capability_inventory` / `scoped_ipc_destination_inventory`）和 **verdict 级**
（`security_pipeline.py`），不是逐入口的 10 态状态机。

**落地要点**：

- `schemas.py`：新增 `EntryDisposition` 枚举（上述 10 态）+ `CoverageItem.disposition` 字段；
- 新增 `disposition_resolver`（建议放在 `security_pipeline.py` 或新 `disposition.py`）：
  任务终局时根据静态证据 / 权限检查 / 调用者校验 / 动态结果，为每个入口收敛到**唯一**状态；
- `quality_metrics.py`：新增「入口枚举覆盖率 / 入口有效处置率 / 无 disposition 入口数 /
  每类入口动态验证率 / 反编译失败覆盖缺口」指标；
- `api.py` + 前端：暴露逐入口 disposition 视图。

### 3.2 方向二：正向与反向双向漏洞搜索

**目标**：在现有"入口 → 危险行为"正向追踪之外，增加"从高危 sink 反向寻找攻击入口"的第二条路线。

**内容**：

正向：`外部 Intent/URI/Binder 参数 → 数据处理 → 权限或身份检查 → 危险操作`。

反向：先枚举高危 sink（`Runtime.exec`/native command、WebView `loadUrl`/`evaluateJavascript`、
ContentResolver 敏感操作、文件写入与 archive extraction、`startActivity`/`sendBroadcast`、
`PendingIntent.send`、`DexClassLoader`/`System.load`、Binder 特权操作、Socket 监听、Token/账号/敏感数据返回），
再反向搜索：哪些函数调用该 sink、caller 是否来自导出组件、参数是否最终受外部输入控制、guard 是否
覆盖全部调用路径、是否存在跨存储/异步/回调传播。两种搜索结果在同一 handler/symbol/sink 汇合时，提高任务优先级。

**当前状态**：🔴 未实现。只有正向 `ChainSpec(source→sink)` + `_bounded_paths`；没有 sink-first 反向可达性。

**落地要点**：

- `android_chains.py`：`AndroidAttackChainAnalyzer` 增加反向遍历（以 sink marker 为根，沿
  adjacency 反查是否可达导出组件 / 外部输入 marker）；
- `security_pipeline.py` / `orchestrator.py`：双向汇合（同一 symbol/handler 同时被正向链与反向
  命中）时提升任务优先级 / 增加 seed；
- `planner.py`：反向命中作为补充任务族（不新增任务族时并入现有 family）；
- 配套合成 fixture：`testapk/` 增加一个"正向可达但反向着重提示"的用例，验证双向汇合提权。

### 3.3 方向三：调用者身份混淆和权限绑定

**目标**：大型系统应用、厂商应用、插件平台中高价值的一类漏洞。不只问"是否检查权限"，而要追踪五身份
（攻击者声称身份 / 真实 UID / 权限检查所用身份 / 敏感资源所属主体 / 最终操作对象）。

**重点模式**：

- Binder 接口信任调用者提供的 package name；
- 先使用调用者参数执行操作，再检查 UID；
- `getCallingUid()` 与 `getPackagesForUid()` 使用不正确；
- shared UID、多包 UID、isolated process 处理错误；
- Activity/Service 只检查登录态，没有检查调用来源；
- WebView/小程序只检查 AppID，不绑定 origin；
- PendingIntent creator identity 被误当成当前呈递者身份；
- Provider 依赖 URI 参数表示用户或租户；
- 插件向宿主自报身份、版本、能力或签名；
- 客户端可修改角色、授权结果或风控状态。

**当前状态**：🟢 已实现为主（本轮重点）。`binder_claimed_identity_authorization` 链 + `Critic` 角色
已覆盖 caller-supplied package、`getCallingUid`/`getPackagesForUid`、签名绑定信号。

**落地要点**：

- `android_chains.py`：扩展 marker 覆盖 shared UID/多包 UID/isolated process、`getCreator*`
  与呈递者身份混淆、插件自报身份（宿主加载插件时信任其自报 package/version/signature）；
- `agent_prompt.py`：强化 Identity Critic 指令——要求输出"声称身份 vs 真实 UID vs 检查所用身份"三元组；
- `rules.py`：补充身份混淆 family 的 guard 定义（签名绑定、calling UID 绑定、origin 绑定）。

### 3.4 方向四：能力委托链

**目标**：分析 Android 中可跨进程转移的"能力对象"，回答 7 个问题：能力由谁创建、使用时继承谁的身份、
通过什么路径泄露给第三方、第三方能否修改目标/参数/flag、是否可重放、是否有作用域和生命周期限制、最终造成什么具体影响。

**能力对象清单**：PendingIntent、IntentSender、content URI grant、ClipData、ParcelFileDescriptor、
Binder handle、ResultReceiver、Messenger、callback Binder、FileProvider URI、SAF document URI。

**建议结构**（Security IR 一等实体，而非普通 marker）：

```json
{
  "capability_type": "pending_intent",
  "creator_identity": "...",
  "holder_identity": "...",
  "target": "...",
  "mutable_fields": [],
  "escape_path": [],
  "use_sites": [],
  "revocation": null
}
```

**当前状态**：🟡 链已实现（`pending_intent_delegation` / `uri_permission_redelegation` /
`nested_intent_redirection` / `activity_result_content_proxy`），但 capability **未一等化**
（仅有 `pending_intent_creator_identity` 一个 marker，无 `CapabilityObject` 实体）。

**落地要点**：

- `models.py` / `db.py`：新增 `CapabilityObject` 表（`capability_type / creator_identity /
  holder_identity / target / mutable_fields / escape_path / use_sites / revocation`）；
- `schemas.py`：对应 Pydantic schema 与 API 响应；
- `android_chains.py`：把链分析产物从"marker 命中"提升为"capability 对象 + 生命周期"，在
  现有 4 条委托链上生成对象并落库；
- `api.py` + 前端：能力对象索引与可视化（创建者 → 持有者 → 逃逸路径 → 使用点）；
- 与方向三打通：能力对象的 `creator_identity` / `holder_identity` 直接喂给 Identity Critic。

### 3.5 方向五：跨存储、异步和生命周期的数据流

**目标**：覆盖 3 跳以上的复杂链路（如 `Intent 输入 → SharedPreferences/SQLite/文件 → 后台任务 →
网络/WebView/命令/IPC sink`，或 `Activity Result → ViewModel → coroutine → Repository →
ContentResolver`）。

**需要识别的中间存储与异步边**：SharedPreferences、SQLite/Room、Bundle/SavedState、文件和缓存、
WorkManager、Handler/Message、coroutine、RxJava、callback/listener、EventBus、Broadcast、JobScheduler。

**建议的"调查事实"表达**（复用现有 Security IR/Evidence，不另建重复数据库）：

- 值 A 由入口 E 控制；
- 值 A 写入存储 K；
- 函数 F 从 K 读取值 B；
- B 到达 sink S；
- guard G 只覆盖其中一条路径。

**当前状态**：🟡 部分。`rules.py` 已有 `SharedPreferences`/`SQLiteDatabase`/`RoomDatabase` 存储
marker，但 coroutine/ViewModel/WorkManager/Handler/RxJava/EventBus/JobScheduler 等异步边完全缺失。

**落地要点**：

- `android_chains.py` / `rules.py`：新增异步/生命周期 marker（`suspend`/`launch`/`ViewModel`/
  `WorkManager`/`Handler.post`/`EventBus`/`JobScheduler` 等）与"存储写 → 存储读"跨方法边；
- 新增"程序事实记忆"（建议 `program_facts.py` 或扩展 `code_index.json`）：记录
  `入口控制值 → 写入存储 K → 从 K 读取 → 到达 sink` 的可复用事实，供 Agent 与反向搜索共用；
- 有界化：只沿显式存储/异步边扩展 `max_hops`，避免全程序爆炸；仍以 `ANALYSIS_ENGINE_VERSION` 区分 schema。

### 3.6 方向六：Java、JNI、Native 联合调查

**目标**：按 Java 入口定向进入 Native，而非对 `.so` 做全量逆向：
`导出组件 → Java native 方法 → JNI 注册/导出 → Native 参数处理 → 文件/命令/内存/Socket sink`。

**Agent 重点调查**：native 方法参数是否来自 Intent/Binder/WebView、JNI 动态注册目标、长度/偏移/整数运算、
路径拼接、shell 命令、archive/parser、Unix Socket、native service、回调 Java 层时是否丢失身份信息。

**可为高价值 native 候选生成**：Frida native trace、ASan/HWASan 测试变体、libFuzzer harness、
JNI-level differential test、真机 crash/minidump Evidence。

**当前状态**：🟡 静态侧有（`native_analysis.py` 859 行 + ArtifactGraph 的 SO/JNI/ELF/符号摘要 +
可选 IDALib MCP），动态侧无（Frida/ASan/fuzzer 为 0 命中）。

**落地要点**：

- `native_analysis.py`：补 JNI 动态注册目标、native 参数来源（Intent/Binder/WebView 字段）、
  路径拼接 / shell / socket / archive 等 native sink 摘要；
- `android_chains.py`：新增 `java_native_sink` / `jni_dynamic_register` 等 marker，把 Java 入口
  经 `native` 声明连到 native sink（当前 ArtifactGraph 已有 Java↔JNI↔SO 静态链接，可直接复用）；
- 动态原生验证（**后置**，依赖方向三/四候选质量）：`poc.py`/`device.py` 增加可选的 Frida/ASan
  执行与 crash/minidump Evidence 收集，独立开关默认关闭。

### 3.7 方向七：Agent 主动提出"安全断言"并尝试反证

**目标**：不只让 Agent 提出漏洞，还要让它说明"如果这里是安全的，必须满足哪些条件"，再由平台将其
转换为反证任务。

**安全断言示例**：

- 只有签名应用能调用该 Binder；
- 所有 archive 输出路径都在目标目录内；
- WebView bridge 只能被可信 origin 调用；
- PendingIntent target 始终显式且不可变；
- Provider 返回的资源属于 calling UID；
- 插件摘要必须与签名清单一致；
- Deep Link 参数不可能控制内部组件。

**转换流程**：`安全断言 → 生成边界输入 → 执行动态实验 → Oracle 检查断言是否被打破`。

**当前状态**：🟡 机制契合、未单独成型。`not_reproduced`（负向 Oracle）+ `Critic`/`Rescue` +
`ImpactContract`/`DynamicExperimentCapsule`/Oracle 已具备全部零件，但缺少"Agent 主动产出安全断言"的显式产物。

**落地要点**：

- `schemas.py`：新增 `SafetyAssertion`（断言文本 + 关联 hypothesis/入口 + 打破条件 + 建议边界输入）；
- `agent_prompt.py`：让 Agent 在 Final 阶段随结论输出一组可证伪的安全断言；
- `orchestrator.py` + `dynamic_experiments.py` + `proof_recipes.py`：新增"断言编译器"——把
  断言转成 `DynamicExperimentCapsule`（边界输入 + assertion step + 负向 Oracle），反证则闭合为
  `not_reproduced` / `refuted_static`，未打破则作为受保护入口的支撑证据。

---

## 4. Agent 架构调整

不建议单纯增加 Agent 数量，围绕职责和证据边界组织：

| Agent 角色 | 职责 | 现状映射 |
| --- | --- | --- |
| Surface Planner | 平台生成任务，不由模型决定覆盖范围 | ✅ 平台确定性 Planner |
| Hunter | 寻找可能成立的攻击链 | ✅ 现有 Hunter/Advocate |
| Path Tracer | 验证 source → control → sink 的代码事实 | 🟡 静态 analyzer 承担，未拆为独立角色 |
| Identity Critic | 专门寻找权限、UID、origin、签名和配置防护 | ✅ 现有 Critic（需强化五身份输出） |
| Proof Planner | 将候选转换成普通 UID 测试或实验计划 | 🟡 平台生成 proof obligations，未独立 |
| Platform Executor | 构建并执行 PoC | ✅ 平台 Harness/PoC/DynamicExperiment |
| Oracle | 独立判断危害是否发生 | ✅ 平台 Oracle |
| Arbiter | 只根据有效 Evidence 决定状态 | ✅ 平台 Evidence 校验后裁决 |
| Variant Sweeper | 确认根因后搜索同类实现 | 🔴 缺失（现有"入口变体归并"是去重，方向相反） |

**落地要点**：现有 Critic/Rescue/Final 逐步承担上述职责，不一定全部新增物理 Agent。优先级：
先加 **Variant Sweeper**（根因确认后按 `semantic_fingerprint` / 同类实现搜索变体），再把
Identity Critic 的输出结构化为五身份三元组，最后评估是否拆出独立 Path Tracer。

---

## 5. 分阶段实施计划

> 排序原则：先"低成本高确定性"（状态机、反向搜索、能力一等化），后"高成本依赖外部能力"（异步全图、
> 动态原生验证）。

### 阶段 0：基线固化（配套清理）
- 落成本文档为唯一权威方向来源；废弃旧「下一步建议」；
- `pytest -q` + `ruff check backend` + 前端 build 全绿，作为后续阶段的回归基线。

### 阶段 1：可验证覆盖与双向搜索（方向一 + 方向二）
- 10 态 `EntryDisposition` 状态机 + 逐入口 disposition 收敛器 + 覆盖指标；
- sink-first 反向搜索 + 双向汇合提权；
- 验收：`scanctl scan testapk/vulntest.apk --investigator none` 每个入口都有 disposition；
  反向命中数可作为 `coverage` 补充指标；新增 fixture 验证双向汇合。

### 阶段 2：能力对象一等化（方向四 + 方向三增强）
- `CapabilityObject` 实体 + 4 条委托链产出对象 + API/前端可视化；
- 身份混淆 marker 扩展（shared UID/多包/isolated/插件自报身份）+ Identity Critic 五身份输出；
- 验收：对 `rescuetest.apk`/`adaptivecases.apk` 生成的能力对象可追溯 creator→holder→escape→use；
  `reproduced_blackbox` 口径不变。

### 阶段 3：跨存储异步数据流（方向五）+ 安全断言反证（方向七）
- 异步/生命周期 marker + 程序事实记忆 + 有界 `max_hops` 扩展；
- `SafetyAssertion` 产物 + 断言→反证实验编译器；
- 验收：跨存储链 fixture 能跨越 3 跳以上；安全断言反证闭合为 `not_reproduced`，未打破则支撑
  `refuted_static`/受保护入口。

### 阶段 4：Variant Sweeper + Native 联合（方向六 + Agent 架构收尾）
- Variant Sweeper 角色（根因 → 同类实现变体）；
- JNI 动态注册/native sink 摘要接入攻击面模型；
- 可选动态原生验证（Frida/ASan/fuzzer）默认关闭、独立开关；
- 验收：确认根因后能枚举同类实现变体；native 候选可定向进入（不触发全量逆向）。

---

## 6. 验收指标与回归

- **入口枚举覆盖率**：`已枚举入口 / 应枚举入口`；
- **入口有效处置率**：`有终局 disposition 的入口 / 已枚举入口`（阶段 1 起）；
- **反向命中兜底**：正向漏掉、由反向搜索捞回的入口数（阶段 1 起）；
- **能力对象覆盖率**：`有 CapabilityObject 的委托链候选 / 委托链候选`（阶段 2 起）；
- **动态验证率**：`reproduced_blackbox + not_reproduced 的入口 / 已枚举入口`；
- **误报口径不变**：`supported_static` 与模型候选仍不进入 Finding 数量/SARIF；只有
  `reproduced_blackbox` 计入 TP；平台确认但不匹配 ground truth 的 Finding 计入 FP。
- 所有方向必须配套 `testapk/` 合成 fixture + ground truth；Benchmark 报告注明 APK 集、ground truth
  版本、commit、模型、设备、Profile、时间。

---

## 7. 模块衔接索引

| 方向 | 主要改动模块 |
| --- | --- |
| 一 入口 disposition | `schemas.py`、`security_pipeline.py`（或新 `disposition.py`）、`quality_metrics.py`、`api.py`、前端 |
| 二 反向搜索 | `android_chains.py`、`security_pipeline.py`、`orchestrator.py`、`planner.py` |
| 三 身份混淆 | `android_chains.py`、`rules.py`、`agent_prompt.py` |
| 四 能力一等化 | `models.py`、`db.py`、`schemas.py`、`android_chains.py`、`api.py`、前端 |
| 五 跨存储异步 | `android_chains.py`、`rules.py`、新 `program_facts.py`（或扩展 `code_index.json`） |
| 六 Native 联合 | `native_analysis.py`、`android_chains.py`、`poc.py`、`device.py` |
| 七 安全断言反证 | `schemas.py`、`agent_prompt.py`、`orchestrator.py`、`dynamic_experiments.py`、`proof_recipes.py` |
| Agent 架构 | `orchestrator.py`、`planner.py`、`agent_prompt.py`（Variant Sweeper / Identity Critic 结构化） |
