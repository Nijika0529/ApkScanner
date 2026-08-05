# APK 版本安全演进与增量扫描

本文规定同一应用多个 APK 版本之间如何复用静态资产、生成安全语义 Diff、重放历史 PoC，并判断漏洞是持续存在、已经修复、重新引入还是新出现。默认动态验证基线为 **Android 16 / API 36 及以上**。

## 1. 不可破坏的原则

1. 新 APK 是新的安全声明。旧版本 Finding 不能直接复制为新版本 Finding。
2. 可以复用计算结果和攻击配方，不能复用“漏洞仍然存在”这个结论。
3. 当前版本只有在 API 36+ 设备上形成新的平台 ProofAttempt，才能成为 `reproduced_blackbox`。
4. 相同 APK SHA-256 的重复扫描不是版本升级，不生成版本 Diff；它可以复用静态缓存，但任务、模型结论、Evidence 和 Agent Session 默认重新生成。
5. 自动基线必须同时满足 package 相同、签名证书相同、APK 内容不同。优先选择最大且小于当前版本的数值型 versionCode，无法比较时才退回最近完成的历史快照。
6. Diff 只决定复用和调度优先级，不能单独确认漏洞或修复。

## 2. 三层复用

### 2.1 Artifact CAS

上传的 APK 按 `artifact_sha256` 保存。重复上传不重复保存 APK 字节，但会创建独立 Scan，以保留每次模型、设备和规则版本的审计结果。

### 2.2 Static Analysis CAS

静态分析缓存键为：

```text
artifact_sha256 + analysis_profile_digest
```

`analysis_profile_digest` 至少包含：

- JADX、apktool、aapt2、apksigner 等工具版本；
- 代码索引算法版本；
- 规则/归一化 Schema 版本；
- 影响反编译结果的参数。

缓存内容包括 canonical JADX、apktool、可搜索 archive、Manifest、签名信息和 `code_index.json`。缓存命中只跳过确定性的静态工具计算；数据库记录、任务、Finding、Evidence、Thread 和动态测试不继承。当前实现位于：

```text
<data_dir>/static-cache/<sha-prefix>/<artifact_sha256>/<analysis_profile>/
```

工具版本或索引算法变化后自然产生新缓存，不覆盖旧缓存。当前缓存没有自动 LRU/容量回收，运维侧必须
监控 Data 目录容量；反编译目录不能按文件名或 package 名复用。

### 2.3 Security Fact / Proof Recipe 复用

版本快照保存包身份、入口、权限、代码安全事实和安全相关资源指纹。历史动态证明只复用其 PoC 源码、Oracle、攻击者模型和前置条件；重建、重签和执行都发生在当前版本任务中。

## 3. 安全快照

每个快照至少包含：

- package、signer、versionName、versionCode、artifact SHA-256；
- analysis profile；
- exported 入口、权限及 protection level、intent filter、deep link、provider authority；
- 每个入口的规范化代码哈希、调用、敏感 sink、caller guard 和有限字符串事实；
- DEX、native library、Manifest、`assets/`、`res/xml/`、`res/raw/` 等安全资源指纹；
- 静态分析降级状态，例如 JADX 部分失败和 Smali fallback。

资源指纹对小型配置保存 SHA-256；对超过哈希预算的大型 DEX/`.so` 至少保存 ZIP CRC、压缩前后大小和 APK 级 SHA-256 归属。它用于快速判断“哪里变化了”，不作为独立漏洞证据。

## 4. Diff 分类

入口先按稳定身份映射，再用规范化代码哈希识别唯一重命名。输出至少包含：

- `unchanged`：入口边界和安全代码事实不变；
- `implementation_changed`：代码变化，但没有确定的加固/削弱信号；
- `security_weakened`：新增导出、移除权限、移除 caller guard 等；
- `security_hardened`：新增强权限或 caller guard 等；
- `entry_added` / `entry_removed`；
- `security_resource_added` / `changed` / `removed`。

`security_weakened` 和新入口进入最高优先级。普通实现变化进入高优先级语义复核。安全资源变化会交给静态安全任务，重点检查风控规则、网络配置、Web 内容、脚本、插件、迁移文件和硬编码凭据。

当前 Diff 以组件和安全事实为主，不提供完整的方法级调用图比较。对从入口可达的 helper、Binder
stub、JSBridge handler、Tool dispatcher、风险评估器和配置加载器，平台只在现有代码索引能够形成
稳定事实时参与匹配；类名混淆变化时禁止只靠名称推断。

## 5. 调度矩阵

| 当前事实 | 历史事实 | 调度行为 |
|---|---|---|
| 完全相同 APK | 任意 | 命中静态 CAS；独立重跑任务，不生成版本 Diff |
| 入口未变且历史漏洞已证明 | proven | 优先迁移并重放历史 PoC |
| 入口代码改变且历史漏洞已证明 | proven | 重放旧 PoC；失败后把代码 Diff 和失败 Evidence 交给 Agent 适配 |
| 权限/guard 加固 | proven | 仍重放一次；成功表示修复无效，失败只能标记“待确认修复” |
| 新入口或安全边界削弱 | 无 | 最高优先级创建新假设并执行完整调查 |
| 安全资源改变 | 无或有 | 对配置/规则/脚本/端点生成静态语义任务 |
| 入口移除 | proven | 检查重命名、替代路由和间接入口；不能仅凭 Manifest 消失宣布修复 |

## 6. Finding 的跨版本状态

平台使用稳定 `finding_id` 表示同一漏洞语义，用 scan-specific `occurrence_id` 表示某个 APK 上的一次结论。版本演进视图展示：

- `persisting`：当前版本重新证明仍存在；
- `fixed_verified`：当前版本在同等或更强前置条件下，旧 PoC 和 Agent 适配均被平台 Oracle 明确反驳；
- `fixed_candidate`：静态上已加固或旧 PoC 失败，但证据还不足；
- `regressed`：中间版本已验证修复，之后再次证明；
- `new`：当前版本首次证明；
- `unknown`：设备、账号、后端或前置条件不足。

Android 平台行为变化必须独立表达。比如 API 36 阻止某个后台启动链，应记录 `mitigated_by_platform` 和精确 API/前后台状态，不能把它等同于应用已经修复。

## 7. 历史 PoC 迁移

只有 `reproduced_blackbox` 或人工 `accepted` Finding 可以生成重放候选：

1. 校验历史 PoC 源码归档 SHA-256；
2. 安全解包到当前 task workspace；
3. 只进行确定性的 package/component/authority 替换；
4. 使用当前 Android 工具链重新编译、签名；
5. 在当前任务独占的 API 36+ 设备上执行；
6. 使用当前版本 Oracle 形成新的 ProofAttempt；
7. 失败结果作为 Agent 适配证据，不自动宣布修复。

每个 hypothesis 独立拥有 ProofAttempt 和预算。一个 hypothesis 成功只关闭它自己，平台继续处理同一组件的其他未闭合 hypothesis。

## 8. Finding Pattern Card

只有动态证明或人工接受的 Finding 可以产生可复用 Pattern Card。卡片包括：

- package 无关的漏洞类型；
- source、control、sink 和 trust boundary；
- 入口形状、关键 API、缺失 guard；
- Android API、账号态、前后台态等适用条件；
- 排除条件和反证；
- PoC/Oracle 配方。

Pattern 匹配只产生 `candidate_match` 并提高任务优先级。新版本仍需自己的 Proof 才能成为 Finding。

## 9. 盲测与已知漏洞集

私有已知报告只作为 Benchmark Oracle 和验收标准，不挂载到被测 Agent workspace。否则模型可能
复述报告而不是真正发现漏洞。盲测流程分别保存：

- APK 输入；
- Agent 可见的反编译与平台证据；
- Agent 不可见的期望漏洞清单；
- 自动匹配规则和人工复核记录。

详细覆盖计划见 [私有已知漏洞集盲测计划](private-benchmark-plan.zh-CN.md)。

## 10. API 与验收

- `GET /api/v1/scans/{scan_id}/security-snapshot`
- `GET /api/v1/scans/{scan_id}/version-diff`
- `GET /api/v1/scans/{scan_id}/pattern-matches`
- `GET /api/v1/patterns`
- `GET /api/v1/patterns/{pattern_id}`

增量扫描发布门禁：

1. 相同 APK 第二次静态扫描必须命中 CAS；
2. 工具版本变化必须产生不同 analysis profile；
3. 同签名的相邻 versionCode 自动建立基线；
4. 不同签名绝不自动迁移 Proof；
5. 配置资源变化和入口安全变化均出现在 Diff；
6. 历史 PoC 必须在 API 36+ 重新执行；
7. 旧 Finding 不得直接出现在新 Scan；
8. Worker/设备中断后，事件线能解释缓存、Diff、重放和最终状态。
