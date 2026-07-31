# APK 版本差分与漏洞回归复验设计

状态：已确认方向，待分阶段实现
日期：2026-07-28

## 1. 目标

把当前“一次扫描一份报告”的工作流扩展为应用版本线，回答四个问题：

1. 新 APK 相比基线新增、移除或改变了哪些攻击面？
2. 新增、持续存在或本次未观测到哪些 Finding？
3. 人工确认的漏洞在新 APK 上是否仍可复现？
4. 两次结果不可直接比较时，具体缺少什么覆盖、能力或身份条件？

首要使用场景是个人维护的私有 APK 与本地已确认漏洞。系统不自动发布门禁，也不因
“本次没找到”就宣称漏洞已修复。

## 2. 核心原则

- **漏洞身份独立于单次 Finding。** Finding 属于一次 Scan；回归漏洞案例属于应用版本线。
- **机器结论和人工结论分离。** `Finding.status` 表示分析结果，人工审核采用追加事件。
- **旧证据不继承证明效力。** 旧 Evidence 只展示来源关系，新版本必须生成自己的
  Proof、Evidence 和 Verdict。
- **匹配结果可解释。** 每个跨版本匹配保存指纹版本、规范化材料和匹配置信度。
- **失败关闭。** 包名不符、入口歧义、签名不连续、覆盖下降或 Oracle 不足时进入
  `inconclusive`/`unmappable`，不能进入“已修复”。
- **基线由用户明确选择。** 当前 `version_code` 是字符串，不能依赖字典序推断版本先后。

## 3. 用户流程

### 3.1 建立回归漏洞库

支持两条入口：

1. 在现有 Finding 上执行“加入回归库”，填写稳定案例编号、实际危害、最低证明等级和
   审核依据。
2. 导入现有 `BenchmarkSpec` 兼容 JSON，将本地真值转换成回归漏洞案例；导入只创建案例，
   不伪造某次扫描已经生成的证明。

现有 Finding 的人工 `accepted` 不能自动提升为回归案例，因为当前字段没有区分
“确认是真漏洞”和“接受风险”，并且可能已经覆盖原机器证明状态。

### 3.2 创建后继扫描

用户从一个 `final` 基线扫描点击“比较并复验新版本”，上传新 APK。系统创建普通扫描及
基线关系；静态解析完成后再校验：

- 包名不同：拒绝建立同一应用版本关系。
- 包名相同、签名证书一致：允许确定性差分和符合条件的自动复验。
- 包名相同、签名变化：允许展示差分，但默认阻止自动复验并给出身份警告。
- 无法取得签名：标记为 `identity_unverified`；必须人工确认后才能复验。

### 3.3 查看差分

有基线关系的扫描新增“版本差分”Tab，按以下顺序展示：

1. 已确认漏洞复验状态。
2. 攻击面变化。
3. Finding 变化。
4. SDK、签名、工具版本和覆盖变化。

页面 URL 保存当前扫描、Tab 和焦点：

```text
/?scan=<scan_id>&tab=comparison&focus=case:<case_id>
```

刷新、浏览器前进后退和从差分跳到任务/Finding/验证链后返回，都应恢复原位置。

## 4. 数据模型

MVP 优先使用新增关联表，避免把跨版本生命周期强塞进 `Scan` 和 `Finding`。所有外键删除
策略都必须保证删除某次 Scan 后，人工维护的漏洞案例仍然存在。

### 4.1 `applications`

| 字段 | 含义 |
| --- | --- |
| `id` | UUID |
| `package_name` | Android 包名，唯一 |
| `display_name` | 可选显示名 |
| `created_at`, `updated_at` | 审计时间 |

### 4.2 `application_scans`

| 字段 | 含义 |
| --- | --- |
| `scan_id` | Scan，一次扫描最多属于一个应用 |
| `application_id` | Application |
| `signer_snapshot` | 规范化证书摘要集合 |
| `identity_status` | `verified / signer_changed / unverified / rejected` |
| `linked_at` | 关联时间 |

静态解析取得包名后，以唯一约束和 UPSERT 关联 Application，不能使用容易竞态的
“先查询、再插入”。

### 4.3 `vulnerability_cases`

| 字段 | 含义 |
| --- | --- |
| `id` | UUID |
| `application_id` | 所属应用 |
| `case_key` | 用户可读稳定编号，如 `LOCAL-2026-001` |
| `fingerprint`, `fingerprint_version` | 平台稳定身份 |
| `identity_json` | 指纹规范化材料 |
| `match_quality` | `strong / weak / legacy` |
| `title`, `description`, `harm`, `remediation` | 人工维护内容 |
| `severity`, `cwe`, `masvs` | 分类 |
| `minimum_proof` | `static / dynamic` |
| `lifecycle` | `active / accepted_risk / retired` |
| `source_scan_id`, `source_finding_id` | 可空来源，删除来源时 `SET NULL` |
| `created_at`, `updated_at` | 审计时间 |

唯一约束：

```text
(application_id, case_key)
(application_id, fingerprint_version, fingerprint)
```

### 4.4 `vulnerability_occurrences`

记录某个案例在某次 Scan 中的观测，不覆盖案例本身：

| 字段 | 含义 |
| --- | --- |
| `case_id`, `scan_id` | 唯一组合 |
| `finding_id`, `hypothesis_id`, `proof_attempt_id` | 可空当前版本对象 |
| `analysis_status` | 当前 APK 的机器结论 |
| `proof_level` | 当前证明等级 |
| `match_quality`, `match_reason` | 映射依据 |
| `observed_identity_json` | 当次规范化身份快照 |
| `created_at`, `updated_at` | 审计时间 |

### 4.5 `vulnerability_reviews`

人工审核采用不可变追加事件：

| 字段 | 含义 |
| --- | --- |
| `id` | 单调递增 ID |
| `case_id` | 回归漏洞案例 |
| `occurrence_id` | 可空；空表示版本线级审核 |
| `disposition` | `confirmed / false_positive / accepted_risk / needs_review` |
| `note` | 必填审核依据 |
| `created_at` | 审核时间 |

当前视图取作用域内最新事件，但历史事件不更新、不删除。人工审核不得提升 Evidence
等级，也不得改变 benchmark 对机器发现能力的计分。

### 4.6 `scan_comparisons`

| 字段 | 含义 |
| --- | --- |
| `id` | UUID |
| `application_id` | 所属应用 |
| `baseline_scan_id`, `target_scan_id` | 明确的左右版本 |
| `status` | `pending / identity_rejected / ready / final / failed` |
| `fingerprint_version` | 本次使用的匹配算法版本 |
| `identity_result` | 包名、签名连续性结果 |
| `tool_compatibility` | 分析器版本差异 |
| `result_json` | 可审计的差分快照 |
| `created_at`, `updated_at` | 审计时间 |

唯一约束至少包含：

```text
(baseline_scan_id, target_scan_id, fingerprint_version)
```

### 4.7 `proof_replays`（第二阶段）

这是独立状态机，不复用 manual continuation：

| 字段 | 含义 |
| --- | --- |
| `id` | UUID |
| `comparison_id`, `case_id` | 所属差分与漏洞案例 |
| `source_proof_attempt_id` | 可空来源引用 |
| `target_task_id`, `target_hypothesis_id`, `target_proof_attempt_id` | 新扫描对象 |
| `template_json`, `template_version` | 去除旧运行时 ID 的复验模板 |
| `mapping_json` | 新旧入口映射与置信度 |
| `status` | 持久状态机 |
| `idempotency_key` | 防止重复排队 |
| `error`, `created_at`, `updated_at` | 审计信息 |

状态流：

```text
eligibility_checked
  -> mapped
  -> revalidated
  -> queued
  -> executing
  -> cleaning
  -> evaluated
  -> compared
```

任何阶段都可进入 `ineligible / unmappable / inconclusive / failed`。

## 5. 稳定身份与匹配

所有指纹使用规范化 JSON 后做 SHA-256，并在输入中加入命名空间及算法版本。禁止包含：

- Scan、Task、EntryPoint、Hypothesis UUID；
- 当前状态、严重度、模型名；
- Evidence ID；
- 代码行号和临时 workspace 路径。

### 5.1 应用身份

```text
package_name + normalized signer certificate set
```

包名用于版本归组，证书连续性用于决定是否允许自动复验。证书轮换或缺失必须显式降级，
不能静默当作同一可信制品。

### 5.2 入口身份 `entry-v1`

- Activity/alias/service/receiver：`kind + normalized component name + owner`。
- Provider：上述字段加规范化 authority 集合。
- Deep Link：`owner + scheme + lowercase host + normalized port + path kind + path`。

精确身份相等为 `strong`。重命名、多个候选或仅源码相似只能产生 `weak/ambiguous`，MVP
不自动复验。

### 5.3 Finding 身份 `finding-v1`

- 内置静态规则：`rule namespace + rule_id + semantic entry identities +
  normalized path without line number`。
- Agent Finding：`hypothesis category + semantic entry identities + normalized planner claim`，
  初版标为 `weak`。
- 本地人工案例优先使用用户 `case_key` 和显式绑定，不依赖易变化的标题文本。

当前 `Finding.dedupe_key` 和 `SecurityHypothesis.fingerprint` 都包含单次运行材料，不能用于
跨版本匹配。

### 5.4 差分语义

攻击面：

```text
added / removed / changed / unchanged / ambiguous
```

Finding：

```text
new / persistent / not_observed / analysis_changed / ambiguous
```

`not_observed` 不等于 `fixed`。只有强匹配、覆盖可比、等价前置条件和类型化负 Oracle
全部满足时，后续版本才可给出 `explicitly_refuted`。

## 6. ReplayTemplate

旧 `ProofAttempt.plan` 不能原样复制，因为其中包含旧 `entry_point_id` 和
`hypothesis_id`。应提取版本化模板：

```json
{
  "schema_version": "1.0",
  "prover": "android_entry_probe",
  "prover_version": "1",
  "oracle_type": "typed-impact-oracle",
  "oracle_version": "1",
  "entry_identity": {},
  "state": "guest",
  "uri": null,
  "extras": {},
  "preconditions": [],
  "allowed_side_effects": [],
  "cleanup_contract": {},
  "source_artifact_sha256": "",
  "source_proof_attempt_id": ""
}
```

模板保存来源关系，但创建目标 Proof 时必须：

1. 唯一映射到当前 Scan 的入口；
2. 创建当前 Task/Hypothesis；
3. 重新执行 URI、extras、副作用和设备能力校验；
4. 生成新的 test-case/request ID；
5. 只消费当前 Scan 的 Evidence；
6. 执行强制清理后再形成 Verdict。

MVP 自动重放仅支持：

- 同包名、同签名；
- guest；
- 普通 Probe；
- 无 PoC；
- 无持久化写操作；
- 入口强匹配；
- 已终态的来源 Proof。

PoC、账号数据 fixture 和有持久副作用的用例放到后续阶段。

## 7. API 草案

### 7.1 建立案例

```text
POST /api/v1/findings/{finding_id}/regression-case
POST /api/v1/applications/{application_id}/regression-cases/import
GET  /api/v1/applications/{application_id}/regression-cases
POST /api/v1/regression-cases/{case_id}/reviews
GET  /api/v1/regression-cases/{case_id}/reviews
```

导入接口接受 `BenchmarkSpec` 兼容字段，但语义是维护回归案例，不创建 BenchmarkEvaluation。

### 7.2 创建后继扫描

```text
POST /api/v1/scans/{baseline_scan_id}/successors
Content-Type: multipart/form-data

apk=<file>
investigator=configured|codex|none
retest_scope=active_cases|none
```

上传时尚未解析目标 APK，API 先创建 `pending` comparison；静态阶段负责完成身份校验。

### 7.3 读取差分与启动复验

```text
GET  /api/v1/scans/{target_scan_id}/comparison
POST /api/v1/comparisons/{comparison_id}/replays
GET  /api/v1/comparisons/{comparison_id}/replays
```

差分响应必须直接返回稳定 ID、变化类型、匹配置信度、原因及目标资源 ID。前端不得通过
标题、位置字符串或 UUID 猜测跨版本关系。

## 8. 前端 MVP

- 基线扫描为 `final` 时显示“比较并复验新版本”。
- 复用上传 Dialog，并展示基线包名、版本、SHA-256。
- 有 comparison 的目标 Scan 显示“版本差分”Tab。
- Tab 首屏依次显示：
  - 活跃回归案例总数；
  - 仍可复现、未复现但未证明修复、证据不足、无法映射；
  - 新增攻击面和新增高危；
  - 覆盖及工具兼容性警告。
- 差分行可跳到当前 Finding、Task 或验证链。
- Tabs 改为受控状态并同步 URL；当前 `defaultValue` 无法支持刷新恢复和精确跳转。

不做左右源码 Diff、任意 N 路版本图、聊天助手或自动发布结论。

## 9. 数据迁移与兼容

当前数据库只调用 `metadata.create_all()`，不会给已有 SQLite 表增加列或约束。实现功能前
应引入版本化迁移机制，并先备份本地数据库。

第一批迁移只创建新增表，尽量不 ALTER 现有核心表：

1. 创建 Application、关联、案例、观测、审核和 comparison 表。
2. 按已有 `Scan.package_name` 回填应用归组。
3. 保存每次 Scan 的签名快照；签名缺失标记为 `unverified`。
4. 对旧 `accepted/false_positive` Finding 创建 legacy review 事件，但不自动创建回归案例。
5. 后续将 `Finding.status` 固定为机器结论；旧 review API 双写兼容一个版本后废弃覆盖行为。

历史 `accepted/false_positive` 已经覆盖的机器状态无法总是可靠恢复：仅在平台 Evidence 和
Hypothesis 关系足够时回填，否则保守标记为 `candidate + legacy review`。

## 10. 实施阶段

### Phase 0：隔离和迁移基础

- 阻止任务跨 Scan 加载 EntryPoint。
- 阻止无效 hypothesis ID 静默回退。
- 引入数据库 schema 版本与迁移。
- 将人工 review 从机器状态中分离。

### Phase 1：只读版本差分

- Application 与 Scan 归组。
- `entry-v1`、`finding-v1` 纯函数及测试。
- 明确基线的 successor 上传。
- 攻击面、Finding、SDK、签名、工具和覆盖差分。
- JSON/HTML 差分报告。

### Phase 2：人工回归案例

- 从 Finding 提升与本地真值导入。
- 追加式 review。
- 每个 Scan 的 occurrence 和“本次未观测到”语义。

### Phase 3：受限 Proof 重放

- ReplayTemplate 和持久状态机。
- guest + 普通 Probe + 无持久副作用的强匹配用例。
- 新 Evidence 隔离、清理和显式负 Oracle。

### Phase 4：扩展

- 业务账号态 fixture（后续专项能力）。
- 类型化 Provider/Receiver/Service/Deep Link Oracle。
- PoC 源码快照与内容寻址构建。
- 趋势、批量导出和可选 CI 集成。

## 11. 验收矩阵

| 场景 | 期望 |
| --- | --- |
| APK 与自身比较 | 无语义差异 |
| 新增 exported Provider | `added`，并显示访问边界 |
| 只改变代码行号 | 稳定 Finding 不应变成 new |
| 同包名、同签名 | 可比较；符合限制的案例可排队复验 |
| 包名不同 | comparison 身份拒绝 |
| 签名不同或缺失 | 显示差分，但自动复验失败关闭 |
| 入口零匹配或多匹配 | `unmappable/ambiguous`，不猜测目标 |
| Finding 未再次出现但覆盖下降 | `not_observed`，不能显示已修复 |
| 分析器版本变化 | 明确工具兼容性警告 |
| 旧 Evidence 存在 | 只显示 lineage，不进入新 Verdict |
| 新 Proof 只证明可达 | `inconclusive`，不能证明漏洞仍存在或已修复 |
| 新类型化正 Oracle 成功 | `still_reproduced` |
| 等价条件下类型化负 Oracle 成功 | `explicitly_refuted` |
| 删除来源 Scan | 案例和审核历史保留，来源引用置空 |
| 重复点击复验 | idempotency key 保证只创建一个有效 replay |

## 12. 当前已知阻塞

- 生产 Probe 目前主要证明 reachability，尚缺可稳定产生
  `security_impact_observed/oracle_refuted` 的类型化 Oracle。
- `ProofAttempt` 缺少 plan/prover/oracle/environment 版本及 replay lineage。
- Proof 状态更新尚未使用 CAS，恢复流程也未处理遗留 `executing`。
- PoC 依赖旧 workspace 路径，删除旧扫描后无法可靠重建。
- 设备安装/清理契约需要为跨版本复验明确处理签名冲突和残留状态。
- Finding 缺少 `(scan_id, dedupe_key)` 数据库唯一约束，并行写入仍可能生成重复记录。

这些问题不阻塞 Phase 1 的只读差分，但在 Phase 3 自动复验前必须解决。
