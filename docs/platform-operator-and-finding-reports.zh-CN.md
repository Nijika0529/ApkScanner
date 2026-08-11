# Finding 报告契约与平台 Operator

本文说明两项运行时能力：统一的 Finding 展示契约，以及可直接接受自然语言命令的平台级 Operator Agent。

## 1. Finding 报告契约

Agent 的任务级 `summary` 不再直接充当漏洞报告。平台按 `SecurityHypothesis` 生成
`metadata_json.report`，字段固定为：

- `title`：已复现或待验证状态加具体风险；
- `conclusion`：当前能成立的安全结论；
- `conditions`：最多两个必要触发条件；
- `attack_chain`：最多五个 source、boundary、control、sink 节点；
- `verification`：已知事实、Evidence、缺失证明和唯一下一步；
- `remediation`：最多两条可执行修复建议；
- `task_id`、`hypothesis_id`：追溯到产出任务和验证链。

同一探索任务中的多个假设分别产生报告，不再共用一段任务总结。Adaptive Verifier 和
Operator 的后续结论只更新 `verification`、Evidence 和状态，保留原始静态攻击链。旧扫描没有
结构化字段时，前端会将原字段映射到同一六段式界面，不要求重新扫描。

## 2. Operator 的职责

Operator 是人工发起的跨工具执行层，适合处理不值得固化为平台工作流的一次性操作，例如：

- 读取某个 Finding、ProofAttempt 和历史 Evidence；
- 从旧 Agent 工作区定位并复用 PoC APK；
- 修改、重新构建 PoC，在动态设备池中申请一台设备复现；
- 使用 Web Search 或已配置的 SSH 环境部署辅助页面；
- 把新 Evidence、产物和简洁结论回写到原 Finding。

Operator 不替换普通入口调查、Critic、Rescue 或 Adaptive Verifier。它复用相同的 Codex Docker、
Android SDK、任务级 ADB 网关和 Evidence 存储，只提供更灵活的人工调度入口。

## 3. 会话与容器

- `OperatorSession` 保存用户目标、Scan/Finding 范围、Codex Thread 和工作区；
- `OperatorTurn` 保存每条命令、设备策略、Turn ID、执行状态和结构化回执；
- 同一 Session 的 `thread.json` 持续复用，保持多轮上下文；
- 每轮结束后关闭 worker，下一轮用同一个 Thread 恢复，并注入新的任务级 ADB token；
- Operator 使用独立 Unix UID、HOME 和可写工作区，不直接修改历史 Agent 工作区；
- 主 APK 的完整反编译结果仍通过 `/scan-input` 只读挂载。

设备策略支持：

| 策略 | 行为 |
|---|---|
| `auto` | 有空闲设备时申请；设备忙时先完成无设备工作 |
| `required` | 排队等待设备后执行本轮 |
| `none` | 本轮不申请设备 |

ADB 命令仍由 `AdbDevicePool` 分配独占 serial，并通过 adaptive gateway 记录 Evidence。Operator 不会
绕开设备租约直接调用宿主机 ADB。

## 4. Artifact/PoC 索引

`IndexedArtifact` 对历史 Agent 工作区和 Operator 输出中的 APK、脚本、HTML、JSON、ZIP、报告建立
内容寻址索引。索引记录 SHA-256、原始路径、Scan、Task、Finding 和 Operator Session 归属；实际
文件复制到 `operator_artifacts` CAS。

启动 Operator 时，相关历史产物被复制到其工作区 `imports/`，上下文文件
`platform-context.json` 给出可直接读取的相对路径。新产物应写到 `poc/` 或 `output/`，本轮结束后
自动进入索引并可从前端下载。

## 5. API

| 方法 | 路径 | 用途 |
|---|---|---|
| `POST` | `/api/v1/operator/sessions` | 创建会话并执行首轮命令 |
| `GET` | `/api/v1/operator/sessions` | 列出会话 |
| `GET` | `/api/v1/operator/sessions/{id}` | 获取完整 Turn 历史 |
| `POST` | `/api/v1/operator/sessions/{id}/turns` | 在同一 Thread 继续执行 |
| `POST` | `/api/v1/operator/sessions/{id}/cancel` | 停止当前 Turn 和设备排队 |
| `GET` | `/api/v1/operator/artifacts` | 按 Scan、Finding 或 Session 查询产物 |
| `GET` | `/api/v1/operator/artifacts/{id}/download` | 下载不可变产物 |
| `POST` | `/api/v1/supervisor/operator-dispatch` | 供后续 Supervisor Agent 复用的派发入口 |

前端顶部提供全局“平台 Agent”，每张 Finding 卡也提供“交给平台 Agent”。Finding 入口会自动带入
`scan_id`、`finding_id` 和建议的 PoC 复现命令。

## 6. Operator 回执

Codex 必须按 `OperatorReceipt` 返回：执行结果、摘要、动作、观察、Evidence ID、产物路径、Finding
更新和剩余缺口。平台只接受当前 Scan 中真实存在的 Evidence ID；模型文字本身会作为
`operator.receipt` 留档，但不会伪装成独立运行时事实。
