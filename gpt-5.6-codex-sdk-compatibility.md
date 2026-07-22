# GPT-5.6 与 Codex Python SDK 兼容性调查

调查日期：2026-07-10

> 历史快照：本文保留 2026-07-10 使用 `openai-codex==0.1.0b3` 时的实测结果。
> 2026-07-17 上游已经发布稳定版 `openai-codex==0.144.4`，绑定匹配的
> `openai-codex-cli-bin==0.144.4`，并让 `ReasoningEffort` 对 `max`、`ultra` 等
> 新非空值前向兼容。当前项目尚未升级，仍通过旧 SDK 连接外部新版 CLI。最新结论、
> 迁移方式和源码分析见
> [`codex-python-sdk-integration.md`](codex-python-sdk-integration.md)。

## 结论

当前机器和账号已经可以通过全局 Codex CLI 实际调用以下模型：

- `gpt-5.6-sol`
- `gpt-5.6-terra`
- `gpt-5.6-luna`

三个模型的低推理 smoke test 均成功。官方要求 Codex CLI 至少为
`0.144.0`，本机全局 CLI 为 `0.144.1`，满足要求。

但是，pip 发布的 Python SDK 尚未完整跟进本次模型和协议更新：

- `openai-codex==0.1.0b3` 是当前 pip 最新版本。
- 该 SDK 依赖的 `openai-codex-cli-bin==0.137.0a4` 无法调用 GPT-5.6。
- Python 生成类型不识别新的 `max` 和 `ultra` reasoning effort。
- 基础 turn、fork 和 resume 可以通过 Python SDK 连接外部 `0.144.1`
  CLI 运行，但模型目录和新版多 agent 事件仍存在协议缺口。

因此，当前项目可以受控接入 GPT-5.6 的 `low` 至 `xhigh` 档位，但不应
直接宣称已经完整支持 GPT-5.6、`max` 或 `ultra`。

## 官方发布信息

OpenAI 当前将 GPT-5.6 系列分为三个能力层级：

- Sol：面向复杂推理、编码和专业任务的旗舰模型。
- Terra：在能力、速度和成本之间取得平衡。
- Luna：面向成本敏感和高吞吐任务。

官方资料：

- [GPT-5.6 在 ChatGPT 与 Codex 中的可用性](https://help.openai.com/en/articles/20001354)
- [GPT-5.6 Sol 发布说明](https://openai.com/index/previewing-gpt-5-6-sol/)
- [OpenAI 模型目录](https://developers.openai.com/api/docs/models)
- [Codex 0.144.0 release](https://github.com/openai/codex/releases/tag/rust-v0.144.0)
- [Codex 0.144.1 release](https://github.com/openai/codex/releases/tag/rust-v0.144.1)

## 本机版本快照

| 组件 | 本机版本 | 当日上游版本 | 判断 |
| --- | --- | --- | --- |
| `openai-codex` | `0.1.0b3` | `0.1.0b3` | pip 最新，但生成协议类型落后 |
| Python SDK 内置 CLI | `0.137.0-alpha.4` | `0.137.0-alpha.4` | 无法调用 GPT-5.6 |
| 全局 Codex CLI | `0.144.1` | `0.144.1` | 可调用 GPT-5.6 |
| `/workspace/codex-src` | 2026-07-04 提交 | `rust-v0.144.1` | 落后稳定版 118 个提交 |

检查时，`/workspace/codex-src` 还落后 `origin/main` 153 个提交。调查只执行了
`git fetch --prune --tags origin` 来更新远端引用，没有修改或合并该源码工作区。

Python SDK 当前主分支仍固定依赖：

```toml
openai-codex-cli-bin==0.137.0a4
```

所以直接 editable install `/workspace/codex-src/sdk/python` 也不能让 Python SDK
自动获得与 Codex CLI `0.144.1` 对齐的 runtime 和生成类型。

## 实际兼容性测试

### 模型调用

| 调用方式 | 模型或操作 | 结果 |
| --- | --- | --- |
| 内置 CLI `0.137` | `gpt-5.5` | 成功 |
| 内置 CLI `0.137` | `gpt-5.6-luna` | HTTP 400，服务端要求升级 Codex |
| 全局 CLI `0.144.1` | Sol、Terra、Luna | 三个低推理 smoke test 均成功 |
| Python SDK + 全局 CLI | Luna 完整 turn | 成功，通知流正常结束 |
| Python SDK + 全局 CLI | 持久线程 turn、fork、resume | 成功，测试线程已删除 |
| Python SDK + 全局 CLI | `models()` | Pydantic 校验失败 |

`models()` 失败的直接原因是新版模型目录返回了 `max` 和 `ultra`，而
`openai_codex.types.ReasoningEffort` 只接受：

```text
none, minimal, low, medium, high, xhigh
```

项目现有 runner 会为 thread 显式传入 reasoning effort，所以普通 effort 的
`thread/start` 不受用户全局 `model_reasoning_effort = "max"` 影响。但其他未显式
覆盖配置的 Python SDK 调用仍可能在 response 反序列化时失败。

### 项目测试

执行了现有 runner 回归测试：

```text
python -m pytest -q backend/tests/test_codex_runner.py
....                                                                     [100%]
4 passed in 0.09s
```

## 上游源码的重要变化

### GPT-5.6 reasoning effort

Codex `0.144.1` 的 Rust 协议已经支持：

```text
none, minimal, low, medium, high, xhigh, max, ultra, custom
```

Codex 模型目录中：

- Sol 支持到 `ultra`，默认 `low`，使用 multi-agent v2。
- Terra 支持到 `ultra`，默认 `medium`，使用 multi-agent v2。
- Luna 支持到 `max`，默认 `medium`，使用 multi-agent v1。

`ultra` 不只是更高推理预算，它会启用自动任务委派和子 agent。因此它会改变
平台的运行图，而不只是改变单个节点的模型参数。

### 规范化的多 agent 事件

新版 Codex 开始生成更稳定的协作 ThreadItem：

- `collabAgentToolCall`
- `subAgentActivity`
- collab wait lifecycle

协作工具动作包括：

```text
spawnAgent, sendInput, resumeAgent, wait, closeAgent
```

`collabAgentToolCall` 会携带：

- `senderThreadId`
- `receiverThreadIds`
- `prompt`
- `model`
- `reasoningEffort`
- `agentsStates`

`subAgentActivity` 会携带 agent thread、agent path，以及 `started`、
`interacted`、`interrupted` 等状态。这些数据足以让平台动态补充 SDK 自主创建的
agent 节点和运行时通信边。

但这些动作只表达传输和生命周期，不直接表达 `reviews`、`advises`、`directs`
等业务语义。业务 relation 仍必须由 Topology 或任务元数据提供。

### Thread 与 fork 能力

新版协议还增加或完善了：

- `thread/delete`，可删除线程及其派生后代。
- fork 可通过 `lastTurnId` 指定继承到哪个 turn。
- Thread 暴露 `sessionId`、`parentThreadId`、`agentNickname` 和 `agentRole`。
- 恢复线程时保留 reviewer。
- rollout 可以持久化和分页读取规范化 ThreadItem。

这些字段比基于提示词推断父子关系更可靠，适合成为平台 runtime graph 的事实来源。

### Python Goal 实现

`python-v0.1.0b3` 之后的 Python 源码增加了约 1209 行，核心是持久 Goal 的内部
路由和控制，包括 goal set、clear、pause、连续物理 turn 聚合以及 capacity retry。

Goal 对长期运行的 supervisor 有价值：平台可以给 supervisor 设置长期目标，让
Codex 自己推进多个 turn。但该实现目前仍偏内部化，而且尚未发布到 pip，不应作为
当前版本的项目依赖。

其他 Python 源码变化包括：

- 不再宣传直接使用远程 HTTP 图片 URL，推荐 data URL 或本地路径。
- 支持没有 email 字段的 ChatGPT 账号。
- 发布包开始携带 Code Mode host。

## 当前项目的兼容风险

### 1. 默认 runtime 过旧

`backend/app/services/codex_runner.py` 只有在设置
`CODEX_VISUAL_CODEX_BIN` 时才使用外部 CLI，否则使用 Python wheel 内置的
`0.137.0-alpha.4`。该 runtime 无法调用 GPT-5.6。

### 2. `max` 和 `ultra` 贯穿类型缺失

以下位置目前只允许到 `xhigh`：

- `backend/app/models.py`
- `frontend/src/types.ts`
- 前端 reasoning effort 下拉选项
- Python SDK 的 `ReasoningEffort` 生成枚举

只修改前端枚举会让请求在后端或 SDK 层失败。

### 3. 模型目录不能直接用于动态 UI

项目当前没有调用 `codex.models()`，因此该问题暂时不会阻塞普通 run。但如果后续
将模型选择器改为动态目录，当前 SDK 会因 `max`、`ultra` 反序列化失败。

### 4. SDK 自主子 agent 仍不可观测

当前 runner 认识 `collabAgentToolCall`，但主要把它作为 guidance 的安全点阻塞项。
新版 `subAgentActivity` 不在旧 Python 生成类型中，会退化成
`UnknownNotification`。现有 normalizer 只能显示通用 `item.started` 或
`sdk.event`，无法自动创建 agent 节点、运行实例和 relation。

这意味着即使启用 Ultra，前端也可能只看到主 agent 在运行，看不到它实际创建的
子 agent 及其通信过程。

### 5. 依赖范围过宽

后端当前使用：

```toml
openai-codex>=0.0.0
```

Python SDK 仍处于 beta，协议和内置 CLI 更新节奏不同。无上限、无精确版本的依赖
可能导致部署环境获得未经验证的新 SDK。

## 建议的模型分工

结合当前平台的 supervisor、执行分支和验证节点，建议采用：

| 平台职责 | 推荐模型 | 推荐 effort |
| --- | --- | --- |
| 主审计、监督、最终决策 | Sol | `high` 或 `xhigh` |
| 常规执行和多数专业分支 | Terra | `medium` 或 `high` |
| 大量并行调查、初筛 | Luna | `low` 或 `medium` |

不要立即将所有 agent 切换到 Sol 或 Ultra。并行工作量较大时，Terra 和 Luna 更适合
控制成本与延迟，Sol 应集中在需要跨分支判断和最终决策的位置。

## 编排所有权

接入 Ultra 前应明确两种运行模式：

### Platform-owned

Topologies 和 supervisor 服务负责创建 agent、工作区、relation 和后续动作。
Codex 使用 `low` 至 `max`，但不允许 Ultra 自主扩张 agent 图。

这种模式最符合当前项目的可解释编排目标。

### Codex-owned

允许 Ultra 或 Codex 原生协作工具自主创建子 agent。平台不预先规定完整 agent 图，
而是监听 canonical collab events，并把实际 thread 动态导入 runtime graph。

这种模式下建议为运行时节点记录：

- `orchestration_owner = codex`
- `runtime_thread_id`
- `parent_thread_id`
- `agent_path`
- `runtime_action`
- 可选的 `semantic_relation_id`

不能同时让 Topology 和 Ultra 对同一任务无约束地创建 agent，否则会出现两套互不
知情的编排图、重复分支和不可预测的资源消耗。

## 推荐实施顺序

1. 将后端显式指向已验证的全局 CLI `0.144.1`：

   ```bash
   export CODEX_VISUAL_CODEX_BIN=/root/.nvm/versions/node/v22.14.0/bin/codex
   ```

2. 暂时只开放 `low` 至 `xhigh`，先接入 Sol、Terra、Luna 的普通 turn。
3. 将 `openai-codex` 固定到经过验证的精确版本，并增加 CLI 最低版本检查。
4. 增加启动时 capability probe，不要只依赖 pip package version。
5. 为 `model/list` 增加前向兼容解析，未知 effort 应保留为字符串。
6. 统一解析 typed notification 和 `UnknownNotification.params`。
7. 将 `spawnAgent`、`sendInput`、`wait` 等事件映射为 runtime agent、message 和
   lifecycle edge。
8. 保留 Topology 的业务 relation，并将其与 SDK runtime action 分开存储。
9. 在官方 Python SDK 支持 `max`、`ultra` 后，再增加对应 UI 和运行策略。
10. 最后增加 Ultra 的 Codex-owned 实验模式，并对并发、预算和可观测性设置限制。

建议优先实现协议兼容层和 runtime 事件映射，再调整默认模型或 UI effort 选项。
