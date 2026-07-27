# OpenCode + DeepSeek 接入设计

## 调研结论

OpenCode 官方提供的是 JS/TS SDK。SDK 通过 `createOpencodeServer` 启动本地 server，再用
`createOpencodeClient` 创建类型化客户端；会话主路径是 `session.create`，Flash 使用
`session.prompt`，Pro 使用 `session.promptAsync` 加短连接消息与 session 状态轮询。
只有完整工具循环进入 idle 后才读取最终 assistant 文本。SDK 支持给同步
prompt 传 JSON Schema，并通过内部 `StructuredOutput` 工具收集结构化结果。官方资料：

- [OpenCode SDK](https://opencode.ai/docs/sdk/)
- [OpenCode Providers / DeepSeek](https://opencode.ai/docs/providers)
- [DeepSeek Thinking Mode](https://api-docs.deepseek.com/guides/thinking_mode/)
- [DeepSeek Tool Calls](https://api-docs.deepseek.com/guides/tool_calls)
- [DeepSeek Agent Integration Compatibility](https://api-docs.deepseek.com/quick_start/agent_integrations/oh_my_pi)
- [DeepSeek JSON Output](https://api-docs.deepseek.com/guides/json_mode/)
- [DeepSeek API 更新记录](https://api-docs.deepseek.com/updates/)

截至 2026-07-23，项目锁定 `@opencode-ai/sdk==1.18.4` 与 `opencode-ai==1.18.4`。DeepSeek
当前正式模型使用 `deepseek-v4-pro` 和 `deepseek-v4-flash`；旧的 `deepseek-chat` /
`deepseek-reasoner` 将于 2026-07-24 停用，因此没有把旧别名作为默认值。

这里存在一个必须显式处理的协议差异：

- OpenCode 1.18.4 的 `format: json_schema` 会注册内部 `StructuredOutput` 工具，并固定
  向 provider 下发 `tool_choice: required`；
- DeepSeek V4 Pro 默认使用思考模式。它可以返回 JSON 文本，但思考模式拒绝
  `tool_choice` 参数，因此不能直接使用 OpenCode 这条工具型 StructuredOutput 通道；
- V4 Flash 继续使用 OpenCode 原生 `json_schema` 通道。

因此平台按模型选择输出适配器，而不是在 Pro 失败后静默换成 Flash：

| 模型 | OpenCode format / 传输 | 发给模型的工具 / `tool_choice` | 结果校验 |
| --- | --- | --- | --- |
| `deepseek-v4-pro`（及其版本后缀） | `text`；`promptAsync` + `session.messages/status` 短轮询，等待 idle | 首轮允许 `read/glob/grep/bash`，使用普通自动工具选择，不使用 `required` | prompt 携带精确 Schema 和最小示例；Ajv 8.20.0 本地校验，纠正轮关闭工具，最多 2 次 |
| `deepseek-v4-flash` | `json_schema`；同步 `prompt` | `read/glob/grep/bash` + `StructuredOutput`；`required` | OpenCode 内部校验，最多 2 次重试 |

Pro 通道不会把思考模式关掉，也不会绕过 OpenCode session/provider。它只避开
OpenCode 当前由工具实现的 StructuredOutput。普通文件工具仍按 OpenCode CLI 的常规
tool-call 循环工作；模型完成探索后返回 JSON 文本，再由本地确定性校验器收敛为同一份
`AgentInvestigationResult`。

本地克隆的 OpenCode `dev` 源码与 npm 发布包均为 1.18.4。调研同时发现官网示例、生成
类型和发布包运行时可能短暂不同步，所以不能只依赖文档片段：本项目固定 SDK/CLI 同版，
并使用真实发布包的无计费 capability probe 与本地协议测试守住升级边界。

## 为什么使用 Node bridge

主控制面是 Python，而官方 OpenCode SDK 是 JavaScript。直接从 Python 重写 HTTP 调用会
绕过 SDK 的 provider、session、消息转换和结构化输出语义。因此增加一个很薄的一次性
Node worker：

```mermaid
sequenceDiagram
    participant P as Python Orchestrator
    participant W as Node bridge
    participant O as OpenCode server
    participant D as DeepSeek API

    P->>W: stdin: bounded task JSON + JSON Schema
    W->>O: createOpencodeServer(127.0.0.1, random port)
    W->>O: session.create
    alt deepseek-v4-flash
        W->>O: session.prompt(format=json_schema)
        O->>D: tools=[StructuredOutput], tool_choice=required
        D-->>O: StructuredOutput tool call
        O-->>W: OpenCode-validated result
    else deepseek-v4-pro
        W->>O: session.promptAsync(text)
        O-->>W: 204 accepted
        O->>D: tools=[read,glob,grep,bash], ordinary tool selection
        D->>O: inspect and run commands in the isolated task attempt workspace
        D-->>O: JSON text
        loop bounded short polling until session idle
            W->>O: session.messages
            W->>O: session.status
            O-->>W: current messages and turn state
        end
        W->>W: Ajv validate
        opt invalid, at most 2 corrections
            W->>O: promptAsync(exact validation errors)
        end
    end
    W-->>P: stdout NDJSON: event* + terminal result
    W->>O: session.delete + server.close
```

bridge 不参与任务规划、证据判定或设备操作。Python 仍然负责：

1. 静态工具覆盖面和入口枚举；
2. 生成每个入口的任务与证据摘要；
3. 在每个自适应轮次校验 Agent 提出的受限测试（默认每轮最多接受 100 个）；
4. 在云真机上执行允许的 Probe/ADB/Frida 操作；
5. 验证 Evidence ID，并把不满足条件的结论降级。

## 安全边界

OpenCode 本身是 coding agent，默认会暴露读文件、Shell、编辑、Web、MCP 和 task 工具。
本接入恢复接近本地 CLI 的代码探索和命令执行能力，同时保留设备动作边界：

- OpenCode 的全局和专用 Agent permission 先 `* = deny`，只允许
  `read/glob/grep/bash`；
  Flash 通道另外允许内部 `StructuredOutput`。
- 平台按 `task_id + attempt` 创建隔离 workspace，只物化当前入口的代码上下文和不可变
  Evidence；Docker 将它挂载到 `/workspace`，Host 模式以它为 cwd。Bash 可以在该
  workspace 和 `/tmp` 创建脚本或分析产物，容器根文件系统保持只读，并发任务之间不共享
  可写扫描目录。
- 原生 write/edit/patch、Web、MCP、task/subagent 均保持禁用。ADB 同时通过 Bash
  permission、PATH 阻断程序、无设备参数/Socket 三层禁用；不挂载认证流或宿主机其他目录。
  外部目录访问由 OpenCode `external_directory` permission 拒绝。
- 设置 `OPENCODE_PURE=1`，禁用外部插件；禁用 project config、Claude 配置、模型目录
  自动刷新和自动升级。
- 每次调用使用新 session、新 OpenCode server 和临时 HOME/XDG 数据目录。
- worker 在发送 prompt 前订阅 `event.subscribe()` SSE，并把会话状态、步骤、响应、
  重试、校验和错误归一化为 NDJSON 事件；Python 按 `task_id` 写入实时扫描时间线。
- Pro 不再让 SDK 到 loopback server 的一个同步 HTTP 请求覆盖整段深度推理；异步下发
  后只用短 GET 读取消息状态。安全的本地读取遇到连接重置会指数退避重试 3 次；worker
  本身若因 `fetch failed`、`ECONNRESET` 或 Undici socket/header timeout 退出，Python
  只在剩余任务预算内重建一次 worker/session，不切换模型。
- loopback server 使用随机端口与随机 Basic Auth；进程超时后终止整个进程组。
- Docker 模式使用只读 rootfs、无 capabilities、`no-new-privileges`、PID/CPU/内存限制
  和临时 HOME。
- API Key 不进入 payload、命令参数、日志或数据库；只通过 `DEEPSEEK_API_KEY` 环境变量
  传给 worker。
- 自定义 base URL 不接受凭据、查询参数或 fragment；远程网关必须使用 HTTPS，明文 HTTP
  只允许指向 loopback。

这能收窄主机侧权限，但模型仍会收到任务上下文和证据摘要。启用前必须确认公司对
DeepSeek 或企业代理的区域、保留、训练使用、日志和敏感数据策略；生产部署还应把容器
出口限制到获批端点。

## 配置和选择

服务默认后端由以下变量决定：

```bash
export APKSCANNER_INVESTIGATOR_BACKEND=opencode
export APKSCANNER_OPENCODE_ENABLED=true
export APKSCANNER_OPENCODE_MODEL=deepseek-v4-flash
export DEEPSEEK_API_KEY=...
```

`deepseek-v4-flash` 是当前稳定基线和默认值。`deepseek-v4-pro` 的 prompted-JSON
兼容通道保留为显式选择，待 Flash 全链路基线稳定后再单独回归，不会由平台自动切换。

Web 上传框和 CLI 的 `--investigator` 可以为单个扫描选择：

- `configured`：创建时解析并记录服务默认值，后续只能由用户在扫描控制台显式修改；
- `codex`：使用 Codex；
- `opencode`：使用 OpenCode + DeepSeek；
- `none`：只执行静态规则与确定性动态测试。

不会在一次任务失败后静默切换模型。静默 fallback 会导致同一报告混合不同供应商的
行为、费用和数据边界，也会让结果不可复现。需要切换时应创建新扫描，或明确修改扫描
选择后重跑。

每次调用的审计记录会写明 `output_mode`、`workspace_shell` 工具档位、可写根目录以及
实际工具列表。`agent.events` 保存每次 `read/glob/grep/bash` 的开始、完成、受限参数
摘要和状态。Pro 的
`output_transport.model_calls` 还会保存
每一轮实际 prompt、原始文本响应、解析错误、Schema 校验错误、是否被接受和单轮 usage；
`request_mode=prompt_async_poll` 与 `worker_transport_attempts` 记录实际传输路径及是否重建；
即使 3 次都失败，这些内容也进入 `agent.error` 的不可变 Evidence。API Key 和隐藏思考
内容不进入审计。规范化 SDK 关键事件另存为 `agent.events` Evidence。

## 验证与升级

```bash
npm ci --prefix opencode-worker
npm run check --prefix opencode-worker
npm test --prefix opencode-worker

DEEPSEEK_API_KEY=... \
APKSCANNER_OPENCODE_ENABLED=true \
APKSCANNER_OPENCODE_ISOLATION=host \
scanctl capabilities --deep
```

`npm test` 启动本地假的 DeepSeek OpenAI-compatible SSE 服务，不访问外网、不产生模型
费用。协议测试分别确认：

1. Flash 暴露 workspace 工具和 `StructuredOutput`，并使用 `tool_choice: required`；
2. Pro 首轮暴露 `read/glob/grep/bash`，不发送冲突的 `tool_choice: required`；
3. Pro 能真实调用 `read`、接收文件结果并继续生成 JSON；
4. Pro 能在 workspace 和 `/tmp` 执行 Bash 并继续生成 JSON；
5. PATH 中的 ADB 阻断程序固定返回 126；
6. Pro 首次返回不合格 JSON 时，Ajv 拒绝结果，关闭工具并通过同一 session 下发纠正提示；
7. Pro 使用 `prompt_async_poll`，避免长推理占用一个同步 loopback HTTP 请求；
8. worker 在两种模式下都输出可增量消费的事件 envelope 和唯一 terminal result；
9. 通过本地 Schema 校验后，两个通道归一化为相同的 worker 响应。

升级时必须：

1. SDK 与 CLI 使用同一精确版本；
2. 更新 `opencode-worker/package.json`、lockfile、Python 版本常量和 Docker labels；
3. 跑本地 bridge 协议测试；
4. 跑无计费 `capabilities --deep`，确认目标模型存在；
5. 用非生产测试账号执行一个真实 DeepSeek smoke scan，核对 usage、超时和错误脱敏；
6. 重新评审 OpenCode permission、provider 转换和结构化输出源码。
