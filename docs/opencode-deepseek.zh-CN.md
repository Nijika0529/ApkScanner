# OpenCode + DeepSeek 接入设计

## 调研结论

OpenCode 官方提供的是 JS/TS SDK。SDK 通过 `createOpencodeServer` 启动本地 server，再用
`createOpencodeClient` 创建类型化客户端；会话主路径是 `session.create` 和
`session.prompt`。它支持给 prompt 传 JSON Schema，并通过内部 `StructuredOutput` 工具
收集结构化结果。官方资料：

- [OpenCode SDK](https://opencode.ai/docs/sdk/)
- [OpenCode Providers / DeepSeek](https://opencode.ai/docs/providers)
- [DeepSeek Function Calling](https://api-docs.deepseek.com/guides/function_calling)
- [DeepSeek JSON Output](https://api-docs.deepseek.com/guides/json_mode/)
- [DeepSeek API 更新记录](https://api-docs.deepseek.com/updates/)

截至 2026-07-23，项目锁定 `@opencode-ai/sdk==1.18.4` 与 `opencode-ai==1.18.4`。DeepSeek
当前正式模型使用 `deepseek-v4-pro` 和 `deepseek-v4-flash`；旧的 `deepseek-chat` /
`deepseek-reasoner` 将于 2026-07-24 停用，因此没有把旧别名作为默认值。

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
    W->>O: session.prompt(model=deepseek/*, format=json_schema)
    O->>D: OpenAI-compatible streaming request
    D-->>O: StructuredOutput tool call
    O-->>W: validated structured result + usage
    W-->>P: stdout: one JSON object
    W->>O: session.delete + server.close
```

bridge 不参与任务规划、证据判定或设备操作。Python 仍然负责：

1. 静态工具覆盖面和入口枚举；
2. 生成每个入口的任务与证据摘要；
3. 校验 Agent 提出的最多 12 个测试；
4. 在云真机上执行允许的 Probe/ADB/Frida 操作；
5. 验证 Evidence ID，并把不满足条件的结论降级。

## 安全边界

OpenCode 本身是 coding agent，默认会暴露读文件、Shell、编辑、Web、MCP 和 task 工具。
在 APK 扫描场景里，这些能力不应直接交给模型。本接入采用以下约束：

- OpenCode 的全局和专用 Agent permission 先 `* = deny`，只对内部
  `StructuredOutput = allow`。
- 不给 OpenCode 挂载 APK、反编译 workspace、认证流或 ADB socket；prompt 只包含平台
  生成的 JSON。
- 设置 `OPENCODE_PURE=1`，禁用外部插件；禁用 project config、Claude 配置、模型目录
  自动刷新和自动升级。
- 每次调用使用新 session、新 OpenCode server 和临时 HOME/XDG 数据目录。
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
export APKSCANNER_OPENCODE_MODEL=deepseek-v4-pro
export DEEPSEEK_API_KEY=...
```

Web 上传框和 CLI 的 `--investigator` 可以为单个扫描选择：

- `configured`：创建时解析并固化服务默认值；
- `codex`：使用 Codex；
- `opencode`：使用 OpenCode + DeepSeek；
- `none`：只执行静态规则与确定性动态测试。

不会在一次任务失败后静默切换模型。静默 fallback 会导致同一报告混合不同供应商的
行为、费用和数据边界，也会让结果不可复现。需要切换时应创建新扫描，或明确修改扫描
选择后重跑。

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
费用。测试会确认最终请求只暴露 `StructuredOutput`，并验证 OpenCode 能把 tool call
还原为结构化结果。

升级时必须：

1. SDK 与 CLI 使用同一精确版本；
2. 更新 `opencode-worker/package.json`、lockfile、Python 版本常量和 Docker labels；
3. 跑本地 bridge 协议测试；
4. 跑无计费 `capabilities --deep`，确认目标模型存在；
5. 用非生产测试账号执行一个真实 DeepSeek smoke scan，核对 usage、超时和错误脱敏；
6. 重新评审 OpenCode permission、provider 转换和结构化输出源码。
