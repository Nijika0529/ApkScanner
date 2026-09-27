# Web 语义证明闭环

Deep Link 或 JSBridge 的页面回调先作为运行时事实保存，不能直接把 Agent 的“成功”叙述记为漏洞复现。平台按以下顺序生成正式证明：

1. 平台冻结 Web 实验方案，生成 `experiment_id`、根 nonce 和 attack/control/quiet 各自的阶段 nonce。
2. 普通应用 UID 发起攻击；平台关联 PoC 启动、进程、目标 UID 的 `onPageFinished` 日志，以及目标进程。当前适配器只接受目标应用自己发出的、含本次 attack URL 和阶段 nonce 的主 frame 日志；它不是系统级 WebView 回调，也不能证明 iframe 调用来源。
3. Observer 保存页面访问、Bridge 回调和负对照。回调内容始终标为客户端自报；Chrome 的 `bridge_missing` 与静默页的 `no_bridge_requested` 均出现且平台启动回执有效，才有 `controls_validated=true`。
4. 如方案声明状态 Fixture，平台先执行仅允许查询的 `state_check` 并保存命令回执；只填 Fixture ID 或登录状态文字不算核验。对于仓库内受控 `adaptivecases.apk`，平台还先比对真机已安装 APK 与扫描制品的 SHA-256，再让目标进程内部生成一次性随机 canary。Provider 同时要求 `DUMP` 权限与 shell UID，只返回 token 的 SHA-256 和目标 Bridge 调用计数/URL 摘要，绝不通过 ADB 返回原值。普通攻击应用即使被 ADB 授予 `DUMP` 也不能查询。Agent ADB 网关在 canary 生效期间暂停，只允许平台继续 ProofReplay 与目标读回。
5. 攻击回调出现后，平台重新读取目标 Provider，比较回调值摘要、目标侧 Bridge 调用计数与本次 attack URL 摘要，生成 `web.experiment.target_effect`。这个独立来源只适用于固定 SHA 的受控测试 APK；一般第三方 APK 不会自动获得同等能力。缺回调、目标方法调用、读回或归属不符时不能升格。
6. 高权限验证 Agent 提交 `SemanticProofAssessment` 建议。平台从本次扫描工作区中按候选的源码锚点读取有限行，生成 `static.source_excerpt`；路径必须在 `jadx` 或 `apktool` 下，锚点 SHA 不符、符号链接、越界路径或过大文件均拒绝。源码只支持数据来源判断，不充当动态效果。
7. 独立 Judge 在空临时目录、`Sandbox.read_only` 下只看冻结 Evidence。任何命令、文件工具、Web Search、MCP 工具调用或未知 SDK 事件都会使该次审查失败。平台保存 Judge 的结构化回执。
8. Policy Gate 重新读取 Evidence 原文并核对哈希、摘录、扫描/任务/假设/实验归属、设备、nonce、执行窗口、负对照、APK 身份、独立目标效果和 Judge 回执。全部满足后由平台生成 `semantic.proof_attestation` 与 `platform_semantic_attestation` ProofAttempt，并由平台写入 `harm_demonstrated=true`。

若方案采用远端 HTTPS Observer，Judge 冻结的证据还必须包含同实验、同 nonce、同设备、同部署 ID 的 `web.experiment.remote_receipt`：部署时及快照时的公网 nonce 绑定探针均为 `healthy`，且快照没有远端传输或对照缺口。任一回执缺失、晚于快照、归属不符或探针失败，都保持 Oracle gap。回执只证明传输可用，不能替代目标 WebView 加载或独立影响 Oracle。

Judge 可以判断返回值是否为目标拥有的会话数据、授权边界是否跨越，以及页面自报、直接请求 Observer、旧回调或输入回显是否能解释结果；它不能设置最终 ProofAttempt。`unresolved_obligations` 非空、没有目标 WebView 加载确认、只有页面或 PoC 自己的成功日志、没有独立目标来源、或缺有效对照时，结论保持 Oracle gap。返回 `void` 的操作还需要独立的目标状态前后变化回执，JS 的“调用完成”不算影响。当前主 frame 日志不证明 iframe 的实际调用 Origin，所以 iframe 用例仍保留 Oracle gap。

受控 canary 是验证证明流水线的合成数据，不等同于真实账号凭据。`pm path` 只能证明包已安装，不能证明已登录；当前非受控 account/session/app_state Fixture 即使有一般 shell 查询，也不会被当成目标状态的独立来源。平台对一般 APK 尚无通用 WebView 内容/Bridge 原生回执，不能把本测试夹具的能力泛化为任意产品 APK 的黑盒证明。

该流水线当前面向授权实验室与非恶意 Agent 的回归。Agent 在实验开始前仍可能通过自适应 ADB 留下后台进程、另行驱动目标 WebView；随机值不可由 shell 直接读取能消除最直接的伪造通道，却尚不能严格证明每一次目标调用都由本次普通 UID PoC 唯一触发。对抗性 Agent 场景需要从任务开始限制 ADB 能力，并加入目标 Activity 启动来源的系统级回执。

真实 Bridge 返回值可能是敏感凭据。当前 Web 回调的 `value/error` 在 Evidence 和 Judge 输入中只保留摘要与长度，任务撤销会清理内存事件；但其他 Oracle、API 下载的统一敏感字段策略、鉴权和保留期仍未完成。在此之前只使用合成账号与数据测试 Web 回调。受控 canary 的目标 Provider 不暴露原值，并不能自动保护任意产品 App 的返回值。

## 启用独立 Judge

显式设置 `APKSCANNER_SEMANTIC_JUDGE_ENABLED=true` 和 `APKSCANNER_SEMANTIC_JUDGE_CODEX_HOME`，后者应指向已通过 ChatGPT 登录的专用 Codex 认证目录。可选 `APKSCANNER_SEMANTIC_JUDGE_MODEL`（默认 `gpt-6-luna`）及 `APKSCANNER_SEMANTIC_JUDGE_TIMEOUT_SECONDS`（默认 120）。未配置、调用失败或无有效 Judge 回执均不会升格为 Proof。Judge 不使用 DeepSeek Docker 会话，也不接收 ADB/Observation 网关变量或 SSH 密钥。

本地 Web Observer 通过设备上的 ADB reverse 提供受控 HTTP 页面，因此实际产品应用可能受明文流量策略限制。远端 HTTPS Observer 已支持操作员显式配置的 SSH 反向隧道、公网 nonce 健康检查与撤销，详见[远端部署边界](remote-web-observer.zh-CN.md)；它只解决页面传输，不提高目标侧观测等级。目标 UID 的 `onPageFinished` 回执通常只在专用测试 APK 或目标已有可信日志时可得；缺该硬事实时平台会保留 Oracle gap，不以模型推断代替。通用目标 WebView 内容确认仍是后续能力。
