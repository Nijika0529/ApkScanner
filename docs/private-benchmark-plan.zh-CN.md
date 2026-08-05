# 私有已知漏洞集盲测计划

本文只定义公开的验收方法，不记录客户、产品、包名、报告标题、真实组件、端点或漏洞细节。
私有报告、APK 和逐漏洞 ground truth 必须保存在 Git 忽略目录或独立受控存储中，盲测时不得挂载到
调查 Agent 工作区。

所有正式动态验收默认运行在 Android 16 / API 36+。如果某条链受到新平台行为缓解，应同时记录
应用代码风险、平台缓解条件和实际运行结果，不能把平台缓解直接写成应用已修复。

## 1. 覆盖族

私有 ground truth 应按通用攻击链分类，而不是把真实类名写进公开规则：

| 覆盖族 | 典型 source/control/sink | 动态证明方向 |
| --- | --- | --- |
| Binder 与身份混淆 | exported Service、Parcel、caller UID/package | 普通 App UID bind/transact、敏感 reply/callback、调用者 Oracle |
| WebView / JSBridge | 外部 URL、Deep Link、Web 内容边界、JavaScript interface | 授权测试页面调用桥，观察 Token/账号语义或目标行为 |
| Intent 与能力委托 | 嵌套 Intent、PendingIntent、内部路由、可控 extra | 普通 App 构造调用并观察内部敏感动作或数据返回 |
| Provider 与 URI Grant | authority、path、grant flag、文件名 | 跨 UID 读取、错误委托或受保护文件访问 |
| 文件导入与状态覆盖 | ACTION_SEND、SAF、ZipEntry、目标路径 | canary 文件创建/删除/hash 变化或应用可见状态变化 |
| Receiver 与本地 IPC | 动态广播、localhost TCP、Unix Socket | 普通 App 发送/连接并观察敏感返回或目标副作用 |
| 命令与脚本语义 | shell sink、参数拼接、脚本写入/执行 | 使用无害 canary 验证 substitution、glob、pipeline 等真实语义 |
| 回调与状态机 | browsable callback、nonce/state、授权时间窗 | 在受控授权窗口伪造或重放回调，观察会话状态变化 |
| 配置与持久规则 | 规则文件、数据库、版本闸门、完整性校验 | 可逆替换 canary 配置并比较授权/风控决策 |
| 应用内部工具链 | Tool dispatcher、数据域转换、自动化任务 | 通过显式 Capability 和测试账号验证跨域调用与确认流程 |

## 2. Ground truth 隔离

每个私有案例至少保存：

- 随机化稳定 ID，不包含产品、组件或漏洞标题；
- 真实描述和代码锚点，存放于 Agent 不可见的评测端；
- 攻击者身份、前置账号态、Android API 和可用设备要求；
- 最低证明级别、允许的 Oracle 和成功判定；
- 语义去重材料，避免同一根因的多个入口重复计分；
- 安全对照组和明确反证条件。

盲测输入只包含 APK、平台正常生成的反编译结果和运行时 Evidence。报告文件名、期望标题、匹配
关键词和历史人工结论都不能出现在 Agent prompt、扫描 workspace、Capability 返回值或 Web Search
可访问目录中。

## 3. 分阶段验收

### 阶段 A：平台原生入口

- 组件、Deep Link、Provider、Binder 外部可达性；
- PendingIntent、嵌套 Intent 和 URI Grant 联合分析；
- WebView、路径穿越、Zip 提取、端点和凭据的静态语义种子；
- 每个 hypothesis 独立 Proof、Finding 和去重身份。

### 阶段 B：开放语义实验

- Web 测试页面和回调服务；
- 文件、数据库、规则缓存等可逆 canary mutation；
- 账号、会话、授权窗口和测试数据 fixture；
- 通过 allowlisted MCP 或固定 SHA-256 Python Adapter 暴露的业务 Capability。

Adapter 必须声明输入/输出 Schema、权限、Evidence 类型、超时、清理动作和 Android API 范围。
返回值可以由 Agent做语义判断，但真实调用记录、制品摘要和 cleanup 状态仍由平台保存。

## 4. 评分口径

- `reproduced_blackbox` 必须引用本次扫描、当前 APK 和目标 Profile 的平台 Proof；
- `supported_static` 只统计为候选召回，不能混入动态召回率；
- `mitigated_by_platform` 不算应用修复，也不算当前系统上的成功利用；
- 同一根因可以合并 Finding，但每个入口必须有独立 Coverage 记录；
- 平台确认但无法匹配 ground truth 的 Finding 计入 false positive；
- 未证明的模型候选单独统计为调查噪声；
- Benchmark 报告必须注明 APK 集、ground truth 版本、commit、模型、设备、Profile 和时间；
- 固定数据集达到 100% 只能称为该版本回归通过，不能外推为任意 APK 的全量检出率。

## 5. 对外披露规则

公开仓库只保留通用覆盖族、合成 fixture 和脱敏后的统计方法。以下内容不得提交：

- 客户或产品名称、包名、真实组件与签名信息；
- 私有漏洞报告、截图、日志、扫描 UUID 和设备地址；
- 生产/预发布端点、账号、会话、Token、SSH 配置和 API Key；
- 能够直接映射回未披露漏洞的逐项描述或 PoC。

需要展示项目效果时，优先使用 `testapk/` 的公开合成 APK 及其 ground truth。
