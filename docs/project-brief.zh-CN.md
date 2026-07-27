# APK Scanner 项目简介（汇报版）

## 一句话说明

APK Scanner 是一个运行在安全人员本地电脑上的 Android 上线前安全扫描控制面：先用确定性
静态工具保证攻击面覆盖，再把每个导出组件和 Deep Link 入口拆成有边界的 AI 调查任务，
通过授权云真机验证可达性和影响，最终输出可审计、可人工复核的证据化报告。

## 解决的问题

传统 APK 扫描擅长“发现疑点”，但常把导出组件、Deep Link 或敏感 API 直接当作漏洞，缺少
真实调用身份、前置状态和影响证据。APK Scanner 将流程拆为“全量枚举 → 风险假设 → 设备
验证 → 证据校验 → 人工结论”，让 AI 负责探索策略，平台负责权限边界、测试执行和最终证据
门槛，避免模型文字直接成为漏洞结论。

## 上传一个 APK 后发生什么

1. 校验 APK/ZIP 安全性，计算 SHA-256，提取签名、包名、版本和 SDK 信息。
2. 使用 Apktool 与可选 JADX 反编译；JADX 局部失败时按目标类判断源码是否可用，不重复反编译。
3. 解析 Manifest，枚举 Activity、Activity Alias、Service、Receiver、Provider 和 Deep Link，
   生成 Security IR、内置规则发现和 8 个 MASVS 域覆盖状态；可并入 MobSF 广度结果。
4. 静态阶段先发布 preliminary 报告，再为每个导出组件创建一个任务；同一 handler 的
   Deep Links 合并为一个任务并按风险优先级调度。
5. 若配置云真机，平台完成安装、访客/登录态探测、普通 App UID 的 Probe 调用和可选 Frida
   观察；AI 只能申请受限测试，不能直接操作 ADB。
6. Codex 或 OpenCode + DeepSeek 根据累计证据自适应探索；平台验证每个 Evidence ID，
   不满足证据门槛的“已复现”自动降级为证据不足。
7. Web 展示等待判断、正在分析、已判断、未形成判断和已停止，并输出 Web、JSON、HTML、
   SARIF 四种结果载体。运行中任务可停止，已终止任务可重试或删除。

## 当前可核验的设计数据

| 项目 | 当前值 |
| --- | --- |
| 部署边界 | 单用户、本机 loopback 控制面；可访问已授权远程云真机 |
| 输入限制 | 单 APK；默认最大 512 MiB |
| 动态基线 | Android 16 / API 36；单测试账号；`pm clear` 复位 |
| 单设备调度 | 全局优先级队列；同优先级 FIFO；可取消等待；记录排队/占用时长；重启安全恢复 |
| 入口类型 | 6 类：Activity、Activity Alias、Service、Receiver、Provider、Deep Link |
| 内置规则 | 17 条固定规则 + 5 类导出组件动态规则，共 22 个规则 ID 类型 |
| 覆盖模型 | 8 个 MASVS 域；static、deterministic、blackbox、authenticated、agent、instrumented 多阶段记录 |
| AI 后端 | 2 套：Codex SDK；OpenCode SDK + DeepSeek V4 Pro/Flash |
| AI 运行控制 | 扫描级总开关与后端选择；逐任务开关；运行中配置冻结 |
| 增量补扫 | ADB/模型能力恢复后批量补扫信息不全项，或单入口重新分析；不重复反编译 |
| 深度续跑 | 单任务超时后可手动追加新的 20 分钟，并复用历次静态/ADB/Frida/AI Evidence |
| 漏洞验证链 | 持久化 Hypothesis、Hunter/Critic 论证、Proof Attempt、危害 Oracle 与平台 Verdict |
| 私有真值评测 | final Finding 对照已知漏洞；默认要求动态证明；F0.5 精确率权重为召回率两倍 |
| AI 探索预算 | 默认最多 3 轮、每轮接受 100 个测试；可配范围分别为 1–5 轮、1–100 个 |
| 单任务预算 | 默认 20 分钟；自动尝试最多 2 次，人工续跑不受此限制 |
| 整单时限 | preliminary 目标 4 小时；整单截止 24 小时 |
| AI 审计证据 | 7 类：request、events、response、test validation、result validation、error、cancellation |
| 报告出口 | 4 种：Web、JSON、HTML、SARIF |
| 任务视觉状态 | 5 组：等待判断、正在分析、已判断、未形成判断、已停止 |
| 自动化回归 | 后端 52 项测试；OpenCode Worker 5 项 Pro/Flash/工具/ADB 阻断集成测试；前端 lint + production build |

规则数量按当前代码统计：4 条 Manifest、2 条 Deep Link、4 条 APK/签名、7 条代码模式，以及
Activity、Activity Alias、Service、Receiver、Provider 5 类按入口动态生成的导出规则。

## 核心差异

- **覆盖面可解释**：不仅列出漏洞，还展示每个 MASVS 域和入口在哪个阶段被覆盖、为何未覆盖。
- **AI 有边界**：Agent 不持有 ADB，不能创建子 Agent；测试参数、目标入口和副作用由平台校验。
- **结论有证据**：黑盒复现必须包含普通 App UID 的请求与结果证据；`adb shell` 成功不等价于漏洞。
- **全过程可审计**：保留精确 prompt、模型/SDK、关键事件、原始结构化响应、token usage、
  平台接受/拒绝的证据和用户中止记录，但不展示或持久化隐藏思维链。
- **模型可替换**：同一任务与证据协议可选择 Codex 或 OpenCode + DeepSeek；V4 Pro 使用
  `read/glob/grep/bash` 普通工具循环，最终以文本 JSON + Ajv 校验，避开思考模式与
  `tool_choice: required` 冲突。

## 当前状态与上线前工作

项目已具备从上传、静态扫描、入口规划、云真机验证、双 AI 后端、证据审计到多格式报告的
端到端实现；控制台已支持任务停止、重试和删除。正式作为发布门禁前仍需用公司真实 APK
样本建立性能、误报和复现率基线，完成目标云真机与企业模型网络出口的集成验收，并明确
最终人工审批责任。

### 建议汇报的实测 KPI

以下指标必须由公司样本集测量，当前不虚构结果：

| 指标 | 统计口径 | 当前状态 |
| --- | --- | --- |
| 静态阶段时延 | preliminary 完成时间 P50 / P95 | 待实测 |
| 整单耗时 | final 完成时间 P50 / P95 | 待实测 |
| 入口覆盖率 | 已进入确定性或 AI 验证的入口数 / 枚举入口数 | 待实测 |
| 动态复现率 | `reproduced_blackbox` 数 / AI 深挖候选数 | 待实测 |
| 误报率 | 人工判为 false positive 数 / 候选 Finding 数 | 待实测 |
| 证据降级率 | 被平台降级的 AI 结论数 / AI 结论数 | 待实测 |
| 中止响应 | 点击停止至 worker/turn 确认的 P50 / P95 | 待实测 |
| 单 APK AI 消耗 | token 与模型费用 P50 / P95，按后端拆分 | 待实测 |

> 汇报时建议把上述表替换为至少 20 个有代表性公司 APK 的真实结果，并按 APK 体积、混淆强度、
> 入口数量和是否需要登录分层，避免单一平均数掩盖长尾。
