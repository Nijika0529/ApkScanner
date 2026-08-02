# Android 平台攻击链静态分析

## 1. 范围

本模块只处理 Android 平台暴露面和跨边界调用链，不分析应用内部 Agent、Tool、账号业务流程或服务端授权逻辑。当前覆盖：

1. PendingIntent、嵌套 Intent 与 URI permission grant；
2. FileProvider、ACTION_SEND、SAF、压缩包与文件导入；
3. context-registered Receiver、localhost TCP 与 Unix-domain socket；
4. Android 外部输入到 WebView 内容、导航和 JavaScript bridge 的路径。

输出是供后续 Codex 调查的 `candidate`，不是漏洞结论。静态链仍需证明普通第三方应用可达、缺少有效防护并产生具体的机密性、完整性或权限影响。

## 2. 为什么采用有界标记图

完整 Android 污点分析需要处理生命周期、回调、ICC、反射、异步调度、动态加载、Java/Kotlin/Smali 差异和 WebView 跨语言行为。直接在当前流水线嵌入 Soot/FlowDroid 级全程序分析会显著增加构建时间、内存、平台依赖和失败面。

现阶段使用一个可解释的中间方案：

```text
外部来源标记
    │
    ├── 同类内数据处理
    └── 应用自有类的精确引用边（最多三跳）
              │
              ▼
       能力传播 / 文件 / IPC / WebView 落点
              │
              ├── 风险标记
              └── 已观察到的防护标记
```

每条链保存：

- `source_markers`：外部输入或能力的来源；
- `sink_markers`：派发、授权、写文件、监听或 WebView API；
- `risk_markers`：mutable、隐式目标、宽路径、bridge、不受限 bind 等；
- `guard_markers`：immutable、显式目标、IntentSanitizer、路径规范化、receiver flag、peer/origin 校验等；
- `inferred_risks`：只表示在有界路径内没有观察到某种防护，不能解释成防护一定不存在；
- `path`、`locations`、`hop_count` 和稳定 `fingerprint`。

这让 Codex 能从具体文件和类开始验证，而不是在完整反编译目录里无边界搜索。

## 3. 论文与工程研究带来的设计决策

### 3.1 ICC 解析必须保留不确定性

对六种 ICC resolution 工具的综合评估发现，真实应用静态分析中可能漏掉大量实际 ICC 边，同时图结构可帮助识别错误边。因此本实现不把“没有找到三跳路径”解释为不可达，也不把找到引用边解释为可利用；它只生成正向、有界、可解释候选，交给 Smali 复核或动态验证。

参考：[A Comprehensive Evaluation of Android ICC Resolution Techniques](https://arxiv.org/abs/2111.05649)。

### 3.2 PendingIntent 要分析完整能力流，而不只检查 flag

PIVAT/PIAnalyzer 一类工作强调从 PendingIntent 创建点追踪 base Intent 和传递位置；只检查 `FLAG_MUTABLE` 会漏掉隐式 base Intent、空字段补全、外层 Intent 暴露和能力重放。本实现因此联合记录：

- PendingIntent 创建 API；
- base Intent 的显式/隐式目标信号；
- mutable、immutable 和 one-shot 信号；
- Notification、RemoteViews、result/extra 等能力逃逸位置；
- `send()` 和 creator identity 使用。

参考：[Highly Precise and Efficient Analysis of PendingIntent Vulnerabilities for Android Apps](https://onlinelibrary.wiley.com/doi/10.1155/2024/8663701)、[Android PendingIntent security guidance](https://developer.android.com/privacy-and-security/risks/pending-intent)。

`getCreatorPackage()`/`getCreatorUid()` 只说明令牌创建者，不能单独证明当前呈递者身份。扫描器为这种使用保留了 provenance 信号，后续应结合 Binder calling UID 或不可转移会话凭据复核。参考：[Exploiting PendingIntent Provenance Confusion to Spoof Android SDK Authentication](https://arxiv.org/abs/2603.02539)。

### 3.3 文件链必须同时建模程序路径和授予能力

“Dirty Stream”研究展示了恶意 ContentProvider 可控制流内容和 display name，最终造成私有文件覆盖。PathSentinel 则表明，准确判断路径穿越、hijacking 和 luring 需要把程序路径与访问控制策略结合。因此实现把这些信号放进同一链：

```text
ACTION_SEND / SAF / content URI
  → ContentResolver / DISPLAY_NAME
  → archive entry 或普通 copy
  → FileOutputStream / Files.copy / move
  → canonical/real-path 与 symlink 防护
```

FileProvider 还会解析 grant 配置和宽泛的 `root-path`、`external-path`、`files-path`、`cache-path`。非导出 Provider 不能仅凭 `exported=false` 静态关闭，因为临时 URI grant 本身就是可传播能力。

参考：[Dirty stream attack](https://www.microsoft.com/en-us/security/blog/2024/05/01/dirty-stream-attack-discovering-and-mitigating-a-common-vulnerability-pattern-in-android-apps/)、[Static Detection of Filesystem Vulnerabilities in Android Systems](https://arxiv.org/abs/2407.11279)、[Android FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider)。

### 3.4 Socket 分析必须包含 endpoint、访问控制与 peer authentication

SAUSAGE 对 Android Unix-domain socket 的研究将 socket 地址恢复、系统访问控制和服务端认证检查联合起来。普通 APK 暂时没有设备 SELinux policy 输入，因此本实现先发现：

- `ServerSocket`、`LocalServerSocket`、`AF_UNIX`、NanoHTTPD/Ktor 等监听点；
- `accept`/handler；
- `0.0.0.0` 等宽 bind；
- `SO_PEERCRED`/peer credentials 或应用层 token/auth 信号。

当后续保存设备镜像或 SELinux policy 时，可在同一 chain schema 中加入 `platform_access_control`，不需要改变入口模型。

参考：[SAUSAGE: Security Analysis of Unix domain Socket Usage in Android](https://arxiv.org/abs/2204.01516)。

### 3.5 WebView 需要跨 Android 与 Web 边界

单独发现 `addJavascriptInterface()` 或 `loadUrl()` 不足以说明外部可控。当前实现先连接 Intent、URI、ContentResolver、ACTION_SEND 和 navigation callback 到 WebView load/bridge API，并记录 origin guard。

研究表明 WebView 的 iframe/popup、AppID/domain/capability identity、运行时脚本注入与 Java/JavaScript 信息交换都会破坏只看 Java API 的分析。后续动态阶段应在通用测试器中记录：

- 最终 URL、redirect chain、main frame 与子 frame；
- bridge 注册、移除、方法调用和当前 frame origin；
- `evaluateJavascript`、`postWebMessage` 和运行时注入脚本；
- 页面事件序列，而不是只启动一次 Activity。

参考：[Iframes/Popups Are Dangerous in Mobile WebView](https://www.usenix.org/conference/usenixsecurity19/presentation/yang-guangliang)、[Identity Confusion in WebView-based Mobile App-in-app Ecosystems](https://www.usenix.org/conference/usenixsecurity22/presentation/zhang-lei)、[$\omega$Test: WebView-Oriented Testing for Android Applications](https://arxiv.org/abs/2306.03845)、[WebViewTracer / Cross-Boundary Mobile Tracking](https://www.ndss-symposium.org/ndss-paper/cross-boundary-mobile-tracking-exploring-java-to-javascript-information-diffusion-in-webviews/)。

## 4. 已实现的数据流

实现入口位于 `backend/apkscanner/android_chains.py`：

1. 从 JADX Java/Kotlin 或 Apktool Smali 中优先选择一份应用自有类；
2. 提取语义 marker、Smali descriptor、Java qualified name 和唯一 simple class reference；
3. 构建应用自有类的有向引用图；
4. 对各 chain spec 执行最多三跳的 BFS；
5. 把所有候选链写入 `code_index.json.attack_chains` 作为可复用 inventory；
6. 只为需要审查的链生成四类 `STATIC_SURFACE`，向 Codex 暴露链、位置和防护信号；显式且 immutable 的 PendingIntent、明确 `RECEIVER_NOT_EXPORTED` 的动态 Receiver 仍保留在 inventory，但不制造漏洞任务；
7. 把 chain fingerprint 纳入安全快照。

静态缓存 context version 已更新。旧缓存不会被误用，新 APK 的链分析结果可随反编译产物一起复用。

## 5. 版本 Diff

每条候选链的 fingerprint 不包含行号，避免单纯代码移动造成无意义变化；它包含链种类、类路径、source/sink/risk/guard 和推断风险。

同一 static surface 的变化输出：

- `security_surface_expanded` + `candidate_attack_chains_added`；
- `security_surface_reduced` + `candidate_attack_chains_removed`。

“expanded”只说明新增调查面，不表示新版本已经引入可利用漏洞。新增链会把对应调查任务提升为高优先级。

分析引擎版本也进入快照。引擎升级时 fingerprint 不跨版本直接比较，避免规则更新被误报为应用新增/修复漏洞。

## 6. Android 16+ 解释规范

- 默认动态验证设备最低 API 为 36；
- 记录 APK `targetSdkVersion`，不能只记录设备 API；
- Android 16 的 Intent redirection 等平台缓解应报告为 `platform_mitigated` 或具体前置条件，不应据此删除静态链；
- 动态验证必须使用 ordinary third-party app UID；ADB shell 只能证明 shell 身份行为；
- Receiver 结果必须记录 `RECEIVER_EXPORTED`、`RECEIVER_NOT_EXPORTED`、sender permission 和实际注册生命周期；
- URI grant 结果必须记录 read/write/prefix/persisted flag、接收包、ClipData 和撤销时机。

## 7. 当前限制与下一步

当前限制：

- 是类级引用图，不是 method/context/field-sensitive 污点分析；
- 不解析反射、动态 class loading、Rx/coroutine/Handler 的完整异步边；
- 应用自有代码以 manifest package 为边界，重度混淆或独立命名模块可能漏报；
- 只能说明有界路径内是否观察到 guard，不能证明 guard 对所有执行路径有效；
- WebView 暂不执行 JavaScript，也不恢复服务端动态内容；
- 普通 APK 的 Unix socket 结果暂未联合设备 SELinux policy；
- ZIP/TAR 路径检查暂未做逐语句 def-use 和 TOCTOU/symlink 证明。

建议后续顺序：

1. 增加 method-level def-use slice，优先处理 `Intent`、`Uri`、`File` 和 WebView URL；
2. 把现有 Smali 局部常量恢复扩展为跨基本块/字段的 Intent 状态传播；
3. 增加通用攻击者 APK：PendingIntent 捕获/重放、恶意 ContentProvider、动态广播、localhost/Unix client；
4. 扩展现有 Frida trace，记录 WebView final URL/frame/bridge 与动态 Receiver 注册参数；
5. 用静态链生成最小动态输入矩阵，并将命中的 runtime edge 回写到 chain evidence；
6. 在有设备策略输入后，将 socket 文件权限、SELinux domain 和 peer credential 联合判定。
