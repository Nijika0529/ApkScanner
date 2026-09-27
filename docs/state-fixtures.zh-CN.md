# 可验证的动态测试状态

`ValidationFixture` 的账号、会话和应用状态不再仅靠文字说明。操作员仍需先在目标设备上准备登录态，但要在 `payload.state_check` 中给出平台可重复执行的设备断言。非游客 `AgentRequestedTest` 设置 `state="fixture"` 和 `state_fixture_id`；普通应用 PoC 启动前会立即核验该断言。Dynamic Experiment 引用 `fixture_ids` 时，平台在每次运行和暂停后恢复时均先核验，失败则停止攻击步骤并留下 Evidence 与 Oracle gap。

`state_check` 使用 `DynamicExperimentStepSpec` 格式，必须是 `phase="assert"`，并提供 `stdout_contains` 或 `stdout_regex`。仅允许读当前设备状态的 `dumpsys`、`pm dump/get-app-links/path`、`content query`、`pidof`、`ps`、`getprop` 和 `uiautomator dump`；`echo`、可变实验模板、失败后继续执行均被拒绝。一个断言是“已满足操作员声明的前置条件”的回执，不是漏洞影响 Oracle，也不能证明攻击者权限。

示例结构（须按目标应用实际界面或数据源替换断言）：

```json
{
  "fixture_type": "account",
  "name": "signed-in-test-account",
  "payload": {
    "state_check": {
      "id": "signed-in-state",
      "title": "Confirm current test account",
      "phase": "assert",
      "adb_args": ["shell", "content", "query", "--uri", "content://com.example.fixture.status/session"],
      "stdout_contains": ["signed_in=true"]
    }
  },
  "setup_instructions": ["在设备上手动登录专用测试账号；不要使用真实用户账号。"]
}
```

示例假设测试应用暴露了可查询的状态 Provider；普通应用若没有独立状态通道，不能凭 `pm path` 等无关信号冒充“已登录”。单步 `uiautomator dump` 只报告文件路径，不能直接断言 UI 文本；需要另设计受控的多步观察。平台不代替操作员登录、不清除目标数据，也不把文字 setup/cleanup 当作执行证据。避免把口令、会话令牌写进 fixture `payload`、ADB 命令或模型上下文。一般动态 PoC 的前置条件回执与 Web 正式语义证明是两种门槛：后者目前只承认精确绑定受控 canary 的目标侧状态；仅凭 `content://` URI 前缀、包安装状态或操作员声明，不能证明非受控账号/会话由目标拥有。正式 Web 证明还须满足独立目标侧、Bridge 调用和负对照回执。
