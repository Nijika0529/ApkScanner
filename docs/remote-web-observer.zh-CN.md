# 远端 HTTPS Web Observer（SSH 反向隧道）

平台的 Web 页面、回调接收器和 Evidence 数据库仍运行在本地 Worker。`RemoteObserverBackend` 只建立一条由 Worker 拥有的 SSH 反向隧道，让远端已有 HTTPS 域名上的 `/web-observer/` 路径转发到本地 Observer。一个 Worker 的多个实验共用隧道，但各自保留 `experiment_id`、根 nonce、attack/control/quiet 阶段 nonce、期限和独立部署/健康/撤销回执。不需要将 Agent 工作区、`~/.ssh`、源码或回调日志复制到远端。

## 远端前置条件

- 操作员预先指定一个有效 HTTPS Origin；域名证书必须受本机信任。远端 Nginx 仅将 `/web-observer/` 代理到 `127.0.0.1:15880`，不得代理 `/api/`、内部 ProofReplay 或其他路径。可参考 [仅供 HTTPS server 块内使用的 location 模板](../config/nginx-web-observer.location.conf.example)；该 location 应由操作员单独审查、部署和回滚，运行时后端不修改 Nginx。
- 远端 SSH 用户仅需允许监听 `127.0.0.1:15880` 的反向转发。建议使用专用低权限用户、`PermitListen 127.0.0.1:15880` 和 `GatewayPorts no`；不需要远端 helper、部署目录、Docker 容器或可执行命令。端口必须事先确认空闲，不能覆盖现有服务。
- 不要使用管理员 SSH 账号。正式环境应创建专用低权限账号和密钥，并把允许的监听地址与端口限制在 Observer 所需的远端 loopback 端口。
- 本地提供一个专用、权限不允许组/其他用户写入的 SSH config 文件，其中只有一个字面 `Host`，以及 `HostName`、`User`、`IdentityFile` 等连接参数。运行时拒绝 `Include`、`Match`、`ProxyCommand`、预置端口转发等指令。密钥可以引用已有的操作员密钥路径，不复制到扫描工作区。Host 必须同时在应用配置的 alias allowlist 内。
- `WebExploitObserver` 已在本地网关注册本次实验，且本地 HTTP 端口可由 SSH 客户端通过 `127.0.0.1` 访问。

隧道不是常驻服务，只有 Worker 开始实验时才启动。仅建立 SSH 转发最多只能证明远端 loopback 可达；在公网 HTTPS 的 nonce 绑定探针通过前，平台不会交付攻击 URL 或认定远端 Observer 可用。运行时模块本身不会执行远端文件写入。Nginx 配置、证书续期与回滚由操作员在平台外维护。

## 调用与回执

`RemoteObserverConfig` 要求显式 `ssh_alias`、`allowed_ssh_aliases`、`ssh_config_path`、`public_base_url` 和 `local_observer_port`。`RemoteWebObserverAdapter(observer, backend).deploy(experiment, task_id=...)` 返回 `RemoteWebObserverSession`，其中含 HTTPS attack/control/quiet URL。部署先启动固定的 `ssh -N -T -R 127.0.0.1:15880:127.0.0.1:<本地端口>`，并设置 `ExitOnForwardFailure=yes`、严格主机密钥校验和禁止 Agent forwarding。命令没有远端 shell、远端 helper 或任意参数插槽；专用 SSH config 阻止预置转发或本地命令。不要加 `ClearAllForwardings=yes`，它会清掉命令行的 `-R`。

平台随后通过有效 TLS 向公网请求本实验的 `/web-observer/<id>/attack/health?nonce=<attack 阶段 nonce>`。本地 Observer 的只读 health 分支必须返回不超过 1 KiB、`Cache-Control: no-store` 的 JSON：`schema_version=1.0`、实验 ID、根 nonce、attack 阶段 nonce、`status=healthy`；平台逐项精确核对。该路由不生成页面或回调 Evidence，也不会把健康探针误计入攻击覆盖。仅 SSH 进程存活或收到普通 200/409 不足以通过健康检查。失败会关闭本次启动的隧道并将部署记为 `rolled_back`；若终止失败则记为 `cleanup_pending`，可重试 `revoke`。`health` 会再次校验进程和公网路径；最后一个活跃实验撤销或过期后才关闭共享隧道。调用方应在任务结束时逐一 `revoke` 并持久化 `receipts`；即使网关异常中断而未再调用它，后端每条隧道自带的 daemon 租约线程也会在 TTL 到期时自动清理（最多 30 秒调度间隔），空闲后线程退出。`close()` 会唤醒并等待线程结束；正常解释器退出还有 best-effort 清理，强制杀死整个 Worker 进程则仍应由进程管理器负责杀掉其 SSH 子进程。

回执里的 `deployment_id`、`tunnel_id`、实验 ID、nonce、平台时间和公网探针结果仅证明传输链与实验归属，不能证明目标 WebView 加载、JSBridge 调用或安全影响。真正页面/回调依旧由本地 `WebExploitObserver` 收集；回调仍为 `client_reported=true`。因此 `RemoteWebObserverAdapter.events(...)` 直接读取本地已保存的事件，不存在“远端 collect 的 Agent 自报事件”或第二套 Evidence 来源。最终 Proof 仍须经过独立 Judge 和 SemanticProofPolicy 的目标 UID、执行、对照及影响门槛。

## 部署状态边界

Nginx 专用路径须由操作员预先部署；Worker 仍须显式启用远端 Observer 配置并通过每次实验的公网健康检查。不要让运行时自动改写现有 Nginx 站点、启用远端 root shell、复制 `~/.ssh` 或开放远端高端口到公网。若将来改为远端落盘式 Observer，必须另行设计并审查固定 helper、独立部署目录、原始 HTTP 事件归属和回收机制；当前实现不包含这条路径。

## 操作员诊断烟测

在限定的 Nginx 路由确认后，可从 Worker 主机运行：

```bash
PYTHONPATH=backend python -m apkscanner.runtime.remote_observer_smoke \
  --ssh-alias observer --allowed-ssh-alias observer \
  --ssh-config /path/to/dedicated-observer-ssh-config \
  --public-base-url https://observer.example.com
```

脚本只在本机临时启动回环 HTTP Observer，建立反向隧道，检查 nonce 绑定的公网 health、获取受控页面，并由脚本自己发送一个 `bridge_missing` 测试回调。它不运行目标 App，不产生数据库 Evidence 或 ProofAttempt；输出会明确标明 `target_app_executed=false`。脚本在 `finally` 中撤销实验、关闭自己启动的 SSH 进程和本地 HTTP 服务。若公网路径不可用，部署会失败回滚；不要将其降级为“SSH 进程存活即成功”。

成功的烟测应同时看到 nonce 绑定 health、页面 GET、测试回调 POST，以及 `deploy`、`health`、`revoke` 三类回执。输出中的 `proof_attempt_created=false`、`target_app_executed=false` 是预期结果；该烟测只验证传输链，不验证 Deep Link 或 JSBridge 漏洞。
