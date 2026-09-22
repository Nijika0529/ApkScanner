# APKScanner 架构边界与扩展约定

本文记录当前代码的依赖方向和关键事实归属，避免后续功能再次回到单文件控制面、隐式迁移和多套状态判定。

## 依赖方向

允许的生产代码依赖方向为：

```text
core
  ↑
infrastructure
  ↑
analysis
  ↑
runtime
  ↑
platform
```

- `core`：领域模型、证据/裁决规则、共享契约、数据库迁移；不得导入其他项目层。
- `infrastructure`：进程、文件和内容寻址存储适配器；可依赖 `core`。
- `analysis`：静态分析能力；只依赖 `core` 与 `infrastructure`。
- `runtime`：扫描、Agent、动态验证和收尾编排；可依赖前三层，不得反向依赖 `platform`。
- `platform`：FastAPI 路由和交互服务，是最外层交付适配器。

`backend/tests/test_architecture_boundaries.py` 对这些边界做自动检查。旧模块路径仅作为兼容 facade 存在，新代码应直接引用新的归属模块。

## 事实归属

Finding 的持久化字段仍保留完整审计历史，但用户可见结论只从以下入口生成：

- `core/verdicts.py`：人工审核和 Operator 状态迁移约束、静态 gate 校验、信号元数据规范化。
- `core/finding_policy.py::project_findings`：统一输出 `confirmed` 或 `signal`，并给 signal 计算证据复核后的 tier。
- `core/signal_projection.py`：把平台观察投影为 Oracle 缺口，不把运行行为误写成已证明漏洞。

API、报告、质量指标和扫描收尾应消费 `project_findings`，不应自行用 `Finding.status` 推导“已确认漏洞”。新增状态时必须先扩展核心状态机和对应测试。

## 数据库升级

结构变更由 `core/migrations.py` 管理：

- revision 是追加式标识；已经发布的 revision 不得重写。
- checksum 用来拒绝历史迁移被静默修改。
- migration ledger 为 `apkscanner_schema_migrations`。
- `is_current` 验证已执行迁移的结构不变量；可写启动会修复结构漂移，只读启动会明确报错。
- SQLite 的建表、迁移和启动修复共享数据库旁的跨进程 startup lock，多个服务进程不得各自并发执行首次升级。

数据修复与 DDL 分离。`core/startup_reconciliation.py` 只运行幂等的崩溃恢复和历史数据纠偏。新增一次性结构变化应写 migration；新增持续不变量修复应写 reconciler，并说明其幂等性。
真实数据备份、验证与回滚步骤见 `docs/database-migration-runbook.zh-CN.md`。

## 控制面拆分

- `runtime/live_proof_gateway.py`：实时 Proof/ADB/Observation 网关。
- `runtime/adaptive_verification.py`：候选合并、自适应验证和平台裁决投影。
- `runtime/finalization.py`：最终 Finding 投影、入口 disposition、seal 和 final event。
- `runtime/static_analysis_pipeline.py`：静态工具、入口、Finding seed、Evidence 和调查计划的物化流水线。
- `runtime/agent_audit.py::AgentAuditRecorder`：Agent request/response 审计以及 container/session/turn 生命周期。
- `runtime/device_registry.py`：持久化设备注册、健康探测和运行时 device pool 同步。
- `platform/dependencies.py`：无路由的 FastAPI 依赖和实体查找边界。
- `platform/operator_routes.py`、`platform/device_routes.py`、`platform/execution_routes.py`：按 Operator、设备和任务执行域拆分的路由切片。
- `platform/finding_review_service.py`：人工审核事务，不在路由内维护领域规则。
- `frontend/src/features/artifacts`、`frontend/src/features/devices`、`frontend/src/features/tasks`：前端 feature 切片。

`ScanOrchestrator` 仍负责跨阶段生命周期，但新增能力应优先落到独立 service/mixin，再由它做薄协调；`platform/api.py` 只注册路由和保留尚未拆出的端点。

## 修改清单

新增或调整 Finding 裁决时：

1. 在 `core/verdicts.py` 定义迁移规则。
2. 在 `core/finding_policy.py` 更新统一读模型（如有必要）。
3. 为纯状态机、证据投影和 API 行为各补一层测试。
4. 不允许 Operator、路由或前端通过写 metadata 绕过平台 ProofAttempt。

新增数据库字段或索引时：

1. 更新 ORM metadata。
2. 追加一个带 checksum 和 `is_current` 的 revision。
3. 覆盖 fresh、legacy、重复执行、只读和结构漂移场景。

新增 API/前端能力时：

1. 按业务域建立路由或 feature 模块。
2. 复用核心 read model，不复制状态判断。
3. 保留旧公开导入路径时，只提供无业务逻辑的兼容 facade。
