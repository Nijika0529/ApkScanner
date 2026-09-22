# APKScanner 数据库升级运行手册

本文档适用于当前默认的单机 SQLite 部署。升级过程由
`Database.create_all()` 驱动：先创建当前模型缺少的表，再按
`apkscanner_schema_migrations` 中的版本顺序执行迁移，最后运行可幂等的数据修复。

## 升级前

1. 停止仍可能写入数据库的旧版本服务。启动锁可以串行化同版本进程的迁移，但不能让旧版本进程理解新模式。
2. 确认数据库完整且没有外键破坏：

   ```bash
   sqlite3 -readonly .data/apkscanner.db \
     "PRAGMA quick_check;" \
     "PRAGMA foreign_key_check;"
   ```

3. 使用 SQLite 在线备份接口制作一致性备份，不直接复制可能处于 WAL 模式的数据库文件：

   ```bash
   backup_path=".data/apkscanner.pre-upgrade.db"
   sqlite3 .data/apkscanner.db ".backup '$backup_path'"
   chmod 600 "$backup_path"
   sha256sum "$backup_path"
   ```

## 执行升级

使用准备部署的同一份代码和锁文件启动环境。应用启动会调用
`Database.create_all()`；也可以在停机窗口内显式执行：

```bash
uv run python - <<'PY'
from apkscanner.core.config import Settings
from apkscanner.core.db import Database

settings = Settings.from_env()
settings.ensure_directories()
database = Database(settings)
try:
    database.create_all()
finally:
    database.engine.dispose()
PY
```

SQLite 可写启动会在数据库旁创建权限为 `0600` 的
`apkscanner.db.startup.lock`。该文件由多个本地进程共享，覆盖建表、版本迁移和启动修复三个阶段；锁文件保留是正常现象。

## 升级后验证

```bash
sqlite3 -readonly .data/apkscanner.db \
  "PRAGMA quick_check;" \
  "PRAGMA foreign_key_check;" \
  "SELECT revision, checksum, applied_at
     FROM apkscanner_schema_migrations ORDER BY revision;"
```

当前应存在以下版本：

- `20260921_01_entry_point_disposition`
- `20260921_02_finding_identity_guard`

再次执行升级命令后，迁移表的 `applied_at` 和数据库逻辑 dump 应保持不变。只读部署可使用：

```text
sqlite:///file:/absolute/path/to/apkscanner.db?mode=ro&uri=true
```

只读启动只验证模式和迁移账本，不会自动修复旧库；若模式过旧，会要求先进行一次可写升级。

## 回滚

升级失败时停止所有 APKScanner 进程，保留失败数据库用于诊断，然后从升级前备份恢复。不要在仍有写进程或未完成 WAL checkpoint 时覆盖数据库。恢复后再次执行 `quick_check` 和外键检查，再启动旧版本。

## 2026-09-22 演练记录

本次演练只操作通过 SQLite `.backup` 创建的临时副本，没有修改仓库中的源数据库：

| 样本 | 升级前模式 | 业务数据 | 结果 |
|---|---|---|---|
| `backend/.data/apkscanner.db` | 无迁移账本、无 Finding 唯一约束 | 空业务库 | 升级、重启、只读验证通过 |
| `.data/simulator-runtime-e2e/apkscanner.db` | 无迁移账本、无 disposition 列 | 1 个 scan、1 个 entry point | 行数不变，升级、重启、只读验证通过 |
| `.data/apkscanner.db` | 已是当前模式 | 4 个 scans、50 个 findings、25 个 entry points、32 个 proof attempts | 幂等重启和只读验证通过 |

所有副本均满足 `quick_check=ok`、零外键违规、两条迁移记录和
`findings(scan_id, dedupe_key)` 唯一约束。第二次可写启动前后的逻辑 dump 与迁移时间完全一致；只读启动前后的数据库文件 SHA-256 完全一致。

演练还复现了两个进程同时首次升级时创建迁移账本的竞态。加入启动锁后，同一旧库上的两个独立进程均成功完成启动，最终数据库仍通过完整性和外键检查。
