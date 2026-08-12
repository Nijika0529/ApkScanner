# APKScanner 快速开始指南

本文提供三种启动方式：无 Key 静态体验、Codex Docker 完整调查和真机动态验证。默认服务只监听
`127.0.0.1:8000`。

## 1. 环境要求

基础环境：

- Linux 或 WSL2；
- Python 3.12+；
- Node.js 22.13+ 与 npm；
- 推荐安装 `aapt2`、`apksigner`、`apktool`，JADX 可选。

完整调查另外需要：

- Docker Engine；
- DeepSeek API Key；
- 按 [Worker 镜像准备](worker-image.zh-CN.md)生成的固定镜像。

动态验证另外需要：

- Android platform-tools `adb`；
- 已授权的 USB 设备或 IP:Port 云真机；
- 只在专用测试设备上安装临时验证 Harness、PoC 和故意脆弱测试 APK。

## 2. 安装项目

```bash
git clone https://github.com/Nijika0529/ApkScanner.git
cd ApkScanner

python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'

npm ci --prefix frontend
npm run build --prefix frontend
```

如果曾安装过旧分支，重新安装一次 console scripts，避免旧版任务 Gateway 覆盖宿主 `adb`：

```bash
python -m pip install --force-reinstall --no-deps -e .
hash -r
```

当前项目只注册 `apkscanner-adb-gateway`；宿主的 `adb` 应始终来自 Android platform-tools。

## 3. 无 Key 静态体验

### Web 控制台

```bash
export APKSCANNER_CODEX_ENABLED=false
export APKSCANNER_FRONTEND_DIST="$PWD/frontend/dist"
scanctl serve
```

浏览器访问 `http://127.0.0.1:8000`。没有 ADB、JADX 或其他可选工具时，平台仍会完成可用的
确定性分析，并将缺失能力写入 Coverage Gap。

### CLI 扫描

```bash
scanctl capabilities
scanctl scan "$PWD/testapk/vulntest.apk" --investigator none
```

CLI 会打印 `scan_id` 和最终状态。详细结果可以在同一 Data 目录启动 Web 控制台后查看。

## 4. Codex Docker 完整模式

### 4.1 构建固定 Worker

按 [Worker 镜像准备](worker-image.zh-CN.md)放置 JADX 和 Apktool，再执行：

```bash
docker build \
  --build-arg DEBIAN_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian \
  -f Dockerfile.worker \
  -t apk-scanner-codex-worker:0.2.0 \
  .
```

当前镜像包含 Python、Node、OpenJDK、Codex SDK、Android Platform 36、Build Tools 36.1、
JADX、Apktool、Smali 和常用命令行工具。一次扫描复用一个 keeper 容器，不会为每个入口重复
创建镜像或容器。

### 4.2 本地环境文件

```bash
cp .env.example .env
chmod 600 .env
```

编辑 `.env`：

```dotenv
DEEPSEEK_API_KEY=填入新生成的Key
APKSCANNER_VALIDATION_PROFILE=development
APKSCANNER_DEVICE_RESET_POLICY=never
```

约束如下：

- `.env` 被 Git 忽略，不要使用 `git add -f` 提交；
- `start.sh` 会拒绝非当前用户所有或权限超过 `600` 的文件；
- 文件只解析普通赋值，不执行命令、不展开 `$VAR`；
- 启动 shell 中显式导出的变量覆盖 `.env`；
- 如果 Key 曾出现在提交、日志或聊天中，应先撤销并生成新 Key。

### 4.3 能力预检和启动

```bash
scanctl capabilities --deep
./start.sh
```

`capabilities --deep` 会执行一次小额真实 Provider 请求。`start.sh` 自动构建前端、停止旧的
`scanctl serve` 进程、探测真实 ADB 并启动后台服务。

```bash
curl http://127.0.0.1:8000/api/v1/health
tail -f /tmp/apkscanner.log
```

停止服务：

```bash
kill -TERM "$(cat .data/run/scanctl.pid)"
```

再次运行 `./start.sh` 会安全替换由同一 PID 文件管理的旧服务，不会终止名称不匹配的其他进程。

## 5. 接入 ADB 设备

### USB 设备

```bash
export APKSCANNER_HOST_ADB=/absolute/path/to/platform-tools/adb
"$APKSCANNER_HOST_ADB" devices -l
export APKSCANNER_ADB_SERIALS=DEVICE_SERIAL
./start.sh
```

### IP:Port 设备

```bash
export APKSCANNER_HOST_ADB=/absolute/path/to/platform-tools/adb
"$APKSCANNER_HOST_ADB" connect 192.0.2.10:5555
export APKSCANNER_ADB_SERIALS=192.0.2.10:5555
./start.sh
```

`APKSCANNER_HOST_ADB` 也可以指向一个桥接到宿主系统的包装脚本，只要执行 `adb version` 能返回
真实的 Android Debug Bridge 版本。平台不会把任务级 `apkscanner-adb-gateway` 当作宿主客户端。

运行期间可以通过 Web 控制台管理设备，也可以调用：

- `GET /api/v1/devices?probe=true`：查看设备状态；
- `POST /api/v1/devices`：连接并注册设备；
- `POST /api/v1/devices/{serial}/drain`：停止分配新任务；
- `POST /api/v1/devices/{serial}/reconnect`：重连空闲设备；
- `DELETE /api/v1/devices/{serial}`：移除空闲设备。

设备数量决定动态验证并发：一台设备同一时间只租给一个完整任务，多台设备可以运行多条验证链。

## 6. 开发与正式验证 Profile

本地旧设备使用：

```dotenv
APKSCANNER_VALIDATION_PROFILE=development
APKSCANNER_DEVICE_MIN_API=26
APKSCANNER_ALLOW_LEGACY_DEVICE_SMOKE=true
APKSCANNER_DEVICE_RESET_POLICY=never
```

旧设备可以形成开发范围内的动态 Finding，但固定
`release_gate_eligible=false`。PoC 仍使用 API 36+ compileSdk/targetSdk。

正式 Android 16 环境使用：

```dotenv
APKSCANNER_VALIDATION_PROFILE=android16_release
APKSCANNER_DEVICE_MIN_API=36
APKSCANNER_ALLOW_LEGACY_DEVICE_SMOKE=false
APKSCANNER_DEVICE_RESET_POLICY=never
```

只有 API 36+ 设备生成的 `android16_release` Proof 才能进入正式版本修复、回归或发布结论。

## 7. 数据与缓存

默认数据目录为 `.data/`：

```text
.data/
  apkscanner.db       SQLite 控制面数据库
  artifacts/          内容寻址 APK 与 Evidence
  workspaces/         单次扫描工作区
  static-cache/       可跨扫描复用的确定性静态产物
  run/                PID 等运行文件
```

可以使用 `APKSCANNER_DATA_DIR` 指向其他绝对或相对目录。同一 APK 和相同分析 Profile 可以命中
静态缓存，但新的 Scan 不会继承旧 Finding、Evidence、Codex Thread 或动态 Verdict。

## 8. 常见问题

### `task-scoped APKScanner gateway is unavailable`

当前 shell 找到的是旧版 Gateway 而不是真实 ADB。执行：

```bash
type -a adb
python -m pip install --force-reinstall --no-deps -e .
hash -r
export APKSCANNER_HOST_ADB=/absolute/path/to/platform-tools/adb
```

### 服务启动后没有动态验证

检查 `"$APKSCANNER_HOST_ADB" devices -l`、设备 API、Profile 和 `/api/v1/devices?probe=true`。
没有在线设备时，任务会保留静态结果或等待动态能力，不会伪造真机证明。

### Worker 镜像找不到

确认镜像标签与环境变量一致：

```bash
docker image inspect apk-scanner-codex-worker:0.2.0
```

### Key 已设置但 Provider 仍失败

确认 `.env` 权限为 `600`，然后执行 `scanctl capabilities --deep`。不要把 Key 写进命令参数、
Dockerfile、GitHub Actions 明文变量或扫描输入。

### 为什么重新扫描后应用仍保持登录

这是默认行为。`APKSCANNER_DEVICE_RESET_POLICY=never` 不执行 `pm clear`。只有明确可丢弃的
fixture 才应选择其他 reset policy。
