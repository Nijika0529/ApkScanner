# Codex Worker 镜像准备

Worker 镜像固定 Android 与 Agent 工具版本，避免每次构建从不稳定的 GitHub 路由重新下载大文件。
JADX 和 Apktool 作为本地 vendored 资产放在 `docker/vendor/`；该目录被 Git 忽略，不提交第三方
二进制。

## 固定版本

| 工具 | 版本 | 镜像内位置 |
| --- | --- | --- |
| Codex SDK | `0.144.4` | Python package / bundled Codex CLI |
| JADX | `1.5.6` | `/opt/jadx` |
| Apktool | `3.0.3` | `/opt/apktool/apktool.jar` |
| Android Platform | API 36 `platform-36_r02` | `/usr/lib/android-sdk/platforms/android-36` |
| Android Build Tools | `36.1.0` | `/usr/lib/android-sdk/build-tools/36.1.0` |

## 准备离线资产

下面的命令只下载固定版本，并在解包前校验 SHA-256：

```bash
cd /path/to/ApkScanner
mkdir -p docker/vendor/jadx docker/vendor/apktool

vendor_tmp="$(mktemp -d)"
trap 'rm -rf -- "$vendor_tmp"' EXIT

curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors \
  https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip \
  -o "$vendor_tmp/jadx.zip"
echo '545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974  '"$vendor_tmp/jadx.zip" \
  | sha256sum -c -
unzip -q "$vendor_tmp/jadx.zip" -d docker/vendor/jadx

curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors \
  https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar \
  -o "$vendor_tmp/apktool.jar"
echo 'dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423  '"$vendor_tmp/apktool.jar" \
  | sha256sum -c -
install -m 0644 "$vendor_tmp/apktool.jar" docker/vendor/apktool/apktool.jar
```

如果网络受限，可以在其他机器完成下载和校验，再复制以下内容：

```text
docker/vendor/jadx/bin/
docker/vendor/jadx/lib/
docker/vendor/apktool/apktool.jar
```

不要取消摘要校验，也不要把未经确认的新版本直接覆盖到固定目录。

Android Platform 与 Build Tools 不依赖本机 `docker/vendor/android-sdk`：Docker 构建会从
Google Android Repository 下载固定归档，并使用 Dockerfile 中锁定的 SHA-256 摘要校验后再
解包。因此，干净仓库只需按上文准备 JADX 和 Apktool 两类离线资产。

## 构建与检查

```bash
docker build \
  --build-arg DEBIAN_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian \
  -f Dockerfile.worker \
  -t apk-scanner-codex-worker:0.2.0 \
  .

docker image inspect apk-scanner-codex-worker:0.2.0 \
  --format '{{json .Config.Labels}}'
```

当前镜像约 650 MB，首次构建还需要下载 Android Platform 与 Build Tools。仅修改宿主控制面或
前端时通常不需要重建 Worker；修改 `Dockerfile.worker`、`pyproject.toml`、
`backend/apkscanner/runtime/codex_worker.py`、容器包装器或固定工具版本后应重建并运行 Docker
契约测试。

```bash
APKSCANNER_RUN_DOCKER_TESTS=1 \
  pytest -q backend/tests/test_codex_executor.py backend/tests/test_codex_worker_contract.py
```

## 密钥边界

- 构建参数、Dockerfile、镜像 Layer 和 keeper 容器不包含 Provider Key；
- Key 从宿主 `.env` 进入控制面，仅在目标 UID worker 的 `docker exec` 环境中注入；
- Codex shell 环境策略从 Agent 自己执行的 Bash 子进程中排除 Provider Key；
- `docker inspect`、进程 argv、扫描事件和报告不应出现 Key 值。
