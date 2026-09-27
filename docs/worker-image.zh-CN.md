# Codex Worker 镜像准备

Worker 镜像固定 Android 与 Agent 工具版本，避免每次构建从不稳定的 GitHub 路由重新下载大文件。
JADX 和 Apktool 作为本地 vendored 资产放在 `docker/vendor/`；该目录被 Git 忽略，不提交第三方
二进制。

## 固定版本

| 工具 | 版本 | 镜像内位置 |
| --- | --- | --- |
| Codex SDK | `0.156.1` | Python package / bundled Codex CLI |
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

默认 PyPI 索引使用官方源：本次构建验证了阿里云镜像尚未同步
`openai-codex==0.156.1`，旧索引在那次构建中返回找不到包。网络环境确实需要
镜像时可用 `PYPI_INDEX_URL` 显式覆盖，但必须确认它已有锁定版本；构建参数
不会携带运行时凭据：

```bash
docker build -f Dockerfile.worker -t apk-scanner-codex-worker:candidate .
```

先用候选标签运行镜像能力预检和 Docker 契约测试，确认后再决定是否更新默认标签。

当前镜像约 650 MB，首次构建还需要下载 Android Platform 与 Build Tools。仅修改宿主控制面或
前端时通常不需要重建 Worker；修改 `Dockerfile.worker`、`pyproject.toml`、
`backend/apkscanner/runtime/codex_worker.py`、容器包装器、`config/deepseek-models.json` 或固定
工具版本后应重建并运行 Docker 契约测试。升级 SDK 时先保留旧镜像标签，再构建候选镜像；只有主机
回归、镜像能力检查和 Docker 契约测试全部通过后，才把候选镜像标记为默认版本。

模型目录（含默认 `deepseek-flash` / DeepSeek-V4.1-Flash）会烘焙进镜像。改动
`config/deepseek-models.json` 时必须同步递增 `WORKER_REVISION` 与 `Dockerfile.worker` 的
`io.apkscanner.worker-revision` label；镜像能力门禁会拒绝未重建的旧镜像，避免宿主与 Worker
使用不同的模型目录。

```bash
APKSCANNER_CODEX_DOCKER_IMAGE=apk-scanner-codex-worker:candidate \
APKSCANNER_RUN_DOCKER_TESTS=1 \
  pytest -q backend/tests/test_codex_executor.py backend/tests/test_codex_worker_contract.py
```

镜像契约测试只验证容器能力和密钥边界；它不能代替带固定 APK、真值、设备 Profile
和正负对照的真机 benchmark。候选镜像测试通过后，再以不可变 digest 记录发布回执并更新默认标签。

上述 Docker 门禁会实际启动打包的 App Server，验证持久 Thread 创建、Worker 重启后的 Thread
恢复、失败 Turn 的错误传递、每角色 UID/工作区隔离，以及 Provider Key 不进入镜像配置或 Agent
shell 环境。最后再运行需要真实 DeepSeek Key 的 Provider smoke，确认结构化输出、Web Search 和落盘
脱敏；该步骤不能用占位 Key 替代。

## 密钥边界

- 构建参数、Dockerfile、镜像 Layer 和 keeper 容器不包含 Provider Key；
- Key 从宿主 `.env` 进入控制面，仅在目标 UID worker 的 `docker exec` 环境中注入；
- Codex shell 环境策略从 Agent 自己执行的 Bash 子进程中排除 Provider Key；
- `docker inspect`、进程 argv、扫描事件和报告不应出现 Key 值。
