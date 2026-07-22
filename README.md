# APK Scanner

Evidence-first Android APK security scanning with deterministic attack-surface coverage, remote
ADB validation, and optional Codex investigations.

The v1 product is a single-user, localhost-only Web application. It accepts one installable APK,
builds a versioned security IR, enumerates all Android component and deep-link entry points, records
coverage gaps, and dispatches bounded investigation tasks. Agent output never becomes a reproduced
finding without platform evidence IDs.

## What works

- APK size/ZIP safety checks, SHA-256 content addressing, signing and package metadata.
- Manifest-effective Activity, Service, Receiver, Provider, permission, and Deep Link analysis.
- Correct cross-product expansion of split `<data>` attributes in intent filters.
- Built-in MASVS-oriented manifest, code-pattern, archive, native-library, and hardening rules.
- Apktool baseline with optional JADX enhancement and explicit degraded-coverage states.
- Persistent SQLite scan/task/finding/evidence/coverage/event models.
- Remote ADB adapter, serialized device lease, ordinary-app-UID Probe APK protocol, log evidence,
  guest/authenticated replay, `pm clear` cleanup, and App Link state inspection/reset.
- Bounded Frida side-channel tracing with URI/query redaction and a distinct instrumented verdict.
- Optional MobSF upload/report normalization with explicit degraded coverage when absent.
- Official `openai-codex==0.144.4` integration with strict JSON Schema, fresh threads, no subagent
  fan-out, one platform-mediated follow-up test round, and evidence-backed result downgrades.
- Optional per-task Docker workers with read-only scan mounts and resource/capability limits.
- Responsive React review console, human Finding decisions, live events, JSON/HTML/SARIF exports.

The detailed control flow, trust boundaries, IR, and verdict rules are in
[`docs/architecture.zh-CN.md`](docs/architecture.zh-CN.md).

## Local setup

Python 3.12+ and Node 22+ are recommended. The minimum useful static toolset is `aapt2`,
`apksigner`, and `apktool`; `jadx` is optional but improves code retrieval.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'

cd frontend
npm install
npm run build
cd ..

export APKSCANNER_FRONTEND_DIST="$PWD/frontend/dist"
scanctl serve
```

Open `http://127.0.0.1:8000`. For separate frontend development, run `npm run dev` in
`frontend/`; Vite proxies `/api` to port 8000.

Run a foreground scan without the Web UI:

```bash
scanctl scan /absolute/path/to/application.apk
scanctl capabilities
```

## Dynamic device configuration

Configure a remote Android 16 ADB serial or endpoint already known to the local ADB server:

```bash
adb connect cloud-device.example:5555
export APKSCANNER_ADB_SERIAL=cloud-device.example:5555
```

Build the deliberately exported helper in [`probe/`](probe/) on an Android SDK 36 workstation,
install it only on a dedicated test device, and configure its path:

```bash
export APKSCANNER_PROBE_APK="$PWD/probe/app/build/outputs/apk/debug/app-debug.apk"
```

Without ADB or the Probe APK, scans still complete and explicitly mark dynamic coverage as blocked.
An `adb shell` success is retained as a separate identity and is never treated as equivalent to an
ordinary third-party application.

Configure the single-account login replay with a non-secret JSON flow and OS-keyring references:

```bash
cp config/auth-flow.example.json config/auth-flow.json
export APKSCANNER_AUTH_FLOW="$PWD/config/auth-flow.json"
scanctl auth-set-secret username
scanctl auth-set-secret password
scanctl auth-status
```

The final `assert_text` step is mandatory so accepted input events are not mistaken for a successful
login. ADB text entry intentionally accepts only a shell-safe test-credential character set, and the
input command is redacted before persistence. Target UI evidence can still contain test-account data
and must be handled as sensitive.

For Frida, set the Frida device ID (or a remote frida-server endpoint):

```bash
export APKSCANNER_FRIDA_DEVICE=cloud-device-id
# or: export APKSCANNER_FRIDA_HOST=frida.example.test:27042
```

## Codex configuration

Codex is opt-in. Docker is the secure default isolation mode. Build the pinned worker, provide either
an explicit Codex auth file or `OPENAI_API_KEY`, then enable investigations:

```bash
docker build -f Dockerfile.worker -t apk-scanner-worker:0.1.0 .
export APKSCANNER_CODEX_AUTH_FILE=/absolute/path/to/codex/auth.json
export APKSCANNER_CODEX_ISOLATION=docker
export APKSCANNER_CODEX_ENABLED=true
scanctl capabilities --deep
```

Defaults are `gpt-5.6-terra`/medium for entry workers. The integration starts a fresh thread per
task, sets `agents.max_threads=1`, uses a strict result schema, and rejects unsupported SDK versions.
Do not set `APKSCANNER_CODEX_BIN` unless you have explicitly tested that external CLI against the
pinned SDK; the bundled matching runtime is the default.

`APKSCANNER_CODEX_ISOLATION=host` is an explicit fallback for a personally controlled machine. It
does not provide the worker filesystem boundary and should not be the team-deployment default.

To add MobSF breadth:

```bash
export APKSCANNER_MOBSF_URL=https://mobsf.internal.example
export APKSCANNER_MOBSF_API_KEY=...
```

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `APKSCANNER_DATA_DIR` | `.data` | SQLite, workspaces, APKs, evidence, reports |
| `APKSCANNER_DATABASE_URL` | SQLite in data dir | SQLAlchemy database URL |
| `APKSCANNER_FRONTEND_DIST` | unset | Built frontend directory served by FastAPI |
| `APKSCANNER_ADB_SERIAL` | unset | Remote cloud-device ADB serial |
| `APKSCANNER_PROBE_APK` | unset | Built Probe APK path |
| `APKSCANNER_AUTH_FLOW` | unset | Non-secret login replay JSON |
| `APKSCANNER_FRIDA_DEVICE` | ADB serial | Frida device identifier |
| `APKSCANNER_FRIDA_HOST` | unset | Remote frida-server endpoint |
| `APKSCANNER_CODEX_ENABLED` | `false` | Dispatch Codex investigations |
| `APKSCANNER_CODEX_ISOLATION` | `docker` | `docker` or explicit `host` fallback |
| `APKSCANNER_CODEX_DOCKER_IMAGE` | `apk-scanner-worker:0.1.0` | Worker image |
| `APKSCANNER_CODEX_AUTH_FILE` | unset | Auth file mounted only into the worker |
| `APKSCANNER_CODEX_BIN` | bundled SDK runtime | Explicit tested Codex binary override |
| `APKSCANNER_MOBSF_URL` / `APKSCANNER_MOBSF_API_KEY` | unset | Optional MobSF API |
| `APKSCANNER_ANDROID_VERSION` | `16` | Reported dynamic baseline |
| `APKSCANNER_ANDROID_API` | `36` | Required cloud-device API level |
| `APKSCANNER_MAX_UPLOAD_BYTES` | 512 MiB | Intake limit |
| `APKSCANNER_TASK_TIMEOUT` | 1200 s | Per-investigation budget |
| `APKSCANNER_TASK_MAX_ATTEMPTS` | 2 | Retry budget |

## Verification

```bash
pytest
ruff check backend
cd frontend && npm run lint && npm run build
```

The test corpus uses synthetic APK-shaped ZIPs with safe/vulnerable manifest controls. Add signed
fixture APKs and real Android 16 device tests before treating this as a release gate.

Mutating API calls require `X-APKScanner-Request: console`; the Web console adds it automatically.
The server binds to `127.0.0.1` and rejects untrusted Host headers.

## Security boundaries

- Authorized company APKs and dedicated test backends only.
- APK code, resources, strings, logs, and web content are untrusted prompt data.
- The Probe APK is intentionally dangerous and must never remain on employee/production devices.
- No source code or server authorization context is available; AUTH and PRIVACY remain partial.
- v1 covers one APK, one Android 16 baseline, one authenticated role, and `pm clear` rather than a
  full device snapshot.
- Docker confines the default Agent filesystem view, but its network is intentionally broad enough
  for Codex, a remote device, and the test backend. Restrict egress before a team deployment.
