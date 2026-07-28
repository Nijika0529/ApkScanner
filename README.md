# APK Scanner

Evidence-first Android APK security scanning with deterministic attack-surface coverage, remote
ADB validation, and optional Codex or OpenCode + DeepSeek investigations.

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
- Tamper-evident AI audit trail for exact prompts, normalized SDK runtime events, structured
  outputs, test-policy decisions, evidence downgrades, provider/model identity, thread/turn IDs,
  and usage.
- Three concurrent entry-investigation workers by default, with one global serialized ADB queue;
  model/review turns release the device between validated device-action phases.
- Remote ADB adapter, ordinary-app-UID Probe APK protocol, log evidence, guest/authenticated replay,
  `pm clear` cleanup, and App Link state inspection/reset.
- Bounded Frida side-channel tracing with URI/query redaction and a distinct instrumented verdict.
- Optional MobSF upload/report normalization with explicit degraded coverage when absent.
- Official `openai-codex==0.144.4` integration with strict JSON Schema, streamed turn/item events,
  read-only workspace inspection, no subagent fan-out, bounded adaptive platform-mediated test
  rounds, and evidence-backed result downgrades.
- Pinned `@opencode-ai/sdk`/OpenCode `1.18.4` integration for DeepSeek, with a stable
  single-stage non-thinking StructuredOutput path, local Ajv/semantic and platform-ID validation,
  ADB/subagent denial, bounded phase budgets, and full provider-wire/runtime audit.
- Optional per-task Docker workers with isolated task-attempt mounts and resource/capability limits.
- Responsive React review console, human Finding decisions, live events, JSON/HTML/SARIF exports.
- Light review console with confirmed deletion of completed scans and shared-artifact-safe cleanup.

The detailed control flow, trust boundaries, IR, and verdict rules are in
[`docs/architecture.zh-CN.md`](docs/architecture.zh-CN.md).
The planned release-diff and vulnerability-retest model is documented in
[`docs/release-regression.zh-CN.md`](docs/release-regression.zh-CN.md).

## Local setup

Python 3.12+ and Node 22.13+ are recommended. The minimum useful static toolset is `aapt2`,
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
scanctl scan /absolute/path/to/application.apk --investigator configured
scanctl capabilities
```

The Web upload dialog and CLI can pin each scan to `codex`, `opencode`, or `none`; `configured`
resolves the service default when the scan is created and is persisted with that scan.

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

When `APKSCANNER_ANDROID_SDK_ROOT` points to an SDK containing platform API 36 and build-tools,
an OpenCode Agent may create a source-only PoC under its isolated `poc/` directory. The control
plane rejects build scripts, binaries, symlinks, escaped paths, package collisions, oversized
projects, and undeclared launch activities. It then builds and signs the APK itself, records the
source/APK SHA-256 values, enters the same ADB queue, installs and launches the PoC as an ordinary
application UID, correlates its nonce-tagged log result, and uninstalls it. The Agent never receives
ADB access. A PoC's own impact boolean is retained as a claim and cannot by itself satisfy the
platform harm oracle.

The default worker pool explores up to three entry points concurrently across all scans. Every
install, reset, probe, optional instrumentation action, and cleanup still passes through one global
priority/FIFO device queue. The device is released before model planning, critic, review, and final
evaluation turns; an accepted model-requested test reacquires the lease and prepares the device
again. Device-queue wait is excluded from the 20-minute task budget but remains bounded by the
24-hour scan deadline.

An investigation task receives a 20-minute budget by default. A task that reaches `timed_out`
exposes the **继续深度探索** action in the Web console. Each manual continuation receives a fresh
20-minute budget and reloads the task's prior static, ADB, Frida, and AI Evidence instead of starting
from an empty investigation context. Continuations are explicit and unlimited by the automatic retry
count; every continuation still creates a new attempt, model audit, device lease, and cleanup cycle.

## Private ground-truth model evaluation

The scanner persists each candidate as a security hypothesis with role-separated arguments, proof
attempts, evidence references, and a platform verdict. The Web **验证链** tab exposes that lineage.
For a private APK with known vulnerabilities, copy
[`config/benchmark-ground-truth.example.json`](config/benchmark-ground-truth.example.json), record
the APK SHA-256 and matching selectors, then run:

```bash
scanctl benchmark /path/to/private.apk \
  --truth /path/to/private-ground-truth.json \
  --investigator opencode
```

An existing scan can be evaluated without scanning again:

```bash
scanctl evaluate --scan-id SCAN_ID --truth /path/to/private-ground-truth.json
```

The primary score is precision-weighted F0.5. A successful Probe reachability result is tracked as
`execution_demonstrated`, but dynamic benchmark credit additionally requires a domain Prover's
platform-verifiable `security_impact_observed` signal. `candidate`, `inconclusive`, manually accepted
findings, and model prose without platform proof never count as discoveries. Ground-truth cases
default to `minimum_proof: dynamic`; a merely suspicious exported declaration therefore cannot earn
credit. Confirmed findings that do not match the private ground truth count as false positives, while
unproven AI output is reported separately as noise.

Likewise, a model may emit `not_reproduced` only when a correlated executed test case carries an
explicit platform `oracle_refuted=true` result. Reachability logs or one failed payload alone are
insufficient and are downgraded to `inconclusive`.

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

## OpenCode + DeepSeek configuration

OpenCode is also opt-in and Docker is the default. The integration pins the SDK and CLI together at
`1.18.4`; it uses DeepSeek's built-in provider and defaults to the stable
`deepseek-v4-flash` baseline.

```bash
docker build \
  -f Dockerfile.opencode-worker \
  -t apk-scanner-opencode-worker:0.1.0 \
  .

export DEEPSEEK_API_KEY=...
export APKSCANNER_INVESTIGATOR_BACKEND=opencode
export APKSCANNER_OPENCODE_ISOLATION=docker
export APKSCANNER_OPENCODE_ENABLED=true
scanctl capabilities --deep
```

For a personally controlled host fallback, install the pinned worker dependencies and select host
isolation:

```bash
npm ci --prefix opencode-worker
export DEEPSEEK_API_KEY=...
export APKSCANNER_OPENCODE_ISOLATION=host
export APKSCANNER_OPENCODE_ENABLED=true
export APKSCANNER_INVESTIGATOR_BACKEND=opencode
scanctl capabilities --deep
```

The host worker creates a private temporary HOME/XDG tree and an authenticated loopback OpenCode
server for each invocation. The stable path sends bounded target-code context and evidence directly
to a tool-disabled StructuredOutput turn. Each invocation still receives an isolated
per-task/attempt workspace, but native `read`, `glob`, `grep`, and `bash` are available only when
the experimental thinking explorer is explicitly enabled. Native editing, web, MCP, subagents, and
ADB remain denied. Android actions are requested as data, then validated and executed by the Python
control plane.
Host mode does not isolate same-UID processes or their `/proc` metadata, so it is suitable only for
controlled personal debugging and is not a credential-security boundary. Use the default Docker
mode for production or untrusted APKs.

All orchestration phases use one non-thinking `structured_finalizer` by default. This removes the
text-memo dependency that could leave DeepSeek on `finish=tool-calls` indefinitely. Set
`APKSCANNER_OPENCODE_THINKING_EXPLORER=true` only for explicit protocol experiments; it affects
`test_planning`, `adversarial_review`, and `exploration_round`, while final/recovery evaluation
remains tool-disabled.

DeepSeek thinking requests reject `tool_choice`. OpenCode 1.18.4 injects `tool_choice: auto`, so the
one-shot worker uses a loopback compatibility proxy that removes this field only when
`thinking.type=enabled`; it preserves OpenCode's message/tool loop and full `reasoning_content`
replay. The stable finalizer disables thinking and uses OpenCode `StructuredOutput`
(`tool_choice: required`), then Ajv, semantic rules, and current-task Hypothesis/EntryPoint
allowlists validate the result. Each retry uses a fresh session. A retryable local transport failure
can rebuild the worker once within the original task budget without changing models. The legacy
memo-writer exists only inside the opt-in experimental explorer profile and is not part of normal
scans.

Use the default `deepseek-v4-flash` model. The text-only `deepseek-v4-pro` is rejected early because
it cannot satisfy the scanner's mandatory StructuredOutput contract; no failure silently switches
models. `scanctl capabilities --deep`
performs a small real, billable non-thinking StructuredOutput call rather than only checking a
catalog. An enterprise DeepSeek-compatible gateway can be selected with
`APKSCANNER_DEEPSEEK_BASE_URL`; remote gateways must use HTTPS, while plain HTTP is accepted only on
loopback. Credentials, query parameters, and fragments are rejected. The worker keeps the real API
key only in the compatibility proxy's memory, gives OpenCode a one-time loopback credential, and
removes provider/config/server credentials from the Bash child environment. For the official endpoint use
`https://api.deepseek.com` without `/v1`. Retired `deepseek-chat` and `deepseek-reasoner` aliases are
rejected.

The implementation rationale, protocol, security controls, and upgrade checklist are documented in
[`docs/opencode-deepseek.zh-CN.md`](docs/opencode-deepseek.zh-CN.md).

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
| `APKSCANNER_ANDROID_SDK_ROOT` | Android SDK env/unset | SDK used for platform-managed Agent PoC builds |
| `APKSCANNER_POC_ENABLED` | `true` | Permit validated source-only Agent PoC builds |
| `APKSCANNER_POC_BUILD_TIMEOUT` | 180 s | Per-command PoC build timeout (30–600 s) |
| `APKSCANNER_POC_MAX_SOURCE_BYTES` | 512 KiB | PoC source-project limit (64 KiB–2 MiB) |
| `APKSCANNER_AUTH_FLOW` | unset | Non-secret login replay JSON |
| `APKSCANNER_FRIDA_DEVICE` | ADB serial | Frida device identifier |
| `APKSCANNER_FRIDA_HOST` | unset | Remote frida-server endpoint |
| `APKSCANNER_INVESTIGATOR_BACKEND` | `codex` | Default: `codex`, `opencode`, or `none` |
| `APKSCANNER_CODEX_ENABLED` | `false` | Dispatch Codex investigations |
| `APKSCANNER_CODEX_ISOLATION` | `docker` | `docker` or explicit `host` fallback |
| `APKSCANNER_CODEX_DOCKER_IMAGE` | `apk-scanner-worker:0.1.0` | Worker image |
| `APKSCANNER_CODEX_AUTH_FILE` | unset | Auth file mounted only into the worker |
| `APKSCANNER_CODEX_BIN` | bundled SDK runtime | Explicit tested Codex binary override |
| `APKSCANNER_OPENCODE_ENABLED` | `false` | Allow OpenCode + DeepSeek investigations |
| `APKSCANNER_OPENCODE_MODEL` | `deepseek-v4-flash` | DeepSeek model ID; text-only V4 Pro is rejected |
| `APKSCANNER_OPENCODE_THINKING_EXPLORER` | `false` | Experimental legacy thinking/tool-loop profile |
| `APKSCANNER_OPENCODE_REASONING_EFFORT` | `high` | Experimental explorer effort: `high` or `max` |
| `APKSCANNER_OPENCODE_AGENT_STEPS` | 1000 | Experimental explorer step budget (50–1000) |
| `APKSCANNER_OPENCODE_ISOLATION` | `docker` | `docker` or explicit `host` fallback |
| `APKSCANNER_OPENCODE_DOCKER_IMAGE` | `apk-scanner-opencode-worker:0.1.0` | Worker image |
| `APKSCANNER_OPENCODE_NODE_BIN` | `node` on PATH | Host-mode Node.js override |
| `APKSCANNER_OPENCODE_WORKER_DIR` | repository `opencode-worker/` | Host worker directory |
| `APKSCANNER_DEEPSEEK_BASE_URL` | DeepSeek default | Optional trusted HTTP(S) gateway |
| `DEEPSEEK_API_KEY` | unset | DeepSeek credential delivered to the selected worker over its one-shot stdin request |
| `APKSCANNER_MOBSF_URL` / `APKSCANNER_MOBSF_API_KEY` | unset | Optional MobSF API |
| `APKSCANNER_ANDROID_VERSION` | `16` | Reported dynamic baseline |
| `APKSCANNER_ANDROID_API` | `36` | Required cloud-device API level |
| `APKSCANNER_MAX_UPLOAD_BYTES` | 512 MiB | Intake limit |
| `APKSCANNER_TASK_TIMEOUT` | 1200 s | Per-investigation budget |
| `APKSCANNER_TASK_MAX_ATTEMPTS` | 2 | Retry budget |
| `APKSCANNER_AGENT_CONCURRENCY` | 3 | Global entry-investigation worker limit (1–8); ADB remains single-concurrency |
| `APKSCANNER_AGENT_MAX_ROUNDS` | 3 | Maximum adaptive AI/device rounds per task (1–5) |
| `APKSCANNER_AGENT_TESTS_PER_ROUND` | 800 | Maximum accepted AI-requested tests per round (1–1000) |

## Verification

```bash
pytest
ruff check backend
cd frontend && npm run lint && npm run build
cd ../opencode-worker && npm run check && npm test
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
- The Codex worker gets a read-only task-attempt mount. OpenCode gets a separate writable
  task-attempt workspace with bounded target Java/Smali files and evidence; `read`, `glob`, `grep`,
  and `bash` are enabled there, while ADB, web, MCP, native editing, and subagents remain denied.
- Agent containers still have outbound networking for their selected model provider. Restrict each
  worker's egress to the approved provider/gateway before a team deployment.
- DeepSeek receives the bounded task context and evidence summaries. Confirm company data handling,
  retention, region, and gateway policy before enabling it for production APKs.
