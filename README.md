# APK Scanner

Evidence-first Android APK security scanning with deterministic attack-surface coverage, remote
ADB validation, and optional Codex SDK + DeepSeek V4 Flash investigations.

The v1 product is a single-user, localhost-only Web application. It accepts one installable APK,
builds a versioned security IR, enumerates all Android component and deep-link entry points, records
coverage gaps, and dispatches bounded investigation tasks. Agent output never becomes a reproduced
finding without platform evidence IDs.

## What works

- APK size/ZIP safety checks, SHA-256 content addressing, signing and package metadata.
- Manifest-effective Activity, Service, Receiver, Provider, permission, and Deep Link analysis.
- Correct cross-product expansion of split `<data>` attributes in intent filters.
- Built-in MASVS-oriented manifest, code-pattern, archive, native-library, and hardening rules.
- Apktool/Smali baseline with optional JADX convenience output; partial JADX output never blocks a verdict.
- Persistent SQLite scan/task/finding/evidence/coverage/event models.
- Tamper-evident AI audit trail for exact prompts, normalized SDK runtime events, structured
  outputs, test-policy decisions, evidence downgrades, provider/model identity, thread/turn IDs,
  and usage.
- One global investigation task at a time; it owns the single ADB device through all Agent,
  PoC replay, review, and cleanup rounds.
- Remote ADB adapter, optional ordinary-app-UID Probe fast path, Agent PoCs, objective Oracles, `pm clear` cleanup,
  and App Link state inspection/reset.
- Official `openai-codex==0.144.4` + DeepSeek Responses integration with strict JSON Schema,
  streamed events, a full-access Codex sandbox, no subagent fan-out, and evidence-backed result
  downgrades.
- One keyless keeper container per scan. Each `task + attempt + role` receives a distinct Unix UID,
  HOME, `CODEX_HOME`, TMPDIR, and writable workspace, while JADX/Apktool/archive inputs are mounted
  read-only. The original APK is also mounted read-only at `/scan-input/target.apk`, allowing the
  container-pinned JADX to produce session-local output when host JADX is absent or partial.
- Worker Protocol v3 keeps one SDK process and non-ephemeral Codex Thread per task/attempt/role,
  reuses the primary Thread across exploration and final evaluation, emits heartbeats, and writes a
  redacted host-only event spool.
- A task-scoped container `adb` wrapper and Proof client reach the host control plane through an
  authenticated gateway. The platform fixes the leased serial, rejects transport escape and
  platform-owned mutations, and records accepted commands as Evidence.
- A versioned Capability Registry supports built-ins, SHA-256-pinned Python scripts, and explicitly
  bound MCP adapters. Supervisor REST endpoints expose snapshots, event timelines, plan validation,
  and bounded Campaign launch without exposing Docker, SQLite, ADB server, or provider credentials.
- The executable OpenCode runtime, critic/fallback routes, and Node worker have been removed;
  historical report-read compatibility remains.
- Responsive React review console, human Finding decisions, live events, JSON/HTML/SARIF exports.
- Proven findings are separated from static signals: only platform-verified harm with complete Evidence references counts as a Finding.
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

The Web upload dialog and CLI can pin each scan to `codex` or `none`; `configured`
resolves the service default when the scan is created and is persisted with that scan.

## Dynamic device configuration

Configure a remote Android 16 ADB serial or endpoint already known to the local ADB server:

```bash
adb connect cloud-device.example:5555
export APKSCANNER_ADB_SERIAL=cloud-device.example:5555
```

For two-device parallel investigation, connect both devices and provide a comma-separated pool:

```bash
export APKSCANNER_ADB_SERIALS=cloud-device-a.example:5555,cloud-device-b.example:5555
```

Each investigation keeps one serial for its complete lifecycle. The legacy
`APKSCANNER_ADB_SERIAL` remains supported as a one-device pool.

For fast generic Activity, Service, Receiver, Provider, deep-link, and simple Binder calls from an
ordinary app UID, optionally build the deliberately exported helper in [`probe/`](probe/), install
it only on a dedicated test device, and configure its path. The reproducible build uses the pinned
worker image and does not require a host Gradle/Android SDK installation:

```bash
./probe/build-probe.sh
export APKSCANNER_PROBE_APK="$PWD/probe/app/build/outputs/apk/debug/app-debug.apk"
```

The Probe receiver requires `android.permission.DUMP`, so only the ADB shell/platform can dispatch
requests; target calls still originate from the Probe's ordinary application UID. Platform
`binder_transact` reads a typed reply and evaluates a `binder_reply` Oracle without trusting a
PoC-authored result log.

Without ADB, scans still complete from static evidence. Without the optional Probe APK, raw ADB
exploration and Agent-built dedicated PoCs remain available; the platform reports a gap only when
a requested ordinary-app test actually lacks either execution route. An `adb shell` success is
retained as a separate identity and is never treated as equivalent to an ordinary third-party app.

When `APKSCANNER_ANDROID_SDK_ROOT` points to an SDK containing the configured compile platform and
build-tools,
a Codex Agent may create a source-only PoC or build its own signed APK under the isolated
`poc/` directory. The control plane validates paths, size, signature, package and launch metadata,
records source/APK SHA-256 values, enters the same ADB queue, installs and launches the PoC as an
ordinary application UID, correlates its nonce-tagged result, and uninstalls it. In host
`personal_lab` mode raw ADB is available for exploration, but only platform-correlated Probe/PoC
execution can establish ordinary-app reachability. A PoC's own impact boolean remains a claim and
cannot by itself satisfy the platform harm oracle; an objective UI, target-log, crash, or other
platform observation is still required.

The investigation pool follows the configured ADB device pool. Each task owns one device for its
complete model, PoC replay, review, and cleanup lifecycle; with one serial, only one task runs at a
time. The 24-hour scan deadline remains the outer bound.

An investigation task receives a four-hour budget by default. A task that reaches `timed_out`
exposes the **继续深度探索** action in the Web console. Each manual continuation receives a fresh
four-hour budget and reloads the task's prior static, ADB, and AI Evidence instead of starting
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
  --investigator codex
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
explicit platform `oracle_refuted=true` result. Without that Oracle the platform retains an explicit
static verdict instead of manufacturing a generic “insufficient information” conclusion.

Every scan also seals an Android threat model that fixes the ordinary third-party app/guest attacker,
assets, trust boundaries, and final-evidence policy. Agents close each tested hypothesis separately
with a source/control/sink/reachable-path/boundary/counterevidence/proof-gap tuple; a task-wide
verdict is no longer copied across unrelated hypotheses. Findings carry a cross-version stable
`finding_id` and a scan-specific `occurrence_id`. Finalization emits `scan.seal` Evidence over the
APK, threat model, tasks, findings, Evidence ledger, and coverage ledger.

## Codex configuration

Codex is the only AI investigation backend and remains opt-in. The current route accepts only
DeepSeek V4 Flash over Responses API with `openai-codex==0.144.4`. Build the pinned worker and
provide the DeepSeek key to the control-plane process:

```bash
docker build \
  --build-arg DEBIAN_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian \
  -f Dockerfile.worker \
  -t apk-scanner-codex-worker:0.2.0 \
  .

export DEEPSEEK_API_KEY=...
export APKSCANNER_INVESTIGATOR_BACKEND=codex
export APKSCANNER_CODEX_ISOLATION=docker
export APKSCANNER_CODEX_ENABLED=true
scanctl capabilities --deep
# Or start the console from the already-authorized environment:
./start.sh
```

`start.sh` contains no default credential and fails closed unless the caller exports
`DEEPSEEK_API_KEY`.

A complete scan owns one keyless keeper container instead of creating a container for every small
exploration. Each `task + attempt + role` gets a non-reused Unix UID and private HOME,
`CODEX_HOME`, TMPDIR, cache, and writable workspace. Scan-level `jadx/`, `apktool/`, and `archive/`
directories are mounted read-only at `/scan-input/*`. Within this container boundary Codex uses
`Sandbox.full_access` and `ApprovalMode.deny_all`, with Bash, patching, JADX, Apktool, Android
Platform 36 / Build Tools 36.1, and live Web Search available. SDK subagent fan-out is disabled.

The keeper starts without provider credentials. Only the UID-scoped `docker exec` inherits
`DEEPSEEK_API_KEY`; its value is absent from Docker argv, image metadata, manifests, and events.
Codex shell-environment policy excludes provider credentials from Agent-launched Bash tools, and
the SDK shell-snapshot feature is disabled because it snapshots the worker environment before that
filter is applied and would otherwise persist the Provider key under private `CODEX_HOME`. Terminal
task/scan cleanup also purges that generated directory as a defense-in-depth migration guard.

Host mode is diagnostics-only and requires both `APKSCANNER_CODEX_ISOLATION=host` and
`APKSCANNER_ALLOW_HOST_CODEX=true`. It has no container, UID, or resource boundary. Do not override
`APKSCANNER_CODEX_BIN` unless the external binary has been verified against the pinned SDK.

Worker Protocol v3 uses one persistent, non-ephemeral Thread for each role session. Primary turns
reuse that Thread; a replacement worker attempts `thread_resume` from its private `CODEX_HOME`.
ADB and Proof credentials are issued only to a primary turn while its task owns the device lease;
Critic and Rescue roles receive neither token. Extension manifests live under
`$APKSCANNER_DATA_DIR/capabilities/`, and hash-pinned scripts under
`$APKSCANNER_DATA_DIR/capability-scripts/`. Python entries run in short-lived Docker sidecars with
no network by default, a read-only root filesystem, and all Linux capabilities dropped. MCP
manifests remain unavailable until an application
adapter explicitly binds them. Control-plane endpoints are under `/api/v1/capabilities/*` and
`/api/v1/supervisor/*`. See
[`docs/codex-docker-architecture.zh-CN.md`](docs/codex-docker-architecture.zh-CN.md). The retired
OpenCode design remains only for historical reference in
[`docs/opencode-deepseek.zh-CN.md`](docs/opencode-deepseek.zh-CN.md).

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `APKSCANNER_DATA_DIR` | `.data` | SQLite, workspaces, APKs, evidence, reports |
| `APKSCANNER_DATABASE_URL` | SQLite in data dir | SQLAlchemy database URL |
| `APKSCANNER_FRONTEND_DIST` | unset | Built frontend directory served by FastAPI |
| `APKSCANNER_ADB_SERIAL` | unset | Remote cloud-device ADB serial |
| `APKSCANNER_ADB_SERIALS` | unset | Comma-separated ADB device pool; investigation concurrency follows the pool size |
| `APKSCANNER_PROBE_APK` | unset | Built Probe APK path |
| `APKSCANNER_ANDROID_SDK_ROOT` | Android SDK env/unset | SDK used for platform-managed Agent PoC builds |
| `APKSCANNER_ANDROID_BUILD_TOOLS_VERSION` | newest installed/unset | Pin one coherent SDK `build-tools/<version>` directory; when unset, compatible aapt2 resource-table failures may retry other installed versions |
| `APKSCANNER_POC_ENABLED` | `true` | Permit validated source or Agent-built prebuilt PoC APKs |
| `APKSCANNER_POC_BUILD_TIMEOUT` | 180 s | Per-command PoC build timeout (30–600 s) |
| `APKSCANNER_POC_MAX_SOURCE_BYTES` | 512 KiB | Platform-managed PoC source-project limit (64 KiB–16 MiB) |
| `APKSCANNER_POC_MAX_APK_BYTES` | 128 MiB | Agent-built prebuilt PoC APK limit |
| `APKSCANNER_POC_COMPILE_API` | `APKSCANNER_ANDROID_API` | Installed SDK platform used to compile PoC Java sources |
| `APKSCANNER_POC_MIN_API` | `21` | Requested PoC minimum API; legacy `dx` raises the effective minimum to 26 |
| `APKSCANNER_POC_TARGET_API` | `APKSCANNER_ANDROID_API` | PoC target SDK used to reproduce the selected Android platform behavior |
| `APKSCANNER_INVESTIGATOR_BACKEND` | `codex` | Default: `codex` or `none` |
| `APKSCANNER_AGENT_PERMISSION_PROFILE` | `personal_lab` | `personal_lab` enables full decompiler access and writable tool analysis; `strict` keeps schema-only analysis |
| `APKSCANNER_CODEX_ENABLED` | `false` | Dispatch Codex investigations |
| `APKSCANNER_CODEX_ISOLATION` | `docker` | `docker` or explicit `host` fallback |
| `APKSCANNER_ALLOW_HOST_CODEX` | `false` | Required second switch for host diagnostics |
| `APKSCANNER_CODEX_DOCKER_IMAGE` | `apk-scanner-codex-worker:0.2.0` | Pinned worker image |
| `APKSCANNER_CODEX_PROVIDER` | `deepseek` | Currently the only accepted provider |
| `APKSCANNER_CODEX_MODEL` | `deepseek-v4-flash` | Currently the only accepted model |
| `APKSCANNER_CODEX_REASONING_EFFORT` | `high` | `low`, `high`, or `max` |
| `APKSCANNER_CODEX_MODEL_CATALOG` | `config/deepseek-models.json` | Pinned DeepSeek model catalog |
| `APKSCANNER_CODEX_WEB_SEARCH` | `live` | Codex Web Search mode; the current contract requires `live` |
| `APKSCANNER_CODEX_MAX_CONTAINERS` | `2` | Global concurrent scan-container limit |
| `APKSCANNER_CODEX_MAX_SESSIONS` | `6` | Global UID-session limit |
| `APKSCANNER_CODEX_MAX_SESSIONS_PER_SCAN` | `3` | Per-scan role-session limit |
| `APKSCANNER_CODEX_UID_MIN` / `APKSCANNER_CODEX_UID_MAX` | `21000` / `21999` | Non-reused session UID pool within a scan |
| `APKSCANNER_CODEX_CPU_LIMIT` / `APKSCANNER_CODEX_MEMORY_LIMIT` | `6` / `12g` | Per-scan container limits |
| `APKSCANNER_CODEX_TURN_TIMEOUT` | 3600 s | Hard timeout for one Codex invocation |
| `APKSCANNER_CODEX_NO_EVENT_TIMEOUT` | 900 s | Silent-worker timeout |
| `APKSCANNER_CODEX_BIN` | bundled SDK runtime | Explicit tested Codex binary override |
| `APKSCANNER_DEEPSEEK_BASE_URL` | DeepSeek default | Optional trusted HTTP(S) gateway |
| `DEEPSEEK_API_KEY` | unset | DeepSeek credential inherited only by the UID worker exec |
| `APKSCANNER_ANDROID_VERSION` | `16` | Reported dynamic baseline |
| `APKSCANNER_ANDROID_API` | `36` | Expected audit-device API and default PoC compile/target API |
| `APKSCANNER_DEVICE_MIN_API` / `APKSCANNER_DEVICE_MAX_API` | `36` / `99` | Verdict-device API range; Android 16+ by default |
| `APKSCANNER_ALLOW_LEGACY_DEVICE_SMOKE` | `false` | Permit a pre-API-36 compatibility smoke device; its evidence cannot produce an Android 16 verdict |
| `APKSCANNER_DEVICE_INSTALL_POLICY` | `install_or_reuse` | `replace`, `install_or_reuse`, or `reuse_installed` target policy |
| `APKSCANNER_DEVICE_RESET_POLICY` | `per_round` | `per_test`, `per_round`, or `never`; each requested test may override it |
| `APKSCANNER_MAX_UPLOAD_BYTES` | 512 MiB | Intake limit |
| `APKSCANNER_TASK_TIMEOUT` | 14400 s | Total investigation-task budget |
| `APKSCANNER_TASK_MAX_ATTEMPTS` | 2 | Retry budget |
| `APKSCANNER_AGENT_MAX_ROUNDS` | ignored | Retained for compatibility; adaptive Agent rounds are not count-capped |
| `APKSCANNER_AGENT_TESTS_PER_ROUND` | 8 | Maximum accepted AI-requested tests per round (1–1000) |

## Verification

```bash
pytest
ruff check backend
cd frontend && npm run lint && npm run build

# Optional: requires root, Docker, and the built pinned image
APKSCANNER_RUN_DOCKER_TESTS=1 pytest -q backend/tests/test_codex_executor.py
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
- v1 covers one APK, one dedicated Android test device, and `pm clear` rather than a
  full device snapshot.
- The Codex worker gets read-only scan inputs and a writable per-role workspace under a distinct
  UID. The Codex sandbox is full access inside the container. No device or Docker socket is mounted.
- Agent containers still have outbound networking for their selected model provider. Restrict each
  worker's egress to the approved provider/gateway before a team deployment.
- DeepSeek receives the bounded task context and evidence summaries. Confirm company data handling,
  retention, region, and gateway policy before enabling it for production APKs.
