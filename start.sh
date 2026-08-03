#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNTIME_DIR="${APKSCANNER_RUNTIME_DIR:-$PROJECT_DIR/.data/run}"
DATA_DIR="${APKSCANNER_DATA_DIR:-$PROJECT_DIR/.data}"
if [[ "$DATA_DIR" != /* ]]; then
  DATA_DIR="$PROJECT_DIR/$DATA_DIR"
fi
PID_FILE="$RUNTIME_DIR/scanctl.pid"

mkdir -p "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"

build_frontend() {
  local frontend_dir="$PROJECT_DIR/frontend"
  if ! command -v npm >/dev/null 2>&1; then
    echo "npm is required to build the APKScanner frontend" >&2
    exit 1
  fi
  if [ ! -d "$frontend_dir/node_modules" ]; then
    npm ci --prefix "$frontend_dir"
  fi
  npm run build --prefix "$frontend_dir"
  if [ ! -f "$frontend_dir/dist/index.html" ]; then
    echo "frontend build completed without dist/index.html" >&2
    exit 1
  fi
}

stop_existing() {
  if [ ! -f "$PID_FILE" ]; then
    return
  fi
  local pid command_line
  pid="$(tr -d '[:space:]' <"$PID_FILE")"
  if ! [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
    echo "invalid PID file: $PID_FILE" >&2
    exit 1
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$PID_FILE"
    return
  fi
  command_line="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
  if [[ "$command_line" != *"scanctl"*"serve"* ]]; then
    echo "refusing to stop PID $pid because it is not scanctl serve" >&2
    exit 1
  fi
  kill -TERM "$pid"
  for _ in $(seq 1 20); do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$PID_FILE"
      return
    fi
    sleep 0.5
  done
  kill -KILL "$pid" 2>/dev/null || true
  rm -f "$PID_FILE"
}

resolve_host_adb() {
  local explicit="${APKSCANNER_HOST_ADB:-}"
  local candidate resolved version_output
  local -a candidates=()

  if [ -n "$explicit" ]; then
    if [[ "$explicit" != /* ]]; then
      echo "APKSCANNER_HOST_ADB must be an absolute executable path" >&2
      return 1
    fi
    candidates+=("$explicit")
  else
    [ -n "${ANDROID_SDK_ROOT:-}" ] && candidates+=("$ANDROID_SDK_ROOT/platform-tools/adb")
    [ -n "${ANDROID_HOME:-}" ] && candidates+=("$ANDROID_HOME/platform-tools/adb")
    candidates+=("/usr/local/bin/adb" "/usr/bin/adb")
    candidate="$(command -v adb 2>/dev/null || true)"
    [ -n "$candidate" ] && candidates+=("$candidate")
  fi

  for candidate in "${candidates[@]}"; do
    [ -x "$candidate" ] || continue
    version_output="$("$candidate" version 2>&1 || true)"
    [[ "$version_output" == *"Android Debug Bridge version"* ]] || continue
    resolved="$(readlink -f "$candidate" 2>/dev/null || true)"
    printf '%s\n' "${resolved:-$candidate}"
    return 0
  done
  return 1
}

detect_adb_serials() {
  local -a devices=()
  local attempt
  for attempt in $(seq 1 5); do
    mapfile -t devices < <(
      "$APKSCANNER_HOST_ADB" devices 2>/dev/null |
        awk 'NR > 1 && $2 == "device" { print $1 }'
    )
    if [ "${#devices[@]}" -gt 0 ]; then
      local joined
      joined="$(IFS=,; echo "${devices[*]}")"
      printf '%s\n' "$joined"
      return
    fi
    sleep 1
  done
  echo "no ADB device became ready during startup; device tasks will use static-only mode" >&2
}

# Build before stopping the running service. A failed frontend build therefore
# cannot replace a working process or silently leave FastAPI serving an old bundle.
if resolved_host_adb="$(resolve_host_adb)"; then
  export APKSCANNER_HOST_ADB="$resolved_host_adb"
  echo "host adb: $APKSCANNER_HOST_ADB"
elif [ -n "${APKSCANNER_HOST_ADB:-}" ]; then
  echo "configured APKSCANNER_HOST_ADB is not a real Android platform-tools adb" >&2
  exit 1
else
  export APKSCANNER_HOST_ADB="/nonexistent/apkscanner-host-adb"
  echo "real host adb was not found; device tasks will use static-only mode" >&2
fi
build_frontend
stop_existing

: "${DEEPSEEK_API_KEY:?set DEEPSEEK_API_KEY in the caller environment}"
export APKSCANNER_CODEX_ENABLED="${APKSCANNER_CODEX_ENABLED:-true}"
export APKSCANNER_INVESTIGATOR_BACKEND="${APKSCANNER_INVESTIGATOR_BACKEND:-codex}"
export APKSCANNER_CODEX_ISOLATION="${APKSCANNER_CODEX_ISOLATION:-docker}"
export APKSCANNER_CODEX_PROVIDER="${APKSCANNER_CODEX_PROVIDER:-deepseek}"
export APKSCANNER_CODEX_MODEL="${APKSCANNER_CODEX_MODEL:-deepseek-v4-flash}"
export APKSCANNER_AGENT_PERMISSION_PROFILE="personal_lab"
export APKSCANNER_ADB_SERIALS="${APKSCANNER_ADB_SERIALS:-$(detect_adb_serials)}"
export APKSCANNER_ADB_SERIAL="${APKSCANNER_ADB_SERIAL:-${APKSCANNER_ADB_SERIALS%%,*}}"
export APKSCANNER_DEVICE_INSTALL_POLICY="install_or_reuse"
export APKSCANNER_DEVICE_RESET_POLICY="per_round"
export APKSCANNER_FRONTEND_DIST="$PROJECT_DIR/frontend/dist"
export APKSCANNER_TASK_TIMEOUT="${APKSCANNER_TASK_TIMEOUT:-3600}"

nohup setsid env \
  DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
  APKSCANNER_CODEX_ENABLED="$APKSCANNER_CODEX_ENABLED" \
  APKSCANNER_INVESTIGATOR_BACKEND="$APKSCANNER_INVESTIGATOR_BACKEND" \
  APKSCANNER_CODEX_ISOLATION="$APKSCANNER_CODEX_ISOLATION" \
  APKSCANNER_CODEX_PROVIDER="$APKSCANNER_CODEX_PROVIDER" \
  APKSCANNER_CODEX_MODEL="$APKSCANNER_CODEX_MODEL" \
  APKSCANNER_AGENT_PERMISSION_PROFILE="$APKSCANNER_AGENT_PERMISSION_PROFILE" \
  APKSCANNER_HOST_ADB="$APKSCANNER_HOST_ADB" \
  APKSCANNER_ADB_SERIAL="$APKSCANNER_ADB_SERIAL" \
  APKSCANNER_ADB_SERIALS="$APKSCANNER_ADB_SERIALS" \
  APKSCANNER_DEVICE_INSTALL_POLICY="$APKSCANNER_DEVICE_INSTALL_POLICY" \
  APKSCANNER_DEVICE_RESET_POLICY="$APKSCANNER_DEVICE_RESET_POLICY" \
  APKSCANNER_FRONTEND_DIST="$APKSCANNER_FRONTEND_DIST" \
  APKSCANNER_TASK_TIMEOUT="$APKSCANNER_TASK_TIMEOUT" \
  scanctl serve \
  </dev/null >/tmp/apkscanner.log 2>&1 &

SERVICE_PID=$!
umask 077
printf '%s\n' "$SERVICE_PID" >"$PID_FILE"
echo "started PID=$SERVICE_PID"
for i in $(seq 1 10); do
  sleep 1
  result=$(curl -s --connect-timeout 1 --max-time 3 \
    http://127.0.0.1:8000/api/v1/health 2>/dev/null || true)
  if [ -n "$result" ]; then
    echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'status={d[\"status\"]} enabled={d[\"enabled_investigators\"]}')" 2>/dev/null && break
  fi
  if [ "$i" -eq 10 ]; then
    echo "startup timeout" >&2
    kill -TERM "$SERVICE_PID" 2>/dev/null || true
    rm -f "$PID_FILE"
    exit 1
  fi
done
echo "http://$(hostname -I | awk '{print $1}'):8000"
