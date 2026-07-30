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

cleanup_orphan_opencode_servers() {
  local proc_dir pid parent_pid command_line process_cwd
  local -a targets=()
  for proc_dir in /proc/[1-9]*; do
    [ -r "$proc_dir/status" ] || continue
    pid="${proc_dir##*/}"
    parent_pid="$(awk '/^PPid:/{print $2}' "$proc_dir/status" 2>/dev/null || true)"
    [ "$parent_pid" = "1" ] || continue
    command_line="$(tr '\0' ' ' <"$proc_dir/cmdline" 2>/dev/null || true)"
    [[ "$command_line" == *"opencode"*"serve"* ]] || continue
    process_cwd="$(readlink "$proc_dir/cwd" 2>/dev/null || true)"
    case "$process_cwd/" in
      "$DATA_DIR/workspaces/"*) targets+=("$pid") ;;
    esac
  done
  [ "${#targets[@]}" -gt 0 ] || return 0
  kill -TERM "${targets[@]}" 2>/dev/null || true
  sleep 1
  for pid in "${targets[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  done
  echo "cleaned ${#targets[@]} orphaned OpenCode server(s) from this project"
}

detect_adb_serial() {
  local -a devices=()
  local attempt
  for attempt in $(seq 1 5); do
    mapfile -t devices < <(
      adb devices 2>/dev/null |
        awk 'NR > 1 && $2 == "device" { print $1 }'
    )
    if [ "${#devices[@]}" -eq 1 ]; then
      printf '%s\n' "${devices[0]}"
      return
    fi
    if [ "${#devices[@]}" -gt 1 ]; then
      echo "multiple ADB devices are online; set APKSCANNER_ADB_SERIAL explicitly" >&2
      return
    fi
    sleep 1
  done
  echo "no ADB device became ready during startup; device tasks will use static-only mode" >&2
}

# Build before stopping the running service. A failed frontend build therefore
# cannot replace a working process or silently leave FastAPI serving an old bundle.
build_frontend
stop_existing
cleanup_orphan_opencode_servers

export DEEPSEEK_API_KEY="DEEPSEEK_API_KEY_REMOVED"
export APKSCANNER_OPENCODE_ENABLED="true"
export APKSCANNER_INVESTIGATOR_BACKEND="opencode"
export APKSCANNER_OPENCODE_ISOLATION="host"
export APKSCANNER_OPENCODE_MODEL="deepseek-v4-flash"
export APKSCANNER_OPENCODE_CRITIC_MODEL="deepseek-v4-pro"
export APKSCANNER_OPENCODE_THINKING_EXPLORER="false"
export APKSCANNER_AGENT_PERMISSION_PROFILE="personal_lab"
export APKSCANNER_ADB_SERIAL="${APKSCANNER_ADB_SERIAL:-$(detect_adb_serial)}"
export APKSCANNER_DEVICE_INSTALL_POLICY="install_or_reuse"
export APKSCANNER_DEVICE_RESET_POLICY="per_round"
export APKSCANNER_FRONTEND_DIST="$PROJECT_DIR/frontend/dist"
export APKSCANNER_TASK_TIMEOUT="${APKSCANNER_TASK_TIMEOUT:-3600}"

nohup setsid env \
  DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
  APKSCANNER_OPENCODE_ENABLED="$APKSCANNER_OPENCODE_ENABLED" \
  APKSCANNER_INVESTIGATOR_BACKEND="$APKSCANNER_INVESTIGATOR_BACKEND" \
  APKSCANNER_OPENCODE_ISOLATION="$APKSCANNER_OPENCODE_ISOLATION" \
  APKSCANNER_OPENCODE_MODEL="$APKSCANNER_OPENCODE_MODEL" \
  APKSCANNER_OPENCODE_CRITIC_MODEL="$APKSCANNER_OPENCODE_CRITIC_MODEL" \
  APKSCANNER_OPENCODE_THINKING_EXPLORER="$APKSCANNER_OPENCODE_THINKING_EXPLORER" \
  APKSCANNER_AGENT_PERMISSION_PROFILE="$APKSCANNER_AGENT_PERMISSION_PROFILE" \
  APKSCANNER_ADB_SERIAL="$APKSCANNER_ADB_SERIAL" \
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
