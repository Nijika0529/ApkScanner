#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNTIME_DIR="${APKSCANNER_RUNTIME_DIR:-$PROJECT_DIR/.data/run}"
PID_FILE="$RUNTIME_DIR/scanctl.pid"

mkdir -p "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"

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

stop_existing

export DEEPSEEK_API_KEY="DEEPSEEK_API_KEY_REMOVED"
export APKSCANNER_OPENCODE_ENABLED="true"
export APKSCANNER_INVESTIGATOR_BACKEND="opencode"
export APKSCANNER_OPENCODE_ISOLATION="host"
export APKSCANNER_OPENCODE_MODEL="deepseek-v4-flash"
export APKSCANNER_OPENCODE_THINKING_EXPLORER="false"
export APKSCANNER_ADB_SERIAL="10.170.97.154:23641"
export APKSCANNER_FRONTEND_DIST="$PROJECT_DIR/frontend/dist"
export APKSCANNER_TASK_TIMEOUT="${APKSCANNER_TASK_TIMEOUT:-3600}"

nohup setsid env \
  DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
  APKSCANNER_OPENCODE_ENABLED="$APKSCANNER_OPENCODE_ENABLED" \
  APKSCANNER_INVESTIGATOR_BACKEND="$APKSCANNER_INVESTIGATOR_BACKEND" \
  APKSCANNER_OPENCODE_ISOLATION="$APKSCANNER_OPENCODE_ISOLATION" \
  APKSCANNER_OPENCODE_MODEL="$APKSCANNER_OPENCODE_MODEL" \
  APKSCANNER_OPENCODE_THINKING_EXPLORER="$APKSCANNER_OPENCODE_THINKING_EXPLORER" \
  APKSCANNER_ADB_SERIAL="$APKSCANNER_ADB_SERIAL" \
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
