#!/usr/bin/env bash
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

pkill -9 scanctl 2>/dev/null || true
sleep 1

export DEEPSEEK_API_KEY="DEEPSEEK_API_KEY_REMOVED"
export APKSCANNER_OPENCODE_ENABLED="true"
export APKSCANNER_INVESTIGATOR_BACKEND="opencode"
export APKSCANNER_OPENCODE_ISOLATION="host"
export APKSCANNER_ADB_SERIAL="10.170.97.154:23641"
export APKSCANNER_FRONTEND_DIST="$PROJECT_DIR/frontend/dist"

nohup env \
  DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
  APKSCANNER_OPENCODE_ENABLED="$APKSCANNER_OPENCODE_ENABLED" \
  APKSCANNER_INVESTIGATOR_BACKEND="$APKSCANNER_INVESTIGATOR_BACKEND" \
  APKSCANNER_OPENCODE_ISOLATION="$APKSCANNER_OPENCODE_ISOLATION" \
  APKSCANNER_ADB_SERIAL="$APKSCANNER_ADB_SERIAL" \
  APKSCANNER_FRONTEND_DIST="$APKSCANNER_FRONTEND_DIST" \
  scanctl serve \
  </dev/null >/tmp/apkscanner.log 2>&1 &

echo "started PID=$!"
for i in $(seq 1 10); do
  sleep 1
  result=$(curl -s http://127.0.0.1:8000/api/v1/health 2>/dev/null)
  if [ -n "$result" ]; then
    echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'status={d[\"status\"]} enabled={d[\"enabled_investigators\"]}')" 2>/dev/null && break
  fi
  [ "$i" -eq 10 ] && echo "startup timeout" && exit 1
done
echo "http://$(hostname -I | awk '{print $1}'):8000"
