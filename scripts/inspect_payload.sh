#!/usr/bin/env bash
# scripts/inspect_payload.sh
# Usage: ./scripts/inspect_payload.sh <name>  # example: my_app

set -euo pipefail
name="${1:-my_app}"

# wait for the process to appear (timeout 120s)
echo "[inspect] waiting for process name='$name' (timeout 120s)..."
end=$((SECONDS+120))
PID=""
while [ $SECONDS -lt $end ]; do
  PID=$(pgrep -x "$name" || true)
  if [ -n "$PID" ]; then break; fi
  sleep 0.1
done

if [ -z "$PID" ]; then
  echo "[inspect] ERROR: process '$name' not found after timeout"
  exit 2
fi

echo "[inspect] PID=$PID"

echo "[inspect] ls -l /proc/$PID/fd"
ls -l /proc/$PID/fd 2>/dev/null || echo "[inspect] /proc/$PID/fd not accessible"

echo "[inspect] /proc/$PID/maps grep memfd"
cat /proc/$PID/maps 2>/dev/null | grep -i memfd || echo "[inspect] memfd entry not found in /proc/$PID/maps"

echo "[inspect] lsof (may require sudo)"
if command -v lsof >/dev/null 2>&1; then
  sudo lsof -p "$PID" 2>/dev/null | grep -i memfd || echo "[inspect] lsof: no memfd found (or not visible)"
else
  echo "[inspect] lsof not installed; skipping"
fi

echo "[inspect] ps -p $PID -o pid,comm,args"
ps -p "$PID" -o pid,comm,args

echo "[inspect] done"
