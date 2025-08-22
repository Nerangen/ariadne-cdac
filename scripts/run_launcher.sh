set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p logs
: > logs/run.log

# Start launcher (DEBUG for visibility) and tee to log; run in background
stdbuf -oL ./launcher/launcher_secure examples/app.enc examples/aes.key --debug | tee -a logs/run.log &
LAUNCHER_SHELL_PID=$!

echo "[run_launcher] waiting for payload PID from launcher output..."
for i in {1..50}; do
  if grep -qE '\(PID=[0-9]+\)' logs/run.log; then
    break
  fi
  sleep 0.2
done

PAYLOAD_PID="$(grep -oE 'PID=[0-9]+' logs/run.log | tail -1 | cut -d= -f2 || true)"

if [[ -z "${PAYLOAD_PID:-}" ]]; then
  echo "[run_launcher] ERROR: couldn't detect payload PID. See logs/run.log"
  exit 1
fi

echo "$PAYLOAD_PID" > logs/payload.pid
echo "[run_launcher] detected payload PID=$PAYLOAD_PID"
echo "[run_launcher] launcher shell pid=$LAUNCHER_SHELL_PID (for reference)"
echo "[run_launcher] tail live logs with: tail -f logs/run.log"
