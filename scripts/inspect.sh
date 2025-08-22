set -euo pipefail

# Auto-elevate (WSL commonly requires root to read /proc/<pid>/fd and maps)
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

cd "$(dirname "$0")/.."

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [PID]  (if PID omitted, reads logs/payload.pid)"; exit 2
fi

if [[ $# -eq 1 ]]; then
  PID="$1"
else
  if [[ ! -s logs/payload.pid ]]; then
    echo "No PID provided and logs/payload.pid not found. Run scripts/run_launcher.sh first."
    exit 2
  fi
  PID="$(cat logs/payload.pid)"
fi

echo "== Inspecting PID=$PID =="

echo "-- ps --"
ps -p "$PID" -o pid,comm,args,etimes || { echo "not running"; exit 1; }

echo "-- /proc/$PID/fd --"
ls -l "/proc/$PID/fd" || true

echo "-- maps (grep memfd) --"
grep -i memfd "/proc/$PID/maps" || echo "no memfd label (WSL often hides it; that's OK)"

echo "-- exe & cmdline --"
readlink -f "/proc/$PID/exe" || true
tr '\0' ' ' < "/proc/$PID/cmdline"; echo
