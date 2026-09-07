#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")"

if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi

PORT="${APP_PORT:-7860}"
URL="http://127.0.0.1:${PORT}"

echo "========================================"
echo "  IDDQD Support Analyzer"
echo "========================================"
echo
echo "Starting at $URL"
echo "Press Ctrl+C to stop."
echo

# If the application is already running, just open it.
if command -v curl >/dev/null 2>&1 && curl -fsS "$URL" >/dev/null 2>&1; then
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 || true
  fi
  echo "IDDQD Support Analyzer is already running at $URL"
  echo
  echo "Press Enter to close this window."
  read -r
  exit 0
fi

# Open the browser once the local UI becomes reachable.
(
  for _ in $(seq 1 120); do
    if command -v curl >/dev/null 2>&1 && curl -fsS "$URL" >/dev/null 2>&1; then
      if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$URL" >/dev/null 2>&1 || true
      fi
      exit 0
    fi
    sleep 1
  done
) &

./run.sh
status=$?

echo
if [[ $status -ne 0 ]]; then
  echo "Start failed (exit $status)."
  echo "If this is after an update, run: ./update.sh"
fi
echo "Press Enter to close this window."
read -r
exit "$status"
