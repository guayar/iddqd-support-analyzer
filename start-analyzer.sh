#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi

PORT="${APP_PORT:-7860}"
URL="http://127.0.0.1:${PORT}"

# If the application is already running, just open it.
if command -v curl >/dev/null 2>&1 && curl -fsS "$URL" >/dev/null 2>&1; then
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 || true
  fi
  echo "IDDQD Support Analyzer is already running at $URL"
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

exec ./run.sh
