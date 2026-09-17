#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Local tracked changes detected. Commit or stash them before updating."
  exit 1
fi

echo "Fetching updates..."
git fetch origin main
git pull --ff-only origin main

if [[ -x .venv/bin/python ]]; then
  echo "Refreshing Python dependencies..."
  REQ=requirements.txt
  if [[ -f .env ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
  fi
  if [[ "${IDDQD_EDITION:-}" == "core" || "${IDDQD_EDITION:-}" == "light" || -f LIGHT_EDITION || -f CORE_EDITION ]]; then
    REQ=requirements-core.txt
  fi
  .venv/bin/python -m pip install -r "$REQ"
fi

if [[ "${IDDQD_EDITION:-}" == "core" || "${IDDQD_EDITION:-}" == "light" || -f LIGHT_EDITION || -f CORE_EDITION ]]; then
  echo "IDDQD Support Analyzer Light is up to date."
else
  echo "IDDQD Support Analyzer is up to date."
fi
