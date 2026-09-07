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
  .venv/bin/python -m pip install -r requirements.txt
fi

echo "IDDQD Support Analyzer is up to date."
