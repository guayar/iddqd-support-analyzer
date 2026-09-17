#!/usr/bin/env bash
# Alias for ./run-light.sh (IDDQD Support Analyzer Light).
set -euo pipefail
cd "$(dirname "$0")"
exec ./run-light.sh
