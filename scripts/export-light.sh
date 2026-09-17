#!/usr/bin/env bash
# Pack IDDQD Support Analyzer Light (no LLM) as dist/iddqd-support-analyzer-light-$VERSION.zip
set -euo pipefail
cd "$(dirname "$0")"
exec ./export-core.sh
