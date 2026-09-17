#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi
if [[ "${FORCE_CORE:-}" == "1" || "${FORCE_LIGHT:-}" == "1" ]]; then
  export IDDQD_EDITION=light
fi
if [[ -z "${IDDQD_EDITION:-}" && ( -f LIGHT_EDITION || -f CORE_EDITION ) ]]; then
  export IDDQD_EDITION=light
fi
REQ=requirements.txt
case "${IDDQD_EDITION:-full}" in
  core|light)
    export IDDQD_EDITION=light
    REQ=requirements-core.txt
    ;;
esac
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -r "$REQ"
fi
exec .venv/bin/python app.py
