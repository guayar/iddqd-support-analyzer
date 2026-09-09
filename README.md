# IDDQD Support Analyzer

[![Tests](https://github.com/guayar/iddqd-support-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/guayar/iddqd-support-analyzer/actions/workflows/tests.yml)

**Current version:** `0.13.11`

Local workstation tool for SAML/SSO and `*.log` troubleshooting. The core **Analyze** path is deterministic (no Ollama). Optional modules load from **Config** after a restart. Early-stage, for a private Ubuntu box — not a packaged product.

## What it does

- **Analyze** — decode SAML (POST/Redirect), check protocol/profile rules, XML signatures and metadata trust, correlate Request/Response/Assertion/metadata, parse Java/Maven-style logs, copy or clear the report
- **Anonymize** — local pseudonymization of logs and SAML so a copy can be shared (not DLP; review the residual leak scan)
- **Assistant** — local Ollama only: support/tech help, screenshots + OCR, latest Analyze JSON; no web search
- **General Chat** — separate module: local by default; public web search only when the turn needs current/external info

Default tabs: Analyze + Config. Order with everything on: Analyze → Anonymize → Assistant → General Chat → Config.

| Tab | Model | Web |
|---|---|---|
| Analyze / Anonymize / Config | No | No |
| Assistant | Local Ollama | No |
| General Chat | Local Ollama | Yes (search queries) |

## Start

```bash
git clone https://github.com/guayar/iddqd-support-analyzer.git
cd iddqd-support-analyzer
cp config.example.env .env
./run.sh
```

UI: `http://127.0.0.1:7860`. Desktop: `./start-analyzer.sh`. Update a checkout: `./update.sh`.

Analyze needs Python 3.12+ and `./run.sh`. Assistant / General Chat also need [Ollama](https://ollama.com) and `OLLAMA_MODEL`. OCR is optional Tesseract. Details: [docs/USER.md](docs/USER.md#requirements).

## Docs

- [User guide](docs/USER.md) — modules, prerequisites, config, limitations, tests
- [Architecture](docs/ARCHITECTURE.md)
- [Changelog](CHANGELOG.md)
