# IDDQD Support Analyzer

[![Tests](https://github.com/guayar/iddqd-support-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/guayar/iddqd-support-analyzer/actions/workflows/tests.yml)

**Current version:** `0.17.2`

Local workstation tool for SAML/SSO and `*.log` troubleshooting. The core **Analyze** path is deterministic and does not use an LLM. Optional modules (anonymize, local chat) load from **Config** after a restart. Early-stage; built for my Ubuntu workstation, not a packaged product.

I own the requirements, validation rules, tests and spec interpretation; implementation is AI-assisted.

## What it does

- **Analyze** — SAML decoding (POST/Redirect), protocol/profile checks, XML signatures, metadata trust and Request/Response/Assertion correlation; Java/Maven/OpenSSH logs, Oracle alert stamps/vendor codes, and `[ts] [error]` records
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
- [Third-party test data](docs/THIRD_PARTY_TEST_DATA.md)
- [Changelog](CHANGELOG.md)
