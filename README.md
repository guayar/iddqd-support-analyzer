# IDDQD Support Analyzer

[![Tests](https://github.com/guayar/iddqd-support-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/guayar/iddqd-support-analyzer/actions/workflows/tests.yml)

Local troubleshooting toolkit for SAML/SSO, protocol validation, metadata analysis, log files, anonymization, support writing and coding assistance.

**Current version:** `0.9.0`

The project is designed for local-first technical support workflows. Deterministic parsers and validators handle protocol checks and structured extraction; local inference can be used for explanation, report drafting and coding assistance. Web access is isolated in a separate General Chat tab and is never used automatically by the Analyzer or local Assistant.

## Features

### SAML / SSO analysis

- raw `AuthnRequest`, `Response` and standalone `Assertion` XML
- HTTP-POST Base64 decoding
- HTTP-Redirect URL decoding, Base64 decoding and raw-DEFLATE decompression
- SP and IdP metadata parsing (`EntityDescriptor` / `EntitiesDescriptor`)
- full Response and Assertion field extraction
- Subject / NameID / SubjectConfirmation analysis
- AudienceRestriction and Conditions analysis
- AuthnStatement, session and AuthnContext extraction
- attribute extraction, including multi-valued attributes
- signature presence and XML Signature structure inspection
- certificate fingerprints from SAML metadata
- protocol/profile validation with structured error codes
- cross-document checks across Request ↔ Response ↔ Assertion ↔ SP metadata ↔ IdP metadata

Examples of validator findings:

```text
RESPONSE_ID_MISSING
STATUS_MISSING
NAMEID_EMAIL_FORMAT_INVALID
BEARER_RECIPIENT_ACS_MISMATCH
AUDIENCE_SP_ENTITYID_MISMATCH
DUPLICATE_SAML_ID
XML_NOT_WELL_FORMED
```

Cryptographic XML Signature verification against trusted metadata certificates is not implemented yet. The current validator inspects signature presence and structure only.

### Log analysis

- timestamp range detection
- severity counts
- error/status code extraction
- grouped error events and stack traces
- `Caused by` chain extraction
- first occurrence and representative samples

### Anonymization

Pattern-based local pseudonymization for common sensitive values, including:

- IPv4 / IPv6
- hostnames and domains
- e-mail addresses
- MAC addresses
- UUIDs
- JWTs and Authorization headers
- passwords, tokens, API keys and session identifiers
- sensitive URL query parameters

Stable pseudonyms are used within a single run so repeated values remain correlatable. The anonymizer is not a certified DLP product; generated output should still be reviewed before external sharing.

### Local Assistant

Separate local modes for:

- general technical assistance
- enterprise support mail drafting
- Java / TypeScript / Python / Playwright coding help

The Assistant has no web-search path.

### General Chat

A deliberately separate web-enabled chat. It receives no Analyzer or local Assistant context. Search queries are generated locally, sent to public search providers through `ddgs`, and the returned pages are summarized by the local model.

## Privacy model

| Area | Local model | Web access | Intended data |
|---|---:|---:|---|
| Analyze | Yes | No | Logs, SAML traces, metadata |
| Anonymize log | No model required | No | Sensitive logs |
| Assistant | Yes | No | Technical/support material |
| General Chat | Yes | Yes | Non-sensitive public questions |

The application binds to `127.0.0.1` by default and blocks non-local model endpoints unless explicitly enabled.

## Requirements

- Ubuntu / Linux
- Python 3.12+
- Ollama
- a locally installed text model (default configuration: `qwen3.6:27b`)

## Quick start

```bash
git clone https://github.com/guayar/iddqd-support-analyzer.git
cd iddqd-support-analyzer
cp config.example.env .env
./run.sh
```

`run.sh` creates a local `.venv`, installs dependencies there and starts the application.

Default UI:

```text
http://127.0.0.1:7860
```

## Configuration

`config.example.env` contains the supported environment variables. Common settings:

```text
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen3.6:27b
ALLOW_REMOTE_LLM=false
APP_PORT=7860
MAX_FILE_MB=150
```

Web-enabled General Chat settings:

```text
WEB_SEARCH_RESULTS=6
WEB_FETCH_RESULTS=3
WEB_FETCH_CHARS=16000
WEB_SEARCH_REGION=wt-wt
```

Optional basic authentication can be enabled with `BASIC_AUTH_USER` and `BASIC_AUTH_PASS`.

## Running tests

```bash
source .venv/bin/activate
PYTHONPATH=. python tests/test_analyzers.py
```

The tests use synthetic SAML and log data only.

## Project structure

```text
.
├── analyzers/
│   ├── anonymizer.py
│   ├── logs.py
│   ├── saml.py
│   └── saml_validation.py
├── tests/
│   └── test_analyzers.py
├── .github/workflows/
│   └── tests.yml
├── app.py
├── config.example.env
├── requirements.txt
├── run.sh
├── CHANGELOG.md
└── VERSION
```

## Versioning

The project uses semantic versioning while it is pre-1.0. New functionality increments the minor version (`0.9.0` → `0.10.0`); bug fixes increment the patch version (`0.9.0` → `0.9.1`).
